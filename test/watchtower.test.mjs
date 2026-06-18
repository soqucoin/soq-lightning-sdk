// watchtower.ts — TowerClient against a mock tower + the §1.6 persist→arm→ack ordering
// enforced by SoqLightning.pay() (arm BEFORE returning; failed arm fails the payment).
import { test } from "node:test";
import assert from "node:assert/strict";
import { TowerClient, TowerError, SoqLightning, DilithiumEltooBuilder } from "../dist/index.js";

// mock tower mirroring watchtower/api.go (Bearer auth on register/unregister/channels)
function mockTower({ token = "secret" } = {}) {
  const watched = new Map();
  let checks = 0;
  const calls = [];
  const ok = (o) => new Response(JSON.stringify(o), { status: 200, headers: { "content-type": "application/json" } });
  const fetchImpl = async (url, init) => {
    const path = new URL(url).pathname;
    const auth = init?.headers?.authorization ?? init?.headers?.Authorization;
    const body = init?.body ? JSON.parse(init.body) : {};
    const needsAuth = path !== "/api/v1/tower/status" && path !== "/health";
    if (needsAuth && auth !== `Bearer ${token}`) return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 });
    calls.push({ path, body });
    if (path === "/api/v1/tower/register") {
      // idempotent, newest state wins (tower.go Register semantics)
      const prev = watched.get(body.channel_id);
      if (prev && body.state_index < prev.state_index) return new Response(JSON.stringify({ error: "stale state" }), { status: 400 });
      watched.set(body.channel_id, { ...body, registered_at: "t", last_checked: "t", triggered: false, trigger_txid: "" });
      return ok({ status: "registered", channel_id: body.channel_id, state_index: body.state_index });
    }
    if (path === "/api/v1/tower/unregister") { watched.delete(body.channel_id); return ok({ status: "unregistered", channel_id: body.channel_id }); }
    if (path === "/api/v1/tower/status") return ok({ watched_channels: watched.size, total_checks: checks, total_triggers: 0, last_check: "t", poll_interval: "30s", sla_blocks: 6 });
    if (path === "/api/v1/tower/channels") return ok({ count: watched.size, channels: [...watched.values()] });
    if (path === "/health") return ok({ status: "ok", service: "soq-lightning-watchtower", watched_channels: watched.size });
    return new Response("not found", { status: 404 });
  };
  return { fetchImpl, watched, calls };
}

const reg = (over = {}) => ({
  channel_id: "ch1", funding_txid: "ab".repeat(32), funding_vout: 0, state_index: 1,
  update_tx_hex: "00", settlement_tx_hex: "01", ctv_hash: "ef".repeat(32), ...over,
});

test("TowerClient register/status/channels/unregister", async () => {
  const m = mockTower();
  const c = new TowerClient({ baseUrl: "https://tower", bearerToken: "secret", fetchImpl: m.fetchImpl });
  const r = await c.register(reg());
  assert.equal(r.status, "registered");
  assert.equal(r.state_index, 1);
  const st = await c.status();
  assert.equal(st.watched_channels, 1);
  assert.equal(st.sla_blocks, 6);
  const list = await c.channels();
  assert.equal(list.count, 1);
  assert.equal(list.channels[0].channel_id, "ch1");
  await c.unregister("ch1");
  assert.equal((await c.status()).watched_channels, 0);
});

test("TowerClient: register without token → 401", async () => {
  const m = mockTower();
  const c = new TowerClient({ baseUrl: "https://tower", fetchImpl: m.fetchImpl }); // no token
  await assert.rejects(() => c.register(reg()), (e) => e instanceof TowerError && e.status === 401);
  // but public status works without a token
  assert.equal((await c.status()).watched_channels, 0);
});

test("TowerClient: stale re-arm rejected (newest state wins)", async () => {
  const m = mockTower();
  const c = new TowerClient({ baseUrl: "https://tower", bearerToken: "secret", fetchImpl: m.fetchImpl });
  await c.register(reg({ state_index: 5 }));
  await assert.rejects(() => c.register(reg({ state_index: 3 })), /stale/);
  await c.register(reg({ state_index: 6 })); // forward is fine
  assert.equal((await c.channels()).channels[0].state_index, 6);
});

// ---- SoqLightning integration: persist → arm → ack ordering ----
function lspMock() {
  const ch = { channel_id: "c1", capacity_sat: 100_000_000, initiator_balance_sat: 100_000_000, peer_balance_sat: 0, state_index: 0, state: "open", csv_delay: 288 };
  const ok = (o) => new Response(JSON.stringify(o), { status: 200, headers: { "content-type": "application/json" } });
  return async (url, init) => {
    const path = new URL(url).pathname;
    if (path === "/v1/channels/c1/update") {
      const b = JSON.parse(init.body); ch.state_index = b.state_index; ch.initiator_balance_sat = b.initiator_balance_sat; ch.peer_balance_sat = b.peer_balance_sat;
      return ok({ accepted: true, echo: { state_index: b.state_index, initiator_balance_sat: b.initiator_balance_sat, peer_balance_sat: b.peer_balance_sat } });
    }
    return ok(ch);
  };
}
const builder = () => new DilithiumEltooBuilder({
  funding: { txid: new Uint8Array(32).fill(0xaa), n: 0 }, fundingAmountSat: 100_000_000n,
  initiatorPub: new Uint8Array(1312).fill(1), peerPub: new Uint8Array(1312).fill(2),
  initiatorScriptPubKey: Uint8Array.of(0x51), peerScriptPubKey: Uint8Array.of(0x52),
  secretKey: new Uint8Array(32), mldsa: { sign: () => new Uint8Array(2420).fill(9), verify: () => true },
});

test("pay() arms the watchtower with state i+1 (real signed hex)", async () => {
  const m = mockTower();
  const tower = new TowerClient({ baseUrl: "https://tower", bearerToken: "secret", fetchImpl: m.fetchImpl });
  const ln = new SoqLightning({
    baseUrl: "https://lsp", fetchImpl: lspMock(), txBuilder: builder(),
    watchtower: { client: tower, fundingFor: () => ({ funding_txid: "cd".repeat(32), funding_vout: 0 }) },
  });
  await ln.pay("c1", 30_000_000);
  const armed = m.watched.get("c1");
  assert.ok(armed, "tower was armed");
  assert.equal(armed.state_index, 1, "armed with the NEW state");
  assert.notEqual(armed.update_tx_hex, "placeholder", "armed with real signed update hex");
  assert.equal(armed.funding_txid, "cd".repeat(32));
  // ordering: register call must have happened (proves arm-before-return)
  assert.ok(m.calls.some((c) => c.path === "/api/v1/tower/register"));
});

test("pay() FAILS the payment if arming fails (no silent theft window)", async () => {
  const m = mockTower({ token: "secret" });
  const tower = new TowerClient({ baseUrl: "https://tower", bearerToken: "WRONG", fetchImpl: m.fetchImpl });
  const ln = new SoqLightning({
    baseUrl: "https://lsp", fetchImpl: lspMock(), txBuilder: builder(),
    watchtower: { client: tower, fundingFor: () => ({ funding_txid: "cd".repeat(32), funding_vout: 0 }) },
  });
  await assert.rejects(() => ln.pay("c1", 30_000_000), (e) => e instanceof TowerError && e.status === 401);
});

// ---- tower-status proxy (LSP exposes dual-tower health to spokes) ----
function lspWithTowerStatus(status) {
  const ok = (o) => new Response(JSON.stringify(o), { status: 200, headers: { "content-type": "application/json" } });
  return async (url) => {
    if (new URL(url).pathname === "/v1/tower/status") return ok(status);
    return ok({});
  };
}

test("assertTowersHealthy passes with 2/2 up, throws when degraded", async () => {
  const healthy = { available: true, tower_count: 2, towers: [
    { name: "services-vps", available: true, status: { watched_channels: 2, total_checks: 9, total_triggers: 0, last_check: "t", poll_interval: "30s", sla_blocks: 144 } },
    { name: "mining-vps", available: true, status: { watched_channels: 1, total_checks: 1, total_triggers: 0, last_check: "t", poll_interval: "30s", sla_blocks: 144 } },
  ] };
  const lnHealthy = new SoqLightning({ baseUrl: "https://lsp", fetchImpl: lspWithTowerStatus(healthy) });
  await lnHealthy.assertTowersHealthy(2); // no throw
  const s = await lnHealthy.towerStatus();
  assert.equal(s.tower_count, 2);

  const degraded = { available: true, tower_count: 2, towers: [
    { name: "services-vps", available: true, status: healthy.towers[0].status },
    { name: "mining-vps", available: false, error: "dial timeout" },
  ] };
  const lnDegraded = new SoqLightning({ baseUrl: "https://lsp", fetchImpl: lspWithTowerStatus(degraded) });
  await assert.rejects(() => lnDegraded.assertTowersHealthy(2), /coverage degraded: 1\/2/);
  await lnDegraded.assertTowersHealthy(1); // 1 reachable is fine if you only require 1
});
