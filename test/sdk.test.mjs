// SDK-facade test — SoqLightning open→pay→pay→close against a mock accept-and-store
// peer (manager.go semantics: monotonic state_index, balance conservation).
import { test } from "node:test";
import assert from "node:assert/strict";
import { SoqLightning } from "../dist/index.js";

// reusable mock peer; returns a fetchImpl
function mockPeer() {
  const chans = new Map();
  let seq = 0;
  const ok = (o) => new Response(JSON.stringify(o), { status: 200, headers: { "content-type": "application/json" } });
  return async (url, init) => {
    const path = new URL(url).pathname;
    const body = init?.body ? JSON.parse(init.body) : {};
    if (path === "/v1/faucet" && init?.method === "POST") {
      const id = `ch_${++seq}`;
      chans.set(id, { channel_id: id, initiator_pub_key_hex: body.pub_key_hex, peer_pub_key_hex: "peer",
        capacity_sat: body.amount_sat, initiator_balance_sat: body.amount_sat, peer_balance_sat: 0,
        state_index: 0, state: "open", csv_delay: 288, created_at_unix: 1718000000 });
      return ok({ success: true, txid: "tx", amount_sat: body.amount_sat, channel_id: id });
    }
    const m = path.match(/^\/v1\/channels\/([^/]+)(\/update|\/close)?$/);
    if (m) {
      const ch = chans.get(m[1]);
      if (!ch) return new Response(JSON.stringify({ error: "not found" }), { status: 404 });
      if (m[2] === "/update") {
        if (body.state_index <= ch.state_index) return ok({ accepted: false, reject_reason: "stale" });
        if (body.initiator_balance_sat + body.peer_balance_sat !== ch.capacity_sat) return ok({ accepted: false, reject_reason: "balance" });
        ch.state_index = body.state_index; ch.initiator_balance_sat = body.initiator_balance_sat; ch.peer_balance_sat = body.peer_balance_sat;
        return ok({ accepted: true, peer_signature_hex: "ab", echo: { state_index: body.state_index, initiator_balance_sat: body.initiator_balance_sat, peer_balance_sat: body.peer_balance_sat } });
      }
      if (m[2] === "/close") { ch.state = "closing"; return ok({ accepted: true, settlement_txid: "settle_" + m[1] }); }
      return ok(ch);
    }
    return new Response("{}", { status: 404 });
  };
}

test("SoqLightning fundAndOpen → pay → pay → close (accept-and-store peer)", async () => {
  const ln = new SoqLightning({ baseUrl: "https://mock", fetchImpl: mockPeer() });
  const ch = await ln.fundAndOpen({ pubKeyHex: "aa", address: "soq1x", capacitySat: 500000000 });
  assert.equal(ch.state_index, 0);
  assert.equal(ch.initiator_balance_sat, 500000000);

  await ln.pay(ch.channel_id, 100000000);            // -> state 1, peer has 1 SOQ
  const after = await ln.pay(ch.channel_id, 50000000); // pay() returns the committed channel
  assert.equal(after.state_index, 2);
  assert.equal(after.initiator_balance_sat, 350000000);
  assert.equal(after.peer_balance_sat, 150000000);
  assert.equal(after.initiator_balance_sat + after.peer_balance_sat, after.capacity_sat, "balance conserved");

  const close = await ln.close(ch.channel_id);
  assert.ok(close.settlement_txid?.startsWith("settle_"));
});

// Capped peer reproducing the LIVE stagenet LSP (verified 2026-06-24): the faucet drips
// the requested amount but only opens a channel when amount_sat <= max_channel_sat. Above
// the cap it returns {success, txid} with NO channel_id and NO error — a silent decline.
function cappedPeer(maxChannelSat) {
  const chans = new Map();
  let seq = 0;
  const ok = (o) => new Response(JSON.stringify(o), { status: 200, headers: { "content-type": "application/json" } });
  return async (url, init) => {
    const path = new URL(url).pathname;
    const body = init?.body ? JSON.parse(init.body) : {};
    if (path === "/v1/info") return ok({ network: "stagenet", echo_mode: false, max_channel_sat: maxChannelSat });
    if (path === "/v1/faucet" && init?.method === "POST") {
      if (body.amount_sat > maxChannelSat) return ok({ success: true, txid: "drip_no_chan", amount_sat: body.amount_sat });
      const id = `ch_${++seq}`;
      chans.set(id, { channel_id: id, initiator_pub_key_hex: body.pub_key_hex, peer_pub_key_hex: "peer",
        capacity_sat: body.amount_sat, initiator_balance_sat: body.amount_sat, peer_balance_sat: 0,
        state_index: 0, state: "open", csv_delay: 288, created_at_unix: 1718000000 });
      return ok({ success: true, txid: "tx", amount_sat: body.amount_sat, channel_id: id });
    }
    const m = path.match(/^\/v1\/channels\/([^/]+)$/);
    if (m) { const ch = chans.get(m[1]); return ch ? ok(ch) : new Response(JSON.stringify({ error: "not found" }), { status: 404 }); }
    return new Response("{}", { status: 404 });
  };
}

test("fundAndOpen clamps capacity to max_channel_sat so the faucet actually opens a channel", async () => {
  const ln = new SoqLightning({ baseUrl: "https://mock", fetchImpl: cappedPeer(100_000_000) });
  // Ask for 10 SOQ against a 1 SOQ cap — must NOT throw "did not open a channel".
  const ch = await ln.fundAndOpen({ pubKeyHex: "aa", address: "soq1x", capacitySat: 1_000_000_000 });
  assert.equal(ch.state, "open");
  assert.equal(ch.capacity_sat, 100_000_000, "capacity clamped to the LSP cap");
});

test("fundAndOpen surfaces a descriptive error if the faucet drips but opens no channel", async () => {
  // Cap of 0 forces the drip-without-channel path even after clamping (maxCap=0 -> falls back
  // to requested, faucet still declines) to exercise the error message.
  const peer = cappedPeer(0);
  const ln = new SoqLightning({ baseUrl: "https://mock", fetchImpl: peer });
  await assert.rejects(() => ln.fundAndOpen({ pubKeyHex: "aa", address: "soq1x", capacitySat: 1_000_000_000 }),
    /did not open a channel/);
});

test("SoqLightning.pay rejects overspend locally (no wasted round-trip)", async () => {
  const ln = new SoqLightning({ baseUrl: "https://mock", fetchImpl: mockPeer() });
  const ch = await ln.fundAndOpen({ pubKeyHex: "aa", address: "soq1x", capacitySat: 500000000 });
  await assert.rejects(() => ln.pay(ch.channel_id, 600000000), /insufficient initiator balance/);
});

// echo_mode DEMO peer (the binary deployed on the Services VPS today): countersigns
// state_index = submitted+1, peer_balance = submitted_peer/2, and drops the HTTP
// response on a SUCCESSFUL close (verified live 2026-06-14). pay() must survive both.
function echoModePeer() {
  const chans = new Map();
  let seq = 0;
  const ok = (o) => new Response(JSON.stringify(o), { status: 200, headers: { "content-type": "application/json" } });
  return async (url, init) => {
    const path = new URL(url).pathname;
    const body = init?.body ? JSON.parse(init.body) : {};
    const m = path.match(/^\/v1\/channels\/([^/]+)(\/update|\/close)?$/);
    if (path === "/v1/channels" && init?.method === "POST") {
      const id = `ch_${++seq}`;
      chans.set(id, { channel_id: id, initiator_pub_key_hex: body.initiator_pub_key_hex, peer_pub_key_hex: "peer",
        capacity_sat: body.capacity_sat, initiator_balance_sat: body.capacity_sat, peer_balance_sat: 0,
        state_index: 0, state: "open", csv_delay: body.csv_delay, created_at_unix: 1718000000 });
      return ok({ accepted: true, channel_id: id, peer_pub_key_hex: "peer", peer_address: "soq1demo" });
    }
    if (m) {
      const ch = chans.get(m[1]);
      if (!ch) return new Response(JSON.stringify({ error: "not found" }), { status: 404 });
      if (m[2] === "/update") {
        if (body.state_index <= ch.state_index) return ok({ accepted: false, reject_reason: `stale: got ${body.state_index}, current ${ch.state_index}` });
        ch.state_index = body.state_index + 1;                       // demo: countersign +1
        ch.peer_balance_sat = Math.floor(body.peer_balance_sat / 2); // demo: meet in the middle
        ch.initiator_balance_sat = ch.capacity_sat - ch.peer_balance_sat;
        return ok({ accepted: true, peer_signature_hex: "countersigned", echo: { state_index: ch.state_index, initiator_balance_sat: ch.initiator_balance_sat, peer_balance_sat: ch.peer_balance_sat } });
      }
      if (m[2] === "/close") { ch.state = "closed"; return Response.error(); } // drops response post-mutation
      return ok(ch);
    }
    return new Response("{}", { status: 404 });
  };
}

test("SoqLightning.pay survives echo_mode demo peer (halving + index bump)", async () => {
  const ln = new SoqLightning({ baseUrl: "https://mock", fetchImpl: echoModePeer() });
  const ch = await ln.openChannel({ pubKeyHex: "aa", address: "soq1x", capacitySat: 100000000, csvDelay: 144 });
  const after = await ln.pay(ch.channel_id, 20000000); // we ask +20M to peer; demo commits +10M
  assert.ok(after.state_index > ch.state_index, "state advanced");
  assert.equal(after.peer_balance_sat, 10000000, "demo halved the payment");
  assert.equal(after.initiator_balance_sat + after.peer_balance_sat, after.capacity_sat, "still conserved");
});

test("SoqLightning.close treats dropped-response-after-mutation as success", async () => {
  const ln = new SoqLightning({ baseUrl: "https://mock", fetchImpl: echoModePeer() });
  const ch = await ln.openChannel({ pubKeyHex: "aa", address: "soq1x", capacitySat: 100000000, csvDelay: 144 });
  const r = await ln.close(ch.channel_id);
  assert.ok(r.accepted, "close confirmed via state re-read despite empty reply");
});
