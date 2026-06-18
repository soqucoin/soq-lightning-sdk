// Offline smoke test — proves SDK logic without the live LSP.
//  1. invoice sign→verify→encode→decode round-trip + F-C6 short-form binding
//  2. LspClient open→update→close against a mock accept-and-store peer
//     (mirrors manager.go semantics: monotonic state_index, balance conservation)
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  serializeUnsigned, signInvoice, verifyInvoice, encodeInvoice, decodeInvoice,
  shortInvoice, verifyAgainstShort, freshPreimage, HRP, DILITHIUM_SIG_LEN,
  LspClient,
} from "../dist/index.js";

// deterministic stub ML-DSA: sig = 2420-byte tag derived from message; verify recomputes.
const stubMlDsa = {
  sign(msg) { const s = new Uint8Array(DILITHIUM_SIG_LEN); for (let i = 0; i < msg.length; i++) s[i % DILITHIUM_SIG_LEN] ^= msg[i]; return s; },
  verify(msg, sig, _pk) { const e = this.sign(msg); if (sig.length !== e.length) return false; for (let i = 0; i < e.length; i++) if (sig[i] !== e[i]) return false; return true; },
};
const counter = (() => { let n = 1; return (k) => { const b = new Uint8Array(k); for (let i = 0; i < k; i++) b[i] = (n + i) & 0xff; n += 7; return b; }; })();

test("invoice round-trip + signature", () => {
  const { preimage, paymentHash } = freshPreimage(counter);
  assert.notDeepEqual(preimage, freshPreimage(counter).preimage, "preimages must be fresh (§3.6)");
  const inv = { version: 1, amountSat: 250000000n, paymentHash, destination: counter(32),
    timestamp: 1718000000n, expiry: 3600, description: "coffee", metadata: new Uint8Array() };
  const signed = signInvoice(inv, counter(32), stubMlDsa);
  assert.equal(signed.signature.length, DILITHIUM_SIG_LEN);
  assert.ok(verifyInvoice(signed, counter(32), stubMlDsa));
  const enc = encodeInvoice(signed);
  assert.ok(enc.startsWith(HRP + "1"));
  const dec = decodeInvoice(enc);
  assert.deepEqual(serializeUnsigned(dec), serializeUnsigned(signed), "round-trip must be byte-identical");
  assert.equal(dec.amountSat, 250000000n);
});

test("F-C6 short-form binding", () => {
  const { paymentHash } = freshPreimage(counter);
  const inv = { version: 1, amountSat: 100000000n, paymentHash, destination: counter(32),
    timestamp: 1718000000n, expiry: 3600, description: "", metadata: new Uint8Array() };
  const signed = signInvoice(inv, counter(32), stubMlDsa);
  const uri = shortInvoice("inv123", paymentHash, 100000000n);
  assert.ok(verifyAgainstShort(signed, uri, counter(32), stubMlDsa), "matching short form must verify");
  const tampered = { ...signed, amountSat: 999n };
  assert.ok(!verifyAgainstShort(tampered, uri, counter(32), stubMlDsa), "amount mismatch must fail F-C6");
});

test("client open→update→close against mock accept-and-store peer", async () => {
  const chans = new Map();
  let seq = 0;
  const mockFetch = async (url, init) => {
    const path = new URL(url).pathname;
    const body = init?.body ? JSON.parse(init.body) : {};
    const ok = (o) => new Response(JSON.stringify(o), { status: 200, headers: { "content-type": "application/json" } });
    if (path === "/v1/faucet" && init?.method === "POST") {
      const id = `ch_${++seq}`;
      chans.set(id, { channel_id: id, initiator_pub_key_hex: body.pub_key_hex, peer_pub_key_hex: "peerpub",
        capacity_sat: body.amount_sat, initiator_balance_sat: body.amount_sat, peer_balance_sat: 0,
        state_index: 0, state: "open", csv_delay: 288, created_at_unix: 1718000000 });
      return ok({ success: true, txid: "deadbeef", amount_sat: body.amount_sat, channel_id: id });
    }
    const m = path.match(/^\/v1\/channels\/([^/]+)(\/update|\/close)?$/);
    if (m) {
      const ch = chans.get(m[1]);
      if (!ch) return new Response(JSON.stringify({ error: "not found" }), { status: 404 });
      if (m[2] === "/update") {
        if (body.state_index <= ch.state_index) return ok({ accepted: false, reject_reason: "stale state_index" });
        if (body.initiator_balance_sat + body.peer_balance_sat !== ch.capacity_sat)
          return ok({ accepted: false, reject_reason: "balance not conserved" });
        ch.state_index = body.state_index; ch.initiator_balance_sat = body.initiator_balance_sat; ch.peer_balance_sat = body.peer_balance_sat;
        return ok({ accepted: true, peer_signature_hex: "ab", echo: { state_index: body.state_index, initiator_balance_sat: body.initiator_balance_sat, peer_balance_sat: body.peer_balance_sat } });
      }
      if (m[2] === "/close") { ch.state = "closing"; return ok({ accepted: true, settlement_txid: "settle_" + m[1] }); }
      return ok(ch);
    }
    return new Response("{}", { status: 404 });
  };

  const client = new LspClient({ baseUrl: "https://mock.lsp", fetchImpl: mockFetch });
  const f = await client.faucetDrip({ address: "soq1test", pub_key_hex: "aa", open_channel: true, amount_sat: 500000000 });
  assert.ok(f.success && f.channel_id);
  const ch0 = await client.getChannel(f.channel_id);
  assert.equal(ch0.state_index, 0);
  assert.equal(ch0.initiator_balance_sat, ch0.capacity_sat);
  assert.equal(ch0.peer_balance_sat, 0);

  const up = await client.updateState(f.channel_id, { state_index: 1, initiator_balance_sat: 400000000, peer_balance_sat: 100000000, update_tx_hex: "x", settlement_tx_hex: "x", ctv_hash: "x" });
  assert.ok(up.accepted && up.echo?.state_index === 1);

  const stale = await client.updateState(f.channel_id, { state_index: 1, initiator_balance_sat: 500000000, peer_balance_sat: 0, update_tx_hex: "x", settlement_tx_hex: "x", ctv_hash: "x" });
  assert.ok(!stale.accepted, "stale replay must be rejected");

  const bad = await client.updateState(f.channel_id, { state_index: 2, initiator_balance_sat: 500000000, peer_balance_sat: 100000000, update_tx_hex: "x", settlement_tx_hex: "x", ctv_hash: "x" });
  assert.ok(!bad.accepted, "non-conserved balance must be rejected");

  const close = await client.closeChannel(f.channel_id);
  assert.ok(close.accepted && close.settlement_txid?.startsWith("settle_"));
});
