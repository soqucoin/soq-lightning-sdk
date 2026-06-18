// htlc.ts (multi-hop) — route backward-induction math, §5.2 forwarding checks, §5.2-0
// invoice binding, §2.2 HTLC script/witness shapes, three-timelock layering.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  TIER, GRIEFING, FORWARD_ERR, htlcScript, htlcScriptPubKey,
  htlcSuccessWitness, htlcTimeoutWitness, buildRoute, checkForward, checkInvoiceBinding,
  routeToPayloads, sighashAll, signAllWitness, freshPreimage, signInvoice,
  dilithiumWitnessPubKey,
} from "../dist/index.js";

const stub = { sign: () => new Uint8Array(2420).fill(7), verify: () => true };
const counter = (() => { let n = 1; return (k) => { const b = new Uint8Array(k); for (let i = 0; i < k; i++) b[i] = (n + i) & 0xff; n += 7; return b; }; })();
const H = new Uint8Array(32).fill(0xab);
const payee = new Uint8Array(1312).fill(1);
const payer = new Uint8Array(1312).fill(2);

test("§2.2 HTLC script: IF SHA256<H> EQUALVERIFY <payee> CHECKSIG ELSE <cltv> CLTV DROP <payer> CHECKSIG ENDIF", () => {
  const s = htlcScript(H, payee, payer, 500);
  assert.equal(s[0], 0x63, "OP_IF");
  assert.equal(s[1], 0xa8, "OP_SHA256");
  assert.ok(s.includes(0x88), "OP_EQUALVERIFY");
  assert.equal(s[s.length - 1], 0x68, "OP_ENDIF");
  assert.ok(s.includes(0xb1), "OP_CLTV in timeout branch");
  assert.ok(s.includes(0xac), "OP_CHECKSIG");
  assert.equal(htlcScriptPubKey(H, payee, payer, 500).length, 34, "p2wsh spk = 34 bytes");
  assert.throws(() => htlcScript(new Uint8Array(31), payee, payer, 500), /32 bytes/);
});

test("single-hop route (sender→hub→receiver): fees + absolute cltv layer correctly", () => {
  const r = buildRoute({
    finalAmountSat: 100_000_000n,
    hops: [{ nodeId: "hub", feeBaseSat: 1000n, feePpm: 100, cltvExpiryDelta: TIER.transparent.cltvExpiryDelta }],
    currentBlockHeight: 1_000_000,
    finalCltvExpiryDelta: TIER.transparent.minFinalCltvExpiry, // 576
  });
  // hub forwards exactly the final amount to the receiver
  assert.equal(r.hops[0].amountToForwardSat, 100_000_000n);
  assert.equal(r.hops[0].outgoingCltvExpiry, 1_000_000 + 576);
  // sender locks final + hub fee (1000 base + 100ppm*1e8 = 1000 + 10000 = 11000)
  assert.equal(r.totalFeesSat, 11_000n);
  assert.equal(r.senderAmountSat, 100_011_000n);
  // sender's cltv = final + hub delta = +576 +288
  assert.equal(r.senderCltvExpiry, 1_000_000 + 576 + 288);
  // the hub's claim margin must satisfy §5.2-2 exactly
  assert.equal(r.senderCltvExpiry - r.hops[0].outgoingCltvExpiry, TIER.transparent.cltvExpiryDelta);
});

test("two-hop route compounds fees and cltv deltas backward", () => {
  const r = buildRoute({
    finalAmountSat: 1_000_000n,
    hops: [
      { nodeId: "h1", feeBaseSat: 0n, feePpm: 1000, cltvExpiryDelta: 40 },
      { nodeId: "h2", feeBaseSat: 0n, feePpm: 1000, cltvExpiryDelta: 40 },
    ],
    currentBlockHeight: 100,
    finalCltvExpiryDelta: 144,
  });
  // h2 (closest to receiver) forwards 1.0M at cltv 100+144=244
  assert.equal(r.hops[1].amountToForwardSat, 1_000_000n);
  assert.equal(r.hops[1].outgoingCltvExpiry, 244);
  // h1 forwards h2's incoming amount = 1.0M + 0.1% = 1,001,000 at cltv 244+40=284
  assert.equal(r.hops[0].amountToForwardSat, 1_001_000n);
  assert.equal(r.hops[0].outgoingCltvExpiry, 284);
  // sender locks 1,001,000 + 0.1% = 1,002,001 at cltv 284+40=324
  assert.equal(r.senderAmountSat, 1_002_001n);
  assert.equal(r.senderCltvExpiry, 324);
  assert.deepEqual(routeToPayloads(r).map((p) => p.nodeId), ["h1", "h2"]);
});

test("§5.2 checkForward: fee + cltv-delta obligations", () => {
  const policy = { minFeeSat: 1000n, cltvExpiryDelta: 288 };
  // happy
  assert.ok(checkForward({ amountSat: 100_011_000n, cltvExpiry: 1864 }, { amountSat: 100_000_000n, cltvExpiry: 1576 }, policy).ok);
  // fee too low → 0x30
  let r = checkForward({ amountSat: 100_000_500n, cltvExpiry: 1864 }, { amountSat: 100_000_000n, cltvExpiry: 1576 }, policy);
  assert.equal(r.error, FORWARD_ERR.fee);
  // cltv delta too small → 0x31
  r = checkForward({ amountSat: 100_011_000n, cltvExpiry: 1700 }, { amountSat: 100_000_000n, cltvExpiry: 1576 }, policy);
  assert.equal(r.error, FORWARD_ERR.cltvDelta);
  // amount_out ≤ 0 → 0x30
  assert.equal(checkForward({ amountSat: 1000n, cltvExpiry: 1864 }, { amountSat: 0n, cltvExpiry: 1576 }, policy).error, FORWARD_ERR.fee);
});

test("§5.2-0 invoice binding (Tamarin-required)", () => {
  const { preimage, paymentHash } = freshPreimage(counter);
  const inv = signInvoice({ version: 1, amountSat: 100n, paymentHash, destination: counter(32), timestamp: 1718000000n, expiry: 3600, description: "", metadata: new Uint8Array() }, counter(32), stub);
  const pk = counter(32);
  // bound + valid + unexpired
  assert.ok(checkInvoiceBinding(paymentHash, inv, pk, stub, 1718001000).ok);
  // wrong H → 0x32
  assert.equal(checkInvoiceBinding(new Uint8Array(32).fill(9), inv, pk, stub, 1718001000).error, FORWARD_ERR.unknownPaymentHash);
  // expired → 0x32
  assert.equal(checkInvoiceBinding(paymentHash, inv, pk, stub, 1718000000 + 99999).error, FORWARD_ERR.unknownPaymentHash);
  // already resolved → 0x32
  assert.equal(checkInvoiceBinding(paymentHash, inv, pk, stub, 1718001000, true).error, FORWARD_ERR.unknownPaymentHash);
});

test("HTLC witnesses use the v6 layout: [...satisfaction, witnessScript, trailingPubKey]", () => {
  const ws = htlcScript(H, payee, payer, 500);
  const tx = { version: 2, locktime: 500, vin: [{ prevout: { txid: new Uint8Array(32), n: 0 }, sequence: 0 }], vout: [{ value: 1n, scriptPubKey: Uint8Array.of(0x51), visibility: 0, assetType: 0 }] };
  const P = new Uint8Array(32).fill(7);
  const tpk = dilithiumWitnessPubKey(payee); // 0x00 ‖ pub

  const ok = htlcSuccessWitness(tx, 0, 1n, P, ws, counter(32), tpk, stub);
  assert.equal(ok.length, 5, "[sig, preimage, selector, witnessScript, trailingPubKey]");
  assert.equal(ok[2][0], 0x01, "truthy selector → SUCCESS/IF branch");
  assert.deepEqual(ok[3], ws, "witnessScript is stack[n-2]");
  assert.equal(ok[4][0], 0x00, "trailing item is the 0x00-prefixed Dilithium pubkey (stack[n-1])");
  assert.equal(ok[0].length, 2421, "sig ‖ SIGHASH_ALL byte");
  assert.equal(ok[0][2420], 0x01, "hashtype = SIGHASH_ALL");

  const to = htlcTimeoutWitness(tx, 0, 1n, ws, counter(32), tpk, stub);
  assert.equal(to.length, 4, "[sig, empty selector, witnessScript, trailingPubKey]");
  assert.equal(to[1].length, 0, "empty selector → TIMEOUT/ELSE branch");
  assert.deepEqual(to[2], ws, "witnessScript is stack[n-2]");
  assert.equal(to[3][0], 0x00, "trailing Dilithium pubkey");
});

test("sighashAll commits to prevout/outputs (unlike APO 0x42)", () => {
  const sc = Uint8Array.of(0xac);
  const t = (over = {}) => ({ version: 2, locktime: 0, vin: [{ prevout: { txid: new Uint8Array(32).fill(0xaa), n: 0 }, sequence: 0xffffffff }], vout: [{ value: 5n, scriptPubKey: Uint8Array.of(0x51), visibility: 0, assetType: 0 }], ...over });
  const ref = sighashAll(sc, t(), 0, 100n);
  // changing the prevout MUST change a SIGHASH_ALL sighash (it commits to it)
  assert.notDeepEqual(ref, sighashAll(sc, t({ vin: [{ prevout: { txid: new Uint8Array(32).fill(0xbb), n: 0 }, sequence: 0xffffffff }] }), 0, 100n));
  // changing outputs MUST change it
  assert.notDeepEqual(ref, sighashAll(sc, t({ vout: [{ value: 6n, scriptPubKey: Uint8Array.of(0x51) }] }), 0, 100n));
  assert.deepEqual(ref, sighashAll(sc, t(), 0, 100n), "deterministic");
});

test("tier params + griefing constants match §6.2.1 / §6.3", () => {
  assert.equal(TIER.transparent.cltvExpiryDelta, 288);
  assert.equal(TIER.transparent.minFinalCltvExpiry, 576);
  assert.equal(TIER.confidential.settlementCsv, 360);
  assert.equal(GRIEFING.softTimeoutBlocks, 144);
  assert.equal(GRIEFING.maxAcceptedHtlcs, 30);
});
