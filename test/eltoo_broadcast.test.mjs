// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// eltoo_broadcast.test.mjs — WS2 broadcast orchestration (EltooBroadcaster).
//
// Proves the first-class builder reproduces the b1-canary's transaction GRAPH (the
// canary is node-pinned: b1_script_vectors + a green live stagenet run) and that every
// signature it assembles validates under ML-DSA over the node's sighash.
//
// Byte-equality of the SIGNED witness is intentionally NOT asserted: ML-DSA signing may
// be randomized (see keyhash.test "cross-party"), so the correct invariants are
//   (a) the UNSIGNED tx bytes match the canary's hand-wired graph,
//   (b) the witness STRUCTURE matches the node-accepted layout,
//   (c) each signature cryptographically verifies,
//   (d) assembly is order-robust.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  EltooBroadcaster,
  eltooUpdateScriptV6, eltooUpdateBranchWitness, eltooSettlementBranchWitness,
  combineKeyhash2of2Witness,
  p2wshV6, dilithiumWitnessPubKey, apoSighash,
  serializeTx, serializeTxWithWitness, txid, toHex,
  SIGHASH_ANYPREVOUTANYSCRIPT,
  nobleMlDsa, mlDsaKeygen,
} from "../dist/index.js";

// Deterministic keys so the graph is reproducible (signing may still be randomized).
const A = mlDsaKeygen(new Uint8Array(32).fill(0x11));
const B = mlDsaKeygen(new Uint8Array(32).fill(0x22));
const M = mlDsaKeygen(new Uint8Array(32).fill(0x33)); // Mallory

const CAP = 1_000_000_000n;
const FEE = 10_000_000n;
const STATE = 100;
const CSV = 6;
const fundingOutpoint = { txid: new Uint8Array(32).fill(0xfd), n: 0 };
const spkA = p2wshV6(Uint8Array.of(0x51));        // arbitrary settlement payout scripts
const spkB = p2wshV6(Uint8Array.of(0x51, 0x51));

const params = {
  funding: fundingOutpoint, capacitySat: CAP,
  initiatorPub: A.publicKey, peerPub: B.publicKey,
  initiatorScriptPubKey: spkA, peerScriptPubKey: spkB,
  settlementCsv: CSV, feeSat: FEE,
};
const bc = new EltooBroadcaster(params);

const b1Script = () => eltooUpdateScriptV6(STATE, A.publicKey, B.publicKey, { settlementCsv: CSV });

test("buildFundingUpdateTx uses the spec/LSP locktime convention (stateNum+1)", () => {
  // The canary's U used locktime 0 (consensus-valid since funding has no CLTV), but eLTOO
  // (spec §B.3) + the LSP's Task-7 policy require locktime == stateNum+1. The rest of the
  // graph matches: version 2, spends funding, output = capacity-fee to the eLTOO(stateNum) spk.
  const expected = {
    version: 2, locktime: STATE + 1,
    vin: [{ prevout: fundingOutpoint, sequence: 0xffffffff }],
    vout: [{ value: CAP - FEE, scriptPubKey: p2wshV6(b1Script()) }],
  };
  assert.equal(toHex(serializeTx(bc.buildFundingUpdateTx(STATE))), toHex(serializeTx(expected)));
});

test("assembleFundingSpend: node-layout witness + both 0x42 sigs validate", () => {
  const tx = bc.buildFundingUpdateTx(STATE);
  const pa = bc.signFundingPartial(tx, A.secretKey, A.publicKey, nobleMlDsa);
  const pb = bc.signFundingPartial(tx, B.secretKey, B.publicKey, nobleMlDsa);
  const s = bc.assembleFundingSpend(tx, [pa, pb]);

  // The assembled hex must equal the canary's combine path (same partials in).
  const wit = combineKeyhash2of2Witness(bc.fundingWitnessScript(), [pa, pb], dilithiumWitnessPubKey(A.publicKey));
  assert.equal(s.hex, toHex(serializeTxWithWitness(tx, [wit])));

  // Layout [sigA, pubA, sigB, pubB, witnessScript, trailing] — pubB committed first.
  const [sigA, pubA, sigB, pubB, ws, trailing] = wit;
  assert.equal(wit.length, 6);
  assert.deepEqual(pubA, A.publicKey);
  assert.deepEqual(pubB, B.publicKey);
  assert.deepEqual(ws, bc.fundingWitnessScript());
  assert.equal(sigA.length, 2421);
  assert.equal(sigA[2420], 0x42);
  assert.equal(trailing.length, 1313);
  assert.equal(trailing[0], 0x00);

  const digest = apoSighash(bc.fundingWitnessScript(), tx, 0, SIGHASH_ANYPREVOUTANYSCRIPT, CAP);
  assert.ok(nobleMlDsa.verify(digest, sigA.slice(0, 2420), A.publicKey), "A funding sig must verify");
  assert.ok(nobleMlDsa.verify(digest, sigB.slice(0, 2420), B.publicKey), "B funding sig must verify");
});

test("buildSupersedeTx + assembleSupersede reproduce the canary's at-floor supersession", () => {
  const update = bc.buildFundingUpdateTx(STATE);
  const uTxid = txid(update);
  const uValue = CAP - FEE;
  const floor = STATE + 1;

  // b1-canary.ts buildIfSpend(.., floor): locktime floor, spends update:0 (non-final), output uValue-fee.
  const canaryHi = {
    version: 2, locktime: floor,
    vin: [{ prevout: { txid: uTxid, n: 0 }, sequence: 0xfffffffe }],
    vout: [{ value: uValue - FEE, scriptPubKey: p2wshV6(b1Script()) }],
  };
  const mine = bc.buildSupersedeTx({ prevOutpoint: { txid: uTxid, n: 0 }, prevValueSat: uValue, prevState: STATE, newState: STATE });
  assert.equal(toHex(serializeTx(mine)), toHex(serializeTx(canaryHi)));

  const pa = bc.signEltooPartial(mine, uValue, A.secretKey, A.publicKey, nobleMlDsa);
  const pb = bc.signEltooPartial(mine, uValue, B.secretKey, B.publicKey, nobleMlDsa);
  const s = bc.assembleSupersede(mine, STATE, [pa, pb]);

  const wit = eltooUpdateBranchWitness(b1Script(), pa.sig, A.publicKey, pb.sig, B.publicKey, dilithiumWitnessPubKey(A.publicKey));
  assert.equal(s.hex, toHex(serializeTxWithWitness(mine, [wit])));
  assert.deepEqual(wit[4], Uint8Array.of(0x01), "IF (supersession) selector = truthy 0x01");

  // 0x42 empties scriptCode, so the digest is script-independent.
  const digest = apoSighash(b1Script(), mine, 0, SIGHASH_ANYPREVOUTANYSCRIPT, uValue);
  assert.ok(nobleMlDsa.verify(digest, pa.sig.slice(0, 2420), A.publicKey), "A supersede sig must verify");
  assert.ok(nobleMlDsa.verify(digest, pb.sig.slice(0, 2420), B.publicKey), "B supersede sig must verify");
});

test("assembleSupersede is order-robust (partials in either order → identical bytes)", () => {
  const update = bc.buildFundingUpdateTx(STATE);
  const mine = bc.buildSupersedeTx({ prevOutpoint: { txid: txid(update), n: 0 }, prevValueSat: CAP - FEE, prevState: STATE, newState: STATE });
  const pa = bc.signEltooPartial(mine, CAP - FEE, A.secretKey, A.publicKey, nobleMlDsa);
  const pb = bc.signEltooPartial(mine, CAP - FEE, B.secretKey, B.publicKey, nobleMlDsa);
  assert.equal(bc.assembleSupersede(mine, STATE, [pa, pb]).hex, bc.assembleSupersede(mine, STATE, [pb, pa]).hex);
});

test("assembleSettlement: ELSE/CSV branch, sigs validate", () => {
  const update = bc.buildFundingUpdateTx(STATE);
  const uValue = CAP - FEE;
  const init = 600_000_000n, peer = uValue - FEE - init; // 380_000_000
  const settleTx = bc.buildSettlementTx({
    updateOutpoint: { txid: txid(update), n: 0 }, updateValueSat: uValue,
    initiatorBalanceSat: init, peerBalanceSat: peer,
  });
  assert.equal(settleTx.vin[0].sequence, CSV);            // BIP68 relative CSV
  assert.equal(settleTx.vout[0].value, init);
  assert.equal(settleTx.vout[1].value, peer);

  const pa = bc.signEltooPartial(settleTx, uValue, A.secretKey, A.publicKey, nobleMlDsa);
  const pb = bc.signEltooPartial(settleTx, uValue, B.secretKey, B.publicKey, nobleMlDsa);
  const s = bc.assembleSettlement(settleTx, STATE, [pa, pb]);

  const wit = eltooSettlementBranchWitness(b1Script(), pa.sig, A.publicKey, pb.sig, B.publicKey, dilithiumWitnessPubKey(A.publicKey));
  assert.equal(s.hex, toHex(serializeTxWithWitness(settleTx, [wit])));
  assert.equal(wit[4].length, 0, "empty selector → ELSE (settlement) branch");

  const digest = apoSighash(b1Script(), settleTx, 0, SIGHASH_ANYPREVOUTANYSCRIPT, uValue);
  assert.ok(nobleMlDsa.verify(digest, pa.sig.slice(0, 2420), A.publicKey), "A settlement sig must verify");
  assert.ok(nobleMlDsa.verify(digest, pb.sig.slice(0, 2420), B.publicKey), "B settlement sig must verify");
});

test("buildSignedUpdateAndSettlement: chains settlement→update, both broadcast-serialized", () => {
  const uValue = CAP - FEE;
  const init = 600_000_000n, peer = uValue - FEE - init;
  const { update, settlement } = bc.buildSignedUpdateAndSettlement({
    stateNum: STATE, initiatorBalanceSat: init, peerBalanceSat: peer,
    skA: A.secretKey, pubA: A.publicKey, skB: B.secretKey, pubB: B.publicKey, mldsa: nobleMlDsa,
  });
  // settlement spends the update's output 0 → txid chaining is correct
  assert.deepEqual(settlement.tx.vin[0].prevout.txid, update.txid);
  assert.equal(settlement.tx.vin[0].prevout.n, 0);
  // both are BIP141 witness-serialized (version 2 LE ‖ 0x00 0x01 segwit marker/flag)
  assert.match(update.hex, /^020000000001/);
  assert.match(settlement.hex, /^020000000001/);
});

test("buildSettlementTx rejects non-conserving balances (spec §D.2)", () => {
  assert.throws(() => bc.buildSettlementTx({
    updateOutpoint: { txid: new Uint8Array(32), n: 0 }, updateValueSat: CAP - FEE,
    initiatorBalanceSat: 1n, peerBalanceSat: 1n,
  }), /conservation/);
});

test("assembleSupersede rejects a partial from a non-channel key (footgun guard)", () => {
  const tx = bc.buildSupersedeTx({ prevOutpoint: { txid: new Uint8Array(32).fill(1), n: 0 }, prevValueSat: CAP - FEE, prevState: STATE, newState: STATE });
  const pa = bc.signEltooPartial(tx, CAP - FEE, A.secretKey, A.publicKey, nobleMlDsa);
  const pm = bc.signEltooPartial(tx, CAP - FEE, M.secretKey, M.publicKey, nobleMlDsa);
  assert.throws(() => bc.assembleSupersede(tx, STATE, [pa, pm]), /neither/);
});

test("buildCooperativeCloseTx: spends funding directly to final balances", () => {
  const init = 700_000_000n, peer = CAP - FEE - init;
  const tx = bc.buildCooperativeCloseTx({ initiatorBalanceSat: init, peerBalanceSat: peer });
  assert.deepEqual(tx.vin[0].prevout, fundingOutpoint);
  assert.equal(tx.vout.length, 2);
  const pa = bc.signFundingPartial(tx, A.secretKey, A.publicKey, nobleMlDsa);
  const pb = bc.signFundingPartial(tx, B.secretKey, B.publicKey, nobleMlDsa);
  const s = bc.assembleFundingSpend(tx, [pa, pb]);
  assert.match(s.hex, /^020000000001/);
});
