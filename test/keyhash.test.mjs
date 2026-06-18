// OP_CHECKDILITHIUMKEYHASH (SOQ-COV-013) — key-committed Dilithium 2-of-2.
//
// Proves the SDK builders produce artifacts that are SELF-CONSISTENT with the
// consensus handler (interpreter.cpp:736-795) and the committed-path C++ tests
// (dilithium_keyhash_committed_tests.cpp): committed-keyhash script layout,
// pop-all-3 + OP_1 clean-stack shape, witness ordering (B checked first), and
// CheckSig-style signing (sighash signed DIRECTLY + hashtype byte, not Hash()).
//
// What this CANNOT do: run EvalScript. Script EXECUTION is proven by the 5 C++
// VerifyScript vectors. Here we verify: (a) the script commits SHA256(pubkey) at
// the right offsets, (b) the witness stack matches the handler's expected layout,
// (c) each sig validates under ML-DSA over the SDK's own sighash (so the sig the
// node's CheckSig recomputes will match), (d) a substituted key fails the binding.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  keyhashFunding2of2, signKeyhashFunding2of2, dilithiumKeyHash, dilithiumKeyhash2of2Script,
  dilithiumKeyhashScript, dilithiumKeyhashWitness, signForKeyhash, OP,
  partialSignKeyhash2of2, combineKeyhash2of2Witness,
  apoSighash, sighashAll, SIGHASH_ANYPREVOUTANYSCRIPT, SIGHASH_ALL,
  p2wshV6, dilithiumWitnessPubKey, pushData, toHex,
  nobleMlDsa, mlDsaKeygen,
} from "../dist/index.js";

// Deterministic keys (32-byte seeds) so the emitted vector is reproducible.
const A = mlDsaKeygen(new Uint8Array(32).fill(0x11));
const B = mlDsaKeygen(new Uint8Array(32).fill(0x22));
const M = mlDsaKeygen(new Uint8Array(32).fill(0x33)); // Mallory

const AMOUNT = 100_000_000n;
const fundOutpoint = { txid: new Uint8Array(32).fill(0xfd), n: 0 };

// An eLTOO update tx spending the funding output.
function updateTx() {
  return {
    version: 2, locktime: 101,
    vin: [{ prevout: fundOutpoint, sequence: 0xfffffffe }],
    vout: [{ value: AMOUNT, scriptPubKey: Uint8Array.of(OP.TRUE), visibility: 0, assetType: 0 }],
  };
}

test("keyhash = single SHA256 of the raw 1312-byte pubkey", () => {
  assert.equal(A.publicKey.length, 1312);
  const kh = dilithiumKeyHash(A.publicKey);
  assert.equal(kh.length, 32);
  // must reject a 0x00-prefixed (1313) key — the handler hashes the stripped form
  assert.throws(() => dilithiumKeyHash(dilithiumWitnessPubKey(A.publicKey)));
});

test("funding scriptPubKey is v6 (OP_6 + 32-byte program), 34 bytes", () => {
  const f = keyhashFunding2of2(A.publicKey, B.publicKey);
  assert.equal(f.scriptPubKey.length, 34);
  assert.equal(f.scriptPubKey[0], OP.WITNESS_V6); // 0x56
  assert.equal(f.scriptPubKey[1], 0x20);          // push 32
  assert.deepEqual(f.scriptPubKey, p2wshV6(f.witnessScript));
});

test("witnessScript commits kh(pubB) FIRST, then kh(pubA), ends OP_1", () => {
  const ws = dilithiumKeyhash2of2Script(A.publicKey, B.publicKey);
  // Expected bytes: 0x20 kh(B) 0xb6 0x20 kh(A) 0xb6 0x51
  const expected = new Uint8Array([
    0x20, ...dilithiumKeyHash(B.publicKey), OP.CHECKDILITHIUMKEYHASH,
    0x20, ...dilithiumKeyHash(A.publicKey), OP.CHECKDILITHIUMKEYHASH,
    OP.ONE,
  ]);
  assert.deepEqual(ws, expected);
  assert.equal(ws.length, 1 + 32 + 1 + 1 + 32 + 1 + 1); // 69
});

test("2-of-2 update (0x42): witness layout + both sigs verify under ML-DSA", () => {
  const f = keyhashFunding2of2(A.publicKey, B.publicKey);
  const tx = updateTx();
  const w = signKeyhashFunding2of2(
    f, tx, 0, AMOUNT, SIGHASH_ANYPREVOUTANYSCRIPT,
    A.secretKey, A.publicKey, B.secretKey, B.publicKey, nobleMlDsa,
  );

  // Layout: [sigA(2421), pubA(1312), sigB(2421), pubB(1312), witnessScript, trailing(1313)]
  assert.equal(w.length, 6);
  const [sigA, pubA, sigB, pubB, ws, trailing] = w;
  assert.equal(sigA.length, 2421);          // 2420 ‖ hashType
  assert.equal(sigA[2420], 0x42);           // trailing hashType byte = 0x42
  assert.equal(sigB[2420], 0x42);
  assert.deepEqual(pubA, A.publicKey);
  assert.deepEqual(pubB, B.publicKey);
  assert.deepEqual(ws, f.witnessScript);
  assert.equal(trailing.length, 1313);
  assert.equal(trailing[0], 0x00);

  // Each sig must validate over the SAME sighash the node's CheckSig recomputes.
  // For 0x42, apoSighash ignores scriptCode, so the digest is script-independent.
  const digest = apoSighash(f.witnessScript, tx, 0, SIGHASH_ANYPREVOUTANYSCRIPT, AMOUNT);
  assert.ok(nobleMlDsa.verify(digest, sigA.slice(0, 2420), A.publicKey), "Alice sig must verify");
  assert.ok(nobleMlDsa.verify(digest, sigB.slice(0, 2420), B.publicKey), "Bob sig must verify");
  // cross-key must NOT verify (sig is key-bound)
  assert.ok(!nobleMlDsa.verify(digest, sigA.slice(0, 2420), B.publicKey), "Alice sig must not verify under Bob's key");
});

test("cooperative close (0x01): sighash COMMITS the witnessScript", () => {
  const f = keyhashFunding2of2(A.publicKey, B.publicKey);
  const tx = updateTx();
  const w = signKeyhashFunding2of2(
    f, tx, 0, AMOUNT, SIGHASH_ALL,
    A.secretKey, A.publicKey, B.secretKey, B.publicKey, nobleMlDsa,
  );
  const [sigA] = w;
  assert.equal(sigA[2420], 0x01);
  const digest = sighashAll(f.witnessScript, tx, 0, AMOUNT);
  assert.ok(nobleMlDsa.verify(digest, sigA.slice(0, 2420), A.publicKey));
  // 0x01 commits scriptCode: a DIFFERENT script ⇒ different digest ⇒ sig won't verify.
  const otherDigest = sighashAll(dilithiumKeyhashScript(A.publicKey), tx, 0, AMOUNT);
  assert.notDeepEqual(digest, otherDigest);
});

test("SUBSTITUTION: committed keyhash ≠ Mallory's key (binding would reject)", () => {
  // Output locked to Alice; Mallory tries to spend with her own key+sig.
  const ws = dilithiumKeyhashScript(A.publicKey);
  const tx = updateTx();
  // Mallory produces an internally-valid sig for HER key...
  const mSig = signForKeyhash(ws, tx, 0, SIGHASH_ALL, AMOUNT, M.secretKey, nobleMlDsa);
  const mDigest = sighashAll(ws, tx, 0, AMOUNT);
  assert.ok(nobleMlDsa.verify(mDigest, mSig.slice(0, 2420), M.publicKey), "Mallory's sig is valid for HER key");
  // ...but the handler's step-1 check is SHA256(pubkey) == committed keyhash, and
  // the committed keyhash is Alice's. Mallory's key hashes to something else:
  const committed = dilithiumKeyHash(A.publicKey);
  assert.notDeepEqual(dilithiumKeyHash(M.publicKey), committed,
    "Mallory's keyhash must differ from the committed (Alice) keyhash → SCRIPT_ERR_CHECKDILITHIUMKEYHASH");
});

test("cross-party: independent partials → combine; order-robust + sigs verify", () => {
  const f = keyhashFunding2of2(A.publicKey, B.publicKey);
  const tx = updateTx();
  const HT = SIGHASH_ANYPREVOUTANYSCRIPT;

  // Alice signs with ONLY her key; Bob with ONLY his (no shared secrets).
  const pa = partialSignKeyhash2of2(f.witnessScript, tx, 0, HT, AMOUNT, A.secretKey, A.publicKey, nobleMlDsa);
  const pb = partialSignKeyhash2of2(f.witnessScript, tx, 0, HT, AMOUNT, B.secretKey, B.publicKey, nobleMlDsa);

  // ORDER-ROBUST: passing partials in either order yields the SAME witness bytes.
  const w1 = combineKeyhash2of2Witness(f.witnessScript, [pa, pb]);
  const w2 = combineKeyhash2of2Witness(f.witnessScript, [pb, pa]);
  assert.equal(w1.length, 6);
  for (let i = 0; i < 6; i++) assert.deepEqual(w1[i], w2[i], `witness item ${i} must be order-invariant`);

  // Correct v6 eval order: [sigA, pubA, sigB, pubB, ws, trailing].
  // pubB's keyhash is committed FIRST in the script → checked first → on top.
  const [sigA, pubA, sigB, pubB, ws, trailing] = w1;
  assert.deepEqual(pubA, A.publicKey);
  assert.deepEqual(pubB, B.publicKey);
  assert.deepEqual(ws, f.witnessScript);
  assert.equal(trailing.length, 1313);
  assert.equal(trailing[0], 0x00);
  assert.equal(sigA[2420], 0x42);
  assert.equal(sigB[2420], 0x42);

  // Both INDEPENDENTLY-produced sigs verify over the shared sighash.
  // (We do NOT assert byte-equality vs the single-operator helper: ML-DSA signing
  //  may be randomized, so two signings of the same message can differ — structure
  //  + cryptographic verification is the correct invariant, not sig bytes.)
  const digest = apoSighash(f.witnessScript, tx, 0, HT, AMOUNT);
  assert.ok(nobleMlDsa.verify(digest, sigA.slice(0, 2420), A.publicKey), "Alice partial must verify");
  assert.ok(nobleMlDsa.verify(digest, sigB.slice(0, 2420), B.publicKey), "Bob partial must verify");

  // The single-operator helper produces a STRUCTURALLY identical witness (same code path).
  const wSingle = signKeyhashFunding2of2(f, tx, 0, AMOUNT, HT, A.secretKey, A.publicKey, B.secretKey, B.publicKey, nobleMlDsa);
  assert.equal(wSingle.length, 6);
  assert.deepEqual(wSingle[1], A.publicKey);
  assert.deepEqual(wSingle[3], B.publicKey);
  assert.deepEqual(wSingle[4], f.witnessScript);
});

test("combine REJECTS a partial that matches no committed keyhash (wrong party)", () => {
  const f = keyhashFunding2of2(A.publicKey, B.publicKey);
  const tx = updateTx();
  const HT = SIGHASH_ANYPREVOUTANYSCRIPT;
  const pa = partialSignKeyhash2of2(f.witnessScript, tx, 0, HT, AMOUNT, A.secretKey, A.publicKey, nobleMlDsa);
  // Mallory signs validly for HER key, but her key is not committed in the A+B funding.
  const pm = partialSignKeyhash2of2(f.witnessScript, tx, 0, HT, AMOUNT, M.secretKey, M.publicKey, nobleMlDsa);
  assert.throws(() => combineKeyhash2of2Witness(f.witnessScript, [pa, pm]),
    "a partial whose keyhash is not committed must be rejected at combine");
});

test("combine REJECTS partials that signed different hashTypes", () => {
  const f = keyhashFunding2of2(A.publicKey, B.publicKey);
  const tx = updateTx();
  const pa = partialSignKeyhash2of2(f.witnessScript, tx, 0, SIGHASH_ANYPREVOUTANYSCRIPT, AMOUNT, A.secretKey, A.publicKey, nobleMlDsa);
  const pbAll = partialSignKeyhash2of2(f.witnessScript, tx, 0, SIGHASH_ALL, AMOUNT, B.secretKey, B.publicKey, nobleMlDsa);
  assert.throws(() => combineKeyhash2of2Witness(f.witnessScript, [pa, pbAll]),
    "mixed 0x42/0x01 hashTypes must be rejected");
});

// Deterministic vector — NODE-PINNED as of soqucoin-build commit 171b027cb.
// The C++ test `committed_sdk_crossvector` (dilithium_keyhash_committed_tests.cpp)
// rebuilds the witnessScript from the two keyhashes below, derives the v6
// scriptPubKey, and computes the 0x42 sighash over a matching tx (amount = 1 COIN);
// all three byte-match these values. See lightning/KEYHASH_CROSSVECTOR_HANDOFF.md.
// REMAINING gap (separate workstream): signed-execution determinism end-to-end
// (@noble ML-DSA ↔ pqcrystals keygen interop), gated on vector_mldsa.test.mjs.
test("VECTOR (deterministic) — print for node cross-check", () => {
  const f = keyhashFunding2of2(A.publicKey, B.publicKey);
  const tx = updateTx();
  const digest = apoSighash(f.witnessScript, tx, 0, SIGHASH_ANYPREVOUTANYSCRIPT, AMOUNT);
  console.log("KEYHASH_VECTOR_BEGIN");
  console.log("seedA=0x11*32 seedB=0x22*32");
  console.log("kh_A=" + toHex(dilithiumKeyHash(A.publicKey)));
  console.log("kh_B=" + toHex(dilithiumKeyHash(B.publicKey)));
  console.log("witnessScript=" + toHex(f.witnessScript));
  console.log("scriptPubKey=" + toHex(f.scriptPubKey));
  console.log("apo42_sighash=" + toHex(digest));
  console.log("KEYHASH_VECTOR_END");
  assert.ok(true);
});
