// mldsa.ts — @noble/post-quantum ML-DSA-44 binding. Proves it adapts to the SDK's MlDsa
// interface and signs real invoices/sighashes. NODE-INTEROP is a SEPARATE pending gate
// (test/vector_mldsa.test.mjs) — this file only proves the binding is internally correct.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  nobleMlDsa, mlDsaKeygen, ML_DSA_44,
  signInvoice, verifyInvoice, freshPreimage,
  apoSighash, signApoWitness, SIGHASH_ANYPREVOUTANYSCRIPT,
} from "../dist/index.js";

const seed = (b) => new Uint8Array(32).fill(b);

test("noble ML-DSA-44 round-trip via the MlDsa interface", () => {
  const { publicKey, secretKey } = mlDsaKeygen(seed(7));
  assert.equal(publicKey.length, ML_DSA_44.pubLen, "1312-byte pubkey");
  assert.equal(secretKey.length, ML_DSA_44.secLen, "2560-byte secret key");
  const msg = new Uint8Array(32).fill(9);
  const sig = nobleMlDsa.sign(msg, secretKey);
  assert.equal(sig.length, ML_DSA_44.sigLen, "2420-byte signature");
  assert.ok(nobleMlDsa.verify(msg, sig, publicKey), "valid sig verifies");
  assert.ok(!nobleMlDsa.verify(new Uint8Array(32).fill(8), sig, publicKey), "wrong message rejected");
  // a different key must not verify
  const other = mlDsaKeygen(seed(8));
  assert.ok(!nobleMlDsa.verify(msg, sig, other.publicKey), "wrong key rejected");
});

test("noble signs a real invoice end-to-end (no stub)", () => {
  const { publicKey, secretKey } = mlDsaKeygen(seed(1));
  const { paymentHash } = freshPreimage((n) => new Uint8Array(n).fill(3));
  const inv = { version: 1, amountSat: 250000000n, paymentHash, destination: new Uint8Array(32).fill(2), timestamp: 1718000000n, expiry: 3600, description: "real-sig", metadata: new Uint8Array() };
  const signed = signInvoice(inv, secretKey, nobleMlDsa);
  assert.equal(signed.signature.length, 2420);
  assert.ok(verifyInvoice(signed, publicKey, nobleMlDsa), "real invoice verifies");
});

test("noble signs an APO 0x42 sighash → 2421-byte witness element", () => {
  const { secretKey } = mlDsaKeygen(seed(5));
  const tx = { version: 2, locktime: 0, vin: [{ prevout: { txid: new Uint8Array(32), n: 0 }, sequence: 0 }], vout: [{ value: 100n, scriptPubKey: Uint8Array.of(0x51), visibility: 0, assetType: 0 }] };
  const w = signApoWitness(new Uint8Array(), tx, 0, SIGHASH_ANYPREVOUTANYSCRIPT, 100n, secretKey, nobleMlDsa);
  assert.equal(w.length, 2421, "2420 sig ‖ 0x42 hashtype");
  assert.equal(w[2420], 0x42);
});
