// Byte-exact conformance for the on-chain payment port (src/onchain.ts).
//
// Golden vectors (test/fixtures/onchain_vectors.json) were emitted by soq-signer's
// NODE-PROVEN txbuilder (Phase-4 byte-less CTxOut). The TS port must reproduce every
// byte: address, scriptPubKey, BIP143 sighash, witness (2421/1313), serialization, txid.
// Pubkeys/sig are deterministic patterns so these assertions are independent of ML-DSA
// keygen/sign interop (that is proven separately: vector_mldsa.test.mjs + direction-2).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  deriveAddress, pubkeyToProgram, programToScriptPubKey, addressToScriptPubKey,
  buildSendTransaction, bip143Sighash, assembleWitness, serializeTxHex, txid,
  mlDsaKeygen, nobleMlDsa,
} from "../dist/onchain.js";

const V = JSON.parse(readFileSync(fileURLToPath(new URL("./fixtures/onchain_vectors.json", import.meta.url))));
const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

// Reconstruct the deterministic fixture inputs.
const senderPub = Uint8Array.from({ length: 1312 }, (_, i) => i % 256);
const recipPub = Uint8Array.from({ length: 1312 }, (_, i) => (i + 7) % 256);
const fillerSig = Uint8Array.from({ length: 2420 }, () => 0xab);

test("fixture inputs match the patterns used to generate the vectors", () => {
  assert.equal(toHex(senderPub), V.senderPubHex);
  assert.equal(toHex(recipPub), V.recipPubHex);
  assert.equal(toHex(fillerSig), V.fillerSigHex);
});

test("address derivation (witness v1)", () => {
  assert.equal(deriveAddress(senderPub, V.hrp), V.senderAddr);
  assert.equal(deriveAddress(recipPub, V.hrp), V.recipAddr);
});

test("scriptPubKey = OP_1 0x20 SHA256(pubkey)", () => {
  assert.equal(toHex(programToScriptPubKey(pubkeyToProgram(senderPub))), V.senderSPKHex);
  assert.equal(toHex(programToScriptPubKey(pubkeyToProgram(recipPub))), V.recipSPKHex);
  // address → scriptPubKey round-trips through bech32m decode
  assert.equal(toHex(addressToScriptPubKey(V.hrp, V.senderAddr)), V.senderSPKHex);
});

// Build the identical tx the Go generator built.
function buildFixtureTx() {
  return buildSendTransaction({
    hrp: V.hrp,
    utxos: [{ txid: V.utxoTxID, vout: V.utxoVout, value: BigInt(V.utxoValue), address: V.senderAddr }],
    recipientScriptPubKey: addressToScriptPubKey(V.hrp, V.recipAddr),
    amount: BigInt(V.sendAmount),
    changeScriptPubKey: addressToScriptPubKey(V.hrp, V.senderAddr),
    feeRate: BigInt(V.feeRate),
  });
}

test("fee/change estimation matches node-proven builder", () => {
  const tx = buildFixtureTx();
  assert.equal(tx.vout.length, V.numOutputs);
  assert.equal(tx.vout[0].value, BigInt(V.out0Value));
  assert.equal(tx.vout[1].value, BigInt(V.out1Value)); // 499989280 ⇒ fee 10720
});

test("BIP143 sighash is byte-exact (scriptCode = scriptPubKey, byte-less CTxOut)", () => {
  const tx = buildFixtureTx();
  const digest = bip143Sighash(tx, 0, BigInt(V.utxoValue), 0x01);
  assert.equal(toHex(digest), V.sighashHex);
});

test("witness format (2421 / 1313) and full serialization + txid are byte-exact", () => {
  const tx = buildFixtureTx();
  const w = assembleWitness(fillerSig, senderPub, 0x01);
  assert.equal(w[0].length, V.witness0Len); // sig ‖ 0x01
  assert.equal(w[1].length, V.witness1Len); // 0x00 ‖ pubkey
  tx.vin[0].witness = w;
  assert.equal(serializeTxHex(tx), V.rawTxHex);
  assert.equal(txid(tx), V.txid);
});

test("noble keygen → sign → verify round-trip over a real sighash (direction-1 path)", () => {
  const { publicKey, secretKey } = mlDsaKeygen();
  assert.equal(publicKey.length, 1312);
  const tx = buildFixtureTx();
  const digest = bip143Sighash(tx, 0, BigInt(V.utxoValue), 0x01);
  const sig = nobleMlDsa.sign(digest, secretKey);
  assert.equal(sig.length, 2420);
  assert.ok(nobleMlDsa.verify(digest, sig, publicKey), "noble must verify its own signature");
});
