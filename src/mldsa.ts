// soq-lightning-sdk — concrete ML-DSA-44 binding (@noble/post-quantum, FIPS 204)
//
// Adapts @noble/post-quantum's ml_dsa44 to the SDK's injected `MlDsa` interface so the SDK
// can sign for real (invoices, eLTOO 0x42 updates, HTLC SIGHASH_ALL claims) instead of stubs.
//
// ⚠️ NODE-INTEROP IS UNVERIFIED until the gate passes (test/vector_mldsa.test.mjs). The node
// signs via pqcrystals_dilithium2_ref with EMPTY context over the raw 32-byte digest
// (CKey::Sign, key.cpp:100). This binding must produce signatures the node's CPubKey::Verify
// accepts AND verify the node's signatures. If FIPS 204 domain-separation differs between
// @noble and pqcrystals on any vector, fall back to a WASM build of the reference C.
// DO NOT sign real value until that vector is green.

import { ml_dsa44 } from "@noble/post-quantum/ml-dsa.js";
import type { MlDsa } from "./invoice.js";

export const ML_DSA_44 = {
  sigLen: 2420,
  pubLen: 1312,   // raw FIPS 204 public key (rho ‖ t1); does NOT begin with 0x00
  secLen: 2560,   // @noble expanded secret key
} as const;

/** The MlDsa to inject into invoice/channel/htlc APIs. `secretKey` is the 2560-byte @noble
 *  expanded key (from mlDsaKeygen); `message` is the raw bytes to sign (the SDK passes the
 *  32-byte sighash digest, matching the node's CKey::Sign). Empty context (FIPS 204 pure). */
// @noble/post-quantum@0.6.1 API (verified empirically): sign(message, secretKey),
// verify(signature, message, publicKey).
export const nobleMlDsa: MlDsa = {
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
    return ml_dsa44.sign(message, secretKey);
  },
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
    try { return ml_dsa44.verify(signature, message, publicKey); } catch { return false; }
  },
};

/** Generate an ML-DSA-44 keypair. Pass a 32-byte seed for determinism (tests/vectors);
 *  omit for a random key. Returns { publicKey: 1312 B, secretKey: 2560 B }. */
export function mlDsaKeygen(seed?: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array } {
  return seed ? ml_dsa44.keygen(seed) : ml_dsa44.keygen();
}
