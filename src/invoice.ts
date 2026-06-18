// soq-lightning-sdk — PQ-native invoice (spec §3)
//
// Implements the SOQ Lightning invoice exactly per SOQ_LIGHTNING_PROTOCOL_SPEC.md §3:
//   - canonical big-endian serialization (§3.2)
//   - Dilithium ML-DSA-44 sign/verify (injected — no key-recovery, §3.3)
//   - bech32m `soq1ln` full form + the F-C6 short form (§3.4)
//   - fresh-preimage-per-invoice (§3.6 — formally required by the Tamarin result)
//
// Amount is ALWAYS satoshis (1 SOQ = 1e8 sat), per §3.1. Never whole SOQ.

import { bech32m } from "bech32";
import { sha256 } from "@noble/hashes/sha256";

/** ML-DSA-44 signer/verifier — injected so this module stays pure & testable.
 *  Wire it to the WASM/native binding (or the peer) at the app layer. */
export interface MlDsa {
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;   // 2420 bytes
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
}

export const INVOICE_VERSION = 0x01;
export const HRP = "soq1ln";
export const DILITHIUM_SIG_LEN = 2420;
const BECH32_LIMIT = 1_000_000; // signatures are large; override bech32's default cap

export interface Invoice {
  version: number;
  amountSat: bigint;            // 0 = amountless / any-amount
  paymentHash: Uint8Array;      // 32 — H = SHA256(P)
  destination: Uint8Array;      // 32 — node id = SHA256(payee pubkey)
  timestamp: bigint;            // unix seconds
  expiry: number;               // seconds (0 => default 3600)
  description: string;          // UTF-8 (may be empty)
  metadata: Uint8Array;         // TLV (may be empty)
  signature?: Uint8Array;       // 2420 — set by signInvoice
}

// ---- canonical serialization (§3.2; the SIGNED message is everything before the sig)
export function serializeUnsigned(inv: Invoice): Uint8Array {
  const desc = new TextEncoder().encode(inv.description);
  if (inv.paymentHash.length !== 32) throw new Error("paymentHash must be 32 bytes");
  if (inv.destination.length !== 32) throw new Error("destination must be 32 bytes");
  if (desc.length > 0xffff) throw new Error("description too long");
  if (inv.metadata.length > 0xffff) throw new Error("metadata too long");

  const len = 1 + 8 + 32 + 32 + 8 + 4 + 2 + desc.length + 2 + inv.metadata.length;
  const out = new Uint8Array(len);
  const dv = new DataView(out.buffer);
  let o = 0;
  out[o] = inv.version; o += 1;
  dv.setBigUint64(o, inv.amountSat, false); o += 8;            // BE
  out.set(inv.paymentHash, o); o += 32;
  out.set(inv.destination, o); o += 32;
  dv.setBigUint64(o, inv.timestamp, false); o += 8;
  dv.setUint32(o, inv.expiry >>> 0, false); o += 4;
  dv.setUint16(o, desc.length, false); o += 2;
  out.set(desc, o); o += desc.length;
  dv.setUint16(o, inv.metadata.length, false); o += 2;
  out.set(inv.metadata, o); o += inv.metadata.length;
  return out;
}

export function signInvoice(inv: Invoice, secretKey: Uint8Array, mldsa: MlDsa): Invoice {
  const sig = mldsa.sign(serializeUnsigned(inv), secretKey);
  if (sig.length !== DILITHIUM_SIG_LEN) throw new Error("unexpected Dilithium sig length");
  return { ...inv, signature: sig };
}

export function verifyInvoice(inv: Invoice, payeePubKey: Uint8Array, mldsa: MlDsa): boolean {
  if (!inv.signature) return false;
  // §3.3 trust layering: this is AUTHENTICITY; payment safety comes from the HTLC
  // locking to paymentHash regardless of what `destination` claims.
  return mldsa.verify(serializeUnsigned(inv), inv.signature, payeePubKey);
}

// ---- bech32m `soq1ln` full form (§3.2/§3.3)
export function encodeInvoice(inv: Invoice): string {
  if (!inv.signature) throw new Error("invoice not signed");
  const body = serializeUnsigned(inv);
  const full = new Uint8Array(body.length + inv.signature.length);
  full.set(body, 0);
  full.set(inv.signature, body.length);
  const words = bech32m.toWords(full);
  return bech32m.encode(HRP, words, BECH32_LIMIT);
}

export function decodeInvoice(encoded: string): Invoice {
  const { prefix, words } = bech32m.decode(encoded, BECH32_LIMIT);
  if (prefix !== HRP) throw new Error(`bad HRP: ${prefix}`);
  const bytes = new Uint8Array(bech32m.fromWords(words));
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let o = 0;
  const version = bytes[o]; o += 1;
  const amountSat = dv.getBigUint64(o, false); o += 8;
  const paymentHash = bytes.slice(o, o + 32); o += 32;
  const destination = bytes.slice(o, o + 32); o += 32;
  const timestamp = dv.getBigUint64(o, false); o += 8;
  const expiry = dv.getUint32(o, false); o += 4;
  const descLen = dv.getUint16(o, false); o += 2;
  const description = new TextDecoder().decode(bytes.slice(o, o + descLen)); o += descLen;
  const metaLen = dv.getUint16(o, false); o += 2;
  const metadata = bytes.slice(o, o + metaLen); o += metaLen;
  const signature = bytes.slice(o, o + DILITHIUM_SIG_LEN); o += DILITHIUM_SIG_LEN;
  if (signature.length !== DILITHIUM_SIG_LEN) throw new Error("truncated signature");
  return { version, amountSat, paymentHash, destination, timestamp, expiry, description, metadata, signature };
}

// ---- §3.6 fresh-preimage-per-invoice (formally required — see spec §2.5/§8)
export function freshPreimage(rng: (n: number) => Uint8Array): { preimage: Uint8Array; paymentHash: Uint8Array } {
  const preimage = rng(32);
  return { preimage, paymentHash: sha256(preimage) };
}

// ---- §3.4 short form: soq://ln/<id>?h=<hash_hex>&a=<amount_sat>  (F-C6 binding)
const hex = (b: Uint8Array) => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (s: string) => new Uint8Array((s.match(/.{1,2}/g) ?? []).map((h) => parseInt(h, 16)));

export function shortInvoice(invoiceId: string, paymentHash: Uint8Array, amountSat: bigint): string {
  return `soq://ln/${invoiceId}?h=${hex(paymentHash)}&a=${amountSat.toString()}`;
}

export function parseShortInvoice(uri: string): { id: string; paymentHash: Uint8Array; amountSat: bigint } {
  const m = /^soq:\/\/ln\/([^?]+)\?(.+)$/.exec(uri);
  if (!m) throw new Error("not a soq://ln short invoice");
  const id = m[1];
  const q = new URLSearchParams(m[2]);
  const h = q.get("h"), a = q.get("a");
  if (!h || a === null) throw new Error("short invoice missing h/a binding (F-C6)");
  return { id, paymentHash: unhex(h), amountSat: BigInt(a) };
}

/** F-C6: the QR's h/a is the root of trust. Verify the fetched full invoice MATCHES
 *  the short binding AND is signature-valid; then pay to the QR's h/a (not the blob). */
export function verifyAgainstShort(full: Invoice, uri: string, payeePubKey: Uint8Array, mldsa: MlDsa): boolean {
  const s = parseShortInvoice(uri);
  const hashMatch = hex(full.paymentHash) === hex(s.paymentHash);
  const amountMatch = full.amountSat === s.amountSat;
  return hashMatch && amountMatch && verifyInvoice(full, payeePubKey, mldsa);
}
