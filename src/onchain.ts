// soq-lightning-sdk — on-chain payment primitive for the Builders Gateway playground.
//
// The Lightning SDK only ever built channel/HTLC/invoice transactions; the in-browser
// "send a quantum-safe payment" demo needs a PLAIN witness-v1 (Dilithium P2WPKH-equivalent)
// payment, which lived only in Go. This module ports that path to TS so the playground can
// keygen → build → sign → broadcast entirely client-side.
//
// SOURCE OF TRUTH: soqucoind C++ consensus (primitives/transaction.h, interpreter.cpp) and
// soq-signer/internal/txbuilder (node-proven). NOT the public ~/soqucoin-sdk Go SDK, which is
// stale (still emits the removed nVisibility/nAssetType CTxOut bytes — see bead soqucoin-build-9q6).
//
// VERIFIED FORMAT (direction2_interop_analysis.md, byte-exact vs golden vectors):
//   • Address  = bech32m(hrp, witver=1, SHA256(raw-1312-byte ML-DSA-44 pubkey))
//   • scriptPubKey = OP_1(0x51) ‖ 0x20 ‖ <32-byte program>
//   • CTxOut   = value(LE64) ‖ compactSize(spk) ‖ spk      (Phase 4: NO extension bytes)
//   • sighash  = BIP143 SHA256d preimage; scriptCode = the input's scriptPubKey itself
//   • witness[0] = sig(2420) ‖ 0x01 (SIGHASH_ALL)   = 2421 bytes
//   • witness[1] = 0x00 ‖ pubkey(1312)              = 1313 bytes

import { sha256 } from "@noble/hashes/sha256";
import { bech32m } from "bech32";
import { nobleMlDsa, mlDsaKeygen, ML_DSA_44 } from "./mldsa.js";

// ---- constants (txbuilder/builder.go) ----
export const TX_VERSION = 2;
export const DEFAULT_SEQUENCE = 0xffffffff;
export const SIGHASH_ALL = 0x01;
export const DUST_THRESHOLD = 100_000n; // sat — matches soqucoind nHardDustLimit
const OP_1 = 0x51;
const BECH32_LIMIT = 1023;
// Weight estimation constants (must match txbuilder.go so fee/change agree byte-for-byte).
const EST_INPUT_WEIGHT = 41 * 4 + 3732; // 3896 WU (witness: sig 2420 + pubkey 1312)
const EST_OUTPUT_WEIGHT = 43 * 4; // 172 WU
const EST_OVERHEAD_WEIGHT = 12 * 4; // 48 WU

// ---- byte writers (mirror channel.ts) ----
const concat = (...a: Uint8Array[]) => {
  const n = a.reduce((s, x) => s + x.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const x of a) { out.set(x, o); o += x.length; }
  return out;
};
const u8 = (n: number) => Uint8Array.of(n & 0xff);
const le16 = (n: number) => Uint8Array.of(n & 0xff, (n >> 8) & 0xff);
const le32 = (n: number) => Uint8Array.of(n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff);
const le64 = (v: bigint) => {
  const out = new Uint8Array(8);
  let x = BigInt.asUintN(64, v);
  for (let i = 0; i < 8; i++) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
};
const compactSize = (n: number): Uint8Array => {
  if (n < 0xfd) return u8(n);
  if (n <= 0xffff) return concat(u8(0xfd), le16(n));
  if (n <= 0xffffffff) return concat(u8(0xfe), le32(n));
  throw new Error("compactSize too large");
};
const sha256d = (b: Uint8Array) => sha256(sha256(b));
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (h: string) => Uint8Array.from(h.match(/.{1,2}/g)!.map((x) => parseInt(x, 16)));

// ---- address (witness v1 Dilithium) ----

/** 32-byte witness program for a raw 1312-byte ML-DSA-44 public key. */
export function pubkeyToProgram(pubkey: Uint8Array): Uint8Array {
  if (pubkey.length !== ML_DSA_44.pubLen)
    throw new Error(`pubkey must be ${ML_DSA_44.pubLen} bytes (raw ML-DSA-44), got ${pubkey.length}`);
  return sha256(pubkey);
}

/** scriptPubKey: OP_1 ‖ 0x20 ‖ <32-byte program>. */
export function programToScriptPubKey(program: Uint8Array): Uint8Array {
  if (program.length !== 32) throw new Error(`program must be 32 bytes, got ${program.length}`);
  return concat(u8(OP_1), u8(0x20), program);
}

/** Encode a witness-v1 bech32m address (ssq1p… stagenet, sq1p… mainnet). */
export function encodeAddress(hrp: string, program: Uint8Array): string {
  const words = [1, ...bech32m.toWords(program)]; // witver=1 prepended as a raw 5-bit word
  return bech32m.encode(hrp, words, BECH32_LIMIT);
}

/** Decode a witness-v1 bech32m address → { witver, program }. */
export function decodeAddress(hrp: string, addr: string): { witver: number; program: Uint8Array } {
  const { prefix, words } = bech32m.decode(addr, BECH32_LIMIT);
  if (prefix !== hrp) throw new Error(`wrong HRP: expected ${hrp}, got ${prefix}`);
  const witver = words[0];
  const program = Uint8Array.from(bech32m.fromWords(words.slice(1)));
  return { witver, program };
}

/** Convenience: raw pubkey → bech32m address. */
export function deriveAddress(pubkey: Uint8Array, hrp = "ssq"): string {
  return encodeAddress(hrp, pubkeyToProgram(pubkey));
}

/** Address → scriptPubKey (for outputs / inputs). */
export function addressToScriptPubKey(hrp: string, addr: string): Uint8Array {
  const { program } = decodeAddress(hrp, addr);
  return programToScriptPubKey(program);
}

// ---- transaction model ----
export interface UTXORef { txid: string; vout: number; value: bigint; address: string }
export interface TxIn { txid: Uint8Array; vout: number; sequence: number; scriptPubKey: Uint8Array; witness?: Uint8Array[] }
export interface TxOut { value: bigint; scriptPubKey: Uint8Array }
export interface Tx { version: number; locktime: number; vin: TxIn[]; vout: TxOut[] }

// CTxOut consensus serializer — Phase 4 byte-less (value ‖ compactSize(script) ‖ script).
const serTxOut = (o: TxOut) => concat(le64(o.value), compactSize(o.scriptPubKey.length), o.scriptPubKey);
const serOutpoint = (i: TxIn) => concat(i.txid, le32(i.vout));

/** txid hex (display order, reversed) → internal 32-byte order. */
function txidToInternal(txidHex: string): Uint8Array {
  const b = fromHex(txidHex);
  if (b.length !== 32) throw new Error(`txid must be 32 bytes, got ${b.length}`);
  return b.reverse();
}

/** BIP143 sighash. scriptCode = the input's scriptPubKey (witness program). Returns the
 *  32-byte SHA256d digest that ML-DSA signs. */
export function bip143Sighash(tx: Tx, nIn: number, amount: bigint, hashType = SIGHASH_ALL): Uint8Array {
  const input = tx.vin[nIn];
  const hashPrevouts = sha256d(concat(...tx.vin.map(serOutpoint)));
  const hashSequence = sha256d(concat(...tx.vin.map((i) => le32(i.sequence))));
  const hashOutputs = sha256d(concat(...tx.vout.map(serTxOut)));
  const scriptCode = input.scriptPubKey;

  const preimage = concat(
    le32(tx.version),
    hashPrevouts,
    hashSequence,
    serOutpoint(input),
    compactSize(scriptCode.length), scriptCode,
    le64(amount),
    le32(input.sequence),
    hashOutputs,
    le32(tx.locktime),
    le32(hashType),
  );
  return sha256d(preimage);
}

/** Witness stack for a v1 input: [ sig‖hashType (2421), 0x00‖pubkey (1313) ]. */
export function assembleWitness(sig: Uint8Array, pubkey: Uint8Array, hashType = SIGHASH_ALL): Uint8Array[] {
  if (sig.length !== ML_DSA_44.sigLen) throw new Error(`sig must be ${ML_DSA_44.sigLen} bytes, got ${sig.length}`);
  if (pubkey.length !== ML_DSA_44.pubLen) throw new Error(`pubkey must be ${ML_DSA_44.pubLen} bytes, got ${pubkey.length}`);
  return [concat(sig, u8(hashType)), concat(u8(0x00), pubkey)];
}

function estimateFee(nIn: number, nOut: number, feeRate: bigint): bigint {
  const weight = EST_OVERHEAD_WEIGHT + nIn * EST_INPUT_WEIGHT + nOut * EST_OUTPUT_WEIGHT;
  const vsize = Math.floor((weight + 3) / 4);
  return BigInt(vsize) * feeRate;
}

/** Build an unsigned simple-send tx (1+ inputs → recipient + change). Mirrors
 *  txbuilder.BuildSendTransaction: pessimistic 2-output fee estimate, dust-folds change. */
export function buildSendTransaction(opts: {
  hrp: string;
  utxos: UTXORef[];
  recipientScriptPubKey: Uint8Array;
  amount: bigint;
  changeScriptPubKey: Uint8Array;
  feeRate: bigint;
}): Tx {
  const { hrp, utxos, recipientScriptPubKey, amount, changeScriptPubKey, feeRate } = opts;
  const vin: TxIn[] = utxos.map((u) => ({
    txid: txidToInternal(u.txid),
    vout: u.vout,
    sequence: DEFAULT_SEQUENCE,
    scriptPubKey: addressToScriptPubKey(hrp, u.address),
  }));
  const total = utxos.reduce((s, u) => s + u.value, 0n);
  const fee = estimateFee(vin.length, 2, feeRate); // pessimistic: assume change exists
  let change = total - amount - fee;
  if (change < 0n) throw new Error(`insufficient funds: inputs=${total}, amount=${amount}, fee=${fee}`);

  const vout: TxOut[] = [{ value: amount, scriptPubKey: recipientScriptPubKey }];
  if (change > DUST_THRESHOLD) vout.push({ value: change, scriptPubKey: changeScriptPubKey });
  // else: below dust → folded into fee (output dropped)

  return { version: TX_VERSION, locktime: 0, vin, vout };
}

/** Full tx serialization (BIP144 witness). Marker/flag + witness only if any input is signed. */
export function serializeTx(tx: Tx): Uint8Array {
  const hasWitness = tx.vin.some((i) => i.witness && i.witness.length > 0);
  const parts: Uint8Array[] = [le32(tx.version)];
  if (hasWitness) parts.push(u8(0x00), u8(0x01)); // marker, flag
  parts.push(compactSize(tx.vin.length));
  for (const i of tx.vin) parts.push(serOutpoint(i), compactSize(0), le32(i.sequence)); // empty scriptSig
  parts.push(compactSize(tx.vout.length));
  for (const o of tx.vout) parts.push(serTxOut(o));
  if (hasWitness) {
    for (const i of tx.vin) {
      const w = i.witness ?? [];
      parts.push(compactSize(w.length));
      for (const item of w) parts.push(compactSize(item.length), item);
    }
  }
  parts.push(le32(tx.locktime));
  return concat(...parts);
}

export function serializeTxHex(tx: Tx): string {
  return toHex(serializeTx(tx));
}

/** txid: SHA256d of the non-witness serialization, reversed to display order. */
export function txid(tx: Tx): string {
  const parts: Uint8Array[] = [le32(tx.version), compactSize(tx.vin.length)];
  for (const i of tx.vin) parts.push(serOutpoint(i), compactSize(0), le32(i.sequence));
  parts.push(compactSize(tx.vout.length));
  for (const o of tx.vout) parts.push(serTxOut(o));
  parts.push(le32(tx.locktime));
  return toHex(sha256d(concat(...parts)).reverse());
}

/** High-level: build → sign every input with the sender key → return {rawTxHex, txid}.
 *  Single-key wallet (all inputs owned by senderPubkey/senderSecret). */
export function buildSignedSend(opts: {
  hrp: string;
  utxos: UTXORef[];
  recipientAddress: string;
  amount: bigint;
  changeAddress: string;
  feeRate: bigint;
  senderPubkey: Uint8Array;
  senderSecret: Uint8Array;
}): { rawTxHex: string; txid: string; tx: Tx } {
  const tx = buildSendTransaction({
    hrp: opts.hrp,
    utxos: opts.utxos,
    recipientScriptPubKey: addressToScriptPubKey(opts.hrp, opts.recipientAddress),
    amount: opts.amount,
    changeScriptPubKey: addressToScriptPubKey(opts.hrp, opts.changeAddress),
    feeRate: opts.feeRate,
  });
  tx.vin.forEach((input, i) => {
    const digest = bip143Sighash(tx, i, opts.utxos[i].value, SIGHASH_ALL);
    const sig = nobleMlDsa.sign(digest, opts.senderSecret);
    input.witness = assembleWitness(sig, opts.senderPubkey, SIGHASH_ALL);
  });
  return { rawTxHex: serializeTxHex(tx), txid: txid(tx), tx };
}

// Re-export the crypto helpers so the playground has one import surface.
export { mlDsaKeygen, nobleMlDsa };
