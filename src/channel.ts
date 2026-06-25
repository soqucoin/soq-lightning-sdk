// soq-lightning-sdk — eLTOO transaction construction + 0x42 signing (B1)
//
// Byte-exact reimplementation of the consensus primitives in
// soqucoin-build/src/script/interpreter.cpp + primitives/transaction.h, per
// lightning/B1_SIGHASH_CTV_REFERENCE.md. The two load-bearing pieces:
//
//   apoSighash()  — SIGHASH_ANYPREVOUTANYSCRIPT (0x42) preimage, DOUBLE-SHA256.
//                   Omits prevout / sequence / scriptCode → lets a newer update
//                   rebind onto the prior output (eLTOO).
//   ctvHash()     — BIP119 DefaultCheckTemplateVerifyHash, SINGLE-SHA256, with the
//                   SOQ nVisibility/nAssetType output extension (SOQ-COV-012).
//
// ⚠️ Cross-checked against the C++ ALGORITHM (interpreter.cpp:1031-1129, 1725-1850)
// and the test reference (lightning_script_tests.cpp:51-74). Byte-equality vs a LIVE
// node sighash is PENDING Buddy's dumped vector — see verifyAgainstNodeVector().

import { sha256 } from "@noble/hashes/sha256";
import type { MlDsa } from "./invoice.js";
import type { UpdateTxBuilder, UpdateContext } from "./sdk.js";

// ---- hashes ----
const hash256 = (b: Uint8Array) => sha256(sha256(b)); // Bitcoin GetHash = SHA256d
const sha256d = hash256;

// ---- byte writers ----
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

// Bitcoin compact size (varint) — used for CScript length prefixes in consensus serialization.
const compactSize = (n: number): Uint8Array => {
  if (n < 0xfd) return u8(n);
  if (n <= 0xffff) return concat(u8(0xfd), le16(n));
  if (n <= 0xffffffff) return concat(u8(0xfe), le32(n));
  throw new Error("compactSize too large");
};

// ---- script assembly (matches CScript serialization) ----
export const OP = {
  FALSE: 0x00, TRUE: 0x51, ONE: 0x51, WITNESS_V6: 0x56, IF: 0x63, ELSE: 0x67, ENDIF: 0x68, DROP: 0x75,
  EQUALVERIFY: 0x88, SHA256: 0xa8, CHECKSIG: 0xac, CHECKSIGVERIFY: 0xad,
  CLTV: 0xb1, CSV: 0xb2, NOP4_CTV: 0xb3, NOP5_CSFS: 0xb4,
  // 0xb5 (OP_NOP6) is RESERVED for OP_TXHASH / BIP 346 — do not repurpose.
  CHECKDILITHIUMKEYHASH: 0xb6, // OP_NOP7, key-committed Dilithium sig verify (SOQ-COV-013)
} as const;

// ⚠️ V6 REALITY (Track 1a, interpreter.cpp:615-691 + EvalScript PQ-only). Soqucoin's EvalScript
// implements NO standard Bitcoin opcodes — OP_CHECKSIG, OP_IF/ELSE, OP_DROP, CLTV, CSV all
// fall through as no-ops, and the 520-byte push limit forbids inline 1312-byte pubkeys. So the
// CHECKSIG/IF/CLTV scripts below (eltooUpdateScript/htlcScript/fundingScript) DO NOT EXECUTE on
// the real chain — kept only as spec references. The real V6 signature primitive is CSFS
// (OP_NOP5=0xb4), always VERIFY mode: pops {sig, msg, pubkey}, checks pubkey.Verify(SHA256d(msg), sig).
// ⚠️ OPEN: CSFS authorizes but does NOT bind to the spending tx (msg is a stack item) — secure
// eLTOO needs CSFS composed with CTV (which binds the tx template). See csfs2of2AuthScript note.

// CScript data push (matches CScript::operator<<(vector) length-opcode selection).
export const pushData = (data: Uint8Array): Uint8Array => {
  const n = data.length;
  if (n < 0x4c) return concat(u8(n), data);
  if (n <= 0xff) return concat(u8(0x4c), u8(n), data);
  if (n <= 0xffff) return concat(u8(0x4d), le16(n), data);
  return concat(u8(0x4e), le32(n), data);
};

// CScriptNum minimal encoding (matches CScriptNum::serialize), then pushed as data.
export const scriptNum = (value: number | bigint): Uint8Array => {
  let v = BigInt(value);
  if (v === 0n) return u8(0x00); // CScript << CScriptNum(0) → empty push → OP_0
  const neg = v < 0n;
  let abs = neg ? -v : v;
  const bytes: number[] = [];
  while (abs > 0n) { bytes.push(Number(abs & 0xffn)); abs >>= 8n; }
  if (bytes[bytes.length - 1] & 0x80) bytes.push(neg ? 0x80 : 0x00);
  else if (neg) bytes[bytes.length - 1] |= 0x80;
  return pushData(Uint8Array.from(bytes));
};

/** @deprecated SPEC-REFERENCE ONLY — never executed on V6 (no-op CHECKSIG/IF/CLTV + inline
 *  1312-byte pubkeys > 520 push limit). Use {@link eltooUpdateScriptV6} (keyhash-2-of-2, executes
 *  under SCRIPT_VERIFY_V6_CONTROLFLOW). Kept for the legacy witness/test surface only.
 *  IF  <stateNum+1> CLTV DROP  <A> CHECKSIGVERIFY <B> CHECKSIG / ELSE <csv> CSV DROP ... ENDIF */
export function eltooUpdateScript(stateNum: number, aPub: Uint8Array, bPub: Uint8Array, settlementCsv = 288): Uint8Array {
  return concat(
    u8(OP.IF),
      scriptNum(stateNum + 1), u8(OP.CLTV), u8(OP.DROP),
      pushData(aPub), u8(OP.CHECKSIGVERIFY), pushData(bPub), u8(OP.CHECKSIG),
    u8(OP.ELSE),
      scriptNum(settlementCsv), u8(OP.CSV), u8(OP.DROP),
      pushData(aPub), u8(OP.CHECKSIGVERIFY), pushData(bPub), u8(OP.CHECKSIG),
    u8(OP.ENDIF),
  );
}

/** HTLC hashlock-success script (§2.2): OP_SHA256 <H> OP_EQUALVERIFY OP_TRUE */
export function htlcHashlockScript(paymentHash: Uint8Array): Uint8Array {
  return concat(u8(OP.SHA256), pushData(paymentHash), u8(OP.EQUALVERIFY), u8(OP.TRUE));
}

/** CTV-templated script (§2.3): <ctvHash> OP_NOP4(=CTV) */
export function ctvScript(templateHash: Uint8Array): Uint8Array {
  return concat(pushData(templateHash), u8(OP.NOP4_CTV));
}

/** Standard BIP141 P2WSH scriptPubKey: OP_0 <32-byte sha256(script)>. NOT used by Soqucoin
 *  channels (which are witness v6 — see p2wshV6); kept for completeness/interop. */
export function p2wsh(witnessScript: Uint8Array): Uint8Array {
  return concat(u8(OP.FALSE), pushData(sha256(witnessScript)));
}

/** Soqucoin P2WSH-Dilithium scriptPubKey (witness **v6**): OP_6 <32-byte sha256(script)>.
 *  §1.1 / interpreter.cpp:1468 — all channel/funding/HTLC outputs use this, NOT v0. */
export function p2wshV6(witnessScript: Uint8Array): Uint8Array {
  return concat(u8(OP.WITNESS_V6), pushData(sha256(witnessScript)));
}

/** The trailing witness item every v6 input requires (transaction.cpp:218 HasDilithiumSignatures):
 *  the ML-DSA-44 pubkey 0x00-prefixed. Consumed by the standardness check; NOT on the eval stack. */
export function dilithiumWitnessPubKey(mldsaPubKey: Uint8Array): Uint8Array {
  return concat(u8(0x00), mldsaPubKey); // FIPS 204 Table 3 prefix (stripped before use, interpreter.cpp:1561)
}

/** Assemble a v6 witness stack: [...satisfaction, witnessScript, trailingDilithiumPubKey]
 *  (interpreter.cpp:1470-1492). The witnessScript is stack[n-2]; the pubkey is stack[n-1].
 *  `trailingPubKey` must already be 0x00-prefixed (use dilithiumWitnessPubKey). */
export function p2wshV6Witness(satisfaction: Uint8Array[], witnessScript: Uint8Array, trailingPubKey: Uint8Array): Uint8Array[] {
  if (trailingPubKey[0] !== 0x00) throw new Error("trailing witness pubkey must be 0x00-prefixed (HasDilithiumSignatures)");
  return [...satisfaction, witnessScript, trailingPubKey];
}

/** ⚠️ SPEC-REFERENCE ONLY — does NOT execute on V6 (CHECKSIG unimplemented; 1312-byte pubkey
 *  exceeds the 520-byte push limit). The real V6 funding/close authorization is csfs2of2AuthScript. */
export function fundingScript(pubA: Uint8Array, pubB: Uint8Array): Uint8Array {
  return concat(pushData(pubA), u8(OP.CHECKSIGVERIFY), pushData(pubB), u8(OP.CHECKSIG));
}

// ====================================================================
// CSFS — the real V6 signature primitive (interpreter.cpp:615-691, Track 1a-verified)
// ====================================================================

/** V6 2-of-2 authorization witnessScript: `OP_NOP5 OP_NOP5 OP_1` — two CSFS-VERIFY checks
 *  (each pops {sig, msg, pubkey}), then OP_1 for the clean-stack rule. Pubkeys/sigs/msgs come
 *  from the WITNESS, not the script (520-byte limit).
 *  ⚠️ AUTHORIZES ONLY — does NOT bind to the spending tx. For a binding spend (eLTOO close/
 *  update), compose with OP_CTV: `<ctv_hash> OP_NOP4 OP_NOP5 OP_NOP5 OP_1` so CTV commits the
 *  tx template while CSFS authorizes. (Pending design confirmation — see TRACK1 runbook.) */
export function csfs2of2AuthScript(): Uint8Array {
  return Uint8Array.of(OP.NOP5_CSFS, OP.NOP5_CSFS, OP.ONE);
}

/** Sign for CSFS. CSFS verifies `pubkey.Verify(SHA256d(msg), sig)` with msg taken from the
 *  stack; the convention is msg = the 32-byte SignatureHash. So the signer signs SHA256d(sighash)
 *  and the witness carries the bare 32-byte `sighash` as msg. NO trailing hashtype byte (CSFS is
 *  not CHECKSIG). `sighash32` comes from apoSighash()/sighashAll(). */
export function signCsfs(sighash32: Uint8Array, secretKey: Uint8Array, mldsa: MlDsa): Uint8Array {
  if (sighash32.length !== 32) throw new Error("sighash must be 32 bytes");
  const sig = mldsa.sign(hash256(sighash32), secretKey); // CSFS hashes msg again → sign SHA256d(sighash)
  if (sig.length !== 2420) throw new Error(`expected 2420-byte ML-DSA sig, got ${sig.length}`);
  return sig;
}

/** Build the v6 witness for a CSFS 2-of-2 spend. Eval-stack order (interpreter.cpp:642): the
 *  FIRST OP_NOP5 consumes the top triple, so satisfaction = [sigA, msg, pkA, sigB, msg, pkB]
 *  (B verified first, A second). msg is the shared 32-byte sighash both parties signed.
 *  `trailingPubKey` is 0x00-prefixed (HasDilithiumSignatures). pkA/pkB are raw 1312-byte keys. */
export function csfs2of2Witness(
  sighash32: Uint8Array, sigA: Uint8Array, pkA: Uint8Array, sigB: Uint8Array, pkB: Uint8Array,
  trailingPubKey: Uint8Array, authScript: Uint8Array = csfs2of2AuthScript(),
): Uint8Array[] {
  return p2wshV6Witness([sigA, sighash32, pkA, sigB, sighash32, pkB], authScript, trailingPubKey);
}

// ---- CSFS + CTV: the BINDING V6 spend (provisional, pending Buddy's CSFS+CTV lifecycle test) ----

/** The BINDING V6 2-of-2 spend script: `OP_NOP5 OP_NOP5 <ctv_hash> OP_NOP4`.
 *  CSFS×2 authorize (each consumes {sig, msg, pubkey} in VERIFY mode), then `<ctv_hash> OP_CTV`
 *  binds the spending tx to the 32-byte template (outputs/amounts/sequences) and LEAVES the hash
 *  on the stack as the clean-stack truthy element (interpreter.cpp:607 — no OP_1 needed).
 *  Closes the CSFS authorize-but-don't-bind gap: CTV constrains the outputs, CSFS authorizes.
 *  CTV omits prevouts, so APO input-rebinding is preserved. msg convention = the ctv_hash
 *  (both parties authorize the exact template). ⚠️ PROVISIONAL until Buddy's on-chain test
 *  confirms ordering/msg-convention through VerifyScript. */
export function csfs2of2WithCtvScript(ctvHashValue: Uint8Array): Uint8Array {
  if (ctvHashValue.length !== 32) throw new Error("ctvHash must be 32 bytes");
  return concat(u8(OP.NOP5_CSFS), u8(OP.NOP5_CSFS), pushData(ctvHashValue), u8(OP.NOP4_CTV));
}

/** Witness for the binding spend. msg = ctv_hash; each party's sig = signCsfs(ctv_hash, sk).
 *  Layout: [sigA, ctv_hash, pkA, sigB, ctv_hash, pkB, witnessScript, 0x00‖trailingPubKey]. */
export function csfs2of2WithCtvWitness(
  ctvHashValue: Uint8Array, sigA: Uint8Array, pkA: Uint8Array, sigB: Uint8Array, pkB: Uint8Array,
  trailingPubKey: Uint8Array,
): Uint8Array[] {
  const script = csfs2of2WithCtvScript(ctvHashValue);
  return p2wshV6Witness([sigA, ctvHashValue, pkA, sigB, ctvHashValue, pkB], script, trailingPubKey);
}

// ---- transaction model ----
export interface OutPoint { txid: Uint8Array; n: number }       // txid = 32 bytes, internal byte order
export interface TxIn { prevout: OutPoint; sequence: number; scriptSig?: Uint8Array }
// Phase 4: nVisibility/nAssetType were removed from CTxOut. visibility/assetType remain as
// optional+ignored (asset/visibility now follow the witness version: USDSOQ=v7, confidential=v4).
// @deprecated — not serialized; kept only so existing callers don't break.
export interface TxOut { value: bigint; scriptPubKey: Uint8Array; visibility?: number; assetType?: number }
export interface Tx { version: number; locktime: number; vin: TxIn[]; vout: TxOut[] }

const EMPTY_OUTPOINT = concat(new Uint8Array(32), Uint8Array.of(0xff, 0xff, 0xff, 0xff)); // COutPoint::SetNull → n = 0xFFFFFFFF
const serOutPoint = (o: OutPoint) => concat(o.txid, le32(o.n));

// CTxOut consensus serializer (Phase 4, byte-less): value ‖ script(compactsize). The
// nVisibility/nAssetType bytes were removed — CTxOut is now standard. Cross-pinned via the matrix.
export const serTxOutConsensus = (o: TxOut) =>
  concat(le64(o.value), compactSize(o.scriptPubKey.length), o.scriptPubKey);

// CTV outputs serializer (Phase 4, byte-less): value ‖ scriptlen(LE32) ‖ script — distinct LE32 length
// encoding from the consensus form. MUST match the byte-less C++ CTV output hashing (Section C of the
// Phase-4 plan); eLTOO channel template hashes depend on this agreeing with the node.
export const serTxOutCtv = (o: TxOut) =>
  concat(le64(o.value), le32(o.scriptPubKey.length), o.scriptPubKey);

// ---- APO sighash (0x42 / 0x41) — interpreter.cpp:1048-1128 ----
export const SIGHASH_ANYPREVOUT = 0x41;
export const SIGHASH_ANYPREVOUTANYSCRIPT = 0x42;

/** BIP118 APO sighash. For 0x42 (ANYPREVOUTANYSCRIPT) scriptCode is empty; for 0x41
 *  (ANYPREVOUT) the real scriptCode is committed. Returns the 32-byte DOUBLE-SHA256 digest
 *  that ML-DSA signs. ANYONECANPAY + APO is invalid upstream (returns ONE) — disallowed here. */
export function apoSighash(scriptCode: Uint8Array, tx: Tx, nIn: number, hashType: number, amountSat: bigint): Uint8Array {
  const base = hashType & 0x7f;
  if (base !== SIGHASH_ANYPREVOUT && base !== SIGHASH_ANYPREVOUTANYSCRIPT)
    throw new Error("apoSighash: hashType must be 0x41 or 0x42");
  if (hashType & 0x80) throw new Error("ANYONECANPAY + APO is invalid (SOQ-COV-003)");

  const zero32 = new Uint8Array(32);
  const hashOutputs = sha256d(concat(...tx.vout.map(serTxOutConsensus)));
  // ANYPREVOUT commits to scriptCode; ANYPREVOUTANYSCRIPT serializes an EMPTY script.
  const scriptField = base === SIGHASH_ANYPREVOUT
    ? concat(compactSize(scriptCode.length), scriptCode)
    : u8(0x00); // empty script → compactSize(0)

  const preimage = concat(
    le32(tx.version),
    zero32,                 // hashPrevouts = 0
    zero32,                 // hashSequence = 0
    EMPTY_OUTPOINT,         // outpoint zeroed → 32 zero ‖ 0xFFFFFFFF
    scriptField,
    le64(amountSat),
    le32(0),                // nSequence = 0
    hashOutputs,
    le32(tx.locktime),
    le32(hashType),         // nHashType as a 4-byte int
  );
  return hash256(preimage);
}

/** Assemble a witness signature element: ML-DSA-44 sig (2420) ‖ hashType byte.
 *  `sign` MUST be PURE ML-DSA-44 (FIPS 204), EMPTY context, message = the 32-byte digest. */
export function signApoWitness(
  scriptCode: Uint8Array, tx: Tx, nIn: number, hashType: number, amountSat: bigint,
  secretKey: Uint8Array, mldsa: MlDsa,
): Uint8Array {
  const digest = apoSighash(scriptCode, tx, nIn, hashType, amountSat);
  const sig = mldsa.sign(digest, secretKey);
  if (sig.length !== 2420) throw new Error(`expected 2420-byte ML-DSA sig, got ${sig.length}`);
  return concat(sig, u8(hashType));
}

// ---- standard BIP143 witness-v0 sighash (SIGHASH_ALL) — interpreter.cpp:1188-1211 ----
export const SIGHASH_ALL = 0x01;

/** BIP143 witness-v0 sighash for SIGHASH_ALL (0x01). Used by HTLC SUCCESS/TIMEOUT claims
 *  (spec §2.2: "these OP_CHECKSIG calls use plain SIGHASH_ALL") — a fixed-output spend with
 *  no rebinding, so unlike the eLTOO update it commits to the real prevout/sequence. Returns
 *  the 32-byte DOUBLE-SHA256 digest. Only SIGHASH_ALL is implemented (HTLC needs nothing else). */
export function sighashAll(scriptCode: Uint8Array, tx: Tx, nIn: number, amountSat: bigint): Uint8Array {
  const hashType = SIGHASH_ALL;
  const hashPrevouts = sha256d(concat(...tx.vin.map((i) => serOutPoint(i.prevout))));
  const hashSequence = sha256d(concat(...tx.vin.map((i) => le32(i.sequence))));
  const hashOutputs = sha256d(concat(...tx.vout.map(serTxOutConsensus)));
  const preimage = concat(
    le32(tx.version),
    hashPrevouts,
    hashSequence,
    serOutPoint(tx.vin[nIn].prevout),
    compactSize(scriptCode.length), scriptCode,
    le64(amountSat),
    le32(tx.vin[nIn].sequence),
    hashOutputs,
    le32(tx.locktime),
    le32(hashType),
  );
  return hash256(preimage);
}

/** Witness signature element for a SIGHASH_ALL claim: ML-DSA-44 sig (2420) ‖ 0x01. */
export function signAllWitness(
  scriptCode: Uint8Array, tx: Tx, nIn: number, amountSat: bigint, secretKey: Uint8Array, mldsa: MlDsa,
): Uint8Array {
  const sig = mldsa.sign(sighashAll(scriptCode, tx, nIn, amountSat), secretKey);
  if (sig.length !== 2420) throw new Error(`expected 2420-byte ML-DSA sig, got ${sig.length}`);
  return concat(sig, u8(SIGHASH_ALL));
}

// ====================================================================
// OP_CHECKDILITHIUMKEYHASH (0xb6) — key-committed Dilithium 2-of-2 (SOQ-COV-013)
// ====================================================================
//
// The REAL key-binding primitive for eLTOO funding, and the basis of the funding
// helper below. CSFS authorizes a sig over a WITNESS-supplied pubkey (no key
// binding — a thief substitutes their own key). OP_CHECKDILITHIUMKEYHASH commits
// SHA256(pubkey) as a SCRIPT LITERAL (32 bytes, under the 520-byte push limit;
// the 1312-byte pubkey itself cannot be pushed), verifies the witness pubkey
// hashes to it, then runs CheckSig over the tx sighash. So the output is bound to
// SPECIFIC keys AND to the spending tx.
//
// Execution (interpreter.cpp:736-795). Stack at the opcode, top-first:
//   stacktop(-1) = keyhash  (the script literal — pushed AFTER the witness items,
//                            so it lands on top; this is why it is COMMITTED)
//   stacktop(-2) = pubkey   (raw 1312-byte ML-DSA-44, from the witness)
//   stacktop(-3) = sig      (2420 ‖ hashType, from the witness)
// On success it POPS ALL THREE (push nothing). v6 has no OP_DROP, so a k-of-k
// chains the checks and ends with OP_1 for the BIP141 clean-stack rule.
//
// Unlike CSFS (signCsfs signs Hash(sighash), no hashtype byte), this opcode
// delegates to CheckSig: sign the sighash DIRECTLY and append the hashType byte —
// i.e. reuse signApoWitness (0x41/0x42) / signAllWitness (0x01).
//
// BIP9: DEPLOYMENT_DILITHIUM_KEYHASH (bit 12). Mainnet DORMANT (nStartTime=0,
// pending Halborn Phase 2); stagenet/testnet/regtest ALWAYS_ACTIVE.
// Node-pinned against dilithium_keyhash_committed_tests.cpp (6/6 v6 VerifyScript,
// incl. committed_sdk_crossvector) as of soqucoin-build 171b027cb.

/** SHA256(rawPubKey) — the 32-byte committed keyhash. SINGLE SHA256 (matches the
 *  handler's CSHA256), NOT SHA256d. `rawPubKey` is the 1312-byte ML-DSA-44 key
 *  with NO 0x00 prefix (the handler strips the prefix before hashing). */
export function dilithiumKeyHash(rawPubKey: Uint8Array): Uint8Array {
  if (rawPubKey.length !== 1312) throw new Error(`expected 1312-byte ML-DSA pubkey, got ${rawPubKey.length}`);
  return sha256(rawPubKey);
}

/** Single-key committed script: `<kh(pub)> OP_CHECKDILITHIUMKEYHASH OP_1`.
 *  Witness eval items: [sig, pub]. */
export function dilithiumKeyhashScript(rawPubKey: Uint8Array): Uint8Array {
  return concat(pushData(dilithiumKeyHash(rawPubKey)), u8(OP.CHECKDILITHIUMKEYHASH), u8(OP.ONE));
}

/** Key-committed 2-of-2 script: `<kh(pubB)> OP_CDKH <kh(pubA)> OP_CDKH OP_1`.
 *  pubB's keyhash is committed FIRST because the first opcode checks the TOP eval
 *  item, and the witness puts pubB on top (see dilithiumKeyhash2of2Witness). */
export function dilithiumKeyhash2of2Script(pubA: Uint8Array, pubB: Uint8Array): Uint8Array {
  return dilithiumKeyhash2of2ScriptFromHashes(dilithiumKeyHash(pubA), dilithiumKeyHash(pubB));
}

/** Key-committed 2-of-2 body from raw 32-byte keyhashes: `<khB> OP_CDKH <khA> OP_CDKH OP_1`. */
export function dilithiumKeyhash2of2ScriptFromHashes(khA: Uint8Array, khB: Uint8Array): Uint8Array {
  if (khA.length !== 32 || khB.length !== 32) throw new Error("keyhash must be 32 bytes");
  return concat(
    pushData(khB), u8(OP.CHECKDILITHIUMKEYHASH),
    pushData(khA), u8(OP.CHECKDILITHIUMKEYHASH),
    u8(OP.ONE),
  );
}

/** B1 eLTOO update output witnessScript (DL-V6-CONTROLFLOW-RESTORE §4.1):
 *    IF  <stateNum+1> CLTV DROP  <khBupdate> CDKH <khAupdate> CDKH OP_1   (supersession, APO-0x42)
 *    ELSE <csv> CSV DROP         <khBsettle> CDKH <khAsettle> CDKH OP_1   (settlement after CSV)
 *    ENDIF
 *  The CLTV ratchet + CSV delay EXECUTE on V6 once SCRIPT_VERIFY_V6_CONTROLFLOW is active. REPLACES
 *  the old eltooUpdateScript (IF/CLTV/CHECKSIG inline-pubkey form, which never executed on V6:
 *  no-op opcodes + 1312-byte pubkeys > 520 push limit). Settlement keyhashes default to update.
 *  Node-pinned: lightning_script_tests.cpp/b1_script_vectors. */
export function eltooUpdateScriptV6FromKeyhashes(
  stateNum: number, khAupdate: Uint8Array, khBupdate: Uint8Array,
  opts: { khAsettle?: Uint8Array; khBsettle?: Uint8Array; settlementCsv?: number } = {},
): Uint8Array {
  const csv = opts.settlementCsv ?? 288;
  return concat(
    u8(OP.IF),
      scriptNum(stateNum + 1), u8(OP.CLTV), u8(OP.DROP),
      dilithiumKeyhash2of2ScriptFromHashes(khAupdate, khBupdate),
    u8(OP.ELSE),
      scriptNum(csv), u8(OP.CSV), u8(OP.DROP),
      dilithiumKeyhash2of2ScriptFromHashes(opts.khAsettle ?? khAupdate, opts.khBsettle ?? khBupdate),
    u8(OP.ENDIF),
  );
}

/** [eltooUpdateScriptV6FromKeyhashes] taking raw 1312-byte ML-DSA pubkeys (hashed internally). */
export function eltooUpdateScriptV6(
  stateNum: number, updateA: Uint8Array, updateB: Uint8Array,
  opts: { settleA?: Uint8Array; settleB?: Uint8Array; settlementCsv?: number } = {},
): Uint8Array {
  return eltooUpdateScriptV6FromKeyhashes(stateNum, dilithiumKeyHash(updateA), dilithiumKeyHash(updateB), {
    khAsettle: opts.settleA ? dilithiumKeyHash(opts.settleA) : undefined,
    khBsettle: opts.settleB ? dilithiumKeyHash(opts.settleB) : undefined,
    settlementCsv: opts.settlementCsv,
  });
}

// ── B1 branch witnesses (step 4) ──
// Node-accepted v6 satisfaction layouts for spending the B1 eLTOO output (lightning_script_tests
// eltoo_v6_ratchet_target): the 2-of-2 keyhash satisfaction + the OP_IF selector (0x01 = IF
// update, empty = ELSE settlement), then witnessScript + trailing 0x00-prefixed pubkey.

/** B1 eLTOO UPDATE-branch (supersession, IF) witness: [sigA, pubA, sigB, pubB, TRUE]. sigA/pubA
 *  commit to khAupdate, sigB/pubB to khBupdate (B is checked first → on top). The spending
 *  next-state update tx sets nLockTime ≥ stateNum+1 so its CLTV ratchet passes. */
export function eltooUpdateBranchWitness(
  eltooScript: Uint8Array, sigA: Uint8Array, pubA: Uint8Array, sigB: Uint8Array, pubB: Uint8Array,
  trailingPubKey: Uint8Array,
): Uint8Array[] {
  return p2wshV6Witness([sigA, pubA, sigB, pubB, Uint8Array.of(0x01)], eltooScript, trailingPubKey);
}

/** B1 eLTOO SETTLEMENT-branch (close, ELSE) witness: same 2-of-2 satisfaction with a FALSE
 *  (empty) selector. The settlement tx must spend with nSequence ≥ settlementCsv (the CSV delay). */
export function eltooSettlementBranchWitness(
  eltooScript: Uint8Array, sigA: Uint8Array, pubA: Uint8Array, sigB: Uint8Array, pubB: Uint8Array,
  trailingPubKey: Uint8Array,
): Uint8Array[] {
  return p2wshV6Witness([sigA, pubA, sigB, pubB, new Uint8Array(0)], eltooScript, trailingPubKey);
}

/** v6 witness for a single-key committed spend. Eval items: [sig, pub] (pub on top).
 *  `sig` = signForKeyhash(...); `rawPubKey` = raw 1312-byte key; `trailingPubKey` is
 *  0x00-prefixed (use dilithiumWitnessPubKey). */
export function dilithiumKeyhashWitness(
  sig: Uint8Array, rawPubKey: Uint8Array, trailingPubKey: Uint8Array,
  witnessScript: Uint8Array = dilithiumKeyhashScript(rawPubKey),
): Uint8Array[] {
  return p2wshV6Witness([sig, rawPubKey], witnessScript, trailingPubKey);
}

/** v6 witness for the key-committed 2-of-2. Eval-stack order: the first OP_CDKH
 *  consumes the TOP triple, so satisfaction = [sigA, pubA, sigB, pubB] (B checked
 *  first, A second — matching dilithiumKeyhash2of2Script's commit order).
 *  pubA/pubB are raw 1312-byte keys; trailingPubKey is 0x00-prefixed. */
export function dilithiumKeyhash2of2Witness(
  sigA: Uint8Array, pubA: Uint8Array, sigB: Uint8Array, pubB: Uint8Array,
  trailingPubKey: Uint8Array, witnessScript: Uint8Array = dilithiumKeyhash2of2Script(pubA, pubB),
): Uint8Array[] {
  return p2wshV6Witness([sigA, pubA, sigB, pubB], witnessScript, trailingPubKey);
}

/** Sign an OP_CHECKDILITHIUMKEYHASH input. The opcode delegates to CheckSig, which
 *  signs the sighash DIRECTLY (not Hash(sighash) like CSFS) and reads the trailing
 *  hashType byte. scriptCode = the FULL witnessScript (what EvalScript passes to
 *  CheckSig as `script`). hashType: 0x01 (close), 0x41/0x42 (eLTOO update rebinding). */
export function signForKeyhash(
  witnessScript: Uint8Array, tx: Tx, nIn: number, hashType: number, amountSat: bigint,
  secretKey: Uint8Array, mldsa: MlDsa,
): Uint8Array {
  if (hashType === SIGHASH_ALL) return signAllWitness(witnessScript, tx, nIn, amountSat, secretKey, mldsa);
  if (hashType === SIGHASH_ANYPREVOUT || hashType === SIGHASH_ANYPREVOUTANYSCRIPT)
    return signApoWitness(witnessScript, tx, nIn, hashType, amountSat, secretKey, mldsa);
  throw new Error(`signForKeyhash: unsupported hashType 0x${hashType.toString(16)}`);
}

// ---- the funding helper (the V6_KEY_BINDING_ANALYSIS deliverable) ----

/** A key-committed eLTOO funding output: the 2-of-2 both parties must co-sign with
 *  their SPECIFIC Dilithium keys. Supersedes the CSFS 2-of-2 for funding once
 *  SOQ-COV-013 is BIP9-active (CSFS does not bind keys). `pubA`/`pubB` are raw
 *  1312-byte ML-DSA-44 keys. */
export interface KeyhashFunding {
  witnessScript: Uint8Array;   // <kh(pubB)> OP_CDKH <kh(pubA)> OP_CDKH OP_1
  scriptPubKey: Uint8Array;    // p2wshV6(witnessScript) = OP_6 <sha256(witnessScript)>
}

export function keyhashFunding2of2(pubA: Uint8Array, pubB: Uint8Array): KeyhashFunding {
  const witnessScript = dilithiumKeyhash2of2Script(pubA, pubB);
  return { witnessScript, scriptPubKey: p2wshV6(witnessScript) };
}

/** Co-sign a spend of a key-committed 2-of-2 funding output and assemble the v6
 *  witness. `hashType` = 0x42 for an eLTOO update (rebindable) or 0x01 for a
 *  cooperative close. Both signatures cover the same witnessScript-bound sighash.
 *  In a real channel the two sigs are produced independently; this convenience
 *  signs both for the test/helper path. The trailing HasDilithiumSignatures pubkey
 *  is pubA (any party key works — it is consumed by the standardness check only). */
// ---- cross-party 2-of-2 (the real protocol: A and B sign independently) ----
//
// In a live channel the two parties never share secret keys: each signs the SAME
// witnessScript-bound sighash with only their own key (partialSignKeyhash2of2),
// then either side assembles the final witness from the two contributions
// (combineKeyhash2of2Witness). combine is ORDER-ROBUST — it matches each partial
// to its committed keyhash slot in the script, so a caller can pass them in any
// order and cannot misorder A/B (a class of footgun that would silently produce
// an invalid witness). signKeyhashFunding2of2 below is just the single-operator
// convenience: sign both partials locally, then combine — same code path.

const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((x, i) => x === b[i]);

/** Validate + extract the two committed keyhashes from a keyhash-2-of-2 witnessScript.
 *  Shape: 0x20 <khFirst> 0xb6 0x20 <khSecond> 0xb6 0x51 (69 bytes). khFirst is checked
 *  FIRST by the script (so its key must end up on TOP of the eval stack). */
function parseKeyhash2of2Script(ws: Uint8Array): { khFirst: Uint8Array; khSecond: Uint8Array } {
  if (ws.length !== 69 || ws[0] !== 0x20 || ws[33] !== OP.CHECKDILITHIUMKEYHASH ||
      ws[34] !== 0x20 || ws[67] !== OP.CHECKDILITHIUMKEYHASH || ws[68] !== OP.ONE) {
    throw new Error("not a keyhash-2-of-2 witnessScript");
  }
  return { khFirst: ws.slice(1, 33), khSecond: ws.slice(35, 67) };
}

/** One party's contribution to a keyhash-2-of-2 spend: their pubkey + their signature. */
export interface KeyhashPartial { pubKey: Uint8Array; sig: Uint8Array; }

/** Produce ONE party's partial signature over a keyhash-2-of-2 spend. The party needs
 *  only their own secret key. `hashType` = 0x42 (eLTOO update) or 0x01 (close/settlement);
 *  both signers must use the same one. Returns {pubKey, sig(2421)} for combine. */
export function partialSignKeyhash2of2(
  witnessScript: Uint8Array, tx: Tx, nIn: number, hashType: number, amountSat: bigint,
  secretKey: Uint8Array, pubKey: Uint8Array, mldsa: MlDsa,
): KeyhashPartial {
  if (pubKey.length !== 1312) throw new Error(`expected 1312-byte pubkey, got ${pubKey.length}`);
  return { pubKey, sig: signForKeyhash(witnessScript, tx, nIn, hashType, amountSat, secretKey, mldsa) };
}

/** Assemble the v6 witness from two independently-produced partials. ORDER-ROBUST:
 *  each partial is matched to its committed keyhash slot, so [pa,pb] and [pb,pa] yield
 *  the identical witness. The party whose keyhash is committed FIRST in the script is
 *  checked first, so its (sig,pubkey) must sit on TOP of the eval stack (last pair).
 *  Throws if a partial matches no committed slot (wrong key) or both map to one slot. */
export function combineKeyhash2of2Witness(
  witnessScript: Uint8Array, partials: [KeyhashPartial, KeyhashPartial],
  trailingPubKey?: Uint8Array,
): Uint8Array[] {
  const { khFirst, khSecond } = parseKeyhash2of2Script(witnessScript);
  const match = (target: Uint8Array): KeyhashPartial => {
    const found = partials.filter((p) => bytesEqual(dilithiumKeyHash(p.pubKey), target));
    if (found.length !== 1) throw new Error("combineKeyhash2of2Witness: exactly one partial must match each committed keyhash");
    return found[0];
  };
  const pFirst = match(khFirst);    // committed first → checked first → TOP of eval stack (last pair)
  const pSecond = match(khSecond);  // committed second → first eval pair
  if (pFirst === pSecond) throw new Error("both partials map to the same committed key");
  for (const p of [pFirst, pSecond])
    if (p.sig.length !== 2421) throw new Error(`partial sig must be 2421 bytes (2420 + hashType), got ${p.sig.length}`);
  if (pFirst.sig[2420] !== pSecond.sig[2420]) throw new Error("partials signed different hashTypes");
  // Default trailing pubkey is derived from the SCRIPT-matched ordering (pFirst), NOT the
  // caller's arg order, so the assembled witness is identical for [pa,pb] and [pb,pa].
  const trailing = trailingPubKey ?? dilithiumWitnessPubKey(pFirst.pubKey);
  // eval items bottom→top: [sigSecond, pubSecond, sigFirst, pubFirst] (First on top)
  return p2wshV6Witness([pSecond.sig, pSecond.pubKey, pFirst.sig, pFirst.pubKey], witnessScript, trailing);
}

/** Single-operator convenience: sign both sides locally, then combine. Identical output
 *  (structurally) to two parties signing independently and combining — it IS that path. */
export function signKeyhashFunding2of2(
  funding: KeyhashFunding, tx: Tx, nIn: number, amountSat: bigint, hashType: number,
  skA: Uint8Array, pubA: Uint8Array, skB: Uint8Array, pubB: Uint8Array, mldsa: MlDsa,
): Uint8Array[] {
  const pa = partialSignKeyhash2of2(funding.witnessScript, tx, nIn, hashType, amountSat, skA, pubA, mldsa);
  const pb = partialSignKeyhash2of2(funding.witnessScript, tx, nIn, hashType, amountSat, skB, pubB, mldsa);
  return combineKeyhash2of2Witness(funding.witnessScript, [pa, pb], dilithiumWitnessPubKey(pubA));
}

// ---- CTV template hash — interpreter.cpp:1725-1850 / test ref :51-74 ----
/** BIP119 DefaultCheckTemplateVerifyHash (SINGLE SHA256). scriptSigsHash is included
 *  ONLY if any input scriptSig is non-empty (omitted for segwit eLTOO spends). */
export function ctvHash(tx: Tx, nIn: number): Uint8Array {
  const parts: Uint8Array[] = [le32(tx.version), le32(tx.locktime)];

  const anyScriptSig = tx.vin.some((i) => i.scriptSig && i.scriptSig.length > 0);
  if (anyScriptSig) {
    const sigsConcat = concat(...tx.vin.map((i) => {
      const s = i.scriptSig ?? new Uint8Array();
      return concat(le32(s.length), s);
    }));
    parts.push(sha256(sigsConcat));
  }

  parts.push(le32(tx.vin.length));
  parts.push(sha256(concat(...tx.vin.map((i) => le32(i.sequence)))));
  parts.push(le32(tx.vout.length));
  parts.push(sha256(concat(...tx.vout.map(serTxOutCtv))));
  parts.push(le32(nIn));

  return sha256(concat(...parts)); // single SHA256, NOT double
}

// ---- legacy/whole tx serialization (non-witness, for update_tx_hex transport) ----
const serScript = (s: Uint8Array) => concat(compactSize(s.length), s);
const serTxIn = (i: TxIn) => concat(serOutPoint(i.prevout), serScript(i.scriptSig ?? new Uint8Array()), le32(i.sequence));
/** Non-witness consensus serialization of a tx (sufficient for the LSP's opaque hex transport). */
export function serializeTx(tx: Tx): Uint8Array {
  return concat(
    le32(tx.version),
    compactSize(tx.vin.length), ...tx.vin.map(serTxIn),
    compactSize(tx.vout.length), ...tx.vout.map(serTxOutConsensus),
    le32(tx.locktime),
  );
}
export const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const fromHex = (s: string) => Uint8Array.from((s.match(/.{1,2}/g) ?? []).map((h) => parseInt(h, 16)));

/** The txid (BIP141: hash256 of the NON-witness serialization, displayed reversed). */
export function txid(tx: Tx): Uint8Array { return hash256(serializeTx(tx)); }

/** BIP141 segwit serialization WITH witness — required for broadcast (sendrawtransaction).
 *  `witnesses[i]` is input i's witness stack (array of items, e.g. the p2wsh stack
 *  [...args, witnessScript]). Layout: version ‖ 0x00 0x01 ‖ vin ‖ vout ‖ witnesses ‖ locktime.
 *  scriptSig stays empty for segwit inputs (the witness carries the data). */
export function serializeTxWithWitness(tx: Tx, witnesses: Uint8Array[][]): Uint8Array {
  if (witnesses.length !== tx.vin.length) throw new Error("one witness stack required per input");
  const serStackItem = (it: Uint8Array) => concat(compactSize(it.length), it);
  const serWitness = (stack: Uint8Array[]) => concat(compactSize(stack.length), ...stack.map(serStackItem));
  return concat(
    le32(tx.version),
    u8(0x00), u8(0x01),                                    // segwit marker + flag
    compactSize(tx.vin.length), ...tx.vin.map(serTxIn),    // scriptSig empty for segwit inputs
    compactSize(tx.vout.length), ...tx.vout.map(serTxOutConsensus),
    ...witnesses.map(serWitness),
    le32(tx.locktime),
  );
}

// ====================================================================
// DilithiumEltooBuilder — plugs into SoqLightning as the real UpdateTxBuilder
// ====================================================================

export interface EltooBuilderOpts {
  funding: OutPoint;               // the funding (or genesis) outpoint the channel anchors on
  fundingAmountSat: bigint;        // channel capacity in sats (the input amount being spent)
  initiatorPub: Uint8Array;        // ML-DSA-44 pubkey, "Alice"
  peerPub: Uint8Array;             // ML-DSA-44 pubkey, "Bob"
  initiatorScriptPubKey: Uint8Array; // settlement payout spk for the initiator
  peerScriptPubKey: Uint8Array;      // settlement payout spk for the peer
  secretKey: Uint8Array;           // OUR ML-DSA-44 secret key (signs the update with 0x42)
  mldsa: MlDsa;                    // pure ML-DSA-44, empty context (see key.cpp:100)
  settlementCsv?: number;          // default 288
}

/**
 * Builds the eLTOO update + settlement transactions for one channel state and signs the
 * update input with SIGHASH_ANYPREVOUTANYSCRIPT (0x42). Returns the transport hex + the
 * CTV hash committing to the settlement payout (the LSP stores these opaquely today).
 *
 * NOTE: this constructs the canonical eLTOO tx graph (update output re-commits the state-N
 * script; settlement spends it via the CSV branch paying both balances). The exact graph
 * must be byte-validated against a node vector before mainnet — see B1 doc §3.5.
 */
export class DilithiumEltooBuilder implements UpdateTxBuilder {
  constructor(private o: EltooBuilderOpts) {}

  buildUpdateTx(stateNum: number): Tx {
    const csv = this.o.settlementCsv ?? 288;
    const witnessScript = eltooUpdateScriptV6(stateNum, this.o.initiatorPub, this.o.peerPub, { settlementCsv: csv });
    return {
      version: 2,
      locktime: stateNum + 1, // satisfies the prior script's IF-branch CLTV <stateNum+1>
      vin: [{ prevout: this.o.funding, sequence: 0 }],
      vout: [{ value: this.o.fundingAmountSat, scriptPubKey: p2wshV6(witnessScript) }], // v6, not v0
    };
  }

  buildSettlementTx(updateTxid: Uint8Array, initiatorBalanceSat: bigint, peerBalanceSat: bigint): Tx {
    const csv = this.o.settlementCsv ?? 288;
    return {
      version: 2,
      locktime: 0,
      vin: [{ prevout: { txid: updateTxid, n: 0 }, sequence: csv }], // ELSE branch: relative CSV
      vout: [
        { value: initiatorBalanceSat, scriptPubKey: this.o.initiatorScriptPubKey },
        { value: peerBalanceSat, scriptPubKey: this.o.peerScriptPubKey },
      ],
    };
  }

  async build(ctx: UpdateContext): Promise<{ update_tx_hex: string; settlement_tx_hex: string; ctv_hash: string }> {
    const stateNum = ctx.nextStateIndex;
    const updateTx = this.buildUpdateTx(stateNum);

    // Sign the update input with 0x42 (scriptCode empty — rebindable across states).
    const witnessSig = signApoWitness(
      new Uint8Array(), updateTx, 0, SIGHASH_ANYPREVOUTANYSCRIPT,
      this.o.fundingAmountSat, this.o.secretKey, this.o.mldsa,
    );
    // attach as the input's scriptSig surrogate for opaque transport (real broadcast uses witness)
    updateTx.vin[0].scriptSig = witnessSig;

    const updateTxid = hash256(serializeTx({ ...updateTx, vin: updateTx.vin.map((i) => ({ ...i, scriptSig: undefined })) }));
    const settlementTx = this.buildSettlementTx(
      updateTxid,
      BigInt(ctx.nextInitiatorBalanceSat),
      BigInt(ctx.nextPeerBalanceSat),
    );

    return {
      update_tx_hex: toHex(serializeTx(updateTx)),
      settlement_tx_hex: toHex(serializeTx(settlementTx)),
      ctv_hash: toHex(ctvHash(settlementTx, 0)),
    };
  }
}

/** Hook for Buddy's known-good vector: feed a (scriptCode, tx, nIn, hashType, amount) the
 *  node computed a sighash for, plus that 32-byte digest, and assert byte-equality. This is
 *  the proof that closes the gap between "matches the documented algorithm" and "matches the
 *  node". Until this passes against a real vector, do NOT broadcast SDK-built txs to mainnet. */
export function verifyAgainstNodeVector(v: {
  scriptCode: Uint8Array; tx: Tx; nIn: number; hashType: number; amountSat: bigint; expectedDigestHex: string;
}): boolean {
  return toHex(apoSighash(v.scriptCode, v.tx, v.nIn, v.hashType, v.amountSat)) === v.expectedDigestHex.toLowerCase();
}
