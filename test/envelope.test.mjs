// serializeTxWithWitness() — BIP141 witness ENVELOPE byte-exactness.
//
// NODE-PINNED against the C++ CTransaction serializer via the canonical vector
// (test/vectors/eltoo_envelope_vector.json). PHASE 4: regenerated from the live e2e
// cooperative-close 2b559965 — a real, node-accepted, BYTE-LESS keyhash-2-of-2 tx.
// We parse raw_hex INDEPENDENTLY (per BIP141), cross-check every field against the
// JSON's structured values, then re-serialize through serializeTxWithWitness and assert
// byte-equality with raw_hex AND a matching txid. This pins: marker/flag, compactSize
// stack count + per-item length prefixes, and the byte-less consensus CTxOut field
// order (value ‖ compactSize(scriptLen) ‖ script — no nVisibility/nAssetType).
//
// The pin is keygen-independent: it parses + re-serializes the wire bytes (the witness
// items are real eLTOO sizes), so it needs no keys, signatures, or keygen interop.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { serializeTxWithWitness, toHex, fromHex, txid } from "../dist/index.js";

const J = JSON.parse(readFileSync(
  fileURLToPath(new URL("./vectors/eltoo_envelope_vector.json", import.meta.url)), "utf8"));

// --- independent BIP141 parser (does NOT reuse the SDK serializer's assumptions) ---
function parse(raw) {
  let p = 0;
  const u32 = () => { const v = (raw[p]|(raw[p+1]<<8)|(raw[p+2]<<16)|(raw[p+3]<<24))>>>0; p += 4; return v; };
  const take = (n) => { const s = raw.slice(p, p + n); p += n; return s; };
  const cs = () => { const a = raw[p++]; if (a < 0xfd) return a;
    if (a === 0xfd) { const v = raw[p]|(raw[p+1]<<8); p += 2; return v; }
    if (a === 0xfe) { const v = (raw[p]|(raw[p+1]<<8)|(raw[p+2]<<16)|(raw[p+3]<<24))>>>0; p += 4; return v; }
    throw new Error("compactSize too large for this vector"); };
  const version = u32();
  const marker = raw[p++], flag = raw[p++];
  const vinN = cs(), vin = [];
  for (let i = 0; i < vinN; i++) { const h = take(32), n = u32(), sl = cs(), ss = take(sl), seq = u32();
    vin.push({ prevout: { txid: h, n }, scriptSig: ss, sequence: seq }); }
  const voutN = cs(), vout = [];
  for (let i = 0; i < voutN; i++) { const lo = u32(), hi = u32(); const value = BigInt(lo) + (BigInt(hi) << 32n);
    const sl = cs(), spk = take(sl);   // PHASE 4: byte-less — no nVisibility/nAssetType
    vout.push({ value, scriptPubKey: spk }); }
  const witnesses = [];
  for (let i = 0; i < vinN; i++) { const k = cs(), st = []; for (let j = 0; j < k; j++) st.push(take(cs())); witnesses.push(st); }
  const locktime = u32();
  return { version, marker, flag, vin, vout, witnesses, locktime, consumed: p };
}

test("envelope: parse cross-checks the JSON's structured fields", () => {
  const raw = fromHex(J.raw_hex);
  const t = parse(raw);
  assert.equal(t.consumed, raw.length, "parser must consume every byte (no trailing/short read)");
  assert.equal(t.marker, 0x00); assert.equal(t.flag, 0x01);
  assert.equal(t.version, J.nVersion); assert.equal(t.locktime, J.nLockTime);
  assert.equal(t.vin[0].scriptSig.length, 0, "segwit input scriptSig is empty");
  assert.equal(t.vin[0].sequence >>> 0, J.input.nSequence >>> 0);
  assert.equal(toHex(t.vin[0].prevout.txid), J.input.prevout_hash);
  assert.equal(t.vout[0].value, BigInt(J.output.value_sat));
  assert.equal(toHex(t.vout[0].scriptPubKey), J.output.scriptPubKey);
  // Buddy's JSON encodes witness_item_sizes as a string ("[2421, ...]"), so normalize.
  const expectSizes = typeof J.input.witness_item_sizes === "string"
    ? JSON.parse(J.input.witness_item_sizes) : J.input.witness_item_sizes;
  assert.deepEqual(t.witnesses[0].map((x) => x.length), expectSizes);
  assert.equal(toHex(t.witnesses[0][4]), J.witnessScript_hex, "item 4 is the keyhash-2-of-2 witnessScript");
});

// PHASE 4 (byte-less): vector regenerated from the live e2e coop-close 2b559965 — a real node-accepted
// byte-less tx. raw_hex/txid carry NO nVisibility/nAssetType; parse() reads the byte-less CTxOut above.
test("envelope: serializeTxWithWitness reproduces the node bytes + txid", () => {
  const raw = fromHex(J.raw_hex);
  const t = parse(raw);
  // Reconstruct the Tx (scriptSig stays empty for segwit) and feed the EXACT witness items back.
  const tx = {
    version: t.version, locktime: t.locktime,
    vin: [{ prevout: t.vin[0].prevout, sequence: t.vin[0].sequence }],
    vout: t.vout,
  };
  assert.equal(toHex(serializeTxWithWitness(tx, t.witnesses)), J.raw_hex.toLowerCase(),
    "TS witness serialization must be byte-identical to the C++ node serializer");
  // txid = hash256(non-witness serialization), displayed big-endian (reversed).
  assert.equal(toHex(txid(tx).slice().reverse()), J.txid, "non-witness txid must match the node");
});
