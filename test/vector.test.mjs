// B1 node-vector proof — closes the gap between "matches the documented algorithm" and
// "matches the node". PASTE Buddy's `b1_dump_vectors` output into V below, then:
//   npm test
// Until V.digest_apo_0x42 is filled (not the "PASTE_" sentinel), these tests SKIP.
import { test } from "node:test";
import assert from "node:assert/strict";
import { apoSighash, ctvHash, toHex, fromHex, SIGHASH_ANYPREVOUT, SIGHASH_ANYPREVOUTANYSCRIPT } from "../dist/index.js";

// ---------- PASTE FROM b1_dump_vectors OUTPUT ----------
const V = {
  version: 2,
  locktime: 1,
  vin0_prevout_hash: "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100", // internal byte order
  vin0_prevout_n: 3,
  vin0_sequence: 0,
  vout0_value: 10000000000n,           // 100 * COIN
  vout0_scriptpubkey_hex: "51",        // OP_TRUE
  scriptcode_hex: "76a914aabbccddeeff00112233445566778899aabbccdd88ac",
  amount_sat: 10000000000n,
  // PHASE 4 (byte-less): pinned from node dump (b1_dump_vectors), cross-checked against
  // TS-computed values (DL-PHASE4-VECTOR-REGEN.md). All 4 digests matched.
  digest_apo_0x42: "4c8c1f5ee5be7a8d654f8bbe281b469423d3cf9b180319baf638b288579084ce",
  digest_apo_0x41: "3e5752e00dd14ef60bf41fce71ab27ea96be2d3ec9e6d331040e815a29d51edb",
  ctv_hash: "4a0575860c4e73b17c3e5ba537b094cdf9b2c9b9d866032c59b7ff0a2db8d396",
};
// -------------------------------------------------------

const ready = true; // Phase 4: node-pinned digests confirmed

function buildTx() {
  return {
    version: V.version, locktime: V.locktime,
    vin: [{
      prevout: { txid: fromHex(V.vin0_prevout_hash), n: V.vin0_prevout_n },
      sequence: V.vin0_sequence,
    }],
    vout: [{
      value: V.vout0_value, scriptPubKey: fromHex(V.vout0_scriptpubkey_hex),
    }],
  };
}

test("node vector: APO 0x42 digest matches", { skip: !ready }, () => {
  // 0x42 ignores scriptCode — pass empty, as channel.ts does
  const got = toHex(apoSighash(new Uint8Array(), buildTx(), 0, SIGHASH_ANYPREVOUTANYSCRIPT, V.amount_sat));
  assert.equal(got, V.digest_apo_0x42.toLowerCase());
});

test("node vector: APO 0x41 digest matches (validates scriptCode serialization)", { skip: !ready }, () => {
  const got = toHex(apoSighash(fromHex(V.scriptcode_hex), buildTx(), 0, SIGHASH_ANYPREVOUT, V.amount_sat));
  assert.equal(got, V.digest_apo_0x41.toLowerCase());
});

test("node vector: CTV hash matches (validates CTV output serializer)", { skip: !ready }, () => {
  const got = toHex(ctvHash(buildTx(), 0));
  assert.equal(got, V.ctv_hash.toLowerCase());
});
