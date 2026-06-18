// SIGHASH_ALL node-vector proof — closes the gap on channel.ts `sighashAll()` (the standard
// BIP143 path used by HTLC claims) + bonus byte-equality on htlc.ts `htlcScript()`.
// PASTE Buddy's `sighashall_dump_vectors` output into V, then: npm test
// Until V.digest_sighash_all is filled (not "PASTE_"), these tests SKIP.
import { test } from "node:test";
import assert from "node:assert/strict";
import { sighashAll, htlcScript, toHex, fromHex } from "../dist/index.js";
import { sha256 } from "@noble/hashes/sha256";

// ---------- VECTORS FROM sighashall_dump_vectors (Jun 15 2026, Mining VPS node) ----------
const V = {
  version: 2,
  locktime: 0,
  vin0_prevout_hash: "1111111111111111111111111111111111111111111111111111111111111111", // internal byte order — COMMITTED by SIGHASH_ALL
  vin0_prevout_n: 0,
  vin0_sequence: 4294967294,            // 0xfffffffe
  vout0_value: 4900000000n,             // 49 * COIN
  vout0_scriptpubkey_hex: "51",         // OP_TRUE
  vout1_value: 0n,                      // anchor
  vout1_scriptpubkey_hex: "51",
  scriptcode_hex: "76a914aabbccddeeff00112233445566778899aabbccdd88ac",
  amount_sat: 4900000000n,
  // PHASE 4 (byte-less): pinned from node dump (sighashall_dump_vectors), cross-checked
  // against TS-computed value (DL-PHASE4-VECTOR-REGEN.md). Match confirmed.
  digest_sighash_all: "cd77a89ae224a3d3c492888ba1af91711ea94fa5a9e59ad5c547d304177fdf80",
  htlc_script_sha256: "8e878955ba84d8fda67d623a984c8a31f2e86fc62dd2c18fc0098c7d3d0a5560",  // script hash, unaffected
};
// ---------------------------------------------------------------

const ready = true; // Phase 4: node-pinned digest confirmed

function buildTx() {
  return {
    version: V.version, locktime: V.locktime,
    vin: [{
      prevout: { txid: fromHex(V.vin0_prevout_hash), n: V.vin0_prevout_n },
      sequence: V.vin0_sequence,
    }],
    vout: [
      { value: V.vout0_value, scriptPubKey: fromHex(V.vout0_scriptpubkey_hex) },
      { value: V.vout1_value, scriptPubKey: fromHex(V.vout1_scriptpubkey_hex) },
    ],
  };
}

test("node vector: SIGHASH_ALL digest matches (validates standard BIP143 path)", { skip: !ready }, () => {
  const got = toHex(sighashAll(fromHex(V.scriptcode_hex), buildTx(), 0, V.amount_sat));
  assert.equal(got, V.digest_sighash_all.toLowerCase());
});

test("node vector: §2.2 htlcScript() is byte-identical to the node (via sha256)", { skip: !ready }, () => {
  // same deterministic inputs as the snippet: H=0xab×32, payee=0x11×1312, payer=0x22×1312, cltv=500
  const script = htlcScript(new Uint8Array(32).fill(0xab), new Uint8Array(1312).fill(0x11), new Uint8Array(1312).fill(0x22), 500);
  assert.equal(toHex(sha256(script)), V.htlc_script_sha256.toLowerCase());
});
