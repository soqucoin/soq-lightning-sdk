// CTxOut cross-format golden-matrix — TS reimpl cross-pin (CTxOut migration Phase 4 re-pin).
//
// Phase 4 removed the nVisibility/nAssetType bytes — CTxOut is now the single STANDARD format
// (value ‖ script). This pins the TS serializers to the byte-less golden, the SAME fixture the
// C++ ctxout_format_matrix_tests + the Go reimpls use (value 12345678, scriptPubKey=OP_TRUE), so
// node + every reimpl agree byte-for-byte. (visibility/assetType on the fixture are ignored now.)
import { test } from "node:test";
import assert from "node:assert/strict";
import { serTxOutConsensus, serTxOutCtv, toHex } from "../dist/index.js";

const FIXTURE = { value: 12345678n, scriptPubKey: Uint8Array.of(0x51) };

// Post-Phase-4 byte-less goldens (== old SERIALIZE_TXOUT_STANDARD form; the +2 bytes are gone).
// consensus: value(8 LE) ‖ compactSize(len) ‖ script
const GOLDEN_CONSENSUS = "4e61bc00000000000151";
// CTV order: value(8 LE) ‖ scriptLen(LE32) ‖ script  (distinct LE32 length encoding)
const GOLDEN_CTV = "4e61bc00000000000100000051";

test("CTxOut consensus serialization matches the byte-less golden", () => {
  assert.equal(toHex(serTxOutConsensus(FIXTURE)), GOLDEN_CONSENSUS);
  // Phase-4 regression guard: OP_TRUE output = value(8)+len(1)+script(1) = 10 bytes (was 12).
  assert.equal(serTxOutConsensus(FIXTURE).length, 10);
});

test("CTV-order serialization matches the byte-less golden (distinct LE32 length)", () => {
  assert.equal(toHex(serTxOutCtv(FIXTURE)), GOLDEN_CTV);
  assert.notEqual(toHex(serTxOutCtv(FIXTURE)), GOLDEN_CONSENSUS);
  // visibility/assetType are ignored post-Phase-4 — setting them changes nothing.
  assert.equal(toHex(serTxOutConsensus({ ...FIXTURE, visibility: 1, assetType: 1 })), GOLDEN_CONSENSUS);
});

test("VECTOR — emit for C++/Go/Dart cross-pin", () => {
  console.log("CTXOUT_MATRIX_BEGIN");
  console.log("fixture=value:12345678 script:OP_TRUE(0x51) (byte-less, post-Phase-4)");
  console.log("consensus=" + toHex(serTxOutConsensus(FIXTURE)));
  console.log("ctv=" + toHex(serTxOutCtv(FIXTURE)));
  console.log("CTXOUT_MATRIX_END");
  assert.ok(true);
});
