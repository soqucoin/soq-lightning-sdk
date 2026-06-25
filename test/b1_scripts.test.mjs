// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// b1_scripts.test.mjs — pins the B1 eLTOO + HTLC witnessScript bytes to the node.
// Ground truth: soqucoin-build lightning_script_tests.cpp/b1_script_vectors
// (DL-V6-CONTROLFLOW-RESTORE §4). Keyhash = SHA256(pubkey) is separately pinned (P4).

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  eltooUpdateScriptV6FromKeyhashes,
  eltooUpdateScriptV6,
  htlcScriptV6FromKeyhashes,
  htlcScriptV6,
  dilithiumKeyHash,
} from "../dist/index.js";

const fill = (b) => new Uint8Array(32).fill(b);
const hex = (u) => Buffer.from(u).toString("hex");

test("B1 eLTOO update script byte-matches the node vector", () => {
  const ws = eltooUpdateScriptV6FromKeyhashes(600000, fill(0x11), fill(0x22), {
    khAsettle: fill(0x33), khBsettle: fill(0x44), settlementCsv: 288,
  });
  assert.equal(
    hex(ws),
    "6303c12709b175202222222222222222222222222222222222222222222222222222222222222222b6201111111111111111111111111111111111111111111111111111111111111111b65167022001b275204444444444444444444444444444444444444444444444444444444444444444b6203333333333333333333333333333333333333333333333333333333333333333b65168",
  );
});

test("B1 HTLC script byte-matches the node vector", () => {
  const ws = htlcScriptV6FromKeyhashes(fill(0xab), fill(0x55), fill(0x66), 500);
  assert.equal(
    hex(ws),
    "63a820abababababababababababababababababababababababababababababababab88205555555555555555555555555555555555555555555555555555555555555555b6516702f401b175206666666666666666666666666666666666666666666666666666666666666666b65168",
  );
});

test("pubkey wrappers agree with the from-keyhash form", () => {
  const pubA = new Uint8Array(1312).fill(0xa1);
  const pubB = new Uint8Array(1312).fill(0xb2);
  assert.equal(
    hex(eltooUpdateScriptV6(7, pubA, pubB, { settlementCsv: 144 })),
    hex(eltooUpdateScriptV6FromKeyhashes(7, dilithiumKeyHash(pubA), dilithiumKeyHash(pubB), { settlementCsv: 144 })),
  );
  const h = new Uint8Array(32).fill(0x07);
  assert.equal(
    hex(htlcScriptV6(h, pubA, pubB, 1000)),
    hex(htlcScriptV6FromKeyhashes(h, dilithiumKeyHash(pubA), dilithiumKeyHash(pubB), 1000)),
  );
});
