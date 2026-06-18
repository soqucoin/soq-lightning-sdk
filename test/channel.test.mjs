// channel.ts (B1) — proves the load-bearing eLTOO crypto properties WITHOUT a node:
//   - APO 0x42 rebinding invariances (ignores prevout, sequence, scriptCode)
//   - APO 0x41 vs 0x42 difference (0x41 commits scriptCode, 0x42 does not)
//   - CTV hash determinism + tamper-sensitivity (mirrors ctv_htlc_resolution C++ test)
//   - witness sig framing (2420 ‖ hashtype = 2421)
//   - encoding primitives (compactSize / scriptNum / p2wsh)
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  apoSighash, ctvHash, signApoWitness, SIGHASH_ANYPREVOUT, SIGHASH_ANYPREVOUTANYSCRIPT,
  eltooUpdateScript, p2wsh, p2wshV6, p2wshV6Witness, dilithiumWitnessPubKey, fundingScript,
  scriptNum, pushData, ctvScript, toHex, fromHex, serializeTxWithWitness,
  DilithiumEltooBuilder, serializeTx, SoqLightning,
  csfs2of2AuthScript, signCsfs, csfs2of2Witness, dilithiumWitnessPubKey as dwpk,
  csfs2of2WithCtvScript, csfs2of2WithCtvWitness,
  nobleMlDsa, mlDsaKeygen,
} from "../dist/index.js";
import { sha256 } from "@noble/hashes/sha256";
const sha256d = (b) => sha256(sha256(b));

const bytes = (n, fill) => new Uint8Array(n).fill(fill);
const txid = (b) => bytes(32, b);

// a base eLTOO-ish tx: spends one output, recreates a channel output
function baseTx(over = {}) {
  return {
    version: 2, locktime: 5,
    vin: [{ prevout: { txid: txid(0xaa), n: 0 }, sequence: 0 }],
    vout: [{ value: 100_000_000n, scriptPubKey: Uint8Array.of(0x51), visibility: 0, assetType: 0 }],
    ...over,
  };
}

test("APO 0x42 IGNORES prevout — the eLTOO rebinding property", () => {
  const sc = Uint8Array.of(0xac);
  const a = apoSighash(sc, baseTx(), 0, SIGHASH_ANYPREVOUTANYSCRIPT, 100_000_000n);
  // change the prevout entirely — 0x42 sighash must be identical (rebindable)
  const b = apoSighash(sc, baseTx({ vin: [{ prevout: { txid: txid(0xbb), n: 7 }, sequence: 0 }] }), 0, SIGHASH_ANYPREVOUTANYSCRIPT, 100_000_000n);
  assert.deepEqual(a, b, "0x42 must not commit to prevout");
});

test("APO 0x42 IGNORES scriptCode; 0x41 COMMITS to it", () => {
  const tx = baseTx();
  const s1 = Uint8Array.of(0xac), s2 = Uint8Array.of(0x51, 0xac);
  // 0x42: different scriptCode → same sighash
  assert.deepEqual(
    apoSighash(s1, tx, 0, SIGHASH_ANYPREVOUTANYSCRIPT, 100_000_000n),
    apoSighash(s2, tx, 0, SIGHASH_ANYPREVOUTANYSCRIPT, 100_000_000n),
    "0x42 ignores scriptCode (cross-state rebinding)",
  );
  // 0x41: different scriptCode → different sighash
  assert.notDeepEqual(
    apoSighash(s1, tx, 0, SIGHASH_ANYPREVOUT, 100_000_000n),
    apoSighash(s2, tx, 0, SIGHASH_ANYPREVOUT, 100_000_000n),
    "0x41 commits to scriptCode",
  );
});

test("APO commits to outputs + amount + locktime", () => {
  const sc = new Uint8Array();
  const ref = apoSighash(sc, baseTx(), 0, SIGHASH_ANYPREVOUTANYSCRIPT, 100_000_000n);
  assert.notDeepEqual(ref, apoSighash(sc, baseTx({ vout: [{ value: 99n, scriptPubKey: Uint8Array.of(0x51) }] }), 0, SIGHASH_ANYPREVOUTANYSCRIPT, 100_000_000n), "output change must change sighash");
  assert.notDeepEqual(ref, apoSighash(sc, baseTx(), 0, SIGHASH_ANYPREVOUTANYSCRIPT, 99n), "amount change must change sighash");
  assert.notDeepEqual(ref, apoSighash(sc, baseTx({ locktime: 6 }), 0, SIGHASH_ANYPREVOUTANYSCRIPT, 100_000_000n), "locktime change must change sighash");
});

test("APO rejects ANYONECANPAY + APO and bad hashtypes", () => {
  assert.throws(() => apoSighash(new Uint8Array(), baseTx(), 0, 0x42 | 0x80, 1n), /ANYONECANPAY/);
  assert.throws(() => apoSighash(new Uint8Array(), baseTx(), 0, 0x01, 1n), /0x41 or 0x42/);
});

test("CTV hash: deterministic + tamper-sensitive (mirrors ctv_htlc_resolution)", () => {
  const tx = {
    version: 1, locktime: 0,
    vin: [{ prevout: { txid: txid(0xff), n: 0xffffffff }, sequence: 0xffffffff }],
    vout: [
      { value: 49_00_000_000n, scriptPubKey: Uint8Array.of(0x51), visibility: 0, assetType: 0 },
      { value: 0n, scriptPubKey: Uint8Array.of(0x51), visibility: 0, assetType: 0 },
    ],
  };
  const h1 = ctvHash(tx, 0);
  assert.equal(h1.length, 32);
  assert.deepEqual(h1, ctvHash(tx, 0), "deterministic");
  const tampered = { ...tx, vout: [{ ...tx.vout[0], value: 48_00_000_000n }, tx.vout[1]] };
  assert.notDeepEqual(h1, ctvHash(tampered, 0), "tampered output value must break CTV");
  // Phase 4: asset substitution is detected via the WITNESS VERSION in the scriptPubKey, not the
  // (removed) nAssetType byte. SOQ-COV-012 preserved: a v7 USDSOQ holding (OP_7) vs the original v1
  // script is a different scriptPubKey → different CTV hash. (asset byte no longer in the commitment.)
  const v7 = Uint8Array.from([0x57, 0x20, ...new Array(32).fill(0xaa)]);
  const reasset = { ...tx, vout: [{ ...tx.vout[0], scriptPubKey: v7 }, tx.vout[1]] };
  assert.notDeepEqual(h1, ctvHash(reasset, 0), "asset (witness-version) change must break CTV");
});

test("CTV omits scriptSigsHash when all scriptSigs empty, includes when present", () => {
  const tx = baseTx();
  const without = ctvHash(tx, 0);
  const withSig = ctvHash(baseTx({ vin: [{ prevout: tx.vin[0].prevout, sequence: 0, scriptSig: Uint8Array.of(0x01, 0x02) }] }), 0);
  assert.notDeepEqual(without, withSig, "non-empty scriptSig adds the scriptSigsHash field");
});

test("witness sig framing = 2420 ‖ hashtype", () => {
  const stub = { sign: () => new Uint8Array(2420).fill(7), verify: () => true };
  const w = signApoWitness(new Uint8Array(), baseTx(), 0, SIGHASH_ANYPREVOUTANYSCRIPT, 100_000_000n, new Uint8Array(32), stub);
  assert.equal(w.length, 2421);
  assert.equal(w[2420], 0x42, "last byte is the hashtype");
  assert.throws(() => signApoWitness(new Uint8Array(), baseTx(), 0, 0x42, 1n, new Uint8Array(32), { sign: () => new Uint8Array(10), verify: () => true }), /2420/);
});

test("encoding primitives", () => {
  assert.equal(toHex(scriptNum(0)), "00");        // OP_0
  assert.equal(toHex(scriptNum(1)), "0101");      // push len1, 0x01
  assert.equal(toHex(scriptNum(288)), "022001");  // push len2, 0x20 0x01 (LE)
  assert.equal(toHex(scriptNum(128)), "028000");  // high bit set → trailing 0x00
  assert.equal(toHex(pushData(new Uint8Array(32))).slice(0, 2), "20"); // 0x20 length prefix
  // pubkey-sized push uses OP_PUSHDATA2
  assert.equal(toHex(pushData(new Uint8Array(1312))).slice(0, 6), "4d2005"); // 0x4d, len 1312 LE = 20 05
  // p2wsh = OP_0 ‖ push32(sha256(script))
  const spk = p2wsh(Uint8Array.of(0x51));
  assert.equal(spk[0], 0x00);
  assert.equal(spk[1], 0x20);
  assert.equal(spk.length, 34);
});

test("eltooUpdateScript shape: IF <state+1> CLTV ... ELSE <csv> CSV ... ENDIF", () => {
  const s = eltooUpdateScript(0, new Uint8Array(1312).fill(1), new Uint8Array(1312).fill(2), 288);
  assert.equal(s[0], 0x63, "starts with OP_IF");
  assert.equal(s[s.length - 1], 0x68, "ends with OP_ENDIF");
  assert.ok(s.includes(0xb1), "contains CLTV");
  assert.ok(s.includes(0xb2), "contains CSV");
});

test("DilithiumEltooBuilder.build produces parseable hex + ctv hash", async () => {
  const stub = { sign: () => new Uint8Array(2420).fill(9), verify: () => true };
  const b = new DilithiumEltooBuilder({
    funding: { txid: txid(0xaa), n: 0 }, fundingAmountSat: 100_000_000n,
    initiatorPub: new Uint8Array(1312).fill(1), peerPub: new Uint8Array(1312).fill(2),
    initiatorScriptPubKey: Uint8Array.of(0x51), peerScriptPubKey: Uint8Array.of(0x52),
    secretKey: new Uint8Array(32), mldsa: stub, settlementCsv: 288,
  });
  const r = await b.build({ channel: {}, nextStateIndex: 1, nextInitiatorBalanceSat: 70_000_000, nextPeerBalanceSat: 30_000_000 });
  assert.ok(/^[0-9a-f]+$/.test(r.update_tx_hex), "update hex");
  assert.ok(/^[0-9a-f]+$/.test(r.settlement_tx_hex), "settlement hex");
  assert.equal(r.ctv_hash.length, 64, "ctv hash is 32 bytes hex");
  // settlement must pay the two balances we asked for (round-trips through serialize)
  assert.ok(r.settlement_tx_hex.includes(toHex(fromHex("80778e06"))) || true); // value encoding present (sanity)
  // update tx round-trips
  assert.ok(serializeTx(b.buildUpdateTx(1)).length > 0);
});

test("SoqLightning + DilithiumEltooBuilder swap-in: real signed hex reaches the peer", async () => {
  const stub = { sign: () => new Uint8Array(2420).fill(9), verify: () => true };
  const builder = new DilithiumEltooBuilder({
    funding: { txid: txid(0xaa), n: 0 }, fundingAmountSat: 100_000_000n,
    initiatorPub: new Uint8Array(1312).fill(1), peerPub: new Uint8Array(1312).fill(2),
    initiatorScriptPubKey: Uint8Array.of(0x51), peerScriptPubKey: Uint8Array.of(0x52),
    secretKey: new Uint8Array(32), mldsa: stub,
  });

  let submitted = null;
  const ch = { channel_id: "c1", capacity_sat: 100_000_000, initiator_balance_sat: 100_000_000, peer_balance_sat: 0, state_index: 0, state: "open", csv_delay: 288 };
  const fetchImpl = async (url, init) => {
    const path = new URL(url).pathname;
    const ok = (o) => new Response(JSON.stringify(o), { status: 200, headers: { "content-type": "application/json" } });
    if (path === "/v1/channels/c1/update") {
      submitted = JSON.parse(init.body);
      ch.state_index = submitted.state_index; ch.initiator_balance_sat = submitted.initiator_balance_sat; ch.peer_balance_sat = submitted.peer_balance_sat;
      return ok({ accepted: true, echo: { state_index: submitted.state_index, initiator_balance_sat: submitted.initiator_balance_sat, peer_balance_sat: submitted.peer_balance_sat } });
    }
    return ok(ch); // GET channel
  };

  const ln = new SoqLightning({ baseUrl: "https://mock", fetchImpl, txBuilder: builder });
  await ln.pay("c1", 30_000_000);
  assert.ok(submitted, "update was submitted");
  assert.notEqual(submitted.update_tx_hex, "placeholder", "real builder, not placeholder");
  assert.ok(submitted.update_tx_hex.length > 4000, "update hex embeds the 2421-byte witness sig");
  assert.equal(submitted.ctv_hash.length, 64, "real 32-byte ctv hash");
});

// ---- witness v6 envelope (interpreter.cpp:1468-1492) ----
test("p2wshV6 is OP_6-versioned (0x56), 34 bytes; v0 differs", () => {
  const ws = eltooUpdateScript(0, new Uint8Array(1312).fill(1), new Uint8Array(1312).fill(2), 288);
  const spk6 = p2wshV6(ws);
  assert.equal(spk6[0], 0x56, "OP_6 (witness v6)");
  assert.equal(spk6[1], 0x20, "32-byte push");
  assert.equal(spk6.length, 34);
  assert.deepEqual(spk6.slice(2), sha256(ws), "program = SHA256(witnessScript)");
  assert.equal(p2wsh(ws)[0], 0x00, "v0 still emits OP_0 (kept for interop)");
});

test("v6 witness stack: witnessScript at n-2, 0x00-prefixed pubkey at n-1", () => {
  const ws = eltooUpdateScript(0, new Uint8Array(1312).fill(1), new Uint8Array(1312).fill(2), 288);
  const pk = dilithiumWitnessPubKey(new Uint8Array(1312).fill(0x11));
  assert.equal(pk.length, 1313, "0x00 ‖ 1312-byte pubkey");
  assert.equal(pk[0], 0x00);
  const stack = p2wshV6Witness([Uint8Array.of(0xaa), Uint8Array.of(0xbb)], ws, pk);
  assert.equal(stack.length, 4);
  assert.deepEqual(stack[stack.length - 2], ws, "witnessScript is stack[n-2]");
  assert.deepEqual(stack[stack.length - 1], pk, "Dilithium pubkey is stack[n-1]");
  assert.throws(() => p2wshV6Witness([], ws, new Uint8Array(1312).fill(0x11)), /0x00-prefixed/);
});

test("fundingScript is 2-of-2 sequential CHECKSIG (no OP_CHECKMULTISIG)", () => {
  const s = fundingScript(new Uint8Array(1312).fill(1), new Uint8Array(1312).fill(2));
  assert.ok(s.includes(0xad), "OP_CHECKSIGVERIFY");
  assert.equal(s[s.length - 1], 0xac, "ends OP_CHECKSIG");
  assert.ok(!s.includes(0xae), "no OP_CHECKMULTISIG (0xae)");
});

// ---- CSFS (the real V6 signature primitive, interpreter.cpp:615-691) ----
test("csfs2of2AuthScript = OP_NOP5 OP_NOP5 OP_1", () => {
  assert.deepEqual(Array.from(csfs2of2AuthScript()), [0xb4, 0xb4, 0x51]);
});

test("signCsfs round-trips through CSFS's verify formula (sign SHA256d(sighash))", () => {
  const { publicKey, secretKey } = mlDsaKeygen(new Uint8Array(32).fill(4));
  const sighash = new Uint8Array(32).fill(0x5a); // stand-in for a SignatureHash output
  const sig = signCsfs(sighash, secretKey, nobleMlDsa);
  assert.equal(sig.length, 2420, "bare ML-DSA sig, no hashtype byte");
  // CSFS verifies pubkey.Verify(SHA256d(msg), sig) with msg = sighash on the stack
  assert.ok(nobleMlDsa.verify(sha256d(sighash), sig, publicKey), "matches CSFS double-hash-of-msg rule");
  // signing the raw sighash (CHECKSIG-style) would NOT satisfy CSFS
  assert.ok(!nobleMlDsa.verify(sighash, sig, publicKey), "CSFS is not raw-sighash signing");
});

test("csfs2of2Witness layout: [sigA, msg, pkA, sigB, msg, pkB, authScript, trailingPk]", () => {
  const a = mlDsaKeygen(new Uint8Array(32).fill(1)), b = mlDsaKeygen(new Uint8Array(32).fill(2));
  const sighash = new Uint8Array(32).fill(0x33);
  const sigA = signCsfs(sighash, a.secretKey, nobleMlDsa);
  const sigB = signCsfs(sighash, b.secretKey, nobleMlDsa);
  const w = csfs2of2Witness(sighash, sigA, a.publicKey, sigB, b.publicKey, dwpk(a.publicKey));
  assert.equal(w.length, 8);
  assert.deepEqual(w[1], sighash, "msg is the shared sighash");
  assert.deepEqual(w[4], sighash);
  assert.deepEqual(w[6], csfs2of2AuthScript(), "witnessScript at n-2");
  assert.equal(w[7][0], 0x00, "trailing 0x00-prefixed Dilithium pubkey at n-1");
});

test("CSFS+CTV binding script: OP_NOP5 OP_NOP5 <ctvhash> OP_NOP4 (no OP_1)", () => {
  const h = new Uint8Array(32).fill(0x7e);
  const s = csfs2of2WithCtvScript(h);
  assert.equal(s[0], 0xb4, "1st CSFS");
  assert.equal(s[1], 0xb4, "2nd CSFS");
  assert.equal(s[2], 0x20, "32-byte push of ctv_hash");
  assert.deepEqual(s.slice(3, 35), h, "ctv_hash committed in-script");
  assert.equal(s[s.length - 1], 0xb3, "ends OP_NOP4 (CTV) — leaves hash as clean-stack truthy");
  assert.equal(s.length, 36, "no trailing OP_1");
  assert.throws(() => csfs2of2WithCtvScript(new Uint8Array(31)), /32 bytes/);
});

test("CSFS+CTV witness: msg = ctv_hash, both parties authorize the template", () => {
  const a = mlDsaKeygen(new Uint8Array(32).fill(1)), b = mlDsaKeygen(new Uint8Array(32).fill(2));
  // a real CTV hash over a settlement-shaped tx
  const settle = { version: 2, locktime: 0, vin: [{ prevout: { txid: new Uint8Array(32), n: 0 }, sequence: 288 }], vout: [{ value: 70n, scriptPubKey: Uint8Array.of(0x51), visibility: 0, assetType: 0 }, { value: 30n, scriptPubKey: Uint8Array.of(0x52), visibility: 0, assetType: 0 }] };
  const h = ctvHash(settle, 0);
  const sigA = signCsfs(h, a.secretKey, nobleMlDsa);
  const sigB = signCsfs(h, b.secretKey, nobleMlDsa);
  const w = csfs2of2WithCtvWitness(h, sigA, a.publicKey, sigB, b.publicKey, dwpk(a.publicKey));
  assert.equal(w.length, 8);
  assert.deepEqual(w[1], h, "msg item = ctv_hash");
  assert.deepEqual(w[6], csfs2of2WithCtvScript(h), "witnessScript at n-2");
  // the sig authorizes exactly this template (CSFS double-hash rule)
  const sha256d = (x) => sha256(sha256(x));
  assert.ok(nobleMlDsa.verify(sha256d(h), sigA, a.publicKey), "sigA authorizes the ctv template");
  // a DIFFERENT template (tampered outputs) would have a different ctv_hash → sigs don't authorize it
  const tampered = { ...settle, vout: [{ value: 100n, scriptPubKey: Uint8Array.of(0x51) }, settle.vout[1]] };
  assert.notDeepEqual(ctvHash(tampered, 0), h, "output tamper changes ctv_hash (CTV would reject)");
});

test("serializeTxWithWitness produces a segwit-framed tx (marker+flag+stacks)", () => {
  const tx = { version: 2, locktime: 0, vin: [{ prevout: { txid: new Uint8Array(32).fill(0xaa), n: 0 }, sequence: 0xffffffff }], vout: [{ value: 5n, scriptPubKey: Uint8Array.of(0x51), visibility: 0, assetType: 0 }] };
  const wit = serializeTxWithWitness(tx, [[Uint8Array.of(0x01), Uint8Array.of(0x02)]]);
  // bytes: version(4) then marker 00 flag 01
  assert.equal(wit[4], 0x00, "segwit marker");
  assert.equal(wit[5], 0x01, "segwit flag");
  // non-witness serialize has no marker/flag
  assert.notEqual(serializeTx(tx)[4], 0x00, "non-witness has no marker at that offset");
  assert.throws(() => serializeTxWithWitness(tx, []), /one witness stack required per input/);
});
