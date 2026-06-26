// Copyright (c) 2026 Soqucoin Labs Inc.
// Distributed under the MIT software license.
//
// two_party_broadcast.test.mjs — the two-SEPARATE-signer path (spec §J open #3).
//
// The b1-canary fused both keys (one signKeyhashFunding2of2 call held skA AND skB). This
// proves the real trust boundary: the user and the LSP each hold ONLY their own key, each
// produces a partial in isolation, and the orchestrator combines them into a broadcastable
// tx — across the full lifecycle (open → supersede → settle → coop close). Offline (no node);
// the live broadcast is src/two-party-canary.ts (Buddy runs it with creds).

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  EltooBroadcaster, LocalParty, TwoPartyChannel, localTwoPartyChannel,
  combineLspRound, lspUpdateRound,
  apoSighash, p2wshV6, txid, toHex, SIGHASH_ANYPREVOUTANYSCRIPT,
  nobleMlDsa, mlDsaKeygen,
} from "../dist/index.js";

const USER = mlDsaKeygen(new Uint8Array(32).fill(0xa1)); // the user (initiator, key A)
const LSP = mlDsaKeygen(new Uint8Array(32).fill(0xb2));  // the LSP (peer, key B)
const MAL = mlDsaKeygen(new Uint8Array(32).fill(0xcc));  // a wrong key

const CAP = 1_000_000_000n;
const FEE = 10_000_000n;
const STATE = 100;
const CSV = 6;

const params = {
  funding: { txid: new Uint8Array(32).fill(0xfd), n: 0 }, capacitySat: CAP,
  initiatorPub: USER.publicKey, peerPub: LSP.publicKey,
  initiatorScriptPubKey: p2wshV6(Uint8Array.of(0x51)),
  peerScriptPubKey: p2wshV6(Uint8Array.of(0x51, 0x51)),
  settlementCsv: CSV, feeSat: FEE,
};

test("each party signs in isolation (own key only) and both partials verify", async () => {
  const bc = new EltooBroadcaster(params);
  const user = new LocalParty(bc, USER.secretKey, USER.publicKey, nobleMlDsa);
  const lsp = new LocalParty(bc, LSP.secretKey, LSP.publicKey, nobleMlDsa);

  const tx = bc.buildFundingUpdateTx(STATE);
  const up = await user.signFunding(tx);
  const lp = await lsp.signFunding(tx);

  // Each partial carries that party's own pubkey — neither party touched the other's key.
  assert.deepEqual(up.pubKey, USER.publicKey);
  assert.deepEqual(lp.pubKey, LSP.publicKey);
  const digest = apoSighash(bc.fundingWitnessScript(), tx, 0, SIGHASH_ANYPREVOUTANYSCRIPT, CAP);
  assert.ok(nobleMlDsa.verify(digest, up.sig.slice(0, 2420), USER.publicKey), "user partial verifies");
  assert.ok(nobleMlDsa.verify(digest, lp.sig.slice(0, 2420), LSP.publicKey), "lsp partial verifies");
});

test("full lifecycle via TwoPartyChannel: open → settle (chains + conserves)", async () => {
  const ch = localTwoPartyChannel(params, { secretKey: USER.secretKey, pub: USER.publicKey }, { secretKey: LSP.secretKey, pub: LSP.publicKey }, nobleMlDsa);

  const update = await ch.openUpdate(STATE);
  assert.match(update.hex, /^020000000001/, "update is BIP141 witness-serialized");

  const uValue = CAP - FEE;
  const init = 600_000_000n, peer = uValue - FEE - init;
  const settlement = await ch.settle({
    updateOutpoint: { txid: update.txid, n: 0 }, updateValueSat: uValue, prevState: STATE,
    initiatorBalanceSat: init, peerBalanceSat: peer,
  });
  // settlement spends the update output → txid chaining is correct
  assert.deepEqual(settlement.tx.vin[0].prevout.txid, update.txid);
  assert.equal(settlement.tx.vin[0].sequence, CSV);
  assert.equal(settlement.tx.vout[0].value, init);
  assert.equal(settlement.tx.vout[1].value, peer);
  assert.match(settlement.hex, /^020000000001/);
});

test("supersede via TwoPartyChannel chains from the prior update", async () => {
  const ch = localTwoPartyChannel(params, { secretKey: USER.secretKey, pub: USER.publicKey }, { secretKey: LSP.secretKey, pub: LSP.publicKey }, nobleMlDsa);
  const update = await ch.openUpdate(STATE);
  const sup = await ch.supersede({ prevOutpoint: { txid: update.txid, n: 0 }, prevValueSat: CAP - FEE, prevState: STATE, newState: STATE + 1 });
  assert.deepEqual(sup.tx.vin[0].prevout.txid, update.txid);
  assert.equal(sup.tx.locktime, STATE + 1, "nLockTime clears the prior IF-branch CLTV floor");
  assert.equal(sup.tx.vin[0].sequence, 0xfffffffe, "non-final so CLTV is active");
});

test("cooperative close via TwoPartyChannel spends funding directly", async () => {
  const ch = localTwoPartyChannel(params, { secretKey: USER.secretKey, pub: USER.publicKey }, { secretKey: LSP.secretKey, pub: LSP.publicKey }, nobleMlDsa);
  const init = 700_000_000n, peer = CAP - FEE - init;
  const close = await ch.cooperativeClose({ initiatorBalanceSat: init, peerBalanceSat: peer });
  assert.deepEqual(close.tx.vin[0].prevout, params.funding);
  assert.equal(close.tx.vout.length, 2);
  assert.match(close.hex, /^020000000001/);
});

test("updateRound co-signs BOTH txs — user can close without the LSP (F1 fix)", async () => {
  const bc = new EltooBroadcaster(params);
  const user = new LocalParty(bc, USER.secretKey, USER.publicKey, nobleMlDsa);
  const lsp = new LocalParty(bc, LSP.secretKey, LSP.publicKey, nobleMlDsa);
  const ch = new TwoPartyChannel(bc, user, lsp);

  const uValue = CAP - FEE;
  const init = 600_000_000n, peer = uValue - FEE - init;
  const { update, settlement } = await ch.updateRound({ stateNum: STATE, initiatorBalanceSat: init, peerBalanceSat: peer });

  // Both fully co-signed + chained → the user can broadcast Tu then Ts to close, no LSP needed.
  assert.match(update.hex, /^020000000001/);
  assert.match(settlement.hex, /^020000000001/);
  assert.deepEqual(settlement.tx.vin[0].prevout.txid, update.txid);
  assert.equal(settlement.tx.vout[0].value, init);
  assert.equal(settlement.tx.vout[1].value, peer);

  // F1 regression guard: WITHOUT the LSP's settlement partial (the bug Buddy's WS2b had —
  // it co-signed only the update), the settlement cannot be assembled from the user's
  // partial alone → the user could not unilaterally close. That is exactly what F1 fixes.
  const settlementTx = bc.buildSettlementTx({ updateOutpoint: { txid: update.txid, n: 0 }, updateValueSat: uValue, initiatorBalanceSat: init, peerBalanceSat: peer });
  const userOnly = await user.signEltoo(settlementTx, uValue);
  assert.throws(() => bc.assembleSettlement(settlementTx, STATE, [userOnly, userOnly]), /initiator/);
});

// A mock LSP that independently rebuilds the round's txs (spec §D.2) and co-signs BOTH with
// its own key, returning the two 2421-byte partials as hex — i.e. the F1-fixed LSP response.
function mockLsp() {
  const lspBc = new EltooBroadcaster(params);
  return {
    async updateState(req) {
      const updateTx = lspBc.buildFundingUpdateTx(req.state_index);
      const uValue = updateTx.vout[0].value;
      const settlementTx = lspBc.buildSettlementTx({
        updateOutpoint: { txid: txid(updateTx), n: 0 }, updateValueSat: uValue,
        initiatorBalanceSat: BigInt(req.initiator_balance_sat), peerBalanceSat: BigInt(req.peer_balance_sat),
      });
      const up = lspBc.signFundingPartial(updateTx, LSP.secretKey, LSP.publicKey, nobleMlDsa);
      const st = lspBc.signEltooPartial(settlementTx, uValue, LSP.secretKey, LSP.publicKey, nobleMlDsa);
      return { accepted: true, peer_signature_hex: toHex(up.sig), settlement_signature_hex: toHex(st.sig) };
    },
  };
}

test("lspUpdateRound stitches both LSP partials → user holds a closeable (Tu, Ts) [F1 E2E]", async () => {
  const bc = new EltooBroadcaster(params);
  const uValue = CAP - FEE;
  const init = 600_000_000n, peer = uValue - FEE - init;
  const { update, settlement } = await lspUpdateRound(bc, mockLsp(), {
    stateNum: STATE, initiatorBalanceSat: init, peerBalanceSat: peer,
    userSecretKey: USER.secretKey, userPub: USER.publicKey, lspPub: LSP.publicKey, mldsa: nobleMlDsa,
  });
  // Fully signed by user + LSP, chained → broadcastable as a unilateral close, no LSP needed.
  assert.match(update.hex, /^020000000001/);
  assert.match(settlement.hex, /^020000000001/);
  assert.deepEqual(settlement.tx.vin[0].prevout.txid, update.txid);
  assert.equal(settlement.tx.vout[0].value, init);
});

test("lspUpdateRound throws if the LSP omits the settlement partial (F1 not deployed)", async () => {
  const bc = new EltooBroadcaster(params);
  const brokenLsp = { async updateState() { return { accepted: true, peer_signature_hex: "00".repeat(2421) }; } };
  await assert.rejects(() => lspUpdateRound(bc, brokenLsp, {
    stateNum: STATE, initiatorBalanceSat: 600_000_000n, peerBalanceSat: (CAP - FEE) - FEE - 600_000_000n,
    userSecretKey: USER.secretKey, userPub: USER.publicKey, lspPub: LSP.publicKey, mldsa: nobleMlDsa,
  }), /settlement_signature_hex missing|BOTH partials/);
});

test("combineLspRound rejects the legacy \"countersigned\" stub", async () => {
  const bc = new EltooBroadcaster(params);
  const updateTx = bc.buildFundingUpdateTx(STATE);
  const uValue = CAP - FEE;
  const settlementTx = bc.buildSettlementTx({ updateOutpoint: { txid: txid(updateTx), n: 0 }, updateValueSat: uValue, initiatorBalanceSat: 600_000_000n, peerBalanceSat: uValue - FEE - 600_000_000n });
  const userUpdate = bc.signFundingPartial(updateTx, USER.secretKey, USER.publicKey, nobleMlDsa);
  const userSettle = bc.signEltooPartial(settlementTx, uValue, USER.secretKey, USER.publicKey, nobleMlDsa);
  assert.throws(() => combineLspRound(bc, {
    updateTx, settlementTx, prevState: STATE, userUpdate, userSettle,
    lspPub: LSP.publicKey, lspUpdateSigHex: "countersigned", lspSettleSigHex: "00".repeat(2421),
  }), /2421 bytes|real ML-DSA/);
});

test("lspUpdateRound: LSP gets LOGICAL balances (sum=capacity); settlement outputs are fee-deducted", async () => {
  // The seam WS5 depends on: the LSP enforces initiator+peer==capacity (manager.go:271), but the
  // on-chain settlement pays capacity−2·fee. So logical (req) and settlement (tx) balances differ.
  const bc = new EltooBroadcaster(params);
  const settleInit = 600_000_000n, settlePeer = 380_000_000n;        // sum 980M = CAP − 2·FEE
  const logicalInit = 620_000_000, logicalPeer = 380_000_000;        // sum 1B = capacity
  let captured;
  const lsp = {
    async updateState(req) {
      captured = req;
      const lspBc = new EltooBroadcaster(params);
      const updateTx = lspBc.buildFundingUpdateTx(req.state_index);
      const uValue = updateTx.vout[0].value;
      const settlementTx = lspBc.buildSettlementTx({ updateOutpoint: { txid: txid(updateTx), n: 0 }, updateValueSat: uValue, initiatorBalanceSat: settleInit, peerBalanceSat: settlePeer });
      const up = lspBc.signFundingPartial(updateTx, LSP.secretKey, LSP.publicKey, nobleMlDsa);
      const st = lspBc.signEltooPartial(settlementTx, uValue, LSP.secretKey, LSP.publicKey, nobleMlDsa);
      return { accepted: true, peer_signature_hex: toHex(up.sig), settlement_signature_hex: toHex(st.sig) };
    },
  };
  const { settlement } = await lspUpdateRound(bc, lsp, {
    stateNum: STATE, initiatorBalanceSat: settleInit, peerBalanceSat: settlePeer,
    reqBalances: { initiatorSat: logicalInit, peerSat: logicalPeer },
    userSecretKey: USER.secretKey, userPub: USER.publicKey, lspPub: LSP.publicKey, mldsa: nobleMlDsa,
  });
  // The LSP received LOGICAL balances summing to capacity (its conservation check passes).
  assert.equal(captured.initiator_balance_sat + captured.peer_balance_sat, Number(CAP));
  assert.equal(captured.initiator_balance_sat, logicalInit);
  // The settlement outputs are fee-deducted (sum = capacity − 2·fee).
  assert.equal(settlement.tx.vout[0].value + settlement.tx.vout[1].value, CAP - 2n * FEE);
  assert.equal(settlement.tx.vout[0].value, settleInit);
});

test("a party with the wrong key cannot co-sign (combine rejects it)", async () => {
  // The LSP party is constructed with Mallory's key, but the channel funding commits the
  // real B key — so the impostor's partial matches no committed keyhash and combine throws.
  const bc = new EltooBroadcaster(params);
  const user = new LocalParty(bc, USER.secretKey, USER.publicKey, nobleMlDsa);
  const impostor = new LocalParty(bc, MAL.secretKey, MAL.publicKey, nobleMlDsa);
  const ch = new TwoPartyChannel(bc, user, impostor);
  await assert.rejects(() => ch.openUpdate(STATE), /exactly one partial must match|neither/);
});
