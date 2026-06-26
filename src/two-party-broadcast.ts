// soq-lightning-sdk — two-party channel orchestration (the live two-separate-signer harness core).
//
// The b1-canary proved the SCRIPT mechanics live, but it FUSED both keys: a single
// signKeyhashFunding2of2(.., skA, pkA, skB, pkB, ..) call held both secrets. That does
// not model a real channel, where the user and the LSP each hold ONLY their own key and
// exchange *partials*. This module closes that gap (spec §J open #3): it drives the
// EltooBroadcaster through funding→update→supersede→settlement with two independent
// ChannelParty signers, neither of which ever sees the other's secret key.
//
// It is PURE COMPOSITION of EltooBroadcaster (which is itself pure composition of the
// node-pinned channel.ts primitives) — no new crypto. The orchestrator returns broadcastable
// SignedTx values; BROADCASTING is the caller's job (the CLI, or a test's mock), so this
// module is fully testable offline.

import {
  EltooBroadcaster, type ChannelParams, type SignedTx,
} from "./eltoo-broadcast.js";
import {
  SIGHASH_ANYPREVOUTANYSCRIPT, txid, toHex, fromHex, serializeTx, ctvHash,
  type Tx, type OutPoint, type KeyhashPartial,
} from "./channel.js";
import type { MlDsa } from "./invoice.js";

/** One channel counterparty. It produces a partial signature using ONLY its own key —
 *  the trust boundary of a real 2-party channel (spec §C.1, §D). `async` so a real LSP
 *  party can fetch its partial over the wire (Mode 2, pending WS2b). */
export interface ChannelParty {
  readonly pub: Uint8Array;
  /** Partial over a funding-2-of-2 spend (Tu,0 or cooperative close). */
  signFunding(tx: Tx, hashType?: number): Promise<KeyhashPartial>;
  /** Partial over an eLTOO branch spend (supersession or settlement); `spentValueSat`
   *  is the value of the output being spent. */
  signEltoo(tx: Tx, spentValueSat: bigint): Promise<KeyhashPartial>;
}

/** A party whose key lives in THIS process (the user side, or a single-operator/test LSP).
 *  Holds only one secret key and exposes only partial-signing — the same isolation a remote
 *  party would have. */
export class LocalParty implements ChannelParty {
  constructor(
    private readonly bc: EltooBroadcaster,
    private readonly secretKey: Uint8Array,
    readonly pub: Uint8Array,
    private readonly mldsa: MlDsa,
  ) {}

  async signFunding(tx: Tx, hashType = SIGHASH_ANYPREVOUTANYSCRIPT): Promise<KeyhashPartial> {
    return this.bc.signFundingPartial(tx, this.secretKey, this.pub, this.mldsa, hashType);
  }

  async signEltoo(tx: Tx, spentValueSat: bigint): Promise<KeyhashPartial> {
    return this.bc.signEltooPartial(tx, spentValueSat, this.secretKey, this.pub, this.mldsa);
  }
}

/**
 * Drives a B1 eLTOO channel between two independent parties. Each protocol step builds the
 * unsigned tx, collects a partial from EACH party (in isolation), and combines them into a
 * broadcastable SignedTx. The orchestrator never holds two secret keys at once — partials
 * are the only thing exchanged.
 */
export class TwoPartyChannel {
  constructor(
    private readonly bc: EltooBroadcaster,
    private readonly user: ChannelParty,
    private readonly lsp: ChannelParty,
  ) {}

  /** Tu,0 — both parties co-sign the funding spend into the first eLTOO(stateNum) output. */
  async openUpdate(stateNum: number): Promise<SignedTx> {
    const tx = this.bc.buildFundingUpdateTx(stateNum);
    const partials = await this.bothFunding(tx);
    return this.bc.assembleFundingSpend(tx, partials);
  }

  /** Tu,next — both parties co-sign a supersession (IF-branch) spend of a prior eLTOO output. */
  async supersede(a: { prevOutpoint: OutPoint; prevValueSat: bigint; prevState: number; newState: number }): Promise<SignedTx> {
    const tx = this.bc.buildSupersedeTx(a);
    const partials = await this.bothEltoo(tx, a.prevValueSat);
    return this.bc.assembleSupersede(tx, a.prevState, partials);
  }

  /** Ts — both parties co-sign the settlement (ELSE/CSV-branch) spend paying both balances. */
  async settle(a: {
    updateOutpoint: OutPoint; updateValueSat: bigint; prevState: number;
    initiatorBalanceSat: bigint; peerBalanceSat: bigint;
  }): Promise<SignedTx> {
    const tx = this.bc.buildSettlementTx(a);
    const partials = await this.bothEltoo(tx, a.updateValueSat);
    return this.bc.assembleSettlement(tx, a.prevState, partials);
  }

  /** One full update round (spec §D + §E) — the F1 fix. Both parties co-sign BOTH the update
   *  AND its settlement in the same round, so the user ends the round holding a fully-signed
   *  (Tu, Ts) pair it can broadcast to close with NO further LSP contact. A round that co-signs
   *  only the update (the F1 bug) leaves Ts half-signed → the user cannot settle → §E
   *  self-custody is broken. The settlement is co-signed over the UPDATE-OUTPUT value
   *  (capacity − fee), NOT the capacity — the 0x42 sighash commits the amount. */
  async updateRound(a: { stateNum: number; initiatorBalanceSat: bigint; peerBalanceSat: bigint }): Promise<{ update: SignedTx; settlement: SignedTx }> {
    const updateTx = this.bc.buildFundingUpdateTx(a.stateNum);
    const update = this.bc.assembleFundingSpend(updateTx, await this.bothFunding(updateTx));

    const updateValueSat = updateTx.vout[0].value;
    const settlementTx = this.bc.buildSettlementTx({
      updateOutpoint: { txid: update.txid, n: 0 }, updateValueSat,
      initiatorBalanceSat: a.initiatorBalanceSat, peerBalanceSat: a.peerBalanceSat,
    });
    const settlement = this.bc.assembleSettlement(settlementTx, a.stateNum, await this.bothEltoo(settlementTx, updateValueSat));

    return { update, settlement };
  }

  /** Cooperative close — both parties co-sign a direct funding spend to final balances (spec §F.1). */
  async cooperativeClose(a: { initiatorBalanceSat: bigint; peerBalanceSat: bigint }): Promise<SignedTx> {
    const tx = this.bc.buildCooperativeCloseTx(a);
    const partials = await this.bothFunding(tx);
    return this.bc.assembleFundingSpend(tx, partials);
  }

  private async bothFunding(tx: Tx): Promise<[KeyhashPartial, KeyhashPartial]> {
    return [await this.user.signFunding(tx), await this.lsp.signFunding(tx)];
  }

  private async bothEltoo(tx: Tx, spentValueSat: bigint): Promise<[KeyhashPartial, KeyhashPartial]> {
    return [await this.user.signEltoo(tx, spentValueSat), await this.lsp.signEltoo(tx, spentValueSat)];
  }
}

/** Convenience: a two-LocalParty channel (user holds skUser, LSP holds skLsp) over `params`.
 *  Models the real isolation with both keys in-process — what the live harness runs until
 *  the LSP co-signs remotely (WS2b). `params.initiatorPub`/`peerPub` MUST match the two keys. */
export function localTwoPartyChannel(
  params: ChannelParams,
  user: { secretKey: Uint8Array; pub: Uint8Array },
  lsp: { secretKey: Uint8Array; pub: Uint8Array },
  mldsa: MlDsa,
): TwoPartyChannel {
  const bc = new EltooBroadcaster(params);
  return new TwoPartyChannel(
    bc,
    new LocalParty(bc, user.secretKey, user.pub, mldsa),
    new LocalParty(bc, lsp.secretKey, lsp.pub, mldsa),
  );
}

// ====================================================================
// F1 self-custody stitch — consume the LSP's two response partials
// ====================================================================

/** Parse one LSP response signature (hex) into a KeyhashPartial under the LSP's pubkey.
 *  The LSP returns a 2421-byte element (2420 ML-DSA ‖ 0x42 hashType). A short/garbage value
 *  (e.g. the legacy "countersigned" stub, or a missing field) is rejected here with a clear
 *  message — that is exactly the F1 failure the round must not silently accept. */
function lspPartial(lspPub: Uint8Array, sigHex: string): KeyhashPartial {
  const sig = fromHex(sigHex);
  if (sig.length !== 2421)
    throw new Error(
      `LSP partial must be 2421 bytes (2420 ‖ hashType), got ${sig.length} — is the LSP returning a ` +
      `real ML-DSA sig (WS2b deployed) rather than the "countersigned" stub?`);
  if (sig[2420] !== SIGHASH_ANYPREVOUTANYSCRIPT)
    throw new Error(`LSP partial hashType must be 0x42, got 0x${sig[2420].toString(16)}`);
  return { pubKey: lspPub, sig };
}

/** F1 stitch: combine the LSP's two response partials with the user's into a fully-signed,
 *  broadcastable (Tu, Ts) the user persists (spec §E) — so it can unilaterally close with no
 *  further LSP contact. `lspUpdateSigHex` = the response `peer_signature_hex` (update),
 *  `lspSettleSigHex` = `settlement_signature_hex` (settlement, F1). Throws if either sig is
 *  the stub/wrong-length, or the combine can't match the committed keys. */
export function combineLspRound(
  bc: EltooBroadcaster,
  a: {
    updateTx: Tx; settlementTx: Tx; prevState: number;
    userUpdate: KeyhashPartial; userSettle: KeyhashPartial;
    lspPub: Uint8Array; lspUpdateSigHex: string; lspSettleSigHex: string;
  },
): { update: SignedTx; settlement: SignedTx } {
  const update = bc.assembleFundingSpend(a.updateTx, [a.userUpdate, lspPartial(a.lspPub, a.lspUpdateSigHex)]);
  const settlement = bc.assembleSettlement(a.settlementTx, a.prevState, [a.userSettle, lspPartial(a.lspPub, a.lspSettleSigHex)]);
  return { update, settlement };
}

/** The LSP round-trip a live `pay()` performs. In production this is `LspClient.updateState`;
 *  injectable so the round is testable with a mock LSP. The response MUST carry BOTH partials. */
export interface LspRoundDeps {
  updateState(req: {
    state_index: number; initiator_balance_sat: number; peer_balance_sat: number;
    update_tx_hex: string; settlement_tx_hex: string; ctv_hash: string;
  }): Promise<{
    accepted: boolean; reject_reason?: string;
    peer_signature_hex?: string; settlement_signature_hex?: string;
  }>;
}

/** One F1-complete update round against the LSP — the real `pay()` path. The user builds the
 *  update + settlement, signs ITS partials locally, sends the txs, and the LSP returns its two
 *  partials; `combineLspRound` stitches them into the fully-signed (Tu, Ts) the user persists.
 *  The user ends the round able to close unilaterally (spec §E) — that is the F1 fix end-to-end.
 *  Throws if the LSP rejects, or omits `settlement_signature_hex` (F1 not deployed on the LSP). */
export async function lspUpdateRound(
  bc: EltooBroadcaster, deps: LspRoundDeps,
  a: {
    stateNum: number; initiatorBalanceSat: bigint; peerBalanceSat: bigint;
    userSecretKey: Uint8Array; userPub: Uint8Array; lspPub: Uint8Array; mldsa: MlDsa;
  },
): Promise<{ update: SignedTx; settlement: SignedTx }> {
  const updateTx = bc.buildFundingUpdateTx(a.stateNum);
  const updateValueSat = updateTx.vout[0].value;
  const settlementTx = bc.buildSettlementTx({
    updateOutpoint: { txid: txid(updateTx), n: 0 }, updateValueSat,
    initiatorBalanceSat: a.initiatorBalanceSat, peerBalanceSat: a.peerBalanceSat,
  });

  // The user signs its own partials (own key only) BEFORE handing the txs to the LSP.
  const userUpdate = bc.signFundingPartial(updateTx, a.userSecretKey, a.userPub, a.mldsa);
  const userSettle = bc.signEltooPartial(settlementTx, updateValueSat, a.userSecretKey, a.userPub, a.mldsa);

  const resp = await deps.updateState({
    state_index: a.stateNum,
    initiator_balance_sat: Number(a.initiatorBalanceSat),
    peer_balance_sat: Number(a.peerBalanceSat),
    update_tx_hex: toHex(serializeTx(updateTx)),
    settlement_tx_hex: toHex(serializeTx(settlementTx)),
    ctv_hash: toHex(ctvHash(settlementTx, 0)),
  });
  if (!resp.accepted) throw new Error(`LSP rejected update: ${resp.reject_reason ?? "unknown"}`);
  if (!resp.peer_signature_hex || !resp.settlement_signature_hex)
    throw new Error(
      "LSP did not return BOTH partials — settlement_signature_hex missing. The user cannot " +
      "self-custodially close without it (F1 not deployed on the LSP?).");

  return combineLspRound(bc, {
    updateTx, settlementTx, prevState: a.stateNum,
    userUpdate, userSettle,
    lspPub: a.lspPub, lspUpdateSigHex: resp.peer_signature_hex, lspSettleSigHex: resp.settlement_signature_hex,
  });
}
