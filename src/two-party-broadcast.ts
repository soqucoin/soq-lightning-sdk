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
  SIGHASH_ANYPREVOUTANYSCRIPT, type Tx, type OutPoint, type KeyhashPartial,
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
