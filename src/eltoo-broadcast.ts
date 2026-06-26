// soq-lightning-sdk — WS2: first-class broadcast orchestration for B1 eLTOO channels.
//
// The b1-canary proved the script mechanics live, but it wired the transaction graph
// by hand inside main() (signKeyhashFunding2of2 + eltooUpdateBranchWitness +
// serializeTxWithWitness, with the txid chaining and fee/value arithmetic inlined).
// This module turns that ad-hoc assembly into a tested, reusable API.
//
// It is PURE COMPOSITION of the node-pinned primitives in channel.ts — it introduces
// NO new crypto, scripts, sighash, or serializers. Every byte it emits is produced by
// the same functions the canary used (which are pinned against the node's
// lightning_script_tests vectors). The WS2 canary-equivalence test asserts exactly
// that: for the canary's inputs, this builder reproduces its bytes.
//
// Spec contract (SOQ_LIGHTNING_B1_CHANNEL_PROTOCOL.md §K):
//   (funding outpoint + state + both partials) -> fully-signed broadcastable (Tu, Ts).
//
// Two-party model (spec §D): each party produces a KeyhashPartial with ONLY its own
// secret key (signFundingPartial / signEltooPartial); this builder orders + combines
// the two partials and emits witness-serialized hex ready for sendrawtransaction. The
// single-operator path (both keys in one process — tests, force-close from held state)
// is the same code with both partials supplied locally.

import {
  keyhashFunding2of2, eltooUpdateScriptV6,
  partialSignKeyhash2of2, combineKeyhash2of2Witness,
  eltooUpdateBranchWitness, eltooSettlementBranchWitness,
  dilithiumWitnessPubKey, dilithiumKeyHash, p2wshV6,
  serializeTxWithWitness, txid, toHex,
  SIGHASH_ANYPREVOUTANYSCRIPT, SIGHASH_ALL,
  type Tx, type OutPoint, type KeyhashPartial,
} from "./channel.js";
import type { MlDsa } from "./invoice.js";

/** Static, per-channel context. Mirrors the durable state of spec §E (items 2 & 5):
 *  everything needed to deterministically rebuild + co-sign any state's txs. */
export interface ChannelParams {
  funding: OutPoint;                  // the funding 2-of-2 keyhash outpoint
  capacitySat: bigint;                // funding output value (the channel capacity)
  initiatorPub: Uint8Array;           // A — raw 1312-byte ML-DSA-44 pubkey
  peerPub: Uint8Array;                // B — raw 1312-byte ML-DSA-44 pubkey
  initiatorScriptPubKey: Uint8Array;  // A's settlement payout scriptPubKey
  peerScriptPubKey: Uint8Array;       // B's settlement payout scriptPubKey
  settlementCsv: number;              // explicit (spec §H: a channel-open param, no hidden default)
  feeSat: bigint;                     // fixed per-tx fee (v1 policy, spec §H)
}

/** A fully-assembled, broadcastable transaction. `hex` is BIP141 witness-serialized
 *  (ready for sendrawtransaction); `txid` is internal byte order, `txidDisplay` reversed. */
export interface SignedTx {
  tx: Tx;
  hex: string;
  txid: Uint8Array;
  txidDisplay: string;
}

const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * Builds, partial-signs, and assembles the broadcastable transactions of a B1 eLTOO
 * channel: the funding→update, update-supersedes-update, settlement (ELSE/CSV), and
 * cooperative close. The build* methods are deterministic (both parties produce the
 * same unsigned tx); the sign* methods each take ONE party's key; the assemble* methods
 * combine two partials into broadcast-ready hex.
 */
export class EltooBroadcaster {
  constructor(readonly p: ChannelParams) {
    if (p.initiatorPub.length !== 1312 || p.peerPub.length !== 1312)
      throw new Error("initiatorPub/peerPub must be raw 1312-byte ML-DSA-44 keys");
  }

  // ---- scripts ----

  /** The funding output's witnessScript: `<kh(B)> CDKH <kh(A)> CDKH OP_1` (bare 2-of-2 keyhash). */
  fundingWitnessScript(): Uint8Array {
    return keyhashFunding2of2(this.p.initiatorPub, this.p.peerPub).witnessScript;
  }

  /** The eLTOO update output's witnessScript for `stateNum` (IF/CLTV ratchet | ELSE/CSV settle). */
  eltooScript(stateNum: number): Uint8Array {
    return eltooUpdateScriptV6(stateNum, this.p.initiatorPub, this.p.peerPub, { settlementCsv: this.p.settlementCsv });
  }

  // ---- unsigned tx builders (deterministic) ----

  /** Tu,0 — spend the funding 2-of-2 to a fresh eLTOO(stateNum) output. value = capacity − fee. */
  buildFundingUpdateTx(stateNum: number): Tx {
    return {
      version: 2,
      locktime: 0, // funding has no CLTV; locktime unconstrained
      vin: [{ prevout: this.p.funding, sequence: 0xffffffff }],
      vout: [{ value: this.p.capacitySat - this.p.feeSat, scriptPubKey: p2wshV6(this.eltooScript(stateNum)) }],
    };
  }

  /** Tu,next — spend a prior eLTOO output via the IF (supersession) branch into a fresh
   *  eLTOO(newState) output. nLockTime defaults to prevState+1 to clear the spent output's
   *  `<prevState+1> CLTV` ratchet floor; sequence is non-final (0xfffffffe) so CLTV is active. */
  buildSupersedeTx(a: {
    prevOutpoint: OutPoint; prevValueSat: bigint; prevState: number; newState: number; lockTime?: number;
  }): Tx {
    if (a.newState < a.prevState) throw new Error("supersede: newState must be ≥ prevState (monotonic)");
    return {
      version: 2,
      locktime: a.lockTime ?? a.prevState + 1,
      vin: [{ prevout: a.prevOutpoint, sequence: 0xfffffffe }],
      vout: [{ value: a.prevValueSat - this.p.feeSat, scriptPubKey: p2wshV6(this.eltooScript(a.newState)) }],
    };
  }

  /** Ts — spend an eLTOO output via the ELSE/CSV branch, paying both balances. The two
   *  outputs MUST sum to (updateValue − fee) (balance conservation, spec §D.2/§1.5). */
  buildSettlementTx(a: {
    updateOutpoint: OutPoint; updateValueSat: bigint; initiatorBalanceSat: bigint; peerBalanceSat: bigint;
  }): Tx {
    this.assertConserves(a.updateValueSat, a.initiatorBalanceSat, a.peerBalanceSat);
    return {
      version: 2,
      locktime: 0,
      vin: [{ prevout: a.updateOutpoint, sequence: this.p.settlementCsv }], // BIP68 relative CSV
      vout: [
        { value: a.initiatorBalanceSat, scriptPubKey: this.p.initiatorScriptPubKey },
        { value: a.peerBalanceSat, scriptPubKey: this.p.peerScriptPubKey },
      ],
    };
  }

  /** Cooperative close (spec §F.1) — spend the funding 2-of-2 directly to final balances:
   *  no eLTOO output, no CSV. Outputs MUST sum to (capacity − fee). */
  buildCooperativeCloseTx(a: { initiatorBalanceSat: bigint; peerBalanceSat: bigint }): Tx {
    this.assertConserves(this.p.capacitySat, a.initiatorBalanceSat, a.peerBalanceSat);
    return {
      version: 2,
      locktime: 0,
      vin: [{ prevout: this.p.funding, sequence: 0xffffffff }],
      vout: [
        { value: a.initiatorBalanceSat, scriptPubKey: this.p.initiatorScriptPubKey },
        { value: a.peerBalanceSat, scriptPubKey: this.p.peerScriptPubKey },
      ],
    };
  }

  // ---- partial signing (each party, own key only) ----

  /** One party's partial over a funding-2-of-2 spend (Tu,0 or cooperative close). amount =
   *  capacity. hashType 0x42 (eLTOO update, rebindable) or 0x01 (SIGHASH_ALL close). */
  signFundingPartial(tx: Tx, secretKey: Uint8Array, pubKey: Uint8Array, mldsa: MlDsa, hashType = SIGHASH_ANYPREVOUTANYSCRIPT): KeyhashPartial {
    if (hashType !== SIGHASH_ANYPREVOUTANYSCRIPT && hashType !== SIGHASH_ALL)
      throw new Error("funding-spend hashType must be 0x42 or 0x01");
    return partialSignKeyhash2of2(this.fundingWitnessScript(), tx, 0, hashType, this.p.capacitySat, secretKey, pubKey, mldsa);
  }

  /** One party's partial over an eLTOO branch spend (supersede or settlement). Always 0x42:
   *  ANYPREVOUTANYSCRIPT empties the scriptCode in the digest, so the empty scriptCode here is
   *  byte-identical to signing over the spent eLTOO script (and lets the update rebind). amount =
   *  the spent output's value. */
  signEltooPartial(tx: Tx, spentValueSat: bigint, secretKey: Uint8Array, pubKey: Uint8Array, mldsa: MlDsa): KeyhashPartial {
    return partialSignKeyhash2of2(new Uint8Array(), tx, 0, SIGHASH_ANYPREVOUTANYSCRIPT, spentValueSat, secretKey, pubKey, mldsa);
  }

  // ---- assemble fully-signed broadcastable tx from two partials ----

  /** Assemble a funding-2-of-2 spend (Tu,0 or coop close). combineKeyhash2of2Witness is
   *  order-robust (matches each partial to its committed keyhash). Trailing pubkey defaults
   *  to the initiator's (the canary convention) — any party key is valid (standardness-only). */
  assembleFundingSpend(tx: Tx, partials: [KeyhashPartial, KeyhashPartial], trailingPubKey?: Uint8Array): SignedTx {
    const wit = combineKeyhash2of2Witness(
      this.fundingWitnessScript(), partials, trailingPubKey ?? dilithiumWitnessPubKey(this.p.initiatorPub),
    );
    return this.signed(tx, wit);
  }

  /** Assemble a supersession (IF-branch) spend of the eLTOO(prevState) output. */
  assembleSupersede(tx: Tx, prevState: number, partials: [KeyhashPartial, KeyhashPartial], trailingPubKey?: Uint8Array): SignedTx {
    const { a, b } = this.orderAB(partials);
    const wit = eltooUpdateBranchWitness(
      this.eltooScript(prevState), a.sig, a.pubKey, b.sig, b.pubKey,
      trailingPubKey ?? dilithiumWitnessPubKey(this.p.initiatorPub),
    );
    return this.signed(tx, wit);
  }

  /** Assemble a settlement (ELSE/CSV-branch) spend of the eLTOO(prevState) output. */
  assembleSettlement(tx: Tx, prevState: number, partials: [KeyhashPartial, KeyhashPartial], trailingPubKey?: Uint8Array): SignedTx {
    const { a, b } = this.orderAB(partials);
    const wit = eltooSettlementBranchWitness(
      this.eltooScript(prevState), a.sig, a.pubKey, b.sig, b.pubKey,
      trailingPubKey ?? dilithiumWitnessPubKey(this.p.initiatorPub),
    );
    return this.signed(tx, wit);
  }

  // ---- single-operator convenience (the spec §K headline; tests / force-close-from-state) ----

  /** Build + co-sign (both keys local) + assemble the funding→update tx and its settlement,
   *  returning both broadcastable. This realizes the §K contract for the single-operator case
   *  (a force-close from a held state, or a test). The real 2-party path uses the granular
   *  build/sign/assemble methods above, each party signing separately. */
  buildSignedUpdateAndSettlement(a: {
    stateNum: number; initiatorBalanceSat: bigint; peerBalanceSat: bigint;
    skA: Uint8Array; pubA: Uint8Array; skB: Uint8Array; pubB: Uint8Array; mldsa: MlDsa;
  }): { update: SignedTx; settlement: SignedTx } {
    const updateTx = this.buildFundingUpdateTx(a.stateNum);
    const update = this.assembleFundingSpend(updateTx, [
      this.signFundingPartial(updateTx, a.skA, a.pubA, a.mldsa),
      this.signFundingPartial(updateTx, a.skB, a.pubB, a.mldsa),
    ]);

    const updateValueSat = updateTx.vout[0].value;
    const settlementTx = this.buildSettlementTx({
      updateOutpoint: { txid: update.txid, n: 0 }, updateValueSat,
      initiatorBalanceSat: a.initiatorBalanceSat, peerBalanceSat: a.peerBalanceSat,
    });
    const settlement = this.assembleSettlement(settlementTx, a.stateNum, [
      this.signEltooPartial(settlementTx, updateValueSat, a.skA, a.pubA, a.mldsa),
      this.signEltooPartial(settlementTx, updateValueSat, a.skB, a.pubB, a.mldsa),
    ]);

    return { update, settlement };
  }

  // ---- internals ----

  /** Match the two partials to the initiator (A) / peer (B) slots by pubkey, rejecting a
   *  partial whose key is neither (a footgun that would silently build an invalid witness). */
  private orderAB(partials: [KeyhashPartial, KeyhashPartial]): { a: KeyhashPartial; b: KeyhashPartial } {
    const khA = dilithiumKeyHash(this.p.initiatorPub);
    const khB = dilithiumKeyHash(this.p.peerPub);
    let a: KeyhashPartial | undefined, b: KeyhashPartial | undefined;
    for (const part of partials) {
      const kh = dilithiumKeyHash(part.pubKey);
      if (bytesEqual(kh, khA)) a = part;
      else if (bytesEqual(kh, khB)) b = part;
      else throw new Error("partial pubkey matches neither the initiator nor the peer channel key");
    }
    if (!a || !b) throw new Error("need exactly one partial from the initiator and one from the peer");
    return { a, b };
  }

  private assertConserves(inputValueSat: bigint, initiatorBalanceSat: bigint, peerBalanceSat: bigint): void {
    if (initiatorBalanceSat < 0n || peerBalanceSat < 0n) throw new Error("balances must be non-negative");
    if (initiatorBalanceSat + peerBalanceSat !== inputValueSat - this.p.feeSat)
      throw new Error(`balance conservation violated: ${initiatorBalanceSat} + ${peerBalanceSat} ≠ ${inputValueSat} − ${this.p.feeSat} (fee)`);
  }

  private signed(tx: Tx, witness: Uint8Array[]): SignedTx {
    const id = txid(tx);
    return {
      tx,
      hex: toHex(serializeTxWithWitness(tx, [witness])),
      txid: id,
      txidDisplay: toHex(id.slice().reverse()),
    };
  }
}
