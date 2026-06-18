// soq-lightning-sdk — multi-hop HTLC forwarding (spec §2.2, §5, §6)
//
// PQ multi-hop is HASHLOCK-based, NOT PTLC (Dilithium has no production adaptor sigs;
// spec §2.1). One SHA-256 payment hash H = SHA256(P) links every hop; the receiver
// reveals P, which propagates back hop-by-hop (§5.3). SHA-256 is PQ-acceptable
// (Grover → ~128-bit preimage security).
//
// THREE TIMELOCKS, do not conflate (§2.2 / §6.2):
//   - settlement_csv      : RELATIVE (CSV), update→settlement, single-channel
//   - cltv_expiry         : ABSOLUTE (CLTV), the cross-hop deadline, MUST be absolute
//   - confirmation buffers: reorg/congestion margins, layered on both
//
// STATUS: this is the client-side construction + validation layer. The deployed LSP has
// NO forwarding endpoints yet (rest.go is single-hop accept-and-store), so live multi-hop
// needs the Go-side update_add_htlc/update_fulfill_htlc wire (Buddy). Everything here is
// pure + offline-tested and ready to wire when those land.

import {
  OP, pushData, scriptNum, p2wshV6, p2wshV6Witness, signAllWitness, type Tx,
} from "./channel.js";
import { verifyInvoice, type Invoice, type MlDsa } from "./invoice.js";

// ---- §6.2.1 tier parameters (transparent FINAL; confidential PROVISIONAL on proof-cap) ----
export const TIER = {
  transparent: { cltvExpiryDelta: 288, settlementCsv: 288, minFinalCltvExpiry: 576 },
  confidential: { cltvExpiryDelta: 360, settlementCsv: 360, minFinalCltvExpiry: 720 }, // PROVISIONAL (§6.2.1)
} as const;
export type Tier = keyof typeof TIER;

// ---- §6.3 griefing calibration ----
export const GRIEFING = {
  upfrontFeePpm: 100,        // ≥100 ppm of HTLC value
  softTimeoutBlocks: 144,    // fail off-chain before on-chain timeout (½ of CSV)
  maxAcceptedHtlcs: 30,      // per-peer slot cap
  maxHtlcInFlightPct: 50,    // ≤50% of channel capacity per peer
} as const;

// ---- §5 forwarding error codes ----
export const FORWARD_ERR = {
  fee: 0x30,            // amount_out ≤ 0 or fee below minimum
  cltvDelta: 0x31,      // cltv_in − cltv_out < cltv_expiry_delta
  unknownPaymentHash: 0x32, // H not bound to a verified invoice (§5.2-0)
  downstreamFail: 0x40, // fail backward on downstream failure/timeout
} as const;

// ---- §2.2 HTLC output script ----
/** OP_IF  OP_SHA256 <H> OP_EQUALVERIFY <payeePub> OP_CHECKSIG   (SUCCESS: reveal P + sign)
 *  OP_ELSE <cltv_expiry> OP_CLTV OP_DROP <payerPub> OP_CHECKSIG (TIMEOUT: absolute CLTV)
 *  OP_ENDIF.  All CHECKSIGs use plain SIGHASH_ALL (§2.2 note). */
export function htlcScript(paymentHash: Uint8Array, payeePub: Uint8Array, payerPub: Uint8Array, cltvExpiry: number): Uint8Array {
  if (paymentHash.length !== 32) throw new Error("paymentHash must be 32 bytes");
  const c = (...xs: Uint8Array[]) => { const n = xs.reduce((s, x) => s + x.length, 0); const o = new Uint8Array(n); let p = 0; for (const x of xs) { o.set(x, p); p += x.length; } return o; };
  const b = (n: number) => Uint8Array.of(n);
  return c(
    b(OP.IF),
      b(OP.SHA256), pushData(paymentHash), b(OP.EQUALVERIFY),
      pushData(payeePub), b(OP.CHECKSIG),
    b(OP.ELSE),
      scriptNum(cltvExpiry), b(OP.CLTV), b(OP.DROP),
      pushData(payerPub), b(OP.CHECKSIG),
    b(OP.ENDIF),
  );
}

/** Soqucoin witness-v6 P2WSH scriptPubKey for an HTLC output. */
export function htlcScriptPubKey(paymentHash: Uint8Array, payeePub: Uint8Array, payerPub: Uint8Array, cltvExpiry: number): Uint8Array {
  return p2wshV6(htlcScript(paymentHash, payeePub, payerPub, cltvExpiry));
}

// ---- HTLC claim witnesses (v6: [...satisfaction, witnessScript, trailingDilithiumPubKey]) ----
/** SUCCESS branch witness. satisfaction = [sig‖0x01, preimage, <truthy selector>]; then the
 *  witnessScript and the claimer's 0x00-prefixed pubkey (HasDilithiumSignatures). */
export function htlcSuccessWitness(claimTx: Tx, nIn: number, amountSat: bigint, preimage: Uint8Array, witnessScript: Uint8Array, payeeSecretKey: Uint8Array, trailingPubKey: Uint8Array, mldsa: MlDsa): Uint8Array[] {
  const sig = signAllWitness(witnessScript, claimTx, nIn, amountSat, payeeSecretKey, mldsa);
  return p2wshV6Witness([sig, preimage, Uint8Array.of(0x01)], witnessScript, trailingPubKey); // 0x01 → IF/SUCCESS
}
/** TIMEOUT branch witness. satisfaction = [sig‖0x01, <empty selector>]. claimTx.locktime MUST
 *  be ≥ cltv_expiry and the input non-final for OP_CLTV to pass. */
export function htlcTimeoutWitness(claimTx: Tx, nIn: number, amountSat: bigint, witnessScript: Uint8Array, payerSecretKey: Uint8Array, trailingPubKey: Uint8Array, mldsa: MlDsa): Uint8Array[] {
  const sig = signAllWitness(witnessScript, claimTx, nIn, amountSat, payerSecretKey, mldsa);
  return p2wshV6Witness([sig, new Uint8Array(0)], witnessScript, trailingPubKey); // empty → ELSE/TIMEOUT
}

// ---- route construction (backward induction) ----
export interface ChannelHop {        // an intermediary (forwarding) node on the path
  nodeId: string;                    // hex node id / pubkey of the forwarder
  feeBaseSat: bigint;
  feePpm: number;
  cltvExpiryDelta: number;           // this hop's required cltv margin (§6.2.1 per tier)
}
export interface RouteHop {
  nodeId: string;
  amountToForwardSat: bigint;        // amount this node forwards to the NEXT hop
  outgoingCltvExpiry: number;        // cltv of the HTLC this node offers onward
}
export interface BuiltRoute {
  hops: RouteHop[];                  // sender→…→receiver order
  senderAmountSat: bigint;           // total the SENDER locks (final + all hop fees)
  senderCltvExpiry: number;          // cltv of the sender's outgoing HTLC (the largest)
  totalFeesSat: bigint;
}

/** Compute per-hop amounts + absolute CLTVs by backward induction from the receiver.
 *  hops are the intermediaries in sender→receiver order (e.g. [hub] for sender→hub→receiver). */
export function buildRoute(opts: {
  finalAmountSat: bigint;
  hops: ChannelHop[];
  currentBlockHeight: number;
  finalCltvExpiryDelta: number;      // = TIER[tier].minFinalCltvExpiry
}): BuiltRoute {
  if (opts.finalAmountSat <= 0n) throw new Error("finalAmountSat must be positive");
  let amount = opts.finalAmountSat;
  let cltv = opts.currentBlockHeight + opts.finalCltvExpiryDelta;
  const hops: RouteHop[] = [];
  // walk receiver→sender (reverse), prepending each hop's forwarding instruction
  for (let k = opts.hops.length - 1; k >= 0; k--) {
    const h = opts.hops[k];
    hops.unshift({ nodeId: h.nodeId, amountToForwardSat: amount, outgoingCltvExpiry: cltv });
    const fee = h.feeBaseSat + (amount * BigInt(h.feePpm)) / 1_000_000n;
    amount = amount + fee;          // upstream must offer more (covers this hop's fee)
    cltv = cltv + h.cltvExpiryDelta; // and a larger absolute deadline
  }
  return { hops, senderAmountSat: amount, senderCltvExpiry: cltv, totalFeesSat: amount - opts.finalAmountSat };
}

// ---- §5.2 forwarding obligation checks (a Hub runs these on update_add_htlc) ----
export interface ForwardCheck { ok: boolean; error?: number; reason?: string }

/** §5.2-1 (fee) + §5.2-2 (cltv delta). minFeeSat is the channel's negotiated minimum. */
export function checkForward(
  incoming: { amountSat: bigint; cltvExpiry: number },
  outgoing: { amountSat: bigint; cltvExpiry: number },
  policy: { minFeeSat: bigint; cltvExpiryDelta: number },
): ForwardCheck {
  const fee = incoming.amountSat - outgoing.amountSat;
  if (outgoing.amountSat <= 0n) return { ok: false, error: FORWARD_ERR.fee, reason: "amount_out ≤ 0" };
  if (fee < policy.minFeeSat) return { ok: false, error: FORWARD_ERR.fee, reason: `fee ${fee} < min ${policy.minFeeSat}` };
  const delta = incoming.cltvExpiry - outgoing.cltvExpiry;
  if (delta < policy.cltvExpiryDelta) return { ok: false, error: FORWARD_ERR.cltvDelta, reason: `cltv delta ${delta} < ${policy.cltvExpiryDelta}` };
  return { ok: true };
}

/** §5.2-0 invoice binding (Tamarin-required): lock/forward only against a verified, unexpired,
 *  unresolved invoice whose payment hash equals H. Omitting this re-enables the cross-payment
 *  reuse attack the Tamarin run falsified. */
export function checkInvoiceBinding(
  paymentHash: Uint8Array, invoice: Invoice, payeePubKey: Uint8Array, mldsa: MlDsa, nowSec: number,
  resolved = false,
): ForwardCheck {
  const hx = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  if (hx(invoice.paymentHash) !== hx(paymentHash)) return { ok: false, error: FORWARD_ERR.unknownPaymentHash, reason: "H not bound to this invoice" };
  if (!verifyInvoice(invoice, payeePubKey, mldsa)) return { ok: false, error: FORWARD_ERR.unknownPaymentHash, reason: "invoice signature invalid" };
  if (resolved) return { ok: false, error: FORWARD_ERR.unknownPaymentHash, reason: "invoice already resolved" };
  const expiry = invoice.expiry || 3600;
  if (nowSec > Number(invoice.timestamp) + expiry) return { ok: false, error: FORWARD_ERR.unknownPaymentHash, reason: "invoice expired" };
  return { ok: true };
}

// ---- forwarding payloads (source-routed; Sphinx onion deferred per §5.5) ----
export interface HopPayload {
  nodeId: string;
  amountToForwardSat: bigint;
  outgoingCltvExpiry: number;
}
/** Per-hop forwarding instructions. NOTE: this is cleartext source routing — the privacy
 *  layer (Sphinx onion encryption) is explicitly DEFERRED in §5.5. Do not present these as
 *  private until onion routing lands. */
export function routeToPayloads(route: BuiltRoute): HopPayload[] {
  return route.hops.map((h) => ({ nodeId: h.nodeId, amountToForwardSat: h.amountToForwardSat, outgoingCltvExpiry: h.outgoingCltvExpiry }));
}
