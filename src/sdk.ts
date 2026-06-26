// soq-lightning-sdk — high-level developer API (B3)
//
// One ergonomic facade over the REST client + invoices. The eLTOO transaction
// construction (0x42-signed update/settlement TXs, CTV templates) is abstracted
// behind UpdateTxBuilder: today the default is a placeholder (the peer is
// accept-and-store on the happy path); when channel.ts lands, plug in the real
// signer with NO change to this API.
//
//   const ln = new SoqLightning({ baseUrl: LSP_URL });
//   const ch = await ln.openChannel({ pubKeyHex, address, capacitySat: 5_0000_0000 });
//   await ln.pay(ch.channel_id, 1_0000_0000);     // move 1 SOQ to the peer
//   await ln.close(ch.channel_id);

import {
  LspClient, RestClientOpts, Channel, CloseResp, FaucetResp,
} from "./client.js";
import type { TowerClient } from "./watchtower.js";
import { EltooBroadcaster, type ChannelParams, type SignedTx } from "./eltoo-broadcast.js";
import { lspUpdateRound } from "./two-party-broadcast.js";
import { fromHex, toHex, ctvHash, type OutPoint } from "./channel.js";
import type { MlDsa } from "./invoice.js";

/** Everything the SDK needs to co-sign + self-custody a channel that the LSP-side facade does
 *  NOT hold: the user's key, the funding outpoint (tracked at open), the on-chain payout
 *  scripts, and the fee. Supplied per call so the demo `pay()` path stays key-free. */
export interface SelfCustodyContext {
  userSecretKey: Uint8Array;
  userPub: Uint8Array;                  // MUST equal fromHex(channel.initiator_pub_key_hex)
  funding: OutPoint;                    // the channel's funding outpoint (internal byte order)
  initiatorScriptPubKey: Uint8Array;    // the user's on-chain settlement payout script
  peerScriptPubKey: Uint8Array;         // the LSP's on-chain settlement payout script
  feeSat: bigint;                       // fixed per-tx fee (v1, spec §H)
  mldsa: MlDsa;
}

/** Context handed to the TX builder for one state transition. */
export interface UpdateContext {
  channel: Channel;            // current on-LSP state (pre-update)
  nextStateIndex: number;
  nextInitiatorBalanceSat: number;
  nextPeerBalanceSat: number;
}

/** Produces the eLTOO update/settlement TX hex for a state transition.
 *  channel.ts will implement this with SIGHASH_ANYPREVOUTANYSCRIPT (0x42). */
export interface UpdateTxBuilder {
  build(ctx: UpdateContext): Promise<{ update_tx_hex: string; settlement_tx_hex: string; ctv_hash: string }>;
}

/** Default builder for the happy path — opaque placeholders accepted by the
 *  accept-and-store peer. Swap for the real signer before relying on the
 *  unilateral dispute path. */
export const placeholderTxBuilder: UpdateTxBuilder = {
  async build() { return { update_tx_hex: "placeholder", settlement_tx_hex: "placeholder", ctv_hash: "placeholder" }; },
};

/** Wires a watchtower into the payment path. When set, pay() arms the tower with state
 *  i+1 (the freshly-built update/settlement TXs) BEFORE returning — the spec §1.6
 *  persist→arm→ack ordering. `fundingFor` supplies the funding outpoint the tower monitors. */
export interface WatchtowerArming {
  client: TowerClient;
  fundingFor(channelId: string): { funding_txid: string; funding_vout: number } | Promise<{ funding_txid: string; funding_vout: number }>;
}

export interface SoqLightningOpts extends RestClientOpts {
  txBuilder?: UpdateTxBuilder;
  watchtower?: WatchtowerArming;
}

export interface OpenChannelParams {
  pubKeyHex: string;           // ML-DSA-44 public key (hex)
  address: string;             // L1 settlement address
  capacitySat: number;
  name?: string;
  csvDelay?: number;           // settlement_csv tier (default 288, transparent — spec §6.2.1)
}

export class SoqLightning {
  readonly client: LspClient;
  private builder: UpdateTxBuilder;
  private watchtower?: WatchtowerArming;
  constructor(opts: SoqLightningOpts) {
    this.client = new LspClient(opts);
    this.builder = opts.txBuilder ?? placeholderTxBuilder;
    this.watchtower = opts.watchtower;
  }

  /** Fund via faucet + auto-open a channel (stagenet path). Returns the opened channel.
   *  The LSP caps channel capacity at max_channel_sat; the faucet will drip the requested
   *  funds but SILENTLY decline to open a channel if asked for more (it returns success+txid
   *  with no channel_id — verified live 2026-06-24). We clamp the request to the advertised
   *  cap so the open actually happens; the returned Channel reflects the real capacity. */
  async fundAndOpen(p: OpenChannelParams): Promise<Channel> {
    const info: any = await this.client.info().catch(() => ({}));
    const maxCap = Number(info?.max_channel_sat) || p.capacitySat;
    const capacitySat = Math.min(p.capacitySat, maxCap);
    const r: FaucetResp = await this.client.faucetDrip({
      address: p.address, pub_key_hex: p.pubKeyHex, open_channel: true,
      amount_sat: capacitySat, name: p.name ?? "sdk",
    });
    if (!r.success) throw new Error(`faucet failed: ${r.error ?? "unknown"}`);
    if (!r.channel_id)
      throw new Error(
        `faucet dripped ${r.amount_sat ?? capacitySat} sat (txid ${r.txid ?? "?"}) but did not open a ` +
        `channel — requested capacity may exceed the LSP max_channel_sat (${maxCap})`);
    return this.client.getChannel(r.channel_id);
  }

  /** Open a channel directly (when you already hold funds — no faucet). */
  async openChannel(p: OpenChannelParams): Promise<Channel> {
    const r = await this.client.openChannel({
      initiator_pub_key_hex: p.pubKeyHex, capacity_sat: p.capacitySat,
      initiator_name: p.name ?? "sdk", csv_delay: p.csvDelay ?? 288, initiator_address: p.address,
    });
    if (!r.accepted || !r.channel_id) throw new Error(`open rejected: ${r.reject_reason ?? "unknown"}`);
    return this.client.getChannel(r.channel_id);
  }

  /** Move `amountSat` from the initiator (us) to the peer — one eLTOO state bump.
   *  Proposes the transition, then re-reads: the LSP is the source of truth for the
   *  committed balances/index (a countersigning peer may meet-in-the-middle or bump
   *  the index — verified live against echo_mode), so we never assume our proposal
   *  was stored verbatim. Returns the channel AS COMMITTED by the peer. */
  async pay(channelId: string, amountSat: number): Promise<Channel> {
    if (amountSat <= 0) throw new Error("amount must be positive");
    const ch = await this.client.getChannel(channelId);
    if (ch.state !== "open") throw new Error(`channel not open (state=${ch.state})`);
    if (amountSat > ch.initiator_balance_sat) throw new Error("insufficient initiator balance");

    const next: UpdateContext = {
      channel: ch,
      nextStateIndex: ch.state_index + 1,
      nextInitiatorBalanceSat: ch.initiator_balance_sat - amountSat,
      nextPeerBalanceSat: ch.peer_balance_sat + amountSat,
    };
    const tx = await this.builder.build(next);
    const resp = await this.client.updateState(channelId, {
      state_index: next.nextStateIndex,
      initiator_balance_sat: next.nextInitiatorBalanceSat,
      peer_balance_sat: next.nextPeerBalanceSat,
      ...tx,
    });
    if (!resp.accepted) throw new Error(`update rejected: ${resp.reject_reason ?? "unknown"}`);

    // §1.6 persist→arm→ack: the LSP has now persisted+countersigned state i+1 (persist).
    // Arm the watchtower with i+1 BEFORE we return success (ack). If arming fails we throw —
    // the payment is NOT safely locked, and surfacing that beats a silent theft window.
    if (this.watchtower) {
      const f = await this.watchtower.fundingFor(channelId);
      await this.watchtower.client.register({
        channel_id: channelId,
        funding_txid: f.funding_txid,
        funding_vout: f.funding_vout,
        state_index: next.nextStateIndex,
        update_tx_hex: tx.update_tx_hex,
        settlement_tx_hex: tx.settlement_tx_hex,
        ctv_hash: tx.ctv_hash,
      });
    }

    const after = await this.client.getChannel(channelId);
    // invariant true in BOTH echo_mode and accept-and-store: state advanced + funds conserved
    if (after.state_index <= ch.state_index)
      throw new Error(`state did not advance: ${ch.state_index} -> ${after.state_index}`);
    if (after.initiator_balance_sat + after.peer_balance_sat !== after.capacity_sat)
      throw new Error("balance not conserved after update");
    return after;
  }

  /** Self-custodial pay — one F1-complete LSP round (spec §D + §E). Moves `amountSat` to the
   *  peer and returns the fully-signed (Tu, Ts) the caller MUST persist: with them the user can
   *  unilaterally close WITHOUT the LSP. Unlike pay() (the demo/opaque path) this does real
   *  2-of-2 co-signing — the user signs locally; the LSP returns BOTH partials; they're combined.
   *
   *  Balance/fee model: the LSP accounts LOGICAL balances (sum == capacity, manager.go:271), but
   *  the on-chain settlement can only pay capacity − 2·fee (one fee for the update tx, one for the
   *  settlement). ⚠️ v1 policy (§H — FLAG): the INITIATOR pays both on-chain force-close fees (the
   *  LN default), so its settlement output = logical balance − 2·fee. Revisit when fee policy lands.
   *
   *  ⚠️ TRUST GAP (WS2b Task 7): the LSP currently co-signs the settlement WITHOUT validating its
   *  outputs match the recorded balances — a malicious spoke could submit a settlement that
   *  over-pays itself. Safe only until the LSP settlement-output validation lands. */
  async selfCustodialPay(channelId: string, amountSat: number, ctx: SelfCustodyContext): Promise<{ channel: Channel; update: SignedTx; settlement: SignedTx }> {
    if (amountSat <= 0) throw new Error("amount must be positive");
    const ch = await this.client.getChannel(channelId);
    if (ch.state !== "open") throw new Error(`channel not open (state=${ch.state})`);
    if (amountSat > ch.initiator_balance_sat) throw new Error("insufficient initiator balance");

    const lspPub = fromHex(ch.peer_pub_key_hex);
    const params: ChannelParams = {
      funding: ctx.funding,
      capacitySat: BigInt(ch.capacity_sat),
      initiatorPub: ctx.userPub,
      peerPub: lspPub,
      initiatorScriptPubKey: ctx.initiatorScriptPubKey,
      peerScriptPubKey: ctx.peerScriptPubKey,
      settlementCsv: ch.csv_delay,
      feeSat: ctx.feeSat,
    };
    const bc = new EltooBroadcaster(params);

    // Logical balances after the payment (sum == capacity, for the LSP), then the on-chain
    // settlement split: the initiator absorbs the 2·fee force-close cost.
    const logicalInitiator = ch.initiator_balance_sat - amountSat;
    const logicalPeer = ch.peer_balance_sat + amountSat;
    const settlementInitiator = BigInt(logicalInitiator) - 2n * ctx.feeSat;
    if (settlementInitiator < 0n)
      throw new Error(`initiator balance ${logicalInitiator} cannot cover ${2n * ctx.feeSat} on-chain fees`);

    const { update, settlement } = await lspUpdateRound(
      bc,
      { updateState: (req) => this.client.updateState(channelId, req) },
      {
        stateNum: ch.state_index + 1,
        initiatorBalanceSat: settlementInitiator,
        peerBalanceSat: BigInt(logicalPeer),
        reqBalances: { initiatorSat: logicalInitiator, peerSat: logicalPeer }, // logical → LSP accounting
        userSecretKey: ctx.userSecretKey, userPub: ctx.userPub, lspPub, mldsa: ctx.mldsa,
      },
    );

    // §1.6 persist→arm→ack: arm the watchtower with the FULLY-SIGNED txs that will broadcast.
    if (this.watchtower) {
      await this.watchtower.client.register({
        channel_id: channelId,
        funding_txid: toHex(ctx.funding.txid.slice().reverse()),
        funding_vout: ctx.funding.n,
        state_index: ch.state_index + 1,
        update_tx_hex: update.hex,
        settlement_tx_hex: settlement.hex,
        ctv_hash: toHex(ctvHash(settlement.tx, 0)),
      });
    }

    const after = await this.client.getChannel(channelId);
    return { channel: after, update, settlement };
  }

  /** Cooperative close → L1 settlement enqueued via the LSP.
   *  Resilient to the deployed binary's bug where a SUCCESSFUL close mutates state to
   *  "closed" but drops the HTTP response (empty reply): on a transport error we
   *  re-read the channel and treat closed/closing as success. */
  async close(channelId: string): Promise<CloseResp> {
    try {
      const r = await this.client.closeChannel(channelId);
      if (!r.accepted) throw new Error(`close rejected: ${r.reject_reason ?? "unknown"}`);
      return r;
    } catch (e) {
      const ch = await this.client.getChannel(channelId).catch(() => null);
      if (ch && (ch.state === "closed" || ch.state === "closing"))
        return { accepted: true, reject_reason: "(response dropped; state confirms closed)" };
      throw e;
    }
  }

  /** LSP liveness — `{ status: "ok", ... }` when the peer + its node backend are healthy. */
  health(): Promise<any> { return this.client.health(); }
  /** LSP identity/capabilities — peer name, version, network, fee policy, etc. */
  info(): Promise<any> { return this.client.info(); }

  channel(id: string): Promise<Channel> { return this.client.getChannel(id); }
  channels(): Promise<{ channels: Channel[] }> { return this.client.listChannels(); }

  /** Watchtower health, proxied through the LSP. On stagenet the LSP arms the (firewalled,
   *  dual) towers on the spoke's behalf, so the spoke verifies LIVENESS here — "a tower is
   *  watching" — not per-state arming (that's mainnet Phase-1 signed receipts). */
  towerStatus() { return this.client.towerStatus(); }

  /** Throws unless at least `minTowers` watchtowers are reachable — call before relying on
   *  offline safety. Default 2 reflects the dual-tower defense-in-depth deployment. */
  async assertTowersHealthy(minTowers = 2): Promise<void> {
    const s = await this.client.towerStatus();
    const up = s.towers.filter((t) => t.available).length;
    if (!s.available || up < minTowers)
      throw new Error(`watchtower coverage degraded: ${up}/${s.tower_count} reachable (need ${minTowers})`);
  }
}
