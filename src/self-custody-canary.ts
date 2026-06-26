// soq-lightning-sdk — LIVE §E self-custody proof (the real-LSP successor to two-party-canary).
//
// Drives SoqLightning.selfCustodialPay against the REAL co-signing LSP: open a channel, fund a
// real on-chain 2-of-2, do one co-signed update round, then BROADCAST the resulting (Tu, Ts) to
// the node. Funds landing at the USER's settlement script — with no further LSP contact — is §E
// self-custody proven on-chain (the real closure of §J open #3; the canary fused keys, the LSP
// here co-signs with its OWN key only).
//
// SAFETY: --dry-run default (assembles the round against a LOCAL mock LSP, no network). --live
// opens + funds + broadcasts. Credentials from the ENVIRONMENT only:
//   LSP_URL                                   (the live LSP, e.g. https://lsp.soqu.org)
//   SOQ_SIGNER_URL, SOQ_SIGNER_TOKEN          (soq-signer faucet — funds the 2-of-2)
//   SOQ_RPC_URL, SOQ_RPC_USER, SOQ_RPC_PASS   (soqucoind JSON-RPC — broadcast + confirm)
// Run: source .env && node dist/self-custody-canary.js --live --amount=1000000000 --pay=200000000 --fee=10000000 --csv=6 --settle
import {
  SoqLightning, EltooBroadcaster,
  keyhashFunding2of2, dilithiumKeyhashScript, p2wshV6, toHex, fromHex, txid,
  nobleMlDsa, mlDsaKeygen, type SelfCustodyContext,
} from "./index.js";
import { broadcastRawTx, getRawTransaction, nodeRpc } from "./noderpc.js";

interface Cfg {
  lspUrl?: string; signerUrl?: string; signerToken?: string;
  rpcUrl?: string; rpcUser?: string; rpcPass?: string;
  amount: bigint; pay: bigint; fee: bigint; feeRate: number;
  csv: number; live: boolean; settle: boolean; confs: number; timeoutMs: number;
}

function parseArgs(argv: string[]): Cfg {
  const get = (k: string) => { const a = argv.find((x) => x.startsWith(`--${k}=`)); return a ? a.split("=").slice(1).join("=") : undefined; };
  const flag = (k: string) => argv.includes(`--${k}`);
  return {
    lspUrl: process.env.LSP_URL,
    signerUrl: process.env.SOQ_SIGNER_URL, signerToken: process.env.SOQ_SIGNER_TOKEN,
    rpcUrl: process.env.SOQ_RPC_URL, rpcUser: process.env.SOQ_RPC_USER, rpcPass: process.env.SOQ_RPC_PASS,
    amount: BigInt(get("amount") ?? "1000000000"),
    pay: BigInt(get("pay") ?? "200000000"),
    fee: BigInt(get("fee") ?? "10000000"),
    feeRate: Number(get("fee-rate") ?? "10000"),
    csv: Number(get("csv") ?? "6"),
    live: flag("live"), settle: flag("settle"),
    confs: Number(get("confs") ?? "1"),
    timeoutMs: Number(get("timeout-ms") ?? "1200000"),
  };
}

const log = (...a: unknown[]) => console.error("[sc-canary]", ...a);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const opR = (cfg: Cfg) => ({ url: cfg.rpcUrl, user: cfg.rpcUser, pass: cfg.rpcPass });

async function signerFund(cfg: Cfg, witnessScriptHex: string): Promise<string> {
  if (!cfg.signerUrl) throw new Error("SOQ_SIGNER_URL not set");
  const res = await fetch(`${cfg.signerUrl}/api/v1/send-to-witness-script`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(cfg.signerToken ? { authorization: `Bearer ${cfg.signerToken}` } : {}) },
    body: JSON.stringify({ witness_script: witnessScriptHex, amount: Number(cfg.amount), fee_rate: cfg.feeRate }),
  });
  const text = await res.text();
  let body: any; try { body = JSON.parse(text); } catch { throw new Error(`signer non-JSON (HTTP ${res.status})`); }
  if (body.error) throw new Error(`signer error: ${JSON.stringify(body.error)}`);
  if (!body.txid) throw new Error(`signer response missing txid (HTTP ${res.status})`);
  return body.txid as string;
}
async function findVout(cfg: Cfg, txidDisplay: string, spkHex: string): Promise<number> {
  const tx = await getRawTransaction(txidDisplay, true, opR(cfg));
  for (const v of tx.vout ?? []) if (v.scriptPubKey?.hex === spkHex) return v.n;
  throw new Error(`no vout of ${txidDisplay} matches ${spkHex.slice(0, 16)}…`);
}
async function waitConfirmed(cfg: Cfg, txidDisplay: string): Promise<void> {
  const deadline = Date.now() + cfg.timeoutMs;
  while (Date.now() < deadline) {
    try { const tx = await getRawTransaction(txidDisplay, true, opR(cfg)); if ((tx.confirmations ?? 0) >= cfg.confs) return; } catch { /* not yet */ }
    log(`  waiting for ${txidDisplay.slice(0, 12)}… (>=${cfg.confs} conf)`); await sleep(15000);
  }
  throw new Error(`timeout waiting for ${txidDisplay}`);
}

/** A LOCAL real-key mock LSP (dry-run only) — co-signs BOTH partials with a generated key so the
 *  round assembles with no network. Mirrors the F1 LSP response + the v1 fee policy. */
function mockLspFetch(lsp: { secretKey: Uint8Array; publicKey: Uint8Array }, user: Uint8Array, ctx: SelfCustodyContext, amount: bigint, csv: number) {
  const params = {
    funding: ctx.funding, capacitySat: amount, initiatorPub: user, peerPub: lsp.publicKey,
    initiatorScriptPubKey: ctx.initiatorScriptPubKey, peerScriptPubKey: ctx.peerScriptPubKey,
    settlementCsv: csv, feeSat: ctx.feeSat,
  };
  const bc = new EltooBroadcaster(params);
  const ok = (o: any) => new Response(JSON.stringify(o), { status: 200, headers: { "content-type": "application/json" } });
  const chans = new Map<string, any>();
  return async (url: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const path = new URL(String(url)).pathname;
    const body = init?.body ? JSON.parse(init.body as string) : {};
    const m = path.match(/^\/v1\/channels\/([^/]+)(\/update)?$/);
    if (!m) return new Response("{}", { status: 404 });
    const id = m[1];
    if (!chans.has(id)) chans.set(id, { channel_id: id, initiator_pub_key_hex: toHex(user), peer_pub_key_hex: toHex(lsp.publicKey),
      capacity_sat: Number(amount), initiator_balance_sat: Number(amount), peer_balance_sat: 0, state_index: 0, state: "open", csv_delay: csv, created_at_unix: 0 });
    const ch = chans.get(id);
    if (m[2] === "/update") {
      const updateTx = bc.buildFundingUpdateTx(body.state_index);
      const uValue = updateTx.vout[0].value;
      const settlementTx = bc.buildSettlementTx({ updateOutpoint: { txid: txid(updateTx), n: 0 }, updateValueSat: uValue,
        initiatorBalanceSat: BigInt(body.initiator_balance_sat) - 2n * ctx.feeSat, peerBalanceSat: BigInt(body.peer_balance_sat) });
      const up = bc.signFundingPartial(updateTx, lsp.secretKey, lsp.publicKey, nobleMlDsa);
      const st = bc.signEltooPartial(settlementTx, uValue, lsp.secretKey, lsp.publicKey, nobleMlDsa);
      ch.state_index = body.state_index; ch.initiator_balance_sat = body.initiator_balance_sat; ch.peer_balance_sat = body.peer_balance_sat;
      return ok({ accepted: true, peer_signature_hex: toHex(up.sig), settlement_signature_hex: toHex(st.sig) });
    }
    return ok(ch);
  };
}

async function main() {
  const cfg = parseArgs(process.argv.slice(2));
  if (cfg.pay >= cfg.amount - cfg.fee * 3n) throw new Error("pay must leave room for 3× fee");

  const user = mlDsaKeygen();
  const userPayout = p2wshV6(dilithiumKeyhashScript(user.publicKey));

  if (!cfg.live) {
    const lsp = mlDsaKeygen();
    const ctx: SelfCustodyContext = {
      userSecretKey: user.secretKey, userPub: user.publicKey,
      funding: { txid: new Uint8Array(32), n: 0 },
      initiatorScriptPubKey: userPayout, peerScriptPubKey: p2wshV6(dilithiumKeyhashScript(lsp.publicKey)),
      feeSat: cfg.fee, mldsa: nobleMlDsa,
    };
    const ln = new SoqLightning({ baseUrl: "https://mock", fetchImpl: mockLspFetch(lsp, user.publicKey, ctx, cfg.amount, cfg.csv) });
    const { update, settlement } = await ln.selfCustodialPay("dryrun", Number(cfg.pay), ctx);
    log("DRY-RUN: §E round assembled vs a local mock LSP (no network).");
    console.log(JSON.stringify({ mode: "dry_run", update: update.txidDisplay, settlement: settlement.txidDisplay }, null, 2));
    return;
  }

  if (!cfg.lspUrl) throw new Error("LSP_URL not set");
  const ln = new SoqLightning({ baseUrl: cfg.lspUrl });

  // --- 0. LSP must be co-signing for real (post key deploy) ---
  const info: any = await ln.info();
  log(`0: LSP ${cfg.lspUrl} cosign_enabled=${info.cosign_enabled} pub=${String(info.pub_key_hex).slice(0, 16)}…`);
  if (!info.cosign_enabled) throw new Error("LSP cosign_enabled=false — deploy the WS2b binary + set LSP_SIGNER_ADDRESS first");

  // --- 1. open a channel; the LSP's co-signing pubkey is peer_pub_key_hex ---
  const ch = await ln.openChannel({ pubKeyHex: toHex(user.publicKey), address: toHex(userPayout), capacitySat: Number(cfg.amount), csvDelay: cfg.csv });
  const lspPub = fromHex(ch.peer_pub_key_hex);
  log(`1: channel ${ch.channel_id} opened; lspPub=${ch.peer_pub_key_hex.slice(0, 16)}…`);

  // --- 2. fund the REAL on-chain 2-of-2(user, lsp) via soq-signer ---
  const funding = keyhashFunding2of2(user.publicKey, lspPub);
  const fundTxid = await signerFund(cfg, toHex(funding.witnessScript));
  const fundVout = await findVout(cfg, fundTxid, toHex(funding.scriptPubKey));
  log(`2: funded ${fundTxid}:${fundVout}`); await waitConfirmed(cfg, fundTxid);

  // --- 3. the co-signed update round → fully-signed (Tu, Ts) the USER holds (spec §E) ---
  const ctx: SelfCustodyContext = {
    userSecretKey: user.secretKey, userPub: user.publicKey,
    funding: { txid: fromHex(fundTxid).reverse(), n: fundVout },
    initiatorScriptPubKey: userPayout, peerScriptPubKey: p2wshV6(dilithiumKeyhashScript(lspPub)),
    feeSat: cfg.fee, mldsa: nobleMlDsa,
  };
  const { update, settlement } = await ln.selfCustodialPay(ch.channel_id, Number(cfg.pay), ctx);
  log(`3: round co-signed; update=${update.txidDisplay} settlement=${settlement.txidDisplay}`);

  // --- 4. BROADCAST the update WITHOUT the LSP (unilateral force-close, step 1) ---
  const utxid = await broadcastRawTx(update.hex, opR(cfg));
  log(`4: update broadcast ${utxid} (no LSP)`); await waitConfirmed(cfg, utxid);

  let settleTxid: string | undefined;
  if (cfg.settle) {
    // --- 5. after the CSV, broadcast the settlement → funds at the USER's script (§E) ---
    log(`5: settlement — waiting ${cfg.csv} confs for CSV…`);
    for (;;) { const t = await getRawTransaction(utxid, true, opR(cfg)); if ((t.confirmations ?? 0) >= cfg.csv) break; await sleep(15000); }
    settleTxid = await broadcastRawTx(settlement.hex, opR(cfg));
    log(`  settlement broadcast ${settleTxid}`); await waitConfirmed(cfg, settleTxid);
  }

  console.log(JSON.stringify({ mode: "live", channel: ch.channel_id, funding: `${fundTxid}:${fundVout}`, update: utxid, settle: settleTxid ?? null }, null, 2));
  log("✅ §E SELF-CUSTODY PROVEN LIVE: the user broadcast its co-signed (Tu, Ts) and closed WITHOUT the LSP.");
}

main().catch((e) => { console.error("[sc-canary] FAILED:", e?.message ?? e); process.exit(1); });
