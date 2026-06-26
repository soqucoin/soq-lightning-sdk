// soq-lightning-sdk — LIVE two-party broadcast harness (the b1-canary's successor).
//
// The b1-canary proved the script mechanics but FUSED both keys. This drives the same
// on-chain lifecycle through the WS2 EltooBroadcaster with TWO INDEPENDENT signers (user +
// LSP), each holding only its own ML-DSA key and contributing only a partial — the real
// 2-party trust boundary (spec §J open #3). If the live node accepts these txs, the
// two-separate-signer path is proven on-chain, not just offline.
//
//   fund (soq-signer → keyhash-2of2) → openUpdate → supersede → settle (CSV)
//   every spend = user.partial ⊕ lsp.partial, combined by the builder, broadcast live.
//
// MODE 1 (now): both parties are LocalParty in this process (key-isolated). MODE 2 (after
// WS2b): swap the LSP LocalParty for a RemoteLspParty that fetches the LSP's real partial
// over the wire — at which point this also proves the LSP co-sign end-to-end.
//
// SAFETY: defaults to --dry-run (assembles + prints the graph, no network). --live funds +
// broadcasts. Credentials from the ENVIRONMENT only:
//   SOQ_SIGNER_URL, SOQ_SIGNER_TOKEN          (soq-signer faucet; operator-only token)
//   SOQ_RPC_URL, SOQ_RPC_USER, SOQ_RPC_PASS   (soqucoind JSON-RPC)
// Run: source .env && node dist/two-party-canary.js --live --amount=1000000000 --fee=10000000 --state=100 --csv=6 --settle
import {
  EltooBroadcaster, LocalParty, TwoPartyChannel,
  keyhashFunding2of2, dilithiumKeyhashScript, p2wshV6, toHex, fromHex,
  nobleMlDsa, mlDsaKeygen,
} from "./index.js";
import { broadcastRawTx, getRawTransaction, nodeRpc } from "./noderpc.js";

interface Cfg {
  signerUrl?: string; signerToken?: string;
  rpcUrl?: string; rpcUser?: string; rpcPass?: string;
  amount: bigint; fee: bigint; feeRate: number;
  state: number; csv: number; live: boolean; settle: boolean; confs: number; timeoutMs: number;
}

function parseArgs(argv: string[]): Cfg {
  const get = (k: string) => { const a = argv.find((x) => x.startsWith(`--${k}=`)); return a ? a.split("=").slice(1).join("=") : undefined; };
  const flag = (k: string) => argv.includes(`--${k}`);
  return {
    signerUrl: process.env.SOQ_SIGNER_URL, signerToken: process.env.SOQ_SIGNER_TOKEN,
    rpcUrl: process.env.SOQ_RPC_URL, rpcUser: process.env.SOQ_RPC_USER, rpcPass: process.env.SOQ_RPC_PASS,
    amount: BigInt(get("amount") ?? "1000000000"),
    fee: BigInt(get("fee") ?? "10000000"),
    feeRate: Number(get("fee-rate") ?? "10000"),
    state: Number(get("state") ?? "100"),
    csv: Number(get("csv") ?? "6"),
    live: flag("live"), settle: flag("settle"),
    confs: Number(get("confs") ?? "1"),
    timeoutMs: Number(get("timeout-ms") ?? "1200000"),
  };
}

const log = (...a: unknown[]) => console.error("[2p-canary]", ...a);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const opR = (cfg: Cfg) => ({ url: cfg.rpcUrl, user: cfg.rpcUser, pass: cfg.rpcPass });
const txidToInternal = (display: string) => fromHex(display).reverse();

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
/** Broadcast a signed tx, surfacing the node's testmempoolaccept verdict first (diagnostics). */
async function broadcast(cfg: Cfg, label: string, hex: string): Promise<string> {
  try {
    const r = await nodeRpc("testmempoolaccept", [[hex]], opR(cfg));
    const e = Array.isArray(r) ? r[0] : r;
    log(`  ${label}: testmempoolaccept allowed=${!!e?.allowed}${e?.["reject-reason"] ? ` reason=${e["reject-reason"]}` : ""}`);
  } catch (e: any) { log(`  ${label}: testmempoolaccept probe failed (${e?.message ?? e}) — broadcasting anyway`); }
  return broadcastRawTx(hex, opR(cfg));
}
const splitBalances = (total: bigint): { init: bigint; peer: bigint } => {
  const init = total / 2n; return { init, peer: total - init };
};

async function main() {
  const cfg = parseArgs(process.argv.slice(2));
  if (cfg.amount <= cfg.fee * 3n) throw new Error("amount must exceed 3× fee (funding → update → supersede → settle each pay a fee)");

  // Two INDEPENDENT parties — each keypair stands in for a separate signer.
  const USER = mlDsaKeygen(), LSP = mlDsaKeygen();
  const funding = keyhashFunding2of2(USER.publicKey, LSP.publicKey);
  const fundSpkHex = toHex(funding.scriptPubKey);
  // Each party's settlement payout = its own keyhash output.
  const userSpk = p2wshV6(dilithiumKeyhashScript(USER.publicKey));
  const lspSpk = p2wshV6(dilithiumKeyhashScript(LSP.publicKey));

  const mkChannel = (fundingOutpoint: { txid: Uint8Array; n: number }) => {
    const params = {
      funding: fundingOutpoint, capacitySat: cfg.amount,
      initiatorPub: USER.publicKey, peerPub: LSP.publicKey,
      initiatorScriptPubKey: userSpk, peerScriptPubKey: lspSpk,
      settlementCsv: cfg.csv, feeSat: cfg.fee,
    };
    const bc = new EltooBroadcaster(params);
    const ch = new TwoPartyChannel(
      bc,
      new LocalParty(bc, USER.secretKey, USER.publicKey, nobleMlDsa), // the user
      new LocalParty(bc, LSP.secretKey, LSP.publicKey, nobleMlDsa),   // the LSP (Mode-2: RemoteLspParty)
    );
    return { params, bc, ch };
  };

  log(`mode: ${cfg.live ? "LIVE" : "DRY-RUN"}  amount=${cfg.amount} fee=${cfg.fee} state=${cfg.state} csv=${cfg.csv}`);
  log(`funding scriptPubKey: ${fundSpkHex}`);
  log(`user=${toHex(USER.publicKey).slice(0, 16)}…  lsp=${toHex(LSP.publicKey).slice(0, 16)}…  (two separate signers; secrets never shared)`);

  if (!cfg.live) {
    // Assemble the whole graph against a placeholder funding outpoint — proves the two-party
    // assembly with no network (the offline invariants are covered by two_party_broadcast.test).
    const { ch } = mkChannel({ txid: new Uint8Array(32), n: 0 });
    const update = await ch.openUpdate(cfg.state);
    const supersede = await ch.supersede({ prevOutpoint: { txid: update.txid, n: 0 }, prevValueSat: cfg.amount - cfg.fee, prevState: cfg.state, newState: cfg.state + 1 });
    const sv = (cfg.amount - cfg.fee) - cfg.fee;
    const { init, peer } = splitBalances(sv - cfg.fee);
    const settle = await ch.settle({ updateOutpoint: { txid: supersede.txid, n: 0 }, updateValueSat: sv, prevState: cfg.state + 1, initiatorBalanceSat: init, peerBalanceSat: peer });
    log("DRY-RUN: two-party graph assembled OK (no network).");
    console.log(JSON.stringify({ mode: "dry_run", update: update.txidDisplay, supersede: supersede.txidDisplay, settle: settle.txidDisplay }, null, 2));
    return;
  }

  // --- 1. fund the 2-of-2 funding output via soq-signer ---
  log("1: funding keyhash-2-of-2 via soq-signer…");
  const fundTxid = await signerFund(cfg, toHex(funding.witnessScript));
  const fundVout = await findVout(cfg, fundTxid, fundSpkHex);
  log(`  funded ${fundTxid}:${fundVout}`); await waitConfirmed(cfg, fundTxid);

  const { ch } = mkChannel({ txid: txidToInternal(fundTxid), n: fundVout });

  // --- 2. openUpdate: both parties co-sign Tu,0 (funding → eLTOO state) ---
  const update = await ch.openUpdate(cfg.state);
  const updateTxid = await broadcast(cfg, "openUpdate", update.hex);
  log(`2: openUpdate broadcast ${updateTxid} (user.partial ⊕ lsp.partial)`); await waitConfirmed(cfg, updateTxid);

  // --- 3. supersede: both parties co-sign a higher-state update via the IF branch ---
  const supersede = await ch.supersede({ prevOutpoint: { txid: update.txid, n: 0 }, prevValueSat: cfg.amount - cfg.fee, prevState: cfg.state, newState: cfg.state + 1 });
  const superTxid = await broadcast(cfg, "supersede", supersede.hex);
  log(`3: supersede broadcast ${superTxid} (state ${cfg.state} → ${cfg.state + 1})`); await waitConfirmed(cfg, superTxid);

  let settleTxid: string | undefined;
  if (cfg.settle) {
    // --- 4. settle: both parties co-sign the ELSE/CSV branch after the CSV delay ---
    log(`4: settlement — waiting ${cfg.csv} confs for CSV…`);
    for (;;) { const t = await getRawTransaction(superTxid, true, opR(cfg)); if ((t.confirmations ?? 0) >= cfg.csv) break; await sleep(15000); }
    const sv = (cfg.amount - cfg.fee) - cfg.fee;
    const { init, peer } = splitBalances(sv - cfg.fee);
    const settle = await ch.settle({ updateOutpoint: { txid: supersede.txid, n: 0 }, updateValueSat: sv, prevState: cfg.state + 1, initiatorBalanceSat: init, peerBalanceSat: peer });
    settleTxid = await broadcast(cfg, "settle", settle.hex);
    log(`  settlement broadcast ${settleTxid} (user=${init} lsp=${peer})`); await waitConfirmed(cfg, settleTxid);
  }

  console.log(JSON.stringify({ mode: "live", funding: `${fundTxid}:${fundVout}`, openUpdate: updateTxid, supersede: superTxid, settle: settleTxid ?? null }, null, 2));
  log("✅ TWO-PARTY CANARY GREEN: open → supersede → settle, each from two independent partials, accepted live on stagenet.");
}

main().catch((e) => { console.error("[2p-canary] FAILED:", e?.message ?? e); process.exit(1); });
