// soq-lightning-sdk — Track 1 §1b: full TS eLTOO lifecycle on stagenet.
//
// Proves the PRODUCT capability: the TypeScript SDK funds, signs, and broadcasts a real
// keyhash-2-of-2 channel on the deployed stagenet node — fund → update(0x42) → coop-close.
// Every byte the SDK emits is already node-pinned (sighash/script/witnessScript/envelope) and
// ML-DSA interop is green, so this is the assembly, not new crypto.
//
// SAFETY: defaults to --dry-run (no network). Pass --live to actually fund + broadcast (an
// outward, hard-to-reverse action). All credentials come from the ENVIRONMENT — never args,
// never a committed file:
//   SOQ_SIGNER_URL, SOQ_SIGNER_TOKEN      (soq-signer; token is operator-only)
//   SOQ_RPC_URL, SOQ_RPC_USER, SOQ_RPC_PASS  (soqucoind JSON-RPC, sendrawtransaction/query)
//
// Run:  source .env && node dist/stagenet-e2e.js --live --amount=1000000000 --fee=10000000
import {
  keyhashFunding2of2, signKeyhashFunding2of2,
  serializeTxWithWitness, txid, toHex, fromHex,
  SIGHASH_ANYPREVOUTANYSCRIPT, SIGHASH_ALL,
} from "./channel.js";
import { broadcastRawTx, getRawTransaction } from "./noderpc.js";
import { nobleMlDsa, mlDsaKeygen } from "./mldsa.js";

interface Cfg {
  signerUrl?: string; signerToken?: string;
  rpcUrl?: string; rpcUser?: string; rpcPass?: string;
  amount: bigint; fee: bigint; feeRate: number;
  live: boolean; confs: number; timeoutMs: number;
}

function parseArgs(argv: string[]): Cfg {
  const get = (k: string) => { const a = argv.find((x) => x.startsWith(`--${k}=`)); return a ? a.split("=").slice(1).join("=") : undefined; };
  const flag = (k: string) => argv.includes(`--${k}`);
  return {
    signerUrl: process.env.SOQ_SIGNER_URL,
    signerToken: process.env.SOQ_SIGNER_TOKEN,
    rpcUrl: process.env.SOQ_RPC_URL,
    rpcUser: process.env.SOQ_RPC_USER,
    rpcPass: process.env.SOQ_RPC_PASS,
    amount: BigInt(get("amount") ?? "1000000000"),   // 10 SOQ default
    fee: BigInt(get("fee") ?? "10000000"),            // 0.1 SOQ per spend (generous; covers ~2.4 KvB witness)
    feeRate: Number(get("fee-rate") ?? "10000"),      // soq-signer fee_rate for the funding tx
    live: flag("live"),
    confs: Number(get("confs") ?? "1"),
    timeoutMs: Number(get("timeout-ms") ?? "600000"),
  };
}

const log = (...a: unknown[]) => console.error("[1b]", ...a);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const opR = (cfg: Cfg) => ({ url: cfg.rpcUrl, user: cfg.rpcUser, pass: cfg.rpcPass });

/** Fund a v6 witnessScript via soq-signer. Returns the funding txid (display/big-endian). */
async function signerFund(cfg: Cfg, witnessScriptHex: string): Promise<string> {
  if (!cfg.signerUrl) throw new Error("SOQ_SIGNER_URL not set");
  const res = await fetch(`${cfg.signerUrl}/api/v1/send-to-witness-script`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(cfg.signerToken ? { authorization: `Bearer ${cfg.signerToken}` } : {}),
    },
    body: JSON.stringify({ witness_script: witnessScriptHex, amount: Number(cfg.amount), fee_rate: cfg.feeRate }),
  });
  const text = await res.text();
  let body: any;
  try { body = JSON.parse(text); } catch { throw new Error(`signer non-JSON (HTTP ${res.status})`); }
  if (body.error) throw new Error(`signer error: ${JSON.stringify(body.error)}`);
  if (!body.txid) throw new Error(`signer response missing txid (HTTP ${res.status})`);
  return body.txid as string;
}

/** Find the vout index whose scriptPubKey hex matches `targetSpkHex`. */
async function findVout(cfg: Cfg, txidDisplay: string, targetSpkHex: string): Promise<number> {
  const tx = await getRawTransaction(txidDisplay, true, opR(cfg));
  for (const v of tx.vout ?? []) if (v.scriptPubKey?.hex === targetSpkHex) return v.n;
  throw new Error(`no vout of ${txidDisplay} matches scriptPubKey ${targetSpkHex.slice(0, 16)}…`);
}

/** Poll until a tx has >= confs confirmations (or timeout). */
async function waitConfirmed(cfg: Cfg, txidDisplay: string): Promise<void> {
  const deadline = Date.now() + cfg.timeoutMs;
  while (Date.now() < deadline) {
    try {
      const tx = await getRawTransaction(txidDisplay, true, opR(cfg));
      if ((tx.confirmations ?? 0) >= cfg.confs) return;
    } catch { /* not yet in a queryable state */ }
    log(`  waiting for ${txidDisplay.slice(0, 12)}… (>=${cfg.confs} conf)`);
    await sleep(15000);
  }
  throw new Error(`timeout waiting for ${txidDisplay} to confirm`);
}

// internal byte order for an OutPoint.txid = the RPC display txid reversed.
const txidToOutpoint = (display: string) => fromHex(display).reverse();
const displayTxid = (tx: any) => toHex(txid(tx).slice().reverse());

async function main() {
  const cfg = parseArgs(process.argv.slice(2));
  if (cfg.amount <= cfg.fee * 2n) throw new Error("amount must exceed 2× fee (one fee per spend)");

  // Two ephemeral ML-DSA parties (the runner holds both — single-operator e2e).
  const A = mlDsaKeygen();
  const B = mlDsaKeygen();
  const funding = keyhashFunding2of2(A.publicKey, B.publicKey);
  const spkHex = toHex(funding.scriptPubKey);

  log(`mode: ${cfg.live ? "LIVE" : "DRY-RUN"}  amount=${cfg.amount} fee/spend=${cfg.fee}`);
  log(`funding witnessScript: ${toHex(funding.witnessScript)}`);
  log(`funding scriptPubKey : ${spkHex}`);
  // Keys printed so a half-completed LIVE run is recoverable (valueless stagenet).
  log(`A.sk=${toHex(A.secretKey).slice(0, 24)}…  B.sk=${toHex(B.secretKey).slice(0, 24)}…`);

  if (!cfg.live) {
    log("DRY-RUN: stopping before any network call. Re-run with --live (and a sourced .env) to fund+broadcast.");
    console.log(JSON.stringify({ mode: "dry_run", witnessScript: toHex(funding.witnessScript), scriptPubKey: spkHex }));
    return;
  }

  // --- Step 1: fund the v6 keyhash-2-of-2 output via soq-signer ---
  log("step 1: funding via soq-signer…");
  const fundTxid = await signerFund(cfg, toHex(funding.witnessScript));
  const fundVout = await findVout(cfg, fundTxid, spkHex);
  log(`  funded: ${fundTxid}:${fundVout}`);
  await waitConfirmed(cfg, fundTxid);

  // --- Step 2: build + sign the WHOLE spend graph BEFORE broadcasting (pre-flight) ---
  const U = {
    version: 2, locktime: 0,
    vin: [{ prevout: { txid: txidToOutpoint(fundTxid), n: fundVout }, sequence: 0xffffffff }],
    // update output re-commits the same 2-of-2 (re-closable), value = funded − fee
    vout: [{ value: cfg.amount - cfg.fee, scriptPubKey: funding.scriptPubKey, visibility: 0, assetType: 0 }],
  };
  // U spends F:0 with APO 0x42 (sighash amount = F:0 value = cfg.amount)
  const uWit = signKeyhashFunding2of2(funding, U, 0, cfg.amount, SIGHASH_ANYPREVOUTANYSCRIPT,
    A.secretKey, A.publicKey, B.secretKey, B.publicKey, nobleMlDsa);
  const uHex = toHex(serializeTxWithWitness(U, [uWit]));
  const uTxidDisplay = displayTxid(U);

  // coop-close spends U:0 with SIGHASH_ALL (sighash amount = U:0 value).
  // Settle to the v6 channel scriptPubKey (a standard, relay-accepted output).
  // A bare OP_TRUE output is TX_NONSTANDARD and rejected under fRequireStandard
  // (stagenet/mainnet) — it only relays on regtest.
  const u0Value = cfg.amount - cfg.fee;
  const C = {
    version: 2, locktime: 0,
    vin: [{ prevout: { txid: txid(U), n: 0 }, sequence: 0xffffffff }],
    vout: [{ value: u0Value - cfg.fee, scriptPubKey: funding.scriptPubKey }],
  };
  const cWit = signKeyhashFunding2of2(funding, C, 0, u0Value, SIGHASH_ALL,
    A.secretKey, A.publicKey, B.secretKey, B.publicKey, nobleMlDsa);
  const cHex = toHex(serializeTxWithWitness(C, [cWit]));
  const cTxidDisplay = displayTxid(C);
  log(`pre-flight signed: U=${uTxidDisplay} close=${cTxidDisplay}`);

  // --- Step 3: broadcast U, confirm, then coop-close ---
  log("step 3: broadcasting U (update, 0x42)…");
  const uBroadcast = await broadcastRawTx(uHex, opR(cfg));
  if (uBroadcast !== uTxidDisplay) log(`  ⚠ node txid ${uBroadcast} != computed ${uTxidDisplay}`);
  await waitConfirmed(cfg, uBroadcast);
  log(`  U mined: ${uBroadcast}`);

  log("step 4: broadcasting cooperative close (0x01)…");
  const cBroadcast = await broadcastRawTx(cHex, opR(cfg));
  await waitConfirmed(cfg, cBroadcast);
  log(`  close mined: ${cBroadcast}`);

  console.log(JSON.stringify({
    mode: "live", funding: `${fundTxid}:${fundVout}`, update: uBroadcast, close: cBroadcast,
  }, null, 2));
  log("✅ 1b: full eLTOO lifecycle confirmed on-chain via the TypeScript SDK.");
}

main().catch((e) => { console.error("[1b] FAILED:", e?.message ?? e); process.exit(1); });
