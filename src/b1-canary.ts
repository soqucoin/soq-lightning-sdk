// soq-lightning-sdk — B1 stagenet canary (the FIRST thing run on the fresh chain post-reset).
//
// Proves the B1 control-flow restore is LIVE end-to-end on the deployed stagenet node:
//   0. activation — getdeploymentinfo shows v6_controlflow active
//   1. fund       — soq-signer funds a keyhash-2-of-2 v6 output
//   2. update     — spend funding (APO 0x42) -> a B1 eLTOO output (IF/CLTV ratchet, state S)
//   3. ratchet-   — spend U via the IF branch BELOW the state floor -> node REJECTS (OP_CLTV enforces)
//   4. ratchet+   — spend U via the IF branch AT the state floor    -> node ACCEPTS (supersession)
//   (optional --settle: spend a B1 output via the ELSE/CSV branch after `csv` confs)
//
// This is the on-chain proof the local in-process harness could not give (that harness segfaults;
// see soqucoin-build-jgg). Every byte is node-pinned (b1_script_vectors) and ML-DSA interop is
// closed, so this is assembly, not new crypto.
//
// SAFETY: defaults to --dry-run (prints the graph, no network). --live funds + broadcasts.
// Credentials from the ENVIRONMENT only:
//   SOQ_SIGNER_URL, SOQ_SIGNER_TOKEN          (soq-signer faucet; token operator-only)
//   SOQ_RPC_URL, SOQ_RPC_USER, SOQ_RPC_PASS   (soqucoind JSON-RPC)
// Run:  source .env && node dist/b1-canary.js --live --amount=1000000000 --fee=10000000 --state=100 --csv=6
import {
  keyhashFunding2of2, signKeyhashFunding2of2, signForKeyhash,
  eltooUpdateScriptV6, eltooUpdateBranchWitness, eltooSettlementBranchWitness,
  p2wshV6, dilithiumWitnessPubKey,
  serializeTxWithWitness, txid, toHex, fromHex,
  SIGHASH_ANYPREVOUTANYSCRIPT, type Tx,
} from "./channel.js";
import { broadcastRawTx, getRawTransaction, nodeRpc } from "./noderpc.js";
import { nobleMlDsa, mlDsaKeygen } from "./mldsa.js";

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
    state: Number(get("state") ?? "100"),     // B1 update-branch CLTV floor = state+1
    csv: Number(get("csv") ?? "6"),           // settlement-branch relative timelock
    live: flag("live"), settle: flag("settle"),
    confs: Number(get("confs") ?? "1"),
    timeoutMs: Number(get("timeout-ms") ?? "1200000"),
  };
}

const log = (...a: unknown[]) => console.error("[b1-canary]", ...a);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const opR = (cfg: Cfg) => ({ url: cfg.rpcUrl, user: cfg.rpcUser, pass: cfg.rpcPass });
const txidToOutpoint = (display: string) => fromHex(display).reverse();
const displayTxid = (tx: Tx) => toHex(txid(tx).slice().reverse());

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
/** testmempoolaccept a raw tx — returns { allowed, reason }. Used to assert the ratchet rejection. */
async function mempoolAccept(cfg: Cfg, rawHex: string): Promise<{ allowed: boolean; reason: string }> {
  const r = await nodeRpc("testmempoolaccept", [[rawHex]], opR(cfg));
  const e = Array.isArray(r) ? r[0] : r;
  return { allowed: !!e?.allowed, reason: e?.["reject-reason"] ?? e?.reject_reason ?? "" };
}

async function main() {
  const cfg = parseArgs(process.argv.slice(2));
  if (cfg.amount <= cfg.fee * 3n) throw new Error("amount must exceed 3× fee");

  const A = mlDsaKeygen(), B = mlDsaKeygen();
  const funding = keyhashFunding2of2(A.publicKey, B.publicKey);
  const fundSpkHex = toHex(funding.scriptPubKey);
  const b1 = eltooUpdateScriptV6(cfg.state, A.publicKey, B.publicKey, { settlementCsv: cfg.csv });
  const b1Spk = p2wshV6(b1);
  const floor = cfg.state + 1;
  const trailing = dilithiumWitnessPubKey(A.publicKey);

  log(`mode: ${cfg.live ? "LIVE" : "DRY-RUN"}  amount=${cfg.amount} fee/spend=${cfg.fee} state=${cfg.state} (CLTV floor ${floor}) csv=${cfg.csv}`);
  log(`funding scriptPubKey : ${fundSpkHex}`);
  log(`B1 eLTOO script      : ${toHex(b1)}`);
  log(`B1 output spk        : ${toHex(b1Spk)}`);
  log(`A.sk=${toHex(A.secretKey).slice(0, 24)}…  B.sk=${toHex(B.secretKey).slice(0, 24)}…  (recoverable; valueless stagenet)`);

  // Build an IF-branch (supersede) spend of `prev:0` at a given nLockTime; output re-commits B1.
  const buildIfSpend = (prevTxidDisplay: string, prevValue: bigint, lockTime: number): { hex: string; txidDisplay: string } => {
    const t: Tx = {
      version: 2, locktime: lockTime,
      vin: [{ prevout: { txid: txidToOutpoint(prevTxidDisplay), n: 0 }, sequence: 0xfffffffe }], // non-final for CLTV
      vout: [{ value: prevValue - cfg.fee, scriptPubKey: b1Spk }],
    };
    const sigA = signForKeyhash(b1, t, 0, SIGHASH_ANYPREVOUTANYSCRIPT, prevValue, A.secretKey, nobleMlDsa);
    const sigB = signForKeyhash(b1, t, 0, SIGHASH_ANYPREVOUTANYSCRIPT, prevValue, B.secretKey, nobleMlDsa);
    const wit = eltooUpdateBranchWitness(b1, sigA, A.publicKey, sigB, B.publicKey, trailing);
    return { hex: toHex(serializeTxWithWitness(t, [wit])), txidDisplay: displayTxid(t) };
  };

  if (!cfg.live) {
    // Pre-build the graph against a placeholder funding outpoint so dry-run still validates assembly.
    const fakeFund = "00".repeat(32);
    const u: Tx = {
      version: 2, locktime: 0,
      vin: [{ prevout: { txid: txidToOutpoint(fakeFund), n: 0 }, sequence: 0xffffffff }],
      vout: [{ value: cfg.amount - cfg.fee, scriptPubKey: b1Spk }],
    };
    signKeyhashFunding2of2(funding, u, 0, cfg.amount, SIGHASH_ANYPREVOUTANYSCRIPT, A.secretKey, A.publicKey, B.secretKey, B.publicKey, nobleMlDsa);
    const lo = buildIfSpend(displayTxid(u), cfg.amount - cfg.fee, floor - 50);
    const hi = buildIfSpend(displayTxid(u), cfg.amount - cfg.fee, floor);
    log("DRY-RUN: graph assembled OK (no network). lo/hi IF-branch spends built + signed.");
    console.log(JSON.stringify({ mode: "dry_run", b1Script: toHex(b1), b1Spk: toHex(b1Spk),
      uLow_txid: lo.txidDisplay, uHi_txid: hi.txidDisplay }, null, 2));
    return;
  }

  // --- 0. activation gate ---
  log("0: checking v6_controlflow is active…");
  const dep = await nodeRpc("getdeploymentinfo", [], opR(cfg)).catch(() => null);
  const active = dep?.deployments?.v6_controlflow?.active ?? dep?.deployments?.v6_controlflow?.bip9?.status === "active";
  log(`  v6_controlflow active = ${active}`);
  if (!active) throw new Error("v6_controlflow is NOT active — the reset did not deploy the B1 deployment");

  // --- 1. fund ---
  log("1: funding keyhash-2-of-2 via soq-signer…");
  const fundTxid = await signerFund(cfg, toHex(funding.witnessScript));
  const fundVout = await findVout(cfg, fundTxid, fundSpkHex);
  log(`  funded ${fundTxid}:${fundVout}`); await waitConfirmed(cfg, fundTxid);

  // --- 2. update: F -> B1 eLTOO output ---
  const U: Tx = {
    version: 2, locktime: 0,
    vin: [{ prevout: { txid: txidToOutpoint(fundTxid), n: fundVout }, sequence: 0xffffffff }],
    vout: [{ value: cfg.amount - cfg.fee, scriptPubKey: b1Spk }],
  };
  const uWit = signKeyhashFunding2of2(funding, U, 0, cfg.amount, SIGHASH_ANYPREVOUTANYSCRIPT, A.secretKey, A.publicKey, B.secretKey, B.publicKey, nobleMlDsa);
  const uTxid = await broadcastRawTx(toHex(serializeTxWithWitness(U, [uWit])), opR(cfg));
  log(`2: update broadcast ${uTxid}`); await waitConfirmed(cfg, uTxid);
  const uValue = cfg.amount - cfg.fee;

  // --- 3. ratchet NEGATIVE: IF branch below the floor must be REJECTED by OP_CLTV ---
  const lo = buildIfSpend(uTxid, uValue, floor - 50);
  const loRes = await mempoolAccept(cfg, lo.hex);
  if (loRes.allowed) throw new Error(`RATCHET BROKEN: a below-floor (state<${floor}) update was ACCEPTED — OP_CLTV not enforced`);
  log(`3: ratchet- below-floor update REJECTED ✓ (reason: ${loRes.reason}) — OP_CLTV enforces on-chain`);

  // --- 4. ratchet POSITIVE: IF branch at the floor supersedes ---
  const hi = buildIfSpend(uTxid, uValue, floor);
  const hiTxid = await broadcastRawTx(hi.hex, opR(cfg));
  log(`4: ratchet+ at-floor update broadcast ${hiTxid}`); await waitConfirmed(cfg, hiTxid);

  let settleTxid: string | undefined;
  if (cfg.settle) {
    // --- 5 (optional): settlement via the ELSE/CSV branch of the hi output ---
    log(`5: settlement — waiting ${cfg.csv} confs for CSV…`);
    for (;;) { const t = await getRawTransaction(hiTxid, true, opR(cfg)); if ((t.confirmations ?? 0) >= cfg.csv) break; await sleep(15000); }
    const S: Tx = {
      version: 2, locktime: 0,
      vin: [{ prevout: { txid: txidToOutpoint(hiTxid), n: 0 }, sequence: cfg.csv }], // BIP68 relative lock
      vout: [{ value: uValue - cfg.fee * 2n, scriptPubKey: funding.scriptPubKey }],
    };
    const sa = signForKeyhash(b1, S, 0, SIGHASH_ANYPREVOUTANYSCRIPT, uValue - cfg.fee, A.secretKey, nobleMlDsa);
    const sb = signForKeyhash(b1, S, 0, SIGHASH_ANYPREVOUTANYSCRIPT, uValue - cfg.fee, B.secretKey, nobleMlDsa);
    const sWit = eltooSettlementBranchWitness(b1, sa, A.publicKey, sb, B.publicKey, trailing);
    settleTxid = await broadcastRawTx(toHex(serializeTxWithWitness(S, [sWit])), opR(cfg));
    log(`  settlement broadcast ${settleTxid}`); await waitConfirmed(cfg, settleTxid);
  }

  console.log(JSON.stringify({ mode: "live", v6_controlflow: true,
    funding: `${fundTxid}:${fundVout}`, update: uTxid, ratchet_reject_reason: loRes.reason,
    supersede: hiTxid, settle: settleTxid ?? null }, null, 2));
  log("✅ B1 CANARY GREEN: ratchet enforces (below-floor rejected, at-floor superseded) live on stagenet.");
}

main().catch((e) => { console.error("[b1-canary] FAILED:", e?.message ?? e); process.exit(1); });
