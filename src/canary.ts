// soq-lightning-sdk — stagenet canary
//
// Proves the DoD demo flow end-to-end against the LIVE LSP: open → pay → close, plus
// stale-replay rejection. Discovers the contract at runtime (max_channel_sat, faucet
// availability) so it works against BOTH the deployed echo_mode demo binary AND the
// accept-and-store binary. Asserts only invariants true in both: funds conserved,
// state monotonically advances, stale replay rejected, close → channel closed.
//
// Run:   LSP_URL=https://<lsp> NODE_TLS_REJECT_UNAUTHORIZED=0 node dist/canary.js
//        LSP_URL=... node dist/canary.js --loop 300     (every 300s, for alerting)
//
// NOTE: the stagenet LSP uses a self-signed cert — set NODE_TLS_REJECT_UNAUTHORIZED=0
// (or pin the cert) or fetch will reject the TLS handshake.

import { SoqLightning } from "./sdk.js";
import { LspClient, LspError } from "./client.js";

interface StepResult { name: string; ok: boolean; detail: string; ms: number }

async function runOnce(baseUrl: string): Promise<{ ok: boolean; steps: StepResult[]; warns: string[]; infos: string[] }> {
  const steps: StepResult[] = [];
  const warns: string[] = [];
  const infos: string[] = [];
  const step = async (name: string, fn: () => Promise<string>) => {
    const t0 = Date.now();
    try { const detail = await fn(); steps.push({ name, ok: true, detail, ms: Date.now() - t0 }); }
    catch (e: any) { steps.push({ name, ok: false, detail: e?.message ?? String(e), ms: Date.now() - t0 }); throw e; }
  };

  const ln = new SoqLightning({ baseUrl });
  const client = new LspClient({ baseUrl });
  const tag = Math.floor(Date.now() / 1000).toString(16);
  const pub = "ab".repeat(1312);  // peer stores opaquely; channel.ts will use a real ML-DSA pubkey
  // The faucet drips to a REAL on-chain address (the signer validates bech32m). Provide
  // one via CANARY_FAUCET_ADDR to exercise the faucet leg; otherwise the canary opens
  // directly and reports the faucet as "not exercised" (an INFO, not a defect).
  const faucetAddr = process.env.CANARY_FAUCET_ADDR;
  const faucetPub = process.env.CANARY_FAUCET_PUB ?? pub;
  let channelId = "";
  let capacity = 0;

  try {
    await step("info → discover max_channel_sat", async () => {
      const info: any = await client.info();
      capacity = Number(info.max_channel_sat) || 100_000_000;
      return `network=${info.network} max_channel_sat=${capacity} echo_mode=${info.echo_mode}`;
    });

    await step("open channel", async () => {
      if (faucetAddr) {
        try {
          const ch = await ln.fundAndOpen({ pubKeyHex: faucetPub, address: faucetAddr, capacitySat: capacity, name: "canary" });
          channelId = ch.channel_id;
          return `via faucet (real addr): ${channelId.slice(0, 16)}`;
        } catch (e: any) {
          // A real address was provided but the faucet still failed ⇒ genuine defect.
          warns.push(`faucet FAILED with real address, used direct-open: ${e?.message ?? e}`);
        }
      } else {
        infos.push("faucet leg not exercised (set CANARY_FAUCET_ADDR=<real bech32m> to test the drip)");
      }
      const ch = await ln.openChannel({ pubKeyHex: pub, address: `soq1canary${tag}`, capacitySat: capacity, csvDelay: 144 });
      channelId = ch.channel_id;
      return `via openChannel: ${channelId.slice(0, 16)}`;
    });

    await step("initial state: open, (cap, 0), index 0", async () => {
      const ch = await client.getChannel(channelId);
      capacity = ch.capacity_sat; // trust server's (possibly clamped) capacity
      if (ch.state !== "open") throw new Error(`state=${ch.state}`);
      if (ch.initiator_balance_sat !== ch.capacity_sat) throw new Error("initiator != capacity");
      if (ch.peer_balance_sat !== 0) throw new Error("peer balance != 0");
      if (ch.state_index !== 0) throw new Error(`state_index ${ch.state_index} != 0`);
      return `cap=${capacity} state0`;
    });

    await step("pay → advances + conserves (peer-committed)", async () => {
      const after = await ln.pay(channelId, Math.floor(capacity / 5)); // pay 20% to peer
      return `state${after.state_index} init=${after.initiator_balance_sat} peer=${after.peer_balance_sat}`;
    });

    await step("stale replay rejected (monotonicity)", async () => {
      const cur = await client.getChannel(channelId);
      const r = await client.updateState(channelId, {
        state_index: 0, // <= current ⇒ must be rejected (eltoo: newer supersedes)
        initiator_balance_sat: capacity, peer_balance_sat: 0,
        update_tx_hex: "x", settlement_tx_hex: "x", ctv_hash: "x",
      });
      if (r.accepted) throw new Error(`stale index 0 accepted (current ${cur.state_index})`);
      return `rejected: ${r.reject_reason ?? ""}`;
    });

    await step("cooperative close → closed", async () => {
      await ln.close(channelId); // resilient to the dropped-response bug
      const ch = await client.getChannel(channelId).catch(() => null);
      const st = ch?.state ?? "unknown";
      if (st !== "closed" && st !== "closing") throw new Error(`post-close state=${st}`);
      return `state=${st}`;
    });

    return { ok: true, steps, warns, infos };
  } catch {
    return { ok: false, steps, warns, infos };
  }
}

function report(r: { ok: boolean; steps: StepResult[]; warns: string[]; infos: string[] }): void {
  for (const s of r.steps) console.log(`  ${s.ok ? "✓" : "✗"} ${s.name} (${s.ms}ms)  ${s.detail}`);
  for (const i of r.infos) console.log(`  ℹ ${i}`);
  for (const w of r.warns) console.log(`  ⚠ ${w}`);
  // PASS = economic flow green; a degraded subsystem (e.g. faucet) shows as WARN, not green-washed.
  // INFOs (e.g. faucet leg skipped) do NOT degrade — they're "not tested", not "broken".
  console.log(r.ok ? (r.warns.length ? "CANARY PASS (DEGRADED — see warnings)\n" : "CANARY PASS\n") : "CANARY FAIL\n");
}

async function main() {
  const baseUrl = process.env.LSP_URL;
  if (!baseUrl) { console.error("set LSP_URL to the stagenet LSP base URL"); process.exit(2); }
  const loopArg = process.argv.indexOf("--loop");

  if (loopArg === -1) {
    const r = await runOnce(baseUrl); report(r); process.exit(r.ok ? 0 : 1);
  }
  const intervalMs = (parseInt(process.argv[loopArg + 1] ?? "300", 10) || 300) * 1000;
  for (;;) {
    console.log(`[${new Date().toISOString()}] canary cycle`);
    report(await runOnce(baseUrl));
    await new Promise((res) => setTimeout(res, intervalMs));
  }
}

main();
