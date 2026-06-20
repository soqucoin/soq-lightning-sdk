// Live E2E for the TS on-chain port (src/onchain.ts) against the real stagenet gateway.
// Mirrors soq-signer/cmd/soq-gateway-e2e (the node-proven Go reference), but every byte
// here is produced by the BROWSER-RUNNABLE TS code: keygen → build → sign → broadcast.
//
//   1. noble ML-DSA-44 keygen → bech32m ssq1p address   (client-side)
//   2. POST /v1/faucet           → drip 50k SOQ
//   3. GET  /v1/address/{a}/utxos → wait for the drip
//   4. buildSignedSend (onchain.ts) → POST /v1/tx (testmempoolaccept + sendrawtransaction)
//
// Run: node examples/gateway-e2e.mjs   (after npm run build)

import { onchain } from "../dist/index.js";

const GW = "https://gateway.soqu.org";
const HRP = "ssq";
const SHOR = 100_000_000n; // 1 SOQ = 1e8 shors
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

async function jget(path) {
  const res = await fetch(GW + path);
  const text = await res.text();
  let body; try { body = JSON.parse(text); } catch { body = text; }
  return { status: res.status, body };
}
async function jpost(path, obj) {
  const res = await fetch(GW + path, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(obj),
  });
  const text = await res.text();
  let body; try { body = JSON.parse(text); } catch { body = text; }
  return { status: res.status, body };
}

async function main() {
  // 1. client-side keygen + address
  const { publicKey, secretKey } = onchain.mlDsaKeygen();
  const sender = onchain.deriveAddress(publicKey, HRP);
  const recip = onchain.deriveAddress(onchain.mlDsaKeygen().publicKey, HRP); // fresh dest
  console.log(`[1] noble keygen → sender=${sender}`);
  console.log(`    pub=${publicKey.length}B sec=${secretKey.length}B`);

  // 2. faucet drip
  const drip = await jpost("/v1/faucet", { address: sender });
  console.log(`[2] POST /v1/faucet → ${drip.status} ${JSON.stringify(drip.body)}`);
  if (drip.status !== 200) throw new Error("faucet drip failed");

  // 3. wait for the drip UTXO (ElectrumX returns mempool + confirmed)
  let utxo = null;
  for (let i = 0; i < 36; i++) { // up to ~6 min
    const r = await jget(`/v1/address/${sender}/utxos`);
    if (r.status === 200 && Array.isArray(r.body) && r.body.length > 0) {
      utxo = r.body[0];
      console.log(`[3] drip UTXO seen after ${i * 10}s: ${utxo.tx_hash}:${utxo.tx_pos} value=${utxo.value} shors height=${utxo.height}`);
      break;
    }
    await sleep(10_000);
  }
  if (!utxo) throw new Error("drip UTXO never appeared");

  // 4. feerate
  const fr = await jget("/v1/feerate");
  const feeRate = BigInt(fr.body.feerate_shors_vb ?? 10);
  console.log(`[4] feerate = ${feeRate} shors/vB`);

  // 5. build + sign CLIENT-SIDE with the TS port
  const amount = 1000n * SHOR; // send 1000 SOQ, change back to sender
  const { rawTxHex, txid } = onchain.buildSignedSend({
    hrp: HRP,
    utxos: [{ txid: utxo.tx_hash, vout: utxo.tx_pos, value: BigInt(utxo.value), address: sender }],
    recipientAddress: recip,
    amount,
    changeAddress: sender,
    feeRate,
    senderPubkey: publicKey,
    senderSecret: secretKey,
  });
  console.log(`[5] TS-built signed tx: txid=${txid} (${rawTxHex.length / 2} bytes)`);

  // 6. broadcast → testmempoolaccept + sendrawtransaction
  const bc = await jpost("/v1/tx", { rawtx: rawTxHex });
  console.log(`[6] POST /v1/tx → ${bc.status} ${JSON.stringify(bc.body)}`);
  if (bc.status === 200) {
    console.log(`\n✅ TS E2E PASS — live node ACCEPTED the browser-built ML-DSA tx.`);
    console.log(`   node txid=${bc.body.txid}  local txid=${txid}  match=${bc.body.txid === txid}`);
  } else {
    console.log(`\n❌ node REJECTED: ${JSON.stringify(bc.body)}`);
    process.exitCode = 1;
  }
}

main().catch((e) => { console.error("E2E error:", e); process.exitCode = 1; });
