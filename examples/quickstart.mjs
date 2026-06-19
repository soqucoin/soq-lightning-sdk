// soq-lightning-sdk — quickstart demo
//
// The "60-second quantum-safe Lightning" walkthrough. Everything here is the SAME code
// path the in-browser playground runs: an ephemeral ML-DSA-44 wallet, a PQ-native invoice,
// signed and verified entirely client-side. No node, no LSP, no network required.
//
//   node examples/quickstart.mjs          # offline crypto demo (zero infra)
//   LSP_URL=https://<lsp> node examples/quickstart.mjs   # also runs the live channel flow
//
// ⚠️  Stagenet only. Keys generated here are EPHEMERAL and hold NO real value.

import { randomBytes, createHash } from "node:crypto";
import {
  mlDsaKeygen,
  nobleMlDsa,
  freshPreimage,
  signInvoice,
  verifyInvoice,
  encodeInvoice,
  decodeInvoice,
  shortInvoice,
  verifyAgainstShort,
  SoqLightning,
} from "../dist/index.js";

const rng = (n) => new Uint8Array(randomBytes(n));
const sha256 = (b) => new Uint8Array(createHash("sha256").update(b).digest());
const hex = (b) => Buffer.from(b).toString("hex");

console.log("=== soq-lightning-sdk quickstart (stagenet, ephemeral keys) ===\n");

// 1. Instant wallet — generate an ephemeral ML-DSA-44 (Dilithium) keypair, client-side.
const wallet = mlDsaKeygen();
const destination = sha256(wallet.publicKey); // node id = SHA256(payee pubkey)
console.log("1. Generated ephemeral ML-DSA-44 wallet (post-quantum, no ECDSA):");
console.log(`   public key : ${wallet.publicKey.length} bytes (${hex(wallet.publicKey).slice(0, 32)}…)`);
console.log(`   node id     : ${hex(destination)}\n`);

// 2. Receiver mints a PQ-native invoice — a fresh preimage per invoice (spec §3.6).
const { preimage, paymentHash } = freshPreimage(rng);
const invoice = signInvoice(
  {
    version: 1,
    amountSat: 250_000_000n, // 2.5 SOQ
    paymentHash,
    destination,
    timestamp: BigInt(Math.floor(Date.now() / 1000)),
    expiry: 3600,
    description: "quickstart coffee",
    metadata: new Uint8Array(),
  },
  wallet.secretKey,
  nobleMlDsa,
);
const encoded = encodeInvoice(invoice); // soq1ln1…
console.log("2. Signed a PQ-native invoice (ML-DSA-44, 2420-byte signature):");
console.log(`   ${encoded.slice(0, 64)}…\n`);

// 3. Payer verifies the invoice signature, entirely client-side.
const decoded = decodeInvoice(encoded);
const ok = verifyInvoice(decoded, wallet.publicKey, nobleMlDsa);
console.log(`3. Verified invoice signature client-side: ${ok ? "✅ valid" : "❌ INVALID"}\n`);
if (!ok) process.exit(1);

// 4. QR short-form safety (F-C6): a payer scanning a QR pays to the QR's hash+amount,
//    not to whatever a fetched blob claims. verifyAgainstShort binds the two.
const uri = shortInvoice("inv-demo-1", paymentHash, invoice.amountSat);
const bound = verifyAgainstShort(decoded, uri, wallet.publicKey, nobleMlDsa);
console.log(`4. QR short-form binds to the fetched invoice: ${bound ? "✅ bound" : "❌ mismatch"}\n`);

// 5. (Optional) live channel flow against a stagenet LSP, if LSP_URL is set.
if (process.env.LSP_URL) {
  console.log(`5. LSP_URL set — running live channel flow against ${process.env.LSP_URL} …`);
  const ln = new SoqLightning({ baseUrl: process.env.LSP_URL });
  const info = await ln.info();
  console.log(`   LSP: ${JSON.stringify(info)}`);
  const ch = await ln.fundAndOpen({
    pubKeyHex: hex(wallet.publicKey),
    address: process.env.SETTLEMENT_ADDR ?? hex(destination),
    capacitySat: 500_000_000,
  });
  console.log(`   opened channel ${ch.channel_id}`);
  await ln.pay(ch.channel_id, 100_000_000);
  console.log(`   paid 1 SOQ; channel: ${JSON.stringify(await ln.channel(ch.channel_id))}`);
  await ln.close(ch.channel_id);
  console.log("   cooperative close submitted ✅");
} else {
  console.log("5. (Set LSP_URL to also run the live open→pay→close channel flow.)");
}

console.log("\nDone. That entire crypto path runs in the browser too — that's the playground.");
