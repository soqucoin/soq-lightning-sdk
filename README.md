# soq-lightning-sdk

**Quantum-safe Lightning for Soqucoin.** A TypeScript SDK for eLTOO payment channels secured by ML-DSA-44 (Dilithium). No ECDSA, no penalty/revocation, latest state wins.

> **Status: stagenet alpha (`v0.1.0-alpha`).** The happy path (open, pay, cooperative close) runs against the live LSP today. The unilateral dispute path (0x42-signed eLTOO update/settlement TXs) is landing in `channel.ts`. See the [Roadmap](#roadmap). Do not use for mainnet value.

---

## Why this is different

| | Bitcoin Lightning | soq-lightning |
|---|---|---|
| Channel sigs | ECDSA / Schnorr | **ML-DSA-44 (Dilithium)**, post-quantum |
| Update mechanism | penalty (LN-penalty) | **eLTOO** (ANYPREVOUTANYSCRIPT, no toxic state) |
| Multi-hop | PTLC / HTLC | **HTLC** (SHA-256 hashlocks, PQ-safe, no adaptor sigs) |
| Invoice | BOLT-11 | PQ-native bech32m (`soq1ln`), Dilithium-signed |

eLTOO means no revocation secrets and no justice transactions. The newest signed state always supersedes older ones via APO rebinding, so an old-state broadcast is simply overwritten, never punished. That removes Lightning's single nastiest footgun.

## Install

```bash
npm install soq-lightning-sdk
```

## Quickstart (stagenet)

```ts
import { SoqLightning } from "soq-lightning-sdk";

const ln = new SoqLightning({ baseUrl: process.env.LSP_URL! });

// Fund from the faucet + auto-open a channel with the LSP
const ch = await ln.fundAndOpen({
  pubKeyHex: myDilithiumPubKeyHex,   // ML-DSA-44 public key
  address:   mySettlementAddress,
  capacitySat: 5_0000_0000,          // 5 SOQ
});

await ln.pay(ch.channel_id, 1_0000_0000);   // send 1 SOQ to the peer
console.log(await ln.channel(ch.channel_id)); // balances shifted, state_index bumped

await ln.close(ch.channel_id);                // cooperative close, L1 settlement
```

## Invoices (PQ-native)

```ts
import { freshPreimage, signInvoice, encodeInvoice, verifyAgainstShort } from "soq-lightning-sdk";

// receiver: fresh preimage PER invoice (required, see spec §3.6)
const { preimage, paymentHash } = freshPreimage((n) => crypto.getRandomValues(new Uint8Array(n)));
const invoice = signInvoice({
  version: 1, amountSat: 250000000n, paymentHash, destination, timestamp, expiry: 3600,
  description: "coffee", metadata: new Uint8Array(),
}, mySecretKey, mlDsa);                         // mlDsa: inject your ML-DSA-44 binding
const encoded = encodeInvoice(invoice);         // soq1ln1...

// payer scanning a QR short-form: pay to the QR's hash/amount, not the fetched blob (F-C6)
const trusted = verifyAgainstShort(fetchedInvoice, scannedUri, payeePubKey, mlDsa);
```

`MlDsa` is an injected interface (`sign`/`verify`). Wire it to `@noble/post-quantum` or your native Dilithium binding. The SDK never holds a key-recovery path, and invoice authenticity is separate from payment safety (the HTLC locks to `paymentHash` regardless of what `destination` claims).

## Plugging in real eLTOO transactions

`SoqLightning.pay()` delegates TX construction to an `UpdateTxBuilder`. The default is a placeholder accepted by the accept-and-store LSP on the happy path. When `channel.ts` ships, inject the real 0x42-signer:

```ts
const ln = new SoqLightning({ baseUrl, txBuilder: dilithiumEltooBuilder });
```

The API does not change. Only the bytes on the wire become disputable.

## CLI

```bash
export LSP_URL=https://<stagenet-lsp>
npx soq-ln status                              # LSP health + info
npx soq-ln open --pub <hex> --addr <a> --cap 500000000
npx soq-ln pay  --channel <id> --amount 100000000
npx soq-ln channel <id>
npx soq-ln close --channel <id>
```

## Canary

A standing end-to-end check (faucet, pay, stale-reject, close) for alerting:

```bash
LSP_URL=https://<lsp> npm run canary            # single run, exit 0/1
LSP_URL=https://<lsp> node dist/canary.js --loop 300
```

## Develop

```bash
npm install
npm run build      # tsc -> dist/
npm test           # offline: invoice round-trip + mock-peer open/pay/close
```

The test suite runs fully offline (mock peer, stub ML-DSA), so contributors don't need stagenet access to iterate.

## Watchtower

eLTOO has no penalty or revocation. If a counterparty broadcasts a **stale** update, the defense is to broadcast the **latest** update, which supersedes it (higher CLTV plus 0x42 rebinding). The watchtower holds your latest update/settlement TXs and does this while you're offline.

> **Topology (decided, phased, BASE-style):** the production towers are firewalled internal-only and run by Soqucoin Labs, with dual-tower defense-in-depth (services-vps plus mining-vps, fan-out, any one supersedes). Developers don't run towers, the same way BASE devs don't run sequencers.
> - **Stagenet (now):** the LSP auto-arms both towers on every state update. The spoke verifies liveness via the LSP proxy with `ln.towerStatus()` / `ln.assertTowersHealthy()`. The `TowerClient` and `watchtower:` arming below are for operator / self-hosted use.
> - **Mainnet Phase 1:** signed tower receipts (the tower ML-DSA-signs `(channel_id, state_index, ctv_hash, ts)`) let the spoke *cryptographically* verify its state i+1 is armed.
> - **Mainnet Phase 2:** federated towers. The spoke arms N independent towers directly via the `watchtower:` interface (unchanged across all three phases).
>
> The formal proof holds for all phases: it proves that *if* armed, the spoke is safe. Stagenet's gap is operational (who arms), not protocol.

### Verifying tower coverage (stagenet spoke path)

```ts
const ln = new SoqLightning({ baseUrl: LSP_URL });
const s = await ln.towerStatus();           // { available, tower_count, towers: [{name, available, status}] }
await ln.assertTowersHealthy(2);            // throws unless >= 2 towers reachable (dual-tower)
```

```ts
import { TowerClient, SoqLightning, DilithiumEltooBuilder } from "soq-lightning-sdk";

const tower = new TowerClient({ baseUrl: TOWER_URL, bearerToken: TOWER_TOKEN });

const ln = new SoqLightning({
  baseUrl: LSP_URL,
  txBuilder: new DilithiumEltooBuilder({ /* funding, keys, mldsa ... */ }),
  watchtower: {
    client: tower,
    fundingFor: (channelId) => ({ funding_txid, funding_vout }),
  },
});

// pay() now ARMS the tower with state i+1 BEFORE it returns (spec §1.6 persist, arm, ack).
// If arming fails, pay() throws and the payment is not treated as locked. No silent theft window.
await ln.pay(channelId, 1_0000_0000);
```

You can also drive the tower directly: `tower.register(...)`, `tower.status()` (public), `tower.channels()`, `tower.unregister(id)`.

## Roadmap

- [x] **B2** PQ invoices (sign/verify/bech32m/F-C6 short form)
- [x] **B3** REST client (12 live LSP endpoints) plus the `SoqLightning` facade
- [x] Canary plus offline test suite
- [x] **B1** `channel.ts`: eLTOO update/settlement TX construction, SIGHASH_ANYPREVOUTANYSCRIPT (0x42), CTV templates, eLTOO/HTLC scripts. Plugs into `SoqLightning` via `txBuilder: new DilithiumEltooBuilder({...})`. The sighash and CTV serializers are proven byte-identical to the node (`SignatureHash`/`ComputeCTVHash`) via node-dumped vectors. See `test/vector.test.mjs`.
- [x] **Watchtower client** (`watchtower.ts`): register/unregister/status/channels against `soq-lightning-tower`. Wires into `SoqLightning` so `pay()` arms the tower with state i+1 before returning (spec §1.6 persist, arm, ack; a failed arm fails the payment).
- [x] **Multi-hop HTLC forwarding** (`htlc.ts`): §2.2 HTLC script (SHA-256 hashlock, absolute-CLTV timeout), backward-induction route construction (fees plus per-hop cltv deltas), §5.2 forwarding checks (fee / cltv-delta / invoice-binding, error codes), SUCCESS/TIMEOUT witnesses (plain `SIGHASH_ALL`). `sighashAll` and `htlcScript()` are node-proven byte-exact (`test/vector_sighashall.test.mjs`). This is the construction layer only; the deployed LSP has no `update_add_htlc`/`update_fulfill_htlc` wire yet, so live multi-hop is pending Go-side forwarding. Sphinx onion privacy is deferred per §5.5.
- [ ] Mainnet (package relay, fee bumping)

> Every serialization path the SDK produces is byte-proven against the node: APO 0x42, APO 0x41, CTV hash, SIGHASH_ALL, and `htlcScript()`. See `test/vector.test.mjs` and `test/vector_sighashall.test.mjs`. The only remaining mainnet gate on the SDK is an on-chain tx-graph end-to-end.

## Security model

Formally verified (Tamarin plus TLA+) for no-theft-from-payer, balance conservation under reorg, and watchtower liveness SLA. See `~/soqucoin-ops/lightning/` for the protocol spec and proofs. Stagenet only, not audited for mainnet value.

## License

MIT
