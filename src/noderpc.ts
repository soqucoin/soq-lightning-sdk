// soq-lightning-sdk — minimal soqucoind JSON-RPC client (broadcast + query)
//
// The broadcast leg of the on-chain e2e (Track 1 §1b): take a serializeTxWithWitness()
// hex and relay it via `sendrawtransaction`, then confirm via getrawtransaction/gettxout.
//
// ⚠️ OPERATOR/TEST TOOLING, not a product API. Devs broadcast via their own node or a
// public relay — they do NOT get the operator's hot RPC credential. By design this reads
// credentials from the ENVIRONMENT (SOQ_RPC_URL / SOQ_RPC_USER / SOQ_RPC_PASS) and NEVER
// hardcodes them. Do not commit a populated .env. soqucoind RPC is JSON-RPC 1.0.

export interface NodeRpcOpts {
  url?: string;                  // default process.env.SOQ_RPC_URL
  user?: string;                 // default process.env.SOQ_RPC_USER
  pass?: string;                 // default process.env.SOQ_RPC_PASS
  fetchImpl?: typeof fetch;      // injectable for tests / non-browser
  id?: string;
}

function basicAuth(user: string, pass: string): string {
  // Node global Buffer (the SDK targets Node). base64("user:pass").
  return "Basic " + Buffer.from(`${user}:${pass}`).toString("base64");
}

/** One JSON-RPC 1.0 call. Resolves to `result`; throws on transport/RPC error.
 *  Never logs or returns the credential. */
export async function nodeRpc(method: string, params: unknown[], opts: NodeRpcOpts = {}): Promise<any> {
  const url = opts.url ?? process.env.SOQ_RPC_URL;
  const user = opts.user ?? process.env.SOQ_RPC_USER;
  const pass = opts.pass ?? process.env.SOQ_RPC_PASS;
  if (!url) throw new Error("node RPC url not set (pass opts.url or SOQ_RPC_URL)");

  const headers: Record<string, string> = { "content-type": "application/json" };
  if (user != null && pass != null) headers["authorization"] = basicAuth(user, pass);

  const f = opts.fetchImpl ?? fetch;
  const res = await f(url, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "1.0", id: opts.id ?? "soq-ln", method, params }),
  });

  const text = await res.text();
  let body: any;
  try {
    body = JSON.parse(text);
  } catch {
    // soqucoind returns an HTML/plain error body on auth failure etc. — surface status, not creds.
    throw new Error(`node RPC ${method}: non-JSON response (HTTP ${res.status})`);
  }
  if (body && body.error) {
    // body.error = { code, message } — Soqucoin/Bitcoin convention.
    throw new Error(`node RPC ${method} failed: ${body.error.message ?? JSON.stringify(body.error)} (code ${body.error.code ?? "?"})`);
  }
  return body.result;
}

/** Broadcast a fully-serialized (witness-included) raw tx hex. Returns the txid. */
export async function broadcastRawTx(rawTxHex: string, opts: NodeRpcOpts = {}): Promise<string> {
  if (!/^[0-9a-fA-F]+$/.test(rawTxHex) || rawTxHex.length % 2 !== 0)
    throw new Error("broadcastRawTx: rawTxHex must be even-length hex");
  return nodeRpc("sendrawtransaction", [rawTxHex], opts);
}

/** Fetch a transaction (verbose by default → decoded JSON with witness + scriptPubKey). */
export async function getRawTransaction(txid: string, verbose = true, opts: NodeRpcOpts = {}): Promise<any> {
  return nodeRpc("getrawtransaction", [txid, verbose], opts);
}

/** Query an unspent output (null once spent). Use to confirm a funding outpoint / mining. */
export async function getTxOut(txid: string, n: number, includeMempool = true, opts: NodeRpcOpts = {}): Promise<any> {
  return nodeRpc("gettxout", [txid, n, includeMempool], opts);
}
