// soq-lightning-sdk — REST client for the LSP gateway
//
// Grounded in soq-lightning-peer/internal/server/rest.go (the 12 live endpoints on the
// Services VPS). Request shapes are taken verbatim from the Go structs; response fields
// marked (confirmed) are read from rest.go, others are (verify) against the live API.

export interface RestClientOpts {
  baseUrl: string;                 // e.g. https://lsp.soqu.org  (stagenet LSP, valid TLS)
  fetchImpl?: typeof fetch;        // injectable for tests / non-browser
}

// ---- request types (verbatim from rest.go) ----
export interface OpenChannelReq {
  initiator_pub_key_hex: string;
  capacity_sat: number;
  initiator_name: string;
  csv_delay: number;               // settlement_csv tier (spec §6.2.1: 288 transparent)
  initiator_address: string;
}
export interface UpdateStateReq {
  state_index: number;
  initiator_balance_sat: number;
  peer_balance_sat: number;
  update_tx_hex: string;           // client-built eLTOO update TX (0x42-signed — see channel.ts)
  settlement_tx_hex: string;
  ctv_hash: string;
}

// ---- request types ----
export interface FaucetReq {            // (confirmed) faucet.go:78-96
  address: string;
  amount_sat?: number;                  // default 500M, clamped [100M, 1B]
  open_channel?: boolean;               // default true
  pub_key_hex?: string;                 // required when open_channel
  name?: string;                        // default "faucet-user"
}

// ---- response types (confirmed against rest.go / faucet.go) ----
export interface OpenChannelResp {      // rest.go:161-176
  accepted: boolean;
  reject_reason?: string;
  peer_pub_key_hex?: string;
  channel_id?: string;
  peer_address?: string;
}
export interface FaucetResp {           // faucet.go:258-264
  success?: boolean;
  txid?: string;
  amount_sat?: number;
  amount_soq?: string;
  channel_id?: string;
  error?: string;
  retry_after?: string;
}
export interface Channel {              // channelToMap rest.go:304-317
  channel_id: string;
  initiator_pub_key_hex: string;
  peer_pub_key_hex: string;
  capacity_sat: number;
  initiator_balance_sat: number;
  peer_balance_sat: number;
  state_index: number;
  state: string;                        // "open" | "closing" | "closed" | ...
  csv_delay: number;
  created_at_unix: number;
}
export interface UpdateStateResp {      // rest.go updateState
  accepted: boolean;
  reject_reason?: string;
  peer_signature_hex?: string;          // 2421-byte LSP partial on the UPDATE (real ML-DSA once WS2b deployed)
  settlement_signature_hex?: string;    // F1: 2421-byte LSP partial on the SETTLEMENT — needed to close (spec §E)
  echo?: { state_index: number; initiator_balance_sat: number; peer_balance_sat: number };
}
export interface CloseResp {            // rest.go cooperativeClose
  accepted: boolean;
  reject_reason?: string;
  settlement_txid?: string;             // present when L1 settlement enqueued
}

// ---- watchtower status proxy (LSP exposes tower health to spokes; towers themselves
// are firewalled internal-only — see README topology note) ----
export interface TowerProxyEntry {     // one entry per armed tower (dual-tower fan-out)
  name: string;                        // e.g. "services-vps" | "mining-vps"
  available: boolean;
  error?: string;
  status?: {
    watched_channels: number;
    total_checks: number;
    total_triggers: number;            // >0 means the tower has had to supersede a stale state
    last_check: string;
    poll_interval: string;
    sla_blocks: number;
  };
}
export interface TowerProxyStatus {
  available: boolean;                  // at least one tower reachable
  tower_count: number;
  towers: TowerProxyEntry[];
}

export class LspClient {
  private base: string;
  private f: typeof fetch;
  constructor(opts: RestClientOpts) {
    this.base = opts.baseUrl.replace(/\/$/, "");
    this.f = opts.fetchImpl ?? fetch;
  }

  private async req<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.f(`${this.base}${path}`, {
      method,
      headers: body ? { "content-type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    let json: any;
    try { json = text ? JSON.parse(text) : undefined; }
    catch { json = undefined; } // some endpoints (e.g. 404) return plain text, not JSON
    if (!res.ok) throw new LspError(res.status, json?.error ?? json?.reject_reason ?? text.trim(), json);
    if (json === undefined) throw new LspError(res.status, `non-JSON body: ${text.slice(0, 80)}`, text);
    return json as T;
  }

  health() { return this.req<any>("GET", "/v1/health"); }
  info() { return this.req<any>("GET", "/v1/info"); }

  faucetStatus() { return this.req<any>("GET", "/v1/faucet"); }
  // POST /v1/faucet drips test SOQ AND (default) auto-opens a channel.
  faucetDrip(body: FaucetReq) { return this.req<FaucetResp>("POST", "/v1/faucet", body); }

  openChannel(req: OpenChannelReq) { return this.req<OpenChannelResp>("POST", "/v1/channels", req); }
  listChannels() { return this.req<{ channels: Channel[] }>("GET", "/v1/channels"); }
  getChannel(id: string) { return this.req<Channel>("GET", `/v1/channels/${id}`); }

  updateState(id: string, req: UpdateStateReq) {
    return this.req<UpdateStateResp>("POST", `/v1/channels/${id}/update`, req);
  }
  closeChannel(id: string) {
    return this.req<CloseResp>("POST", `/v1/channels/${id}/close`);
  }

  dashboard() { return this.req<any>("GET", "/v1/dashboard"); }
  channelHealth() { return this.req<any>("GET", "/v1/channels/health"); }
  // Watchtower health, proxied through the LSP (the towers are firewalled internal-only).
  towerStatus() { return this.req<TowerProxyStatus>("GET", "/v1/tower/status"); }
}

export class LspError extends Error {
  constructor(public status: number, message: string, public body?: unknown) {
    super(`LSP ${status}: ${message}`);
  }
}
