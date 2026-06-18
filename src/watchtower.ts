// soq-lightning-sdk — watchtower client
//
// Grounded in soq-lightning-peer/internal/watchtower/api.go + tower.go (the deployed
// soq-lightning-tower, default port 8570). In eLTOO there is NO penalty/revocation: the
// defense against a counterparty broadcasting a STALE update is to broadcast the LATEST
// update, which SUPERSEDES it (higher CLTV in the IF-branch + 0x42 rebinding). The
// watchtower holds your latest (update_tx, settlement_tx) and does exactly that while
// you're offline.
//
// SAFETY ORDERING (spec §1.6 / §9, the line-213 theft window): after each new state i+1
// you MUST  persist(i+1) → arm watchtower(i+1) → THEN treat the update as locked. Arming
// AFTER you act on the new state is a theft window. SoqLightning.pay() enforces this when
// a watchtower is configured: it arms before returning, and throws if arming fails.

export interface TowerClientOpts {
  baseUrl: string;                 // e.g. https://<services-vps>:8570
  bearerToken?: string;            // required for register/unregister/channels
  fetchImpl?: typeof fetch;
}

// ---- request/response types (verbatim from watchtower/api.go + tower.go) ----
export interface RegisterChannelReq {     // RegisterRequest, api.go:53
  channel_id: string;
  funding_txid: string;
  funding_vout: number;
  state_index: number;
  update_tx_hex: string;                  // pre-signed update TX (supersedes stale)
  settlement_tx_hex: string;
  ctv_hash: string;
}
export interface RegisterResp { status: string; channel_id: string; state_index: number }
export interface UnregisterResp { status: string; channel_id: string }
export interface TowerStats {              // tower.go Stats(), :183
  watched_channels: number;
  total_checks: number;
  total_triggers: number;
  last_check: string;
  poll_interval: string;
  sla_blocks: number;
}
export interface WatchedChannel {          // tower.go WatchedChannel, :49
  channel_id: string;
  funding_txid: string;
  funding_vout: number;
  state_index: number;
  update_tx_hex: string;
  settlement_tx_hex: string;
  ctv_hash: string;
  registered_at: string;
  last_checked: string;
  triggered: boolean;                      // true if the tower had to intervene
  trigger_txid: string;                    // txid of the superseding broadcast
}
export interface TowerHealth { status: string; service: string; watched_channels: number }

export class TowerError extends Error {
  constructor(public status: number, message: string, public body?: unknown) {
    super(`tower ${status}: ${message}`);
  }
}

export class TowerClient {
  private base: string;
  private token?: string;
  private f: typeof fetch;
  constructor(opts: TowerClientOpts) {
    this.base = opts.baseUrl.replace(/\/$/, "");
    this.token = opts.bearerToken;
    this.f = opts.fetchImpl ?? fetch;
  }

  private async req<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = {};
    if (body) headers["content-type"] = "application/json";
    if (this.token) headers["authorization"] = `Bearer ${this.token}`;
    const res = await this.f(`${this.base}${path}`, {
      method, headers, body: body ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    let json: any;
    try { json = text ? JSON.parse(text) : undefined; } catch { json = undefined; }
    if (!res.ok) throw new TowerError(res.status, json?.error ?? text.trim(), json);
    if (json === undefined) throw new TowerError(res.status, `non-JSON body: ${text.slice(0, 80)}`, text);
    return json as T;
  }

  /** Arm the tower with state i+1. Call this on EVERY state update, before treating the
   *  payment as locked (idempotent on the tower side — newest state_index wins). */
  register(req: RegisterChannelReq) { return this.req<RegisterResp>("POST", "/api/v1/tower/register", req); }
  unregister(channelId: string) { return this.req<UnregisterResp>("POST", "/api/v1/tower/unregister", { channel_id: channelId }); }
  status() { return this.req<TowerStats>("GET", "/api/v1/tower/status"); }       // public
  channels() { return this.req<{ count: number; channels: WatchedChannel[] }>("GET", "/api/v1/tower/channels"); }
  health() { return this.req<TowerHealth>("GET", "/health"); }
}
