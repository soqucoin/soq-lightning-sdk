// Custodial invoice rail — SDK facade against a mock LSP mirroring
// rest_invoice.go semantics: hub-hop settlement, payee credit = capacity
// growth (credits are debit-backed, so capacity may exceed the open cap),
// exact-amount delta enforcement, idempotent double-pay rejection.
import { test } from "node:test";
import assert from "node:assert/strict";
import { SoqLightning } from "../dist/index.js";

const ID = "ab".repeat(32);

// mock peer with channels + the invoice rail
function mockPeer({ maxChannelSat = 100000000 } = {}) {
  const chans = new Map();
  const invoices = new Map();
  let seq = 0, invSeq = 0;
  const ok = (o) => new Response(JSON.stringify(o), { status: 200, headers: { "content-type": "application/json" } });
  const bad = (o, status = 400) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });
  return async (url, init) => {
    const path = new URL(url).pathname;
    const body = init?.body ? JSON.parse(init.body) : {};
    if (path === "/v1/faucet" && init?.method === "POST") {
      const id = `ch_${++seq}`;
      chans.set(id, { channel_id: id, initiator_pub_key_hex: body.pub_key_hex, peer_pub_key_hex: "peer",
        capacity_sat: body.amount_sat, initiator_balance_sat: body.amount_sat, peer_balance_sat: 0,
        state_index: 0, state: "open", csv_delay: 288, created_at_unix: 1718000000 });
      return ok({ success: true, txid: "tx", amount_sat: body.amount_sat, channel_id: id });
    }
    if (path === "/v1/invoices" && init?.method === "POST") {
      const ch = chans.get(body.channel_id);
      if (!ch) return bad({ error: `channel ${body.channel_id} not found` });
      if (!(body.amount_sat > 0)) return bad({ error: "amount must be positive" });
      if (body.amount_sat > maxChannelSat) return bad({ error: "amount exceeds max" });
      // NO capacity headroom check — credits are debit-backed (live bug 2026-07-03).
      const id = "cd".repeat(31) + String(++invSeq).padStart(2, "0");
      const inv = { invoice_id: id, uri: `soqln:${id}`, channel_id: body.channel_id,
        amount_sat: body.amount_sat, memo: body.memo ?? "", status: "pending",
        created_at: "2026-07-03T00:00:00Z", expires_at: "2026-07-03T01:00:00Z" };
      invoices.set(id, inv);
      return ok(inv);
    }
    const im = path.match(/^\/v1\/invoices\/([^/]+)(\/pay)?$/);
    if (im) {
      const inv = invoices.get(im[1]);
      if (!inv) return bad({ error: "invoice not found" }, 404);
      if (!im[2]) return ok(inv);
      if (inv.status !== "pending") return ok({ accepted: false, reject_reason: `invoice already ${inv.status}` });
      const payer = chans.get(body.channel_id);
      if (!payer) return ok({ accepted: false, reject_reason: "payer channel not found" });
      if (body.channel_id === inv.channel_id) return ok({ accepted: false, reject_reason: "cannot pay an invoice from its own channel" });
      if (body.peer_balance_sat - payer.peer_balance_sat !== inv.amount_sat ||
          body.initiator_balance_sat !== payer.initiator_balance_sat - inv.amount_sat)
        return ok({ accepted: false, reject_reason: "payment must move exactly the invoice amount" });
      payer.state_index = body.state_index;
      payer.initiator_balance_sat = body.initiator_balance_sat;
      payer.peer_balance_sat = body.peer_balance_sat;
      const payee = chans.get(inv.channel_id);
      payee.capacity_sat += inv.amount_sat;
      payee.initiator_balance_sat += inv.amount_sat;
      payee.state_index += 1;
      inv.status = "paid"; inv.paid_at = "2026-07-03T00:30:00Z"; inv.payer_channel_id = body.channel_id;
      return ok({ accepted: true, payee_credited: true, peer_signature_hex: "ab", invoice: inv });
    }
    const m = path.match(/^\/v1\/channels\/([^/]+)$/);
    if (m) {
      const ch = chans.get(m[1]);
      return ch ? ok(ch) : bad({ error: "not found" }, 404);
    }
    return new Response("{}", { status: 404 });
  };
}

async function twoChannels(ln, capA = 50000000, capB = 50000000) {
  const a = await ln.fundAndOpen({ pubKeyHex: "aa", address: "soq1a", capacitySat: capA });
  const b = await ln.fundAndOpen({ pubKeyHex: "bb", address: "soq1b", capacitySat: capB });
  return [a, b];
}

test("create → pay → payee credited via capacity growth", async () => {
  const ln = new SoqLightning({ baseUrl: "https://mock", fetchImpl: mockPeer() });
  const [payee, payer] = await twoChannels(ln);

  const inv = await ln.createInvoice(payee.channel_id, 25000000, { memo: "coffee" });
  assert.equal(inv.status, "pending");
  assert.ok(inv.uri.startsWith("soqln:"));

  const { channel, invoice } = await ln.payInvoice(inv.invoice_id, payer.channel_id);
  assert.equal(invoice.status, "paid");
  assert.equal(invoice.payer_channel_id, payer.channel_id);
  assert.equal(channel.initiator_balance_sat, 25000000); // payer debited

  const after = await ln.channel(payee.channel_id);
  assert.equal(after.capacity_sat, 75000000);            // capacity grew with the credit
  assert.equal(after.initiator_balance_sat, 75000000);
  assert.equal(after.initiator_balance_sat + after.peer_balance_sat, after.capacity_sat, "conservation");
});

test("a channel at the open cap can still receive — capacity grows past it", async () => {
  // Live bug 2026-07-03: at-cap channels could not receive at all.
  const ln = new SoqLightning({ baseUrl: "https://mock", fetchImpl: mockPeer() });
  const [payee, payer] = await twoChannels(ln, 100000000, 50000000); // payee AT the cap

  const inv = await ln.createInvoice(payee.channel_id, 10000000);
  await ln.payInvoice(inv.invoice_id, payer.channel_id);

  const after = await ln.channel(payee.channel_id);
  assert.equal(after.capacity_sat, 110000000); // past max_channel_sat
  assert.equal(after.initiator_balance_sat + after.peer_balance_sat, after.capacity_sat);
});

test("double-pay is refused locally (non-pending invoice)", async () => {
  const ln = new SoqLightning({ baseUrl: "https://mock", fetchImpl: mockPeer() });
  const [payee, payer] = await twoChannels(ln);
  const inv = await ln.createInvoice(payee.channel_id, 1000);
  await ln.payInvoice(inv.invoice_id, payer.channel_id);
  await assert.rejects(() => ln.payInvoice(inv.invoice_id, payer.channel_id), /invoice is paid/);
});

test("insufficient payer balance is refused before any network write", async () => {
  const ln = new SoqLightning({ baseUrl: "https://mock", fetchImpl: mockPeer() });
  const [payee, payer] = await twoChannels(ln, 50000000, 50000000);
  const inv = await ln.createInvoice(payee.channel_id, 60000000);
  await assert.rejects(() => ln.payInvoice(inv.invoice_id, payer.channel_id), /insufficient/);
});

test("awaitInvoicePaid resolves when the invoice settles", async () => {
  const ln = new SoqLightning({ baseUrl: "https://mock", fetchImpl: mockPeer() });
  const [payee, payer] = await twoChannels(ln);
  const inv = await ln.createInvoice(payee.channel_id, 1000);

  const waiter = ln.awaitInvoicePaid(inv.invoice_id, { intervalMs: 20 });
  await ln.payInvoice(inv.invoice_id, payer.channel_id);
  const settled = await waiter;
  assert.equal(settled.status, "paid");
});

test("parseInvoiceUri accepts v1 + host-prefixed forms, rejects junk", () => {
  assert.equal(SoqLightning.parseInvoiceUri(`soqln:${ID}`), ID);
  assert.equal(SoqLightning.parseInvoiceUri(` SOQLN:${ID} `), ID);
  assert.equal(SoqLightning.parseInvoiceUri(`soqln:lsp.soqu.org/${ID}`), ID);
  assert.equal(SoqLightning.parseInvoiceUri(`soqln:${"ab".repeat(31)}`), null); // short
  assert.equal(SoqLightning.parseInvoiceUri(`soqln:${"zz".repeat(32)}`), null); // non-hex
  assert.equal(SoqLightning.parseInvoiceUri(ID), null);                          // no scheme
  assert.equal(SoqLightning.parseInvoiceUri(`lightning:${ID}`), null);
});

test("createInvoice validates amount locally", async () => {
  const ln = new SoqLightning({ baseUrl: "https://mock", fetchImpl: mockPeer() });
  await assert.rejects(() => ln.createInvoice("ch_x", 0), /positive/);
  await assert.rejects(() => ln.createInvoice("ch_x", -5), /positive/);
});
