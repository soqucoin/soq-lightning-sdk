// noderpc.ts — the broadcast leg (sendrawtransaction) with an INJECTED mock fetch.
// No network, no real credentials. Verifies: JSON-RPC shape, Basic auth header,
// txid return, RPC-error surfacing, non-JSON handling, hex validation, env defaults.
import { test } from "node:test";
import assert from "node:assert/strict";
import { broadcastRawTx, getTxOut, nodeRpc } from "../dist/index.js";

// A mock fetch that records the last request and returns a scripted body.
function mockFetch(scripted) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init, body: JSON.parse(init.body) });
    const r = scripted(calls[calls.length - 1]);
    return {
      status: r.status ?? 200,
      text: async () => (typeof r.body === "string" ? r.body : JSON.stringify(r.body)),
    };
  };
  return { fetchImpl, calls };
}

const VALID_HEX = "deadbeef";
const TXID = "a".repeat(64);

test("broadcastRawTx sends a JSON-RPC 1.0 sendrawtransaction and returns the txid", async () => {
  const m = mockFetch(() => ({ body: { result: TXID, error: null, id: "soq-ln" } }));
  const txid = await broadcastRawTx(VALID_HEX, {
    url: "http://node:38334", user: "u", pass: "p", fetchImpl: m.fetchImpl,
  });
  assert.equal(txid, TXID);
  const { body, init } = m.calls[0];
  assert.equal(body.method, "sendrawtransaction");
  assert.deepEqual(body.params, [VALID_HEX]);
  assert.equal(body.jsonrpc, "1.0");
  // Basic auth header present and correctly base64("u:p"); credential never logged elsewhere.
  assert.equal(init.headers["authorization"], "Basic " + Buffer.from("u:p").toString("base64"));
});

test("broadcastRawTx surfaces the node's RPC error (e.g. fee/policy reject)", async () => {
  const m = mockFetch(() => ({
    body: { result: null, error: { code: -26, message: "min relay fee not met" }, id: "soq-ln" },
  }));
  await assert.rejects(
    () => broadcastRawTx(VALID_HEX, { url: "http://node", fetchImpl: m.fetchImpl }),
    /min relay fee not met.*code -26/,
  );
});

test("non-JSON response (e.g. auth failure HTML) surfaces status, not creds", async () => {
  const m = mockFetch(() => ({ status: 401, body: "<html>Unauthorized</html>" }));
  await assert.rejects(
    () => broadcastRawTx(VALID_HEX, { url: "http://node", user: "u", pass: "secret", fetchImpl: m.fetchImpl }),
    (e) => /HTTP 401/.test(e.message) && !/secret/.test(e.message),
  );
});

test("broadcastRawTx rejects non-hex / odd-length input before any network call", async () => {
  const m = mockFetch(() => ({ body: { result: TXID } }));
  await assert.rejects(() => broadcastRawTx("xyz", { url: "http://node", fetchImpl: m.fetchImpl }), /even-length hex/);
  await assert.rejects(() => broadcastRawTx("abc", { url: "http://node", fetchImpl: m.fetchImpl }), /even-length hex/);
  assert.equal(m.calls.length, 0, "no request should be sent for invalid hex");
});

test("missing url throws (no silent default to a wrong endpoint)", async () => {
  const saved = process.env.SOQ_RPC_URL;
  delete process.env.SOQ_RPC_URL;
  try {
    await assert.rejects(() => nodeRpc("getblockcount", [], {}), /url not set/);
  } finally {
    if (saved !== undefined) process.env.SOQ_RPC_URL = saved;
  }
});

test("env vars supply defaults (SOQ_RPC_URL/USER/PASS)", async () => {
  const m = mockFetch(() => ({ body: { result: { value: 1.0 }, error: null } }));
  const saved = { ...process.env };
  process.env.SOQ_RPC_URL = "http://env-node";
  process.env.SOQ_RPC_USER = "envu";
  process.env.SOQ_RPC_PASS = "envp";
  try {
    await getTxOut(TXID, 0, true, { fetchImpl: m.fetchImpl });
    assert.equal(m.calls[0].url, "http://env-node");
    assert.equal(m.calls[0].init.headers["authorization"], "Basic " + Buffer.from("envu:envp").toString("base64"));
    assert.deepEqual(m.calls[0].body.params, [TXID, 0, true]);
  } finally {
    delete process.env.SOQ_RPC_URL; delete process.env.SOQ_RPC_USER; delete process.env.SOQ_RPC_PASS;
    Object.assign(process.env, saved);
  }
});
