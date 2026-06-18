#!/usr/bin/env node
// soq-lightning-sdk — minimal CLI (B5). Thin wrapper over SoqLightning/LspClient.
//   LSP_URL=https://<lsp> soq-ln <command> [flags]
//
//   status                                          LSP health + info
//   open   --pub <hex> --addr <a> --cap <sat> [--name n] [--faucet]
//   pay    --channel <id> --amount <sat>
//   channel <id>                                    show one channel
//   channels                                        list channels
//   close  --channel <id>

import { SoqLightning, LspClient } from "./index.js";

function flags(argv: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--")) {
      const k = argv[i].slice(2);
      const v = argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[++i] : true;
      out[k] = v;
    }
  }
  return out;
}
const out = (o: unknown) => console.log(JSON.stringify(o, null, 2));
function die(msg: string): never { console.error(`error: ${msg}`); process.exit(1); }

async function main() {
  const baseUrl = process.env.LSP_URL;
  if (!baseUrl) die("set LSP_URL to the stagenet LSP base URL");
  const [cmd, ...rest] = process.argv.slice(2);
  const f = flags(rest);
  const ln = new SoqLightning({ baseUrl });
  const client = new LspClient({ baseUrl });

  switch (cmd) {
    case "status": {
      out({ health: await client.health(), info: await client.info() });
      break;
    }
    case "open": {
      const pub = f.pub as string, addr = f.addr as string, cap = Number(f.cap);
      if (!pub || !addr || !cap) die("open requires --pub <hex> --addr <a> --cap <sat>");
      const params = { pubKeyHex: pub, address: addr, capacitySat: cap, name: f.name as string | undefined };
      out(f.faucet ? await ln.fundAndOpen(params) : await ln.openChannel(params));
      break;
    }
    case "pay": {
      const id = f.channel as string, amt = Number(f.amount);
      if (!id || !amt) die("pay requires --channel <id> --amount <sat>");
      out(await ln.pay(id, amt));
      break;
    }
    case "channel": {
      const id = rest.find((a) => !a.startsWith("--"));
      if (!id) die("channel requires <id>");
      out(await ln.channel(id));
      break;
    }
    case "channels":
      out(await ln.channels());
      break;
    case "close": {
      const id = f.channel as string;
      if (!id) die("close requires --channel <id>");
      out(await ln.close(id));
      break;
    }
    default:
      die(`unknown command "${cmd ?? ""}". Try: status | open | pay | channel | channels | close`);
  }
}

main().catch((e) => die(e?.message ?? String(e)));
