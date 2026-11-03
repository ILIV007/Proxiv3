import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeProxy, buildPool } from "../src/pool.js";
import { handleUpdate, menuText, cardText } from "../src/bot.js";

class FakeKV {
  constructor() { this.m = new Map(); }
  async get(k) { return this.m.get(k) ?? null; }
  async put(k, v) { this.m.set(k, String(v)); }
}

const calls = [];
globalThis.fetch = async (url, opts) => {
  calls.push({ url: String(url), body: JSON.parse(opts.body) });
  return { ok: true, status: 200, json: async () => ({ ok: true, result: { message_id: 1 } }) };
};

function makeEnv() {
  const kv = new FakeKV();
  const rows = [0, 1, 2].map((i) =>
    normalizeProxy({
      server: `10.0.0.${i}`, port: 443, secret: "dd" + "a".repeat(32), type: "secure",
      ip: `10.0.0.${i}`, country: "NL", asn_org: "Test", rtt_ms: 50, uptime: 0.99, checks: 40,
    }, "ours"));
  const pool = buildPool(rows, { updatedUnix: Math.floor(Date.now() / 1000) });
  kv.m.set("pool", JSON.stringify(pool));
  return { POOL: kv, BOT_TOKEN: "test", ADMIN_IDS: "42", PROVIDER_RADIKAL_ENABLED: "false" };
}

const msg = (text, uid = 7) => ({ update_id: 1, message: { message_id: 1, chat: { id: 100 }, from: { id: uid }, text } });
const cbq = (data, uid = 7) => ({
  update_id: 2,
  callback_query: { id: "q1", from: { id: uid }, message: { message_id: 5, chat: { id: 100 } }, data },
});

test("menu and card render in English with pool stats", () => {
  const pool = buildPool([normalizeProxy({
    server: "1.1.1.1", port: 443, secret: "dd" + "a".repeat(32), type: "secure",
    ip: "1.1.1.1", country: "IR", rtt_ms: 30, uptime: 1, checks: 9,
  }, "ours")]);
  assert.match(menuText(pool), /Proxiv3/);
  assert.match(menuText(pool), /1<\/b> servers/);
  assert.match(cardText(pool.proxies[Object.keys(pool.proxies)[0]]), /Server: <code>1\.1\.1\.1<\/code>/);
});

test("/start sends the main menu", async () => {
  calls.length = 0;
  await handleUpdate(makeEnv(), msg("/start"));
  const send = calls.find((c) => c.url.endsWith("/sendMessage"));
  assert.ok(send);
  assert.ok(send.body.reply_markup.inline_keyboard.length >= 3);
});

test("tier callback serves a minimal proxy card: connect + next, no votes", async () => {
  calls.length = 0;
  await handleUpdate(makeEnv(), cbq("t:stable"));
  const card = calls.filter((c) => c.url.endsWith("/sendMessage")).at(-1);
  assert.ok(card);
  assert.match(card.body.text, /Server: <code>/);
  assert.match(card.body.text, /Secret: <code>/);
  assert.doesNotMatch(card.body.text, /uptime|feedback|Operator/i);
  const flat = card.body.reply_markup.inline_keyboard.flat();
  assert.ok(flat.some((b) => b.url?.startsWith("https://t.me/proxy")));
  assert.ok(flat.some((b) => b.callback_data?.startsWith("n:")));
  assert.ok(!flat.some((b) => b.callback_data?.startsWith("v:")));
});

test("empty pool: /start still answers with the syncing menu", async () => {
  calls.length = 0;
  const env = { POOL: new FakeKV(), BOT_TOKEN: "test", ADMIN_IDS: "" };
  await handleUpdate(env, msg("/start"));
  const send = calls.find((c) => c.url.endsWith("/sendMessage"));
  assert.match(send.body.text, /still syncing/);
});

test("/admin is owner-only and shows the dependency metric", async () => {
  calls.length = 0;
  await handleUpdate(makeEnv(), msg("/admin", 7)); // not admin -> silence
  assert.equal(calls.filter((c) => c.url.endsWith("/sendMessage")).length, 0);
  await handleUpdate(makeEnv(), msg("/admin", 42));
  const send = calls.find((c) => c.url.endsWith("/sendMessage"));
  assert.match(send.body.text, /Radikal dependency: 0%/);
});
