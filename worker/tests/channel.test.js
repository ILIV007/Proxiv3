import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeProxy, buildPool } from "../src/pool.js";
import { channelPostText, channelKeyboard, pickForChannel, maybePostToChannel } from "../src/channel.js";

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

function makePool(n = 5) {
  const rows = Array.from({ length: n }, (_, i) =>
    normalizeProxy({
      server: `host${i}.example.com`, port: 443, secret: "dd" + "a".repeat(31) + i, type: "secure",
      ip: `10.0.0.${i}`, country: "DE", uptime: 0.99, checks: 40,
    }, "ours"));
  return buildPool(rows, { updatedUnix: Math.floor(Date.now() / 1000) });
}

test("channel post matches Iliya's sample format exactly", () => {
  const pool = makePool(2);
  const ps = Object.values(pool.proxies);
  const text = channelPostText(ps);
  assert.equal(text,
    `Proxy MTProto:\nServer: ${ps[0].server}\nPort: 443\nSecret: ${ps[0].secret}\n\n` +
    `Proxy MTProto:\nServer: ${ps[1].server}\nPort: 443\nSecret: ${ps[1].secret}\n@Proxiv3`);
});

test("glassy connect buttons: one primary-style URL button per proxy", () => {
  const pool = makePool(3);
  const kb = channelKeyboard(Object.values(pool.proxies));
  assert.equal(kb.inline_keyboard.length, 3);
  for (const row of kb.inline_keyboard) {
    assert.equal(row[0].style, "primary");
    assert.ok(row[0].url.startsWith("https://t.me/proxy?"));
    assert.match(row[0].text, /Connect/);
  }
});

test("rotation continues after the cursor and wraps", () => {
  const pool = makePool(5);
  const stable = pool.tiers.stable;
  const a = pickForChannel(pool, null, 3);
  assert.deepEqual(a.picked, stable.slice(0, 3));
  const b = pickForChannel(pool, a.nextCursor, 3);
  assert.deepEqual(b.picked, [stable[3], stable[4], stable[0]]);
});

test("maybePostToChannel posts once, then throttles", async () => {
  calls.length = 0;
  const kv = new FakeKV();
  const pool = makePool(5);
  kv.m.set("pool", JSON.stringify(pool));
  const env = { POOL: kv, BOT_TOKEN: "test", CHANNEL_ID: "-1001", CHANNEL_POST_MINUTES: "180" };
  const now = Date.now();
  const r1 = await maybePostToChannel(env, now);
  assert.equal(r1.posted, true);
  const post = calls.find((c) => c.url.endsWith("/sendMessage"));
  assert.equal(String(post.body.chat_id), "-1001");
  assert.match(post.body.text, /@Proxiv3$/);
  const r2 = await maybePostToChannel(env, now + 60000);
  assert.deepEqual(r2, { posted: false, reason: "throttled" });
});
