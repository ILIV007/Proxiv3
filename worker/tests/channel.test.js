import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeProxy, buildPool } from "../src/pool.js";
import { channelPostText, channelKeyboard, flagStyle, pickForChannel, maybePostToChannel } from "../src/channel.js";

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

function makePool(n = 5, country = "DE") {
  const rows = Array.from({ length: n }, (_, i) =>
    normalizeProxy({
      server: `host${i}.example.com`, port: 443, secret: "dd" + "a".repeat(31) + i, type: "secure",
      ip: `10.0.0.${i}`, country, uptime: 0.99, checks: 40,
    }, "ours"));
  return buildPool(rows, { updatedUnix: Math.floor(Date.now() / 1000) });
}

test("one proxy per post: bold labels, code values, italic tagline, jellyfish blockquote footer", () => {
  const pool = makePool(1);
  const p = Object.values(pool.proxies)[0];
  const text = channelPostText(p);
  assert.equal(text,
    `<b>Proxy MTProto</b> 🇩🇪\n<i>Verified free proxy</i>\n\n` +
    `<b>Server:</b> <code>${p.server}</code>\n<b>Port:</b> <code>443</code>\n<b>Secret:</b> <code>${p.secret}</code>\n\n` +
    `<blockquote>@Proxiv3 🪼</blockquote>`);
  assert.equal((text.match(/Proxy MTProto/g) || []).length, 1);
});

test("glass button color follows the flag: green and red maps, blue default", () => {
  assert.equal(flagStyle("IR"), "success");
  assert.equal(flagStyle("TR"), "danger");
  assert.equal(flagStyle("DE"), "primary");
  assert.equal(flagStyle(null), "primary");
  const pool = makePool(1, "IR");
  const kb = channelKeyboard(Object.values(pool.proxies)[0]);
  assert.equal(kb.inline_keyboard.length, 1);
  assert.equal(kb.inline_keyboard[0][0].style, "success");
  assert.ok(kb.inline_keyboard[0][0].url.startsWith("https://t.me/proxy?"));
});

test("sponsor row appears only when a sponsor is configured", () => {
  const pool = makePool(1);
  const p = Object.values(pool.proxies)[0];
  const withS = channelKeyboard(p, { url: "https://t.me/ILIVIR3", text: "📣 Sponsor · @ILIVIR3" });
  assert.equal(withS.inline_keyboard.length, 2);
  assert.equal(withS.inline_keyboard[1][0].url, "https://t.me/ILIVIR3");
  assert.equal(channelKeyboard(p).inline_keyboard.length, 1);
});

test("rotation advances one key at a time and wraps", () => {
  const pool = makePool(5);
  const stable = pool.tiers.stable;
  const a = pickForChannel(pool, null);
  assert.equal(a.key, stable[0]);
  const b = pickForChannel(pool, a.nextCursor);
  assert.equal(b.key, stable[1]);
  const last = pickForChannel(pool, stable[3]);
  assert.equal(last.key, stable[4]);
  const wrap = pickForChannel(pool, stable[4]);
  assert.equal(wrap.key, stable[0]);
});

test("maybePostToChannel posts a single proxy, then throttles", async () => {
  calls.length = 0;
  const kv = new FakeKV();
  kv.m.set("pool", JSON.stringify(makePool(5)));
  const env = { POOL: kv, BOT_TOKEN: "test", CHANNEL_ID: "-1001", CHANNEL_POST_MINUTES: "60" };
  const now = Date.now();
  const r1 = await maybePostToChannel(env, now);
  assert.equal(r1.posted, true);
  const post = calls.find((c) => c.url.endsWith("/sendMessage"));
  assert.equal(String(post.body.chat_id), "-1001");
  assert.match(post.body.text, /<blockquote>@Proxiv3 🪼<\/blockquote>$/);
  assert.equal(post.body.reply_markup.inline_keyboard.length, 1);
  const r2 = await maybePostToChannel(env, now + 60000);
  assert.deepEqual(r2, { posted: false, reason: "throttled" });
});
