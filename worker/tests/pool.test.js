import { test } from "node:test";
import assert from "node:assert/strict";
import {
  normalizeProxy, fromRadikal, mergeProxies, buildPool, validateFeed,
  tmeLink, tgLink, flag, proxyKey, dependencyRatio, FEED_SCHEMA,
} from "../src/pool.js";

const ROW = {
  server: "1.2.3.4", port: 443, secret: "dd" + "a".repeat(32), type: "secure",
  ip: "1.2.3.4", country: "DE", asn_org: "Hetzner", rtt_ms: 42.4, uptime: 0.95, checks: 30,
};

test("normalizeProxy accepts a valid row and rounds/clamps", () => {
  const p = normalizeProxy(ROW, "radikal");
  assert.equal(p.rtt_ms, 42);
  assert.equal(p.uptime, 0.95);
  assert.equal(p.key, proxyKey(ROW));
  assert.deepEqual(p.origins, ["radikal"]);
});

test("normalizeProxy rejects junk at the trust boundary", () => {
  assert.equal(normalizeProxy(null, "x"), null);
  assert.equal(normalizeProxy({ ...ROW, port: 0 }, "x"), null);
  assert.equal(normalizeProxy({ ...ROW, port: 70000 }, "x"), null);
  assert.equal(normalizeProxy({ ...ROW, secret: "zz".repeat(20) }, "x"), null);
  assert.equal(normalizeProxy({ ...ROW, secret: "abcd" }, "x"), null);
  assert.equal(normalizeProxy({ ...ROW, type: "socks5" }, "x"), null);
  assert.equal(normalizeProxy({ ...ROW, server: "a b.com" }, "x"), null);
  assert.equal(normalizeProxy({ ...ROW, country: "de" }, "x").country, null); // bad country nulled, row kept
});

test("fromRadikal tags the radikal origin", () => {
  assert.deepEqual(fromRadikal(ROW).origins, ["radikal"]);
});

test("mergeProxies dedupes by server identity, keeps most-checked alias, unions origins", () => {
  const a = normalizeProxy(ROW, "radikal");
  const b = normalizeProxy({ ...ROW, server: "alias.example.com", secret: "ee" + "b".repeat(32) + "736f6d65", type: "faketls", checks: 5 }, "ours");
  const merged = mergeProxies([a, b]);
  assert.equal(merged.length, 1);
  assert.equal(merged[0].server, "1.2.3.4"); // 30 checks beats 5
  assert.deepEqual(merged[0].origins.sort(), ["ours", "radikal"]);
});

test("buildPool tiers: stable by rule, fast is quickest quartile, countries indexed", () => {
  const rows = [];
  for (let i = 0; i < 8; i++)
    rows.push(normalizeProxy({ ...ROW, server: `10.0.0.${i}`, ip: `10.0.0.${i}`, rtt_ms: (i + 1) * 10, uptime: i < 4 ? 0.95 : 0.5, checks: 20 }, "ours"));
  const pool = buildPool(rows, { updatedUnix: 123 });
  assert.equal(pool.schema, FEED_SCHEMA);
  assert.equal(pool.count, 8);
  assert.equal(pool.tiers.stable.length, 4);
  assert.equal(pool.tiers.fast.length, 2);
  assert.equal(pool.countries.DE.length, 8);
  assert.equal(dependencyRatio(pool, "radikal"), 0);
  assert.equal(dependencyRatio(pool, "ours"), 1);
});

test("buildPool honors an explicit stable set over the rule", () => {
  const rows = [normalizeProxy({ ...ROW, uptime: 0.1, checks: 1 }, "ours")];
  const pool = buildPool(rows, { stableKeys: new Set([rows[0].key]) });
  assert.deepEqual(pool.tiers.stable, [rows[0].key]);
});

test("validateFeed accepts tgpool/1 and rejects anything else", () => {
  const feed = { schema: FEED_SCHEMA, updated_unix: 99, source: "test", proxies: [ROW] };
  const pool = validateFeed(feed);
  assert.equal(pool.count, 1);
  assert.equal(pool.updated_unix, 99);
  assert.equal(validateFeed({ schema: "other/9", proxies: [ROW] }), null);
  assert.equal(validateFeed({ schema: FEED_SCHEMA, proxies: [] }), null);
  assert.equal(validateFeed(null), null);
});

test("validateFeed preserves sanitized per-row origins from our own feed", () => {
  const feed = { schema: FEED_SCHEMA, proxies: [{ ...ROW, origins: ["tgmtproxy", "radikal", "bad origin!", 42] }] };
  const pool = validateFeed(feed);
  const p = pool.proxies[Object.keys(pool.proxies)[0]];
  assert.deepEqual(p.origins, ["tgmtproxy", "radikal"]);
  assert.equal(dependencyRatio(pool, "radikal"), 0);
});

test("links and flags", () => {
  const p = normalizeProxy(ROW, "x");
  assert.equal(tmeLink(p), `https://t.me/proxy?server=1.2.3.4&port=443&secret=${ROW.secret}`);
  assert.ok(tgLink(p).startsWith("tg://proxy?"));
  assert.equal(flag("IR"), "🇮🇷");
  assert.equal(flag(null), "🌐");
});
