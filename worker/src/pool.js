// Proxiv3 pool core — pure functions only (no I/O), unit-tested in tests/pool.test.js.
// Feed schema "tgpool/1" is OURS: every provider (radikal today, our own pipeline
// from Phase 2) is normalized into it before anything reaches the bot.

export const FEED_SCHEMA = "tgpool/1";
export const TYPES = ["classic", "secure", "faketls"];

// Stable short id for a proxy: FNV-1a over its identity, base36. Fits callback_data easily.
export function proxyKey(p) {
  const s = `${p.server}|${p.port}|${p.secret}`;
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(36);
}

// Validate + normalize one raw row into a tgpool proxy, or return null.
// Trust boundary: provider data is untrusted input.
export function normalizeProxy(raw, origin) {
  if (!raw || typeof raw !== "object") return null;
  const server = String(raw.server ?? "").trim();
  const port = Number(raw.port);
  const secret = String(raw.secret ?? "").trim().toLowerCase();
  const type = TYPES.includes(raw.type) ? raw.type : null;
  if (!server || server.length > 253 || /[\s/\\]/.test(server)) return null;
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  if (!/^[0-9a-f]+$/.test(secret) || secret.length < 32 || secret.length > 4096) return null;
  if (!type) return null;
  const p = {
    server,
    port,
    secret,
    type,
    ip: typeof raw.ip === "string" ? raw.ip : null,
    country: /^[A-Z]{2}$/.test(raw.country ?? "") ? raw.country : null,
    asn_org: typeof raw.asn_org === "string" ? raw.asn_org.slice(0, 80) : null,
    rtt_ms: Number.isFinite(raw.rtt_ms) ? Math.round(raw.rtt_ms) : null,
    uptime: Number.isFinite(raw.uptime) ? Math.min(1, Math.max(0, raw.uptime)) : null,
    checks: Number.isInteger(raw.checks) ? raw.checks : 0,
    origins: [origin],
  };
  p.key = proxyKey(p);
  return p;
}

// Adapter: Free-Telegram-Proxy proxies.json row -> tgpool proxy.
// Their rows already carry exactly these field names (verified 2026-11-03);
// the adapter exists so a format change on their side breaks HERE, not in the bot.
export function fromRadikal(row) {
  return normalizeProxy(row, "radikal");
}

// Merge rows from any providers: dedupe by server identity (ip||server, port),
// keep the alias with the most checks, union the origins.
export function mergeProxies(rows) {
  const byServer = new Map();
  for (const p of rows) {
    if (!p) continue;
    const id = `${p.ip || p.server}|${p.port}`;
    const prev = byServer.get(id);
    if (!prev) {
      byServer.set(id, p);
    } else {
      const keep = p.checks > prev.checks ? p : prev;
      keep.origins = [...new Set([...prev.origins, ...p.origins])];
      byServer.set(id, keep);
    }
  }
  return [...byServer.values()];
}

// Build the servable pool: tiers + country index, all precomputed so the
// request path never sorts or parses (free-plan CPU is 10 ms).
export function buildPool(proxies, { stableKeys = null, updatedUnix = 0, source = "mixed" } = {}) {
  const all = proxies.slice().sort((a, b) => (b.uptime ?? 0) - (a.uptime ?? 0) || (a.rtt_ms ?? 1e9) - (b.rtt_ms ?? 1e9));
  const stable = stableKeys
    ? all.filter((p) => stableKeys.has(p.key))
    : all.filter((p) => (p.uptime ?? 0) >= 0.9 && p.checks >= 12);
  const byRtt = all.filter((p) => p.rtt_ms != null).sort((a, b) => a.rtt_ms - b.rtt_ms);
  const fast = byRtt.slice(0, Math.max(1, Math.ceil(byRtt.length / 4)));
  const tiers = {
    stable: stable.map((p) => p.key),
    fast: fast.map((p) => p.key),
    faketls: all.filter((p) => p.type === "faketls").map((p) => p.key),
    secure: all.filter((p) => p.type === "secure").map((p) => p.key),
    classic: all.filter((p) => p.type === "classic").map((p) => p.key),
  };
  const countries = {};
  for (const p of all) if (p.country) (countries[p.country] ??= []).push(p.key);
  return {
    schema: FEED_SCHEMA,
    updated_unix: updatedUnix,
    source,
    count: all.length,
    tiers,
    countries,
    proxies: Object.fromEntries(all.map((p) => [p.key, p])),
  };
}

// Validate an incoming tgpool/1 feed (the /sync trust boundary).
export function validateFeed(body) {
  if (!body || body.schema !== FEED_SCHEMA || !Array.isArray(body.proxies)) return null;
  const rows = body.proxies.map((r) => normalizeProxy(r, "sync")).filter(Boolean);
  if (!rows.length) return null;
  return buildPool(mergeProxies(rows), {
    updatedUnix: Number.isInteger(body.updated_unix) ? body.updated_unix : Math.floor(Date.now() / 1000),
    source: typeof body.source === "string" ? body.source.slice(0, 40) : "sync",
  });
}

export function tmeLink(p) {
  return `https://t.me/proxy?server=${encodeURIComponent(p.server)}&port=${p.port}&secret=${p.secret}`;
}
export function tgLink(p) {
  return `tg://proxy?server=${encodeURIComponent(p.server)}&port=${p.port}&secret=${p.secret}`;
}

// 🇮🇷 from "IR" via regional indicators — no lookup table needed.
export function flag(cc) {
  if (!cc) return "🌐";
  return String.fromCodePoint(...[...cc].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

// share of pool whose ONLY origin is the given one — the plan's dependency metric.
export function dependencyRatio(pool, origin) {
  const all = Object.values(pool.proxies);
  if (!all.length) return 0;
  return all.filter((p) => p.origins.length === 1 && p.origins[0] === origin).length / all.length;
}
