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

// FakeTLS front domain, decoded from the ee-secret (0xEE + 16-byte key
// + raw domain bytes — the same layout the pipeline's secret.py uses).
// Null for non-FakeTLS secrets and for domains that aren't clean ASCII.
export function frontDomain(p) {
  if (!p || p.type !== "faketls" || typeof p.secret !== "string") return null;
  const hex = p.secret.toLowerCase();
  if (!hex.startsWith("ee") || hex.length <= 34 || hex.length % 2) return null;
  let d = "";
  for (let i = 34; i < hex.length; i += 2) {
    const c = parseInt(hex.slice(i, i + 2), 16);
    if (!(c >= 0x20 && c < 0x7f)) return null;
    d += String.fromCharCode(c);
  }
  d = d.toLowerCase();
  return /^([a-z0-9-]+\.)+[a-z]{2,}$/.test(d) ? d : null;
}

// Fronts that live on major CDN / platform infrastructure. A FakeTLS
// proxy wearing one of these as its SNI survives ISP filtering far
// better (the Aether doctrine: a ubiquitous, whitelist-friendly SNI on
// anycast IPs) — Iliya approved prioritizing them in the ranking.
const CDN_FRONTS = [
  "cloudflare.com", "google.com", "googleapis.com", "gstatic.com",
  "youtube.com", "amazonaws.com", "cloudfront.net", "amazon.com",
  "azure.com", "microsoft.com", "office.com", "office365.com",
  "windows.com", "bing.com", "akamai.net", "akamaized.net",
  "akamaiedge.net", "fastly.net", "apple.com", "icloud.com",
  "facebook.com", "instagram.com", "whatsapp.com", "telegram.org",
  "wikipedia.org", "github.com", "gitlab.com", "mozilla.org",
];

export function isCdnFront(domain) {
  if (!domain) return false;
  return CDN_FRONTS.some((d) => domain === d || domain.endsWith(`.${d}`));
}

// The elite set: what channel posts (and the bot's "Most stable") draw
// from. Iliya's live report (2026-11-03): ~half of the stable tier did
// not answer from Iran, so posting gates are much stricter than the
// stable tier's (uptime ≥0.98 and RTT ≤250 ms; pool order preserved,
// so a country's head is still its best). Relaxes in steps when the
// pool is too small, and never returns less than the stable tier.
// Within the chosen gate, FakeTLS proxies fronted by a major CDN go
// first (stable partition — relative quality order is preserved).
export function eliteKeys(pool, min = 100) {
  const P = pool?.proxies ?? {};
  const stable = pool?.tiers?.stable ?? [];
  const pick = (up, rtt) =>
    stable.filter((k) => (P[k]?.uptime ?? 0) >= up && (P[k]?.rtt_ms ?? 1e9) <= rtt);
  const boost = (keys) => {
    const fronted = keys.filter((k) => isCdnFront(frontDomain(P[k])));
    if (!fronted.length) return keys;
    const rest = keys.filter((k) => !fronted.includes(k));
    return [...fronted, ...rest];
  };
  const a = pick(0.98, 250);
  if (a.length >= min) return boost(a);
  const b = pick(0.95, 400);
  if (b.length >= min) return boost(b);
  return boost(stable);
}

// Validate an incoming tgpool/1 feed (the /sync trust boundary).
export function validateFeed(body) {
  if (!body || body.schema !== FEED_SCHEMA || !Array.isArray(body.proxies)) return null;
  const rows = body.proxies.map((r) => {
    const p = normalizeProxy(r, "sync");
    // Our own feed carries per-row origins — keep them (sanitized), they
    // drive the dependency metric. Foreign rows fall back to ["sync"].
    if (p && Array.isArray(r.origins)) {
      const origins = r.origins.filter((o) => typeof o === "string" && /^[a-z0-9_-]{1,40}$/i.test(o)).slice(0, 8);
      if (origins.length) p.origins = origins;
    }
    return p;
  }).filter(Boolean);
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

// Flag-dominant-color → Telegram glass button style. Telegram offers
// exactly three styles (primary=blue, success=green, danger=red), so
// each flag maps by its DOMINANT color; blue-dominant flags are the
// unlisted default. Iran is the exception (Iliya's rule): colorless.
const FLAG_STYLE = {
  // green-dominant
  IT: "success", MX: "success", BR: "success", PK: "success",
  SA: "success", NG: "success", BD: "success", DZ: "success",
  UZ: "success", LT: "success", BG: "success", PT: "success",
  ZA: "success", AE: "success", IQ: "success", MM: "success",
  IN: "success",
  // red-dominant
  TR: "danger", CN: "danger", ES: "danger", CH: "danger", AT: "danger",
  DK: "danger", CA: "danger", JP: "danger", NO: "danger", ID: "danger",
  VN: "danger", MA: "danger", TN: "danger",
  DE: "danger", NL: "danger", US: "danger", PL: "danger", LV: "danger",
  CZ: "danger", HR: "danger", RS: "danger", LU: "danger", BE: "danger",
  HU: "danger", AM: "danger", GE: "danger", EG: "danger", CL: "danger",
  LA: "danger", PE: "danger", KR: "danger", SG: "danger", MY: "danger",
  TH: "danger", BY: "danger", AF: "danger",
};

export function flagStyle(country) {
  if (country === "IR") return undefined; // colorless, by Iliya's rule
  return FLAG_STYLE[country] ?? "primary";
}

// share of pool whose ONLY origin is the given one — the plan's dependency metric.
export function dependencyRatio(pool, origin) {
  const all = Object.values(pool.proxies);
  if (!all.length) return 0;
  return all.filter((p) => p.origins.length === 1 && p.origins[0] === origin).length / all.length;
}
