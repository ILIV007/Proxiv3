// Pool sync: turn provider data into OUR tgpool/1 pool in KV.
// Order: (1) our own feed (OWN_FEED_URL) — the Phase-2 end state;
// (2) the radikal bootstrap adapter, behind PROVIDER_RADIKAL_ENABLED.
// A failed sync never touches the last good pool.

import { fromRadikal, mergeProxies, buildPool, validateFeed, proxyKey } from "./pool.js";

const RADIKAL_BASE = "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main";

async function fetchJson(url, timeoutMs = 20000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { "user-agent": "Proxiv3-sync" } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

export async function syncPool(env) {
  if (!env.POOL) return { ok: false, error: "POOL KV not bound" };
  try {
    let pool = null;

    if (env.OWN_FEED_URL) {
      pool = validateFeed(await fetchJson(env.OWN_FEED_URL));
      if (!pool) throw new Error("own feed failed validation");
    } else if (env.PROVIDER_RADIKAL_ENABLED !== "false") {
      const base = env.RADIKAL_BASE || RADIKAL_BASE;
      const [resilient, stable] = await Promise.all([
        fetchJson(`${base}/resilient/proxies.json`),
        fetchJson(`${base}/stable/proxies.json`),
      ]);
      const rows = (Array.isArray(resilient) ? resilient : []).map(fromRadikal).filter(Boolean);
      if (!rows.length) throw new Error("radikal feed empty after normalization");
      const stableKeys = new Set((Array.isArray(stable) ? stable : []).map((r) => {
        const p = fromRadikal(r);
        return p ? p.key : null;
      }).filter(Boolean));
      pool = buildPool(mergeProxies(rows), {
        stableKeys,
        updatedUnix: Math.floor(Date.now() / 1000),
        source: "radikal-bootstrap",
      });
    } else {
      return { ok: false, error: "no feed source configured" };
    }

    // Write only on change: KV free tier allows 1,000 writes/day and the
    // cron fires 48×/day; an unchanged pool must cost zero writes.
    const prevRaw = await env.POOL.get("pool");
    if (prevRaw) {
      const prev = JSON.parse(prevRaw);
      const sameSet = prev.count === pool.count &&
        Object.keys(prev.proxies).every((k) => pool.proxies[k]);
      if (sameSet && pool.source === prev.source) return { ok: true, count: pool.count, skipped: true };
    }
    await env.POOL.put("pool", JSON.stringify(pool));
    return { ok: true, count: pool.count };
  } catch (e) {
    console.error("syncPool", e.message);
    return { ok: false, error: e.message };
  }
}

export { proxyKey };
