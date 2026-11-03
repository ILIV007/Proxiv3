// Channel autopost (Iliya's format, revised repeatedly 2026-11-03 after
// his live reviews): a post carries CHANNEL_PROXIES_PER_POST proxies
// (default 2), each as its own clean block — bold «Proxy MTProto» title
// with the flag, bold Server/Port/Secret labels with copyable code
// values, an italic tagline on the first block, and the footer as a
// blockquote with the jellyfish first. Under the post, one glassy
// connect button per proxy in a single row, each button's color
// following its proxy's flag (Telegram offers exactly three glass
// styles — blue/green/red — so each flag maps to its closest).
// Runs on the existing */5 cron, throttled by CHANNEL_POST_MINUTES.

import { flag, tmeLink, flagStyle } from "./pool.js";
import { sendMessage } from "./telegram.js";
import { getPool } from "./bot.js";

export { flagStyle };

// Flag for display, or "" for Iran (no flag by Iliya's rule).
export const displayFlag = (country) => (country === "IR" ? "" : flag(country));

function specBlock(p) {
  return [
    `<b>Server:</b> <code>${p.server}</code>`,
    `<b>Port:</b> <code>${p.port}</code>`,
    `<b>Secret:</b> <code>${p.secret}</code>`,
  ].join("\n");
}

// One header for the whole post (title + the shared flag + tagline),
// then one spec block per proxy. With 3+ proxies Iliya wants the spec
// labels written EMPTY — a single Server/Port/Secret block with no
// values; the Connect buttons carry everything needed.
const EMPTY_SPEC = `<b>Server:</b>\n<b>Port:</b>\n<b>Secret:</b>`;

export function channelPostText(input) {
  const list = Array.isArray(input) ? input : [input];
  const f = displayFlag(list[0]?.country);
  const parts = [`<b>Proxy MTProto</b>${f ? ` ${f}` : ""}\n<i>Verified proxy</i>`];
  if (list.length >= 3) parts.push(EMPTY_SPEC);
  else for (const p of list) parts.push(specBlock(p));
  parts.push(`<blockquote>🪼 @PROXIV3</blockquote>`);
  return parts.join("\n\n");
}

export function channelKeyboard(input) {
  const list = Array.isArray(input) ? input : [input];
  const row = list.map((p) => {
    const f = displayFlag(p.country);
    const btn = { text: f ? `${f} Connect` : "Connect", url: tmeLink(p) };
    const style = flagStyle(p.country);
    if (style) btn.style = style;
    return btn;
  });
  return { inline_keyboard: [row] };
}

// Pick one post's proxies from the stable tier (fallback: fast, then
// everything). Iliya's rule: all proxies in one post share ONE flag, so
// the pick is a single country's group; the tier order is already
// quality-sorted (uptime desc, RTT asc), so the group's head is that
// country's best servers. Countries rotate: each post moves to the
// next country after the cursor's, preferring one that can fill the
// post; a country too small posts what it has.
export function pickForChannel(pool, cursorKey, count = 2) {
  const keys = pool.tiers.stable?.length ? pool.tiers.stable
    : pool.tiers.fast?.length ? pool.tiers.fast
    : Object.keys(pool.proxies);
  if (!keys.length) return { keys: [], nextCursor: cursorKey ?? null };
  const groups = new Map();
  for (const k of keys) {
    const c = pool.proxies[k]?.country ?? "";
    if (!groups.has(c)) groups.set(c, []);
    groups.get(c).push(k);
  }
  const countries = [...groups.keys()];
  let start = 0;
  const cursorCountry = cursorKey ? (pool.proxies[cursorKey]?.country ?? null) : null;
  if (cursorCountry !== null && groups.has(cursorCountry)) {
    start = (countries.indexOf(cursorCountry) + 1) % countries.length;
  }
  const n = Math.max(1, count);
  for (let i = 0; i < countries.length; i++) {
    const g = groups.get(countries[(start + i) % countries.length]);
    if (g.length >= n) return { keys: g.slice(0, n), nextCursor: g[n - 1] };
  }
  const g = groups.get(countries[start]);
  const picked = g.slice(0, n);
  return { keys: picked, nextCursor: picked[picked.length - 1] };
}

// How many proxies a post carries varies (Iliya's call): mostly 2,
// sometimes 1, sometimes 3 — drawn fresh for every post.
export function pickPostCount(rand = Math.random()) {
  if (rand < 0.25) return 1;
  if (rand < 0.75) return 2;
  return 3;
}

// And each posting round is a small burst (Iliya's call): at least
// 2 posts, sometimes 3, each from the next country in rotation.
export function pickBurstCount(rand = Math.random()) {
  return rand < 0.5 ? 2 : 3;
}

export async function maybePostToChannel(env, now = Date.now()) {
  if (!env.CHANNEL_ID || !env.POOL) return { posted: false, reason: "disabled" };
  const everyMs = Math.max(1, Number(env.CHANNEL_POST_MINUTES ?? 25)) * 60000;
  const last = Number((await env.POOL.get("channel:last")) ?? 0);
  if (now - last < everyMs) return { posted: false, reason: "throttled" };
  const pool = await getPool(env);
  if (!pool?.count) return { posted: false, reason: "empty pool" };
  let cursor = await env.POOL.get("channel:cursor");
  const sent = [];
  for (let i = 0, burst = pickBurstCount(); i < burst; i++) {
    const { keys, nextCursor } = pickForChannel(pool, cursor, pickPostCount());
    if (!keys.length) break;
    const proxies = keys.map((k) => pool.proxies[k]);
    await sendMessage(env, env.CHANNEL_ID, channelPostText(proxies), {
      reply_markup: channelKeyboard(proxies),
    });
    sent.push(keys);
    cursor = nextCursor;
  }
  if (!sent.length) return { posted: false, reason: "nothing to post" };
  await env.POOL.put("channel:last", String(now));
  await env.POOL.put("channel:cursor", cursor ?? "");
  return { posted: true, posts: sent.length, keys: sent.flat() };
}
