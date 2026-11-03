// Channel autopost (Iliya's format, revised repeatedly 2026-11-03 after
// his live reviews): a post carries CHANNEL_PROXIES_PER_POST proxies
// (default 2), each as its own clean block — bold «Proxy MTProto» title
// with the flag, bold Server/Port/Secret labels with copyable code
// values, an italic tagline on the first block, and the footer as a
// blockquote with the jellyfish first. Under the post, one glassy
// connect button per proxy in a single row, each button's color
// following its proxy's flag (Telegram offers exactly three glass
// styles — blue/green/red — so each flag maps to its closest).
// Runs on the existing */30 cron, throttled by CHANNEL_POST_MINUTES.

import { flag, tmeLink } from "./pool.js";
import { sendMessage } from "./telegram.js";
import { getPool } from "./bot.js";

// Flag-dominant-color → Telegram glass style. Unlisted = blue (primary).
// Iran is the exception (Iliya's rule): no flag shown, button colorless.
const FLAG_STYLE = {
  // green-dominant flags
  IT: "success", MX: "success", BR: "success", PK: "success",
  SA: "success", NG: "success", BD: "success", DZ: "success",
  // red-dominant flags
  TR: "danger", CN: "danger", ES: "danger", CH: "danger", AT: "danger",
  DK: "danger", CA: "danger", JP: "danger", NO: "danger", ID: "danger",
  VN: "danger", MA: "danger", TN: "danger",
};

export function flagStyle(country) {
  if (country === "IR") return undefined; // colorless
  return FLAG_STYLE[country] ?? "primary";
}

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
// then one spec block per proxy. With 3+ proxies Iliya wants NO specs
// in the text at all — it stays clean and the Connect buttons carry
// everything needed.
export function channelPostText(input) {
  const list = Array.isArray(input) ? input : [input];
  const f = displayFlag(list[0]?.country);
  const parts = [`<b>Proxy MTProto</b>${f ? ` ${f}` : ""}\n<i>Verified proxy</i>`];
  if (list.length < 3) for (const p of list) parts.push(specBlock(p));
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

export async function maybePostToChannel(env, now = Date.now()) {
  if (!env.CHANNEL_ID || !env.POOL) return { posted: false, reason: "disabled" };
  const everyMs = Math.max(1, Number(env.CHANNEL_POST_MINUTES ?? 60)) * 60000;
  const last = Number((await env.POOL.get("channel:last")) ?? 0);
  if (now - last < everyMs) return { posted: false, reason: "throttled" };
  const pool = await getPool(env);
  if (!pool?.count) return { posted: false, reason: "empty pool" };
  const perPost = Math.max(1, Math.min(3, Number(env.CHANNEL_PROXIES_PER_POST ?? 2) || 2));
  const cursor = await env.POOL.get("channel:cursor");
  const { keys, nextCursor } = pickForChannel(pool, cursor, perPost);
  if (!keys.length) return { posted: false, reason: "nothing to post" };
  const proxies = keys.map((k) => pool.proxies[k]);
  await sendMessage(env, env.CHANNEL_ID, channelPostText(proxies), {
    reply_markup: channelKeyboard(proxies),
  });
  await env.POOL.put("channel:last", String(now));
  await env.POOL.put("channel:cursor", nextCursor ?? "");
  return { posted: true, keys };
}
