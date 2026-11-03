// Channel autopost (Iliya's format, revised 2026-11-03 after his live
// review): ONE proxy per post — never several crammed into one message.
// The text shows only that main proxy, formatted: bold labels, copyable
// code values, an italic tagline, and the footer as a blockquote ending
// with the jellyfish. Under the post, a single glassy connect button
// whose color follows the proxy's flag (Telegram offers exactly three
// glass styles — blue/green/red — so each flag maps to its closest).
// Runs on the existing */30 cron, throttled by CHANNEL_POST_MINUTES.

import { flag, tmeLink } from "./pool.js";
import { sendMessage } from "./telegram.js";
import { getPool } from "./bot.js";

// Flag-dominant-color → Telegram glass style. Unlisted = blue (primary).
const FLAG_STYLE = {
  // green-dominant flags
  IR: "success", IT: "success", MX: "success", BR: "success", PK: "success",
  SA: "success", NG: "success", BD: "success", DZ: "success",
  // red-dominant flags
  TR: "danger", CN: "danger", ES: "danger", CH: "danger", AT: "danger",
  DK: "danger", CA: "danger", JP: "danger", NO: "danger", ID: "danger",
  VN: "danger", MA: "danger", TN: "danger",
};

export function flagStyle(country) {
  return FLAG_STYLE[country] ?? "primary";
}

export function channelPostText(p) {
  return [
    `<b>Proxy MTProto</b> ${flag(p.country)}`,
    `<i>Verified free proxy</i>`,
    ``,
    `<b>Server:</b> <code>${p.server}</code>`,
    `<b>Port:</b> <code>${p.port}</code>`,
    `<b>Secret:</b> <code>${p.secret}</code>`,
    ``,
    `<blockquote>🪼 @Proxiv3</blockquote>`,
  ].join("\n");
}

export function channelKeyboard(p, sponsor = null) {
  const rows = [
    [{ text: `${flag(p.country)} Connect`, url: tmeLink(p), style: flagStyle(p.country) }],
  ];
  if (sponsor?.url) rows.push([{ text: sponsor.text, url: sponsor.url }]);
  return { inline_keyboard: rows };
}

export const sponsorOf = (env) =>
  env.SPONSOR_URL ? { url: env.SPONSOR_URL, text: env.SPONSOR_TEXT ?? "📣 Sponsor" } : null;

// Next single key from the stable tier (fallback: fast, then everything),
// continuing after the cursor so posts rotate instead of repeating.
export function pickForChannel(pool, cursorKey) {
  const keys = pool.tiers.stable?.length ? pool.tiers.stable
    : pool.tiers.fast?.length ? pool.tiers.fast
    : Object.keys(pool.proxies);
  if (!keys.length) return { key: null, nextCursor: cursorKey ?? null };
  let start = Math.max(0, keys.indexOf(cursorKey));
  if (cursorKey && keys[start] === cursorKey) start = (start + 1) % keys.length;
  const key = keys[start];
  return { key, nextCursor: key };
}

export async function maybePostToChannel(env, now = Date.now()) {
  if (!env.CHANNEL_ID || !env.POOL) return { posted: false, reason: "disabled" };
  const everyMs = Math.max(1, Number(env.CHANNEL_POST_MINUTES ?? 60)) * 60000;
  const last = Number((await env.POOL.get("channel:last")) ?? 0);
  if (now - last < everyMs) return { posted: false, reason: "throttled" };
  const pool = await getPool(env);
  if (!pool?.count) return { posted: false, reason: "empty pool" };
  const cursor = await env.POOL.get("channel:cursor");
  const { key, nextCursor } = pickForChannel(pool, cursor);
  if (!key) return { posted: false, reason: "nothing to post" };
  const p = pool.proxies[key];
  await sendMessage(env, env.CHANNEL_ID, channelPostText(p), {
    reply_markup: channelKeyboard(p, sponsorOf(env)),
  });
  await env.POOL.put("channel:last", String(now));
  await env.POOL.put("channel:cursor", nextCursor ?? "");
  return { posted: true, key };
}
