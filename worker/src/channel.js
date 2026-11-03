// Channel autopost (Iliya's format, 2026-11-03): classic ProxyMTProto
// blocks, 2–3 proxies per post, one @Proxiv3 signature, and glassy
// (style:"primary") connect buttons under the post — one per proxy.
// Runs on the existing */30 cron, throttled by CHANNEL_POST_MINUTES
// (default 180) and rotated through the stable tier via a KV cursor.

import { flag, tmeLink } from "./pool.js";
import { sendMessage } from "./telegram.js";
import { getPool } from "./bot.js";

export function channelPostText(proxies) {
  const blocks = proxies.map(
    (p) => `Proxy MTProto:\nServer: ${p.server}\nPort: ${p.port}\nSecret: ${p.secret}`
  );
  return `${blocks.join("\n\n")}\n@Proxiv3`;
}

export function channelKeyboard(proxies) {
  return {
    inline_keyboard: proxies.map((p) => [
      { text: `${flag(p.country)} Connect`, url: tmeLink(p), style: "primary" },
    ]),
  };
}

// Next n keys from the stable tier (fallback: fast, then everything),
// continuing after the cursor so posts rotate instead of repeating.
export function pickForChannel(pool, cursorKey, n = 3) {
  const keys = pool.tiers.stable?.length ? pool.tiers.stable
    : pool.tiers.fast?.length ? pool.tiers.fast
    : Object.keys(pool.proxies);
  if (!keys.length) return { picked: [], nextCursor: cursorKey ?? null };
  let start = Math.max(0, keys.indexOf(cursorKey));
  if (cursorKey && keys[start] === cursorKey) start = (start + 1) % keys.length;
  const picked = [];
  for (let i = 0; i < Math.min(n, keys.length); i++) picked.push(keys[(start + i) % keys.length]);
  return { picked, nextCursor: picked[picked.length - 1] };
}

export async function maybePostToChannel(env, now = Date.now()) {
  if (!env.CHANNEL_ID || !env.POOL) return { posted: false, reason: "disabled" };
  const everyMs = Math.max(1, Number(env.CHANNEL_POST_MINUTES ?? 180)) * 60000;
  const last = Number((await env.POOL.get("channel:last")) ?? 0);
  if (now - last < everyMs) return { posted: false, reason: "throttled" };
  const pool = await getPool(env);
  if (!pool?.count) return { posted: false, reason: "empty pool" };
  const cursor = await env.POOL.get("channel:cursor");
  const { picked, nextCursor } = pickForChannel(pool, cursor);
  if (!picked.length) return { posted: false, reason: "nothing to post" };
  const proxies = picked.map((k) => pool.proxies[k]);
  await sendMessage(env, env.CHANNEL_ID, channelPostText(proxies), {
    reply_markup: channelKeyboard(proxies),
  });
  await env.POOL.put("channel:last", String(now));
  await env.POOL.put("channel:cursor", nextCursor ?? "");
  return { posted: true, count: proxies.length };
}
