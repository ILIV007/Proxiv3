// Bot update handling. State lives in KV (pool + per-user recents + rate
// limits) and, when bound, D1 (users + votes). Everything fails soft:
// no KV pool yet -> friendly "syncing" reply; no D1 -> votes are skipped.
// UI language: English by design (Iliya's call, 2026-11-03 — the bot sends
// little text, and proxy channels are an English-format world).

import { flag, tmeLink, dependencyRatio, flagStyle } from "./pool.js";
import { tgApi, sendMessage, editMessageText, answerCallback } from "./telegram.js";
import { syncPool } from "./sync.js";

const WARNING =
  "⚠️ Public proxies are free, and each operator can see your IP and may inject sponsored channels. Do not use them for sensitive accounts.";

export function poolAgeText(pool, now = Date.now()) {
  if (!pool?.updated_unix) return "not synced yet";
  const mins = Math.max(0, Math.round(now / 1000 / 60 - pool.updated_unix / 60));
  if (mins < 60) return `updated ${mins} min ago`;
  return `updated ${Math.floor(mins / 60)}h ${mins % 60}m ago`;
}

export function menuText(pool) {
  const head = pool
    ? `🛡 <b>PROXIV3</b> — verified MTProto proxies\n📦 Current pool: <b>${pool.count}</b> servers · ${poolAgeText(pool)}`
    : "🛡 <b>PROXIV3</b>\n⏳ The pool is still syncing — try again in a minute.";
  return `${head}\n\n${WARNING}`;
}

export function mainKeyboard() {
  return {
    inline_keyboard: [
      [
        { text: "🎲 Random proxy", callback_data: "t:all" },
        { text: "🛡 Most stable", callback_data: "t:stable" },
      ],
      [
        { text: "⚡ Fastest", callback_data: "t:fast" },
        { text: "🎭 FakeTLS", callback_data: "t:faketls" },
      ],
      [{ text: "🌍 By country", callback_data: "cc" }],
      // The growth loop: every bot user sees the channel join button.
      [{ text: "🪼 Join @PROXIV3", url: "https://t.me/Proxiv3" }],
    ],
  };
}

// Minimal card (Iliya's call, 2026-11-03): no stats, no votes — just the
// connection details in the same Server/Port/Secret shape as the channel.
// Iran proxies show no flag and a colorless button (same rule as channel).
export function cardText(p) {
  const f = p.country === "IR" ? "" : flag(p.country);
  return [
    `${f ? `${f} ` : ""}<b>MTProto Proxy</b>`,
    ``,
    `Server: <code>${p.server}</code>`,
    `Port: ${p.port}`,
    `Secret: <code>${p.secret}</code>`,
  ].join("\n");
}

export function cardKeyboard(p, scope, opts = {}) {
  const connect = { text: "🚀 Connect", url: tmeLink(p) };
  const style = flagStyle(p.country);
  if (style) connect.style = style;
  const rows = [
    [connect],
    [
      { text: "⏭ Next", callback_data: `n:${scope}` },
      { text: "🏠 Main menu", callback_data: "m" },
    ],
  ];
  // Admins can push the proxy they are viewing straight to the channel.
  if (opts.admin && opts.key) rows.push([{ text: "📮 Send to channel", callback_data: `pub:${opts.key}` }]);
  return { inline_keyboard: rows };
}

const isAdmin = (env, uid) => (env.ADMIN_IDS ?? "").split(",").map((s) => s.trim()).includes(String(uid));

// Membership gate (Iliya's rule, 2026-11-03): using the bot requires
// membership in @Proxiv3. Checked fresh on every interaction; a
// Telegram API hiccup fails OPEN so an outage never locks everyone out.
export async function isChannelMember(env, uid) {
  if (!env.CHANNEL_ID) return true;
  const m = await tgApi(env, "getChatMember", { chat_id: env.CHANNEL_ID, user_id: uid });
  if (!m) return true;
  if (["creator", "administrator", "member"].includes(m.status)) return true;
  if (m.status === "restricted") return m.is_member === true;
  return false;
}

export function joinText() {
  return "🔒 <b>PROXIV3</b> is for members of our channel.\n\nJoin @PROXIV3 first — then tap «✅ I joined» and the proxies are yours.";
}

export function joinKeyboard() {
  return {
    inline_keyboard: [
      [{ text: "🪼 Join @PROXIV3", url: "https://t.me/Proxiv3" }],
      [{ text: "✅ I joined", callback_data: "j" }],
    ],
  };
}

async function rateLimited(env, uid) {
  if (!env.POOL) return false;
  const key = `rl:${uid}:${Math.floor(Date.now() / 3600000)}`;
  const n = Number((await env.POOL.get(key)) ?? 0) + 1;
  await env.POOL.put(key, String(n), { expirationTtl: 3700 });
  return n > 60; // shortcut: generous cap; tighten when real abuse shows up
}

async function pickKey(env, uid, candidateKeys) {
  if (!candidateKeys?.length) return null;
  let recent = [];
  try {
    recent = JSON.parse((await env.POOL.get(`recent:${uid}`)) ?? "[]");
  } catch { recent = []; }
  const fresh = candidateKeys.filter((k) => !recent.includes(k));
  const list = fresh.length ? fresh : candidateKeys;
  const key = list[Math.floor(Math.random() * list.length)];
  recent = [key, ...recent.filter((k) => k !== key)].slice(0, 20);
  await env.POOL.put(`recent:${uid}`, JSON.stringify(recent));
  return key;
}

async function serve(env, chatId, uid, scope) {
  const pool = await getPool(env);
  if (!pool) return sendMessage(env, chatId, menuText(null), { reply_markup: mainKeyboard() });
  let keys;
  if (scope.startsWith("c:")) keys = pool.countries[scope.slice(2)] ?? [];
  else if (scope === "all") keys = Object.keys(pool.proxies);
  else keys = pool.tiers[scope] ?? [];
  const key = await pickKey(env, uid, keys);
  if (!key) return sendMessage(env, chatId, "No proxies in this category right now — try another one.", { reply_markup: mainKeyboard() });
  const p = pool.proxies[key];
  return sendMessage(env, chatId, cardText(p), { reply_markup: cardKeyboard(p, scope, { key, admin: isAdmin(env, uid) }) });
}

export async function getPool(env) {
  if (!env.POOL) return null;
  try {
    return JSON.parse((await env.POOL.get("pool")) ?? "null");
  } catch { return null; }
}

export async function handleUpdate(env, update, ctx) {
  const msg = update.message;
  const cb = update.callback_query;
  const from = msg?.from ?? cb?.from;
  if (!from || from.is_bot) return;
  const uid = from.id;

  if (msg?.text) {
    const chatId = msg.chat.id;
    if (await rateLimited(env, uid)) return;
    if (!isAdmin(env, uid) && !(await isChannelMember(env, uid))) {
      return void (await sendMessage(env, chatId, joinText(), { reply_markup: joinKeyboard() }));
    }
    if (msg.text.startsWith("/start") || msg.text.startsWith("/menu")) {
      const pool = await getPool(env);
      return void (await sendMessage(env, chatId, menuText(pool), { reply_markup: mainKeyboard() }));
    }
    if (msg.text.startsWith("/admin")) {
      if (!isAdmin(env, uid)) return;
      const pool = await getPool(env);
      const dep = pool ? Math.round(dependencyRatio(pool, "radikal") * 100) : "—";
      const text = pool
        ? `🛠 <b>PROXIV3 panel</b>\n📦 Servers: ${pool.count}\n🕐 ${poolAgeText(pool)}\n🔗 Radikal dependency: ${dep}%\n📡 Feed source: ${pool.source}`
        : "🛠 The pool is still empty.";
      return void (await sendMessage(env, chatId, text, {
        reply_markup: { inline_keyboard: [[{ text: "🔄 Sync now", callback_data: "a:sync" }]] },
      }));
    }
    return;
  }

  if (cb) {
    const chatId = cb.message.chat.id;
    const messageId = cb.message.message_id;
    const data = cb.data ?? "";
    if (await rateLimited(env, uid)) return void (await answerCallback(env, cb.id, "Slow down a bit — try again in a few minutes.", true));
    const done = async (text = "") => answerCallback(env, cb.id, text);

    if (data === "j") {
      if (isAdmin(env, uid) || (await isChannelMember(env, uid))) {
        const pool = await getPool(env);
        await editMessageText(env, chatId, messageId, menuText(pool), { reply_markup: mainKeyboard() });
        return void (await done("✅ Welcome to PROXIV3"));
      }
      return void (await done("Not yet — join @PROXIV3 first, then tap again.", true));
    }
    if (!isAdmin(env, uid) && !(await isChannelMember(env, uid))) {
      await editMessageText(env, chatId, messageId, joinText(), { reply_markup: joinKeyboard() });
      return void (await done("Join @PROXIV3 to use the bot", true));
    }
    if (data === "m") {
      const pool = await getPool(env);
      await editMessageText(env, chatId, messageId, menuText(pool), { reply_markup: mainKeyboard() });
      return void (await done());
    }
    if (data === "cc") {
      const pool = await getPool(env);
      if (!pool) return void (await done("The pool is not ready yet"));
      const top = Object.entries(pool.countries).sort((a, b) => b[1].length - a[1].length).slice(0, 12);
      const rows = [];
      for (let i = 0; i < top.length; i += 3)
        rows.push(top.slice(i, i + 3).map(([cc, ks]) => ({ text: `${flag(cc)} ${cc} (${ks.length})`, callback_data: `c:${cc}` })));
      rows.push([{ text: "🏠 Main menu", callback_data: "m" }]);
      await editMessageText(env, chatId, messageId, "🌍 Pick a country:", { reply_markup: { inline_keyboard: rows } });
      return void (await done());
    }
    if (data.startsWith("t:")) {
      await serve(env, chatId, uid, data.slice(2));
      return void (await done());
    }
    if (data.startsWith("c:")) {
      await serve(env, chatId, uid, data);
      return void (await done());
    }
    if (data.startsWith("n:")) {
      await serve(env, chatId, uid, data.slice(2));
      return void (await done());
    }
    if (data.startsWith("pub:")) {
      if (!isAdmin(env, uid)) return void (await done("No access", true));
      const key = data.slice(4);
      const pool = await getPool(env);
      const p = pool?.proxies[key];
      if (!p || !env.CHANNEL_ID) return void (await done("Not available", true));
      const { channelPostText, channelKeyboard } = await import("./channel.js");
      await sendMessage(env, env.CHANNEL_ID, channelPostText([p]), { reply_markup: channelKeyboard([p]) });
      if (env.POOL) {
        await env.POOL.put("channel:last", String(Date.now()));
        await env.POOL.put("channel:cursor", key);
      }
      return void (await done("✅ Posted to @PROXIV3"));
    }
    if (data === "a:sync") {
      if (!isAdmin(env, uid)) return void (await done("No access", true));
      ctx?.waitUntil?.(syncPool(env).then((r) => sendMessage(env, chatId, r.ok ? `✅ Synced: ${r.count} servers` : `❌ Sync failed: ${r.error}`)));
      return void (await done("Sync started…"));
    }
    return void (await done());
  }
}
