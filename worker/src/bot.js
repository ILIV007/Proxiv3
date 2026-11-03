// Bot update handling. State lives in KV (pool + per-user recents + rate
// limits) and, when bound, D1 (users + votes). Everything fails soft:
// no KV pool yet -> friendly "syncing" reply; no D1 -> votes are skipped.
// UI language: English by design (Iliya's call, 2026-11-03 — the bot sends
// little text, and proxy channels are an English-format world).

import { flag, tmeLink, tgLink, dependencyRatio } from "./pool.js";
import { sendMessage, editMessageText, answerCallback } from "./telegram.js";
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
    ? `🛡 <b>Proxiv3</b> — verified MTProto proxies\n📦 Current pool: <b>${pool.count}</b> servers · ${poolAgeText(pool)}`
    : "🛡 <b>Proxiv3</b>\n⏳ The pool is still syncing — try again in a minute.";
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
    ],
  };
}

export function cardText(p, votes = { up: 0, down: 0 }) {
  const lines = [
    `${flag(p.country)} <b>MTProto Proxy</b> · ${p.country ?? "—"}`,
    `🔐 Type: ${p.type}`,
  ];
  if (p.asn_org) lines.push(`🏢 Operator: ${escapeHtml(p.asn_org)}`);
  if (p.uptime != null) lines.push(`📈 Our verified uptime: ${Math.round(p.uptime * 100)}% (${p.checks} checks)`);
  if (p.rtt_ms != null) lines.push(`⏱ Ping from our runner: ${p.rtt_ms}ms`);
  if (votes.up || votes.down) lines.push(`🗳 User feedback: 👍 ${votes.up} · 👎 ${votes.down}`);
  lines.push("", `👇 Tap the button below to connect, or copy the link:`, `<code>${tgLink(p)}</code>`);
  return lines.join("\n");
}

export function cardKeyboard(p, scope) {
  return {
    inline_keyboard: [
      [{ text: "🚀 Connect to proxy", url: tmeLink(p), style: "primary" }],
      [
        { text: "👍 Works", callback_data: `v:+:${p.key}` },
        { text: "👎 Dead", callback_data: `v:-:${p.key}` },
        { text: "⏭ Next", callback_data: `n:${scope}` },
      ],
      [{ text: "🏠 Main menu", callback_data: "m" }],
    ],
  };
}

const escapeHtml = (s) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const isAdmin = (env, uid) => (env.ADMIN_IDS ?? "").split(",").map((s) => s.trim()).includes(String(uid));

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

async function voteCounts(env, key) {
  if (!env.DB) return { up: 0, down: 0 };
  try {
    const row = await env.DB.prepare(
      "SELECT SUM(vote=1) AS up, SUM(vote=-1) AS down FROM votes WHERE proxy_key=?"
    ).bind(key).first();
    return { up: row?.up ?? 0, down: row?.down ?? 0 };
  } catch { return { up: 0, down: 0 }; }
}

async function recordVote(env, uid, key, vote) {
  if (!env.DB) return;
  try {
    await env.DB.prepare(
      "INSERT INTO votes(proxy_key,user_id,vote,ts) VALUES(?,?,?,?) ON CONFLICT(proxy_key,user_id) DO UPDATE SET vote=excluded.vote, ts=excluded.ts"
    ).bind(key, uid, vote, Math.floor(Date.now() / 1000)).run();
    await env.DB.prepare(
      "INSERT INTO users(id,first_seen,last_seen) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen"
    ).bind(uid, Math.floor(Date.now() / 1000), Math.floor(Date.now() / 1000)).run();
  } catch (e) { console.error("recordVote", e.message); }
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
  return sendMessage(env, chatId, cardText(p, await voteCounts(env, key)), { reply_markup: cardKeyboard(p, scope) });
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
    if (msg.text.startsWith("/start") || msg.text.startsWith("/menu")) {
      const pool = await getPool(env);
      return void (await sendMessage(env, chatId, menuText(pool), { reply_markup: mainKeyboard() }));
    }
    if (msg.text.startsWith("/admin")) {
      if (!isAdmin(env, uid)) return;
      const pool = await getPool(env);
      const dep = pool ? Math.round(dependencyRatio(pool, "radikal") * 100) : "—";
      const text = pool
        ? `🛠 <b>Proxiv3 panel</b>\n📦 Servers: ${pool.count}\n🕐 ${poolAgeText(pool)}\n🔗 Radikal dependency: ${dep}%\n📡 Feed source: ${pool.source}`
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
    if (data.startsWith("v:")) {
      const [, sign, key] = data.split(":");
      await recordVote(env, uid, key, sign === "+" ? 1 : -1);
      return void (await done(sign === "+" ? "Thanks! Noted 👍" : "Noted — try the next one 👎"));
    }
    if (data === "a:sync") {
      if (!isAdmin(env, uid)) return void (await done("No access", true));
      ctx?.waitUntil?.(syncPool(env).then((r) => sendMessage(env, chatId, r.ok ? `✅ Synced: ${r.count} servers` : `❌ Sync failed: ${r.error}`)));
      return void (await done("Sync started…"));
    }
    return void (await done());
  }
}
