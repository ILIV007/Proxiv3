// Bot update handling. State lives in KV (pool + per-user recents + rate
// limits) and, when bound, D1 (users + votes). Everything fails soft:
// no KV pool yet -> friendly "syncing" reply; no D1 -> votes are skipped.

import { flag, tmeLink, tgLink, dependencyRatio } from "./pool.js";
import { sendMessage, editMessageText, answerCallback } from "./telegram.js";
import { syncPool } from "./sync.js";

const TYPE_FA = { classic: "کلاسیک", secure: "امن (dd)", faketls: "FakeTLS (ee)" };
const WARNING =
  "⚠️ پروکسی‌های عمومی رایگان‌اند و اپراتور هر پروکسی آی‌پی شما را می‌بیند و ممکن است کانال تبلیغاتی نشان دهد. برای حساب‌های حساس استفاده نکنید.";

export function poolAgeText(pool, now = Date.now()) {
  if (!pool?.updated_unix) return "هنوز همگام‌سازی نشده";
  const mins = Math.max(0, Math.round(now / 1000 / 60 - pool.updated_unix / 60));
  if (mins < 60) return `${mins} دقیقه پیش به‌روز شده`;
  return `${Math.floor(mins / 60)} ساعت و ${mins % 60} دقیقه پیش به‌روز شده`;
}

export function menuText(pool) {
  const head = pool
    ? `🛡 <b>Proxiv3</b> — پروکسی‌های MTProto تأییدشده\n📦 استخر فعلی: <b>${pool.count}</b> سرور · ${poolAgeText(pool)}`
    : "🛡 <b>Proxiv3</b>\n⏳ استخر در حال همگام‌سازی است؛ یک دقیقه دیگر دوباره تلاش کنید.";
  return `${head}\n\n${WARNING}`;
}

export function mainKeyboard() {
  return {
    inline_keyboard: [
      [
        { text: "🎲 پروکسی تصادفی", callback_data: "t:all" },
        { text: "🛡 پایدارترین‌ها", callback_data: "t:stable" },
      ],
      [
        { text: "⚡ سریع‌ترین‌ها", callback_data: "t:fast" },
        { text: "🎭 FakeTLS", callback_data: "t:faketls" },
      ],
      [{ text: "🌍 بر اساس کشور", callback_data: "cc" }],
    ],
  };
}

export function cardText(p, votes = { up: 0, down: 0 }) {
  const lines = [
    `${flag(p.country)} <b>پروکسی MTProto</b> · ${p.country ?? "—"}`,
    `🔐 نوع: ${TYPE_FA[p.type] ?? p.type}`,
  ];
  if (p.asn_org) lines.push(`🏢 اپراتور: ${escapeHtml(p.asn_org)}`);
  if (p.uptime != null) lines.push(`📈 آپتایم تأیید ما: ${Math.round(p.uptime * 100)}٪ (${p.checks} چک)`);
  if (p.rtt_ms != null) lines.push(`⏱ پینگ از رانر ما: ${p.rtt_ms}ms`);
  if (votes.up || votes.down) lines.push(`🗳 بازخورد کاربران: 👍 ${votes.up} · 👎 ${votes.down}`);
  lines.push("", `👇 برای اتصال دکمه‌ی زیر را بزنید، یا لینک را کپی کنید:`, `<code>${tgLink(p)}</code>`);
  return lines.join("\n");
}

export function cardKeyboard(p, scope) {
  return {
    inline_keyboard: [
      [{ text: "🚀 اتصال به پروکسی", url: tmeLink(p) }],
      [
        { text: "👍 کار کرد", callback_data: `v:+:${p.key}` },
        { text: "👎 کار نکرد", callback_data: `v:-:${p.key}` },
        { text: "⏭ بعدی", callback_data: `n:${scope}` },
      ],
      [{ text: "🏠 منوی اصلی", callback_data: "m" }],
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
  if (!key) return sendMessage(env, chatId, "در این دسته فعلاً پروکسی‌ای نیست؛ دسته‌ی دیگری را امتحان کنید.", { reply_markup: mainKeyboard() });
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
        ? `🛠 <b>پنل Proxiv3</b>\n📦 سرورها: ${pool.count}\n🕐 ${poolAgeText(pool)}\n🔗 وابستگی به رادیکال: ${dep}٪\n📡 منبع فید: ${pool.source}`
        : "🛠 استخر هنوز خالی است.";
      return void (await sendMessage(env, chatId, text, {
        reply_markup: { inline_keyboard: [[{ text: "🔄 سینک فوری", callback_data: "a:sync" }]] },
      }));
    }
    return;
  }

  if (cb) {
    const chatId = cb.message.chat.id;
    const messageId = cb.message.message_id;
    const data = cb.data ?? "";
    if (await rateLimited(env, uid)) return void (await answerCallback(env, cb.id, "کمی آرام‌تر! چند دقیقه دیگر تلاش کنید.", true));
    const done = async (text = "") => answerCallback(env, cb.id, text);

    if (data === "m") {
      const pool = await getPool(env);
      await editMessageText(env, chatId, messageId, menuText(pool), { reply_markup: mainKeyboard() });
      return void (await done());
    }
    if (data === "cc") {
      const pool = await getPool(env);
      if (!pool) return void (await done("استخر هنوز آماده نیست"));
      const top = Object.entries(pool.countries).sort((a, b) => b[1].length - a[1].length).slice(0, 12);
      const rows = [];
      for (let i = 0; i < top.length; i += 3)
        rows.push(top.slice(i, i + 3).map(([cc, ks]) => ({ text: `${flag(cc)} ${cc} (${ks.length})`, callback_data: `c:${cc}` })));
      rows.push([{ text: "🏠 منوی اصلی", callback_data: "m" }]);
      await editMessageText(env, chatId, messageId, "🌍 کشور را انتخاب کنید:", { reply_markup: { inline_keyboard: rows } });
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
      return void (await done(sign === "+" ? "ممنون! ثبت شد 👍" : "ثبت شد؛ بعدی را امتحان کنید 👎"));
    }
    if (data === "a:sync") {
      if (!isAdmin(env, uid)) return void (await done("دسترسی ندارید", true));
      ctx?.waitUntil?.(syncPool(env).then((r) => sendMessage(env, chatId, r.ok ? `✅ سینک شد: ${r.count} سرور` : `❌ سینک ناموفق: ${r.error}`)));
      return void (await done("سینک شروع شد…"));
    }
    return void (await done());
  }
}
