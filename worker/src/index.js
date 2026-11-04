// Proxiv3 worker entry: webhook + /sync + one cron (*/30).
// Phase 0 (see docs/PLAN_FA.md). No runtime dependencies.

import { handleUpdate } from "./bot.js";
import { syncPool } from "./sync.js";
import { validateFeed } from "./pool.js";
import { maybePostToChannel } from "./channel.js";
import { maybeDispatchPipeline } from "./trigger.js";

// D1 dedupe when bound (KV writes are too precious on the free tier).
async function firstTime(env, updateId) {
  if (!env.DB || updateId == null) return true;
  try {
    const r = await env.DB.prepare(
      "INSERT OR IGNORE INTO processed_updates(update_id, ts) VALUES(?,?)"
    ).bind(String(updateId), Math.floor(Date.now() / 1000)).run();
    return (r.meta?.changes ?? 1) > 0;
  } catch { return true; }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/") {
      // Deliberately bland: the public surface says nothing about what
      // this service does or how much data it holds.
      return new Response("ok");
    }

    if (request.method === "POST" && url.pathname === "/webhook") {
      if (!env.WEBHOOK_SECRET) return new Response("webhook secret not configured", { status: 500 });
      if (request.headers.get("x-telegram-bot-api-secret-token") !== env.WEBHOOK_SECRET)
        return new Response("unauthorized", { status: 401 });
      const update = await request.json().catch(() => null);
      if (!update) return new Response("bad update", { status: 400 });
      if (await firstTime(env, update.update_id)) ctx.waitUntil(handleUpdate(env, update, ctx));
      return new Response("ok");
    }

    // Our pipeline (Phase 2) pushes the feed here; until then this is how a
    // hand-built feed can be loaded without the radikal bootstrap.
    if (request.method === "POST" && url.pathname === "/sync") {
      if (!env.SYNC_SECRET) return new Response("not found", { status: 404 });
      if (request.headers.get("authorization") !== `Bearer ${env.SYNC_SECRET}`)
        return new Response("unauthorized", { status: 401 });
      const pool = validateFeed(await request.json().catch(() => null));
      if (!pool) return new Response("invalid feed", { status: 422 });
      await env.POOL.put("pool", JSON.stringify(pool));
      return Response.json({ ok: true, count: pool.count });
    }

    return new Response("not found", { status: 404 });
  },

  async scheduled(_event, env, ctx) {
    // One cron does both: refresh the pool, then (throttled) post to the
    // channel. Channel posting never blocks a sync and fails soft.
    ctx.waitUntil(
      syncPool(env)
        .then(() => maybePostToChannel(env))
        .catch((e) => console.error("scheduled", e.message))
    );
    // Independent of the sync/post chain and fail-soft: keep the
    // pipeline running on OUR cron, not GitHub's flaky schedule.
    ctx.waitUntil(
      maybeDispatchPipeline(env).catch((e) => console.error("dispatch", e.message))
    );
  },
};
