# Proxiv3 Worker (the Telegram bot)

Phase 0 per `docs/PLAN_FA.md`. Zero runtime dependencies; tests: `npm test` (node:test).

## One-time setup (after the Cloudflare account + bot exist)

```bash
cd worker
npx wrangler kv namespace create POOL          # put the id in wrangler.toml
npx wrangler d1 create proxiv3_db              # put the id in wrangler.toml
npx wrangler d1 execute proxiv3_db --file=schema.sql
npx wrangler secret put BOT_TOKEN
npx wrangler secret put WEBHOOK_SECRET         # any long random string
npx wrangler secret put SYNC_SECRET            # any long random string
# set ADMIN_IDS in wrangler.toml to the owner's Telegram user id
npx wrangler deploy
curl "https://api.telegram.org/bot<BOT_TOKEN>/setWebhook" \
  -d "url=https://proxiv3.<account>.workers.dev/webhook" \
  -d "secret_token=<WEBHOOK_SECRET>" \
  -d 'allowed_updates=["message","callback_query"]'
```

## How it runs

- `POST /webhook` — Telegram updates (secret header required, D1-deduped).
- `POST /sync` — our pipeline pushes a `tgpool/1` feed (Bearer `SYNC_SECRET`).
- Cron `*/30` — pool sync: `OWN_FEED_URL` if set, else the radikal bootstrap
  adapter while `PROVIDER_RADIKAL_ENABLED="true"`. Unchanged pools cost
  zero KV writes.
- The bot serves only the KV pool; a failed sync never erases the last good one.
