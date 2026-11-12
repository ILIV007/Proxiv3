# Proxiv3

**Telegram MTProto proxy distribution bot + our own verification pipeline.**

- 🤖 Bot + channel: **@Proxiv3** (Telegram)
- ☁️ Bot runtime: a single Cloudflare Worker (free plan) + KV + D1
- 🔎 Pipeline: our own collector + MTProto verifier on GitHub Actions — see [docs/PLAN_FA.md](docs/PLAN_FA.md)
- 🎯 Design rule: **minimum dependency** on any external project. External lists (incl. Free-Telegram-Proxy) are ordinary sources in our registry, re-verified by our own prober; the bot serves only our own feed.

## Layout (grows phase by phase, per the plan)

```
worker/     Cloudflare Worker — the Telegram bot (Phase 0)
pipeline/   Python collector + MTProto prober (Phases 1–2)
data/       Published pool output (generated; do not hand-edit)
docs/       Plan and notes
```

## Status

✅ Live — bot [@Prox_IVbot](https://t.me/Prox_IVbot) and channel [@Proxiv3](https://t.me/Proxiv3) are running on a single Cloudflare Worker (free plan) + KV + D1. Our own collector + MTProto verifier pipeline runs on GitHub Actions and publishes the pool every 30 minutes; the bot serves only our own verified feed.

License: MIT
