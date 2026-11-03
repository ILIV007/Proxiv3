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

🚧 Prerequisites stage — Cloudflare account + Telegram bot tokens pending (delivered via secure vault).
✅ Phase 0 code is written and unit-tested: the Worker bot (menus, proxy cards, votes,
admin panel with the dependency metric), the `tgpool/1` feed contract, the radikal bootstrap
adapter behind a flag, `/sync` ingestion, and the `*/30` cron sync. Not yet deployed.
✅ Phases 1–2 code is written and unit-tested: our own pipeline (`pipeline/`) — source registry,
collector, MTProto prober (MIT fork, see `pipeline/NOTICE`), state/history, and a GitHub Actions
workflow publishing the feed to the `data` branch every 30 min. End-to-end prober validation
runs in CI (`pipeline-smoke`), because some sandboxes mangle raw TCP egress.

License: MIT
