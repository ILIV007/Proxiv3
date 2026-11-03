# Proxiv3 Pipeline — our own collector + MTProto verifier

Phases 1–2 of `docs/PLAN_FA.md`. This is what makes Proxiv3 independent:
the bot's feed comes from here, not from any external project.

## Run it

```bash
pip install -r requirements.txt
python -m pool --out ./out [--state state.json] [--rounds 3] [--gap 20]
# outputs: out/feed.json (tgpool/1) · proxies.json · index.json · state.json
```

## How it works

1. **Collect** — `pool/sources.py` is OUR registry of public lists/channels
   (plus the radikal feed as one ordinary source). Fetching is stdlib-only,
   read-to-EOF with a 4 MiB cap, per-source failure isolation.
2. **Resolve + guard** — DNS for every hostname; any non-public address in
   an answer rejects the link (SSRF/client safety).
3. **Probe** — every distinct (ip, port, secret) is probed once per round,
   shared across links. A link is *verified* only if it relays a real
   `req_pq_multi` to a Telegram datacenter and returns our nonce in **all**
   rounds, on **all** its dialable addresses.
4. **State** — per-server history (uptime over the last ≤96 runs) is our own
   data asset, persisted in `state.json` on the `data` branch.
5. **Publish** — `.github/workflows/pipeline.yml` runs every 30 min and
   force-pushes a single orphan commit to the `data` branch.

## Fork attribution

`pool/secret.py`, `pool/probe.py`, `pool/links.py` are forks of
0xRadikal/Free-Telegram-Proxy (MIT) — see `NOTICE` and `LICENSE.upstream`.
Everything else here is original Proxiv3 code.

## Known environment limit

The prober needs clean raw-TCP egress. Some sandboxed VMs transparently
mangle non-HTTP TCP: there, even the upstream prober gets `dc:bad-frame` /
`eof` for known-good proxies (verified 2026-11-03 by running both side by
side). GitHub Actions runners work — the CI `pipeline-smoke` job proves the
prober end-to-end on every PR.
