"""Build the published outputs from a run: feed.json (tgpool/1, what the bot
consumes), proxies.json (same rows, bare), index.json (run report incl. the
dependency metric), state.json (persisted history)."""
from __future__ import annotations

import json
import os
import statistics
import time
from collections import Counter

from .state import server_id

# Weak-run publish guard: a run whose deep-verification rate collapsed
# (bad runner egress, a source outage) must not shrink a healthy published
# feed. Healthy runs (2026-11-04): deep rate ~0.95+, count ratio ~0.9+;
# weak runs: deep 0.51–0.59, count ratio 0.53–0.64. A count collapse with
# a HEALTHY deep rate is a genuine source shrink and still publishes.
GUARD_MIN_PREV = 100      # baseline too small to judge against
GUARD_MIN_RATIO = 0.7     # new feed must keep >= 70% of previous servers
GUARD_DEEP_RATE = 0.8     # deep rate under this = the run itself failed


def weak_run(new_count: int, prev_count: int, deep_rate: float | None) -> bool:
    if prev_count < GUARD_MIN_PREV:
        return False
    if new_count >= GUARD_MIN_RATIO * prev_count:
        return False
    return deep_rate is None or deep_rate < GUARD_DEEP_RATE


def build_feed(records, state, require_deep: bool = False) -> tuple[dict, dict]:
    """Group verified links by real server (ip, port); one row per server.
    With require_deep, a link must also have passed the full encrypted-
    session probe (deep.py) — handshake-verified alone is not published."""
    by_server: dict[tuple, list] = {}
    for r in records:
        if r.verified and r.ip and (r.deep_ok or not require_deep):
            by_server.setdefault((r.ip, r.proxy.port), []).append(r)

    rows, exclusive = [], Counter()
    for (ip, port), aliases in by_server.items():
        origins = sorted({s for a in aliases for s in a.proxy.sources})
        if len(origins) == 1:
            exclusive[origins[0]] += 1
        rep = min(aliases, key=lambda a: a.rtt if a.rtt is not None else 1 << 30)
        stats = state.stats(server_id(ip, port)) if state else {"uptime": None, "checks": 0}
        rtts = [a.rtt for a in aliases if a.rtt is not None]
        rows.append({
            "server": rep.proxy.server,
            "port": port,
            "secret": rep.proxy.secret.hex(),
            "type": rep.proxy.secret.kind,
            "ip": ip,
            "country": rep.country,
            "asn_org": rep.asn_org,
            "rtt_ms": int(statistics.median(rtts)) if rtts else None,
            "uptime": stats["uptime"],
            "checks": stats["checks"],
            "origins": origins,
        })
    rows.sort(key=lambda x: (-(x["uptime"] or 0), x["rtt_ms"] if x["rtt_ms"] is not None else 1 << 30))
    feed = {
        "schema": "tgpool/1",
        "updated_unix": int(time.time()),
        "source": "proxiv3-pipeline",
        "proxies": rows,
    }
    return feed, exclusive


def publish(result, state, out_dir: str, prev_feed_path: str | None = None) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    feed, exclusive = build_feed(result.records, state,
                                 require_deep=getattr(result, "deep_enabled", False))
    rows = feed["proxies"]

    found_by_source = Counter()
    for rep in result.reports:
        found_by_source[rep.id] = rep.found
    sources = [{
        "id": rep.id,
        "status": rep.status,
        "error": rep.error,
        "found": rep.found,
        "exclusive_verified_servers": exclusive[rep.id],
    } for rep in result.reports]

    verified_links = sum(1 for r in result.records if r.verified)
    deep_links = sum(1 for r in result.records if r.verified and r.deep_ok)
    deep_rate = (deep_links / verified_links) if (
        getattr(result, "deep_enabled", False) and verified_links) else None

    guard = {"tripped": False}
    prev_feed = None
    if prev_feed_path and os.path.isfile(prev_feed_path):
        try:
            with open(prev_feed_path, encoding="utf-8") as f:
                prev_feed = json.load(f)
        except (OSError, ValueError):
            prev_feed = None
    if prev_feed is not None:
        prev_count = len(prev_feed.get("proxies", []))
        guard = {
            "tripped": weak_run(len(rows), prev_count, deep_rate),
            "prev_servers": prev_count,
            "new_servers": len(rows),
            "deep_rate": round(deep_rate, 4) if deep_rate is not None else None,
        }
        if guard["tripped"]:
            guard["kept_feed_updated_unix"] = prev_feed.get("updated_unix")

    dep = (exclusive["radikal"] / len(rows)) if rows else 0.0
    index = {
        "updated_unix": feed["updated_unix"],
        "runner_seconds": result.timings,
        "funnel": {
            "links_collected": sum(found_by_source.values()),
            "unique_links": len(result.records),
            "targets_probed": result.targets,
            "per_round_ok": result.per_round_ok,
            "verified_links": verified_links,
            "deep_verified_links": deep_links,
            "deep_errors": getattr(result, "deep_errors", {}),
            "verified_servers": len(rows),
        },
        "types": dict(Counter(r["type"] for r in rows)),
        "countries": dict(Counter(r["country"] for r in rows if r["country"])),
        "dependency_radikal": round(dep, 4),
        "sources": sources,
        "guard": guard,
    }

    outputs = (("feed.json", feed), ("proxies.json", rows), ("index.json", index))
    if guard["tripped"]:
        # Weak run: the last good feed stays live. index.json above still
        # reports this run's funnel, so the collapse stays visible.
        outputs = (("feed.json", prev_feed),
                   ("proxies.json", prev_feed["proxies"]),
                   ("index.json", index))
    for name, obj in outputs:
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
    if state is not None:
        state.save(os.path.join(out_dir, "state.json"))
    return index
