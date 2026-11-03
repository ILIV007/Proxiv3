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


def publish(result, state, out_dir: str) -> dict:
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

    dep = (exclusive["radikal"] / len(rows)) if rows else 0.0
    index = {
        "updated_unix": feed["updated_unix"],
        "runner_seconds": result.timings,
        "funnel": {
            "links_collected": sum(found_by_source.values()),
            "unique_links": len(result.records),
            "targets_probed": result.targets,
            "per_round_ok": result.per_round_ok,
            "verified_links": sum(1 for r in result.records if r.verified),
            "deep_verified_links": sum(1 for r in result.records if r.verified and r.deep_ok),
            "deep_errors": getattr(result, "deep_errors", {}),
            "verified_servers": len(rows),
        },
        "types": dict(Counter(r["type"] for r in rows)),
        "countries": dict(Counter(r["country"] for r in rows if r["country"])),
        "dependency_radikal": round(dep, 4),
        "sources": sources,
    }

    for name, obj in (("feed.json", feed), ("proxies.json", rows), ("index.json", index)):
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, separators=(",", ":"))
    if state is not None:
        state.save(os.path.join(out_dir, "state.json"))
    return index
