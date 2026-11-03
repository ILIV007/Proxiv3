"""Source fetching — stdlib urllib in a thread pool (no aiohttp dependency).

Two hard rules learned from upstream bugs:
- read to EOF with a hard cap (a single .read(n) returns early on chunked
  responses and silently truncates big lists);
- a failed source is a report line, never a crashed run.
"""
from __future__ import annotations

import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .links import Proxy, extract

MAX_BYTES = 4 * 1024 * 1024
TIMEOUT = 30


@dataclass
class SourceReport:
    id: str
    url: str
    status: str = "ok"          # ok | error
    error: str | None = None
    found: int = 0
    proxies: list = field(default_factory=list)


def _read_capped(resp) -> bytes:
    chunks, total = [], 0
    while True:
        chunk = resp.read(65536)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > MAX_BYTES:
            raise ValueError("source too large")
        chunks.append(chunk)


def fetch_one(source) -> SourceReport:
    rep = SourceReport(source.id, source.url)
    try:
        req = urllib.request.Request(source.url, headers={"User-Agent": "Proxiv3-pipeline"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            text = _read_capped(resp).decode("utf-8", "replace")
        rep.proxies = extract(text)
        rep.found = len(rep.proxies)
    except Exception as e:  # noqa: BLE001 — per-source isolation is the point
        rep.status, rep.error = "error", f"{type(e).__name__}: {e}"[:200]
    return rep


def fetch_all(sources, workers: int = 12) -> list[SourceReport]:
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(fetch_one, sources))


def merge(reports: list[SourceReport]) -> dict[tuple, Proxy]:
    """Dedupe candidates by link identity, unioning their source ids."""
    pool: dict[tuple, Proxy] = {}
    for rep in reports:
        for p in rep.proxies:
            prev = pool.get(p.key)
            if prev is None:
                pool[p.key] = Proxy(p.server, p.port, p.secret, frozenset({rep.id}))
            else:
                pool[p.key] = Proxy(p.server, p.port, p.secret, prev.sources | {rep.id})
    return pool
