"""Orchestration: collect → resolve → probe ×rounds → state → publish.

Adapted from the upstream pipeline design (MIT, see NOTICE): probe each
distinct (ip, port, secret) once per round, share results across the links
that resolve to it, and require a link to pass EVERY round and EVERY dialable
address before it is called verified.
"""
from __future__ import annotations

import asyncio
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .fetch import fetch_all, merge
from .netinfo import Geo, is_public, resolve_all
from .probe import ProbeResult, probe
from .sources import SOURCES
from .state import State, server_id

MAX_ADDRESSES = 64


@dataclass
class Config:
    rounds: int = 3
    gap: float = 20.0
    timeout: float = 8.0
    concurrency: int = 300
    per_ip: int = 12
    dc: int = 2


@dataclass
class Record:
    proxy: object                 # links.Proxy
    ip: str | None = None
    targets: list = field(default_factory=list)   # [(ip, port, Secret)]
    rounds: list = field(default_factory=list)    # [ProbeResult]
    reject: str | None = None
    country: str | None = None
    asn_org: str | None = None

    @property
    def verified(self) -> bool:
        return bool(self.rounds) and all(r.ok for r in self.rounds)

    @property
    def rtt(self) -> int | None:
        v = [r.rtt_ms for r in self.rounds if r.ok and r.rtt_ms is not None]
        return int(statistics.median(v)) if v else None

    @property
    def sid(self) -> str | None:
        return server_id(self.ip, self.proxy.port) if self.ip else None


def select_addresses(ips: list[str]):
    """Dialable addresses for one hostname, TDLib-style. Any non-public
    address in the answer rejects the link outright (SSRF/client safety)."""
    if not ips:
        return [], "dns"
    if not all(is_public(i) for i in ips):
        return [], "non-public-ip"
    v4 = [i for i in ips if ":" not in i]
    addrs = v4 or list(ips)
    if len(addrs) > MAX_ADDRESSES:
        return [], "too-many-addresses"
    return addrs, None


def _combine(results: list[ProbeResult]) -> ProbeResult:
    if all(r.ok for r in results):
        rtts = [r.rtt_ms for r in results if r.rtt_ms is not None]
        tcps = [r.tcp_ms for r in results if r.tcp_ms is not None]
        return ProbeResult("dc", None, max(tcps) if tcps else None, max(rtts) if rtts else None)
    order = {"none": 0, "tcp": 1, "tls": 2, "dc": 3}
    worst = min((r for r in results if not r.ok), key=lambda r: order[r.level])
    if any(r.ok for r in results):
        return ProbeResult(worst.level, "multi-ip:some-addresses-fail", worst.tcp_ms, None)
    return worst


def _tkey(t):
    return (t[0], t[1], t[2].raw)


async def _probe_targets(targets, cfg, prober=probe):
    sem = asyncio.Semaphore(cfg.concurrency)
    ip_sems = defaultdict(lambda: asyncio.Semaphore(cfg.per_ip))

    async def one(t):
        ip, port, secret = t
        async with sem, ip_sems[ip]:
            return t, await prober(ip, port, secret, dc=cfg.dc, timeout=cfg.timeout, connect_host=ip)

    return dict(await asyncio.gather(*(one(t) for t in targets)))


async def probe_records(records, cfg, prober=probe):
    alive = [r for r in records if r.targets]
    total_targets = len({_tkey(t) for r in alive for t in r.targets})
    per_round_ok = []
    for i in range(cfg.rounds):
        if not alive:
            per_round_ok.append(0)
            continue
        if i:
            await asyncio.sleep(cfg.gap)
        need = {_tkey(t): t for r in alive for t in r.targets}
        res = await _probe_targets(list(need.values()), cfg, prober)
        by_key = {_tkey(t): pr for t, pr in res.items()}
        per_round_ok.append(sum(1 for pr in by_key.values() if pr.ok))
        nxt = []
        for r in alive:
            combined = _combine([by_key[_tkey(t)] for t in r.targets])
            r.rounds.append(combined)
            if combined.ok:
                nxt.append(r)
        alive = nxt
    return per_round_ok, total_targets


@dataclass
class RunResult:
    records: list
    reports: list
    timings: dict
    per_round_ok: list
    targets: int
    started: int


def run(cfg: Config | None = None, state: State | None = None, sources=SOURCES,
        geo: Geo | None = None) -> RunResult:
    cfg = cfg or Config()
    geo = geo or Geo()
    started = int(time.time())
    timings = {}

    t = time.monotonic()
    reports = fetch_all(sources)
    pool = merge(reports)
    timings["fetch"] = round(time.monotonic() - t, 2)

    t = time.monotonic()
    resolved = resolve_all({p.server for p in pool.values()})
    timings["dns"] = round(time.monotonic() - t, 2)

    records = []
    for p in pool.values():
        addrs, reject = select_addresses(resolved.get(p.server, []))
        rec = Record(p, ip=addrs[0] if addrs else None)
        if reject:
            rec.reject = reject
        else:
            rec.targets = [(a, p.port, p.secret) for a in addrs]
        records.append(rec)

    t = time.monotonic()
    per_round_ok, n_targets = asyncio.run(probe_records(records, cfg))
    timings["probe"] = round(time.monotonic() - t, 2)

    for r in records:
        if r.ip:
            r.country = geo.country(r.ip)
            _, r.asn_org = geo.asn(r.ip)

    if state is not None:
        now = int(time.time())
        for r in records:
            if r.rounds and r.sid:
                state.record(r.sid, r.verified, now, r.rtt)
        found, ok = Counter(), Counter()
        for r in records:
            for s in r.proxy.sources:
                found[s] += 1
                ok[s] += r.verified
        for rep in reports:
            state.record_source(rep.id, found[rep.id], ok[rep.id], now)
        state.prune(now)

    return RunResult(records, reports, timings, per_round_ok, n_targets, started)
