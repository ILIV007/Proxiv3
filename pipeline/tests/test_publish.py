import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pool.fetch import SourceReport  # noqa: E402
from pool.links import Proxy  # noqa: E402
from pool.probe import ProbeResult  # noqa: E402
from pool.publish import build_feed, publish, weak_run  # noqa: E402
from pool.run import Record, RunResult  # noqa: E402
from pool.secret import Secret  # noqa: E402
from pool.state import State  # noqa: E402


def rec(server, ip, secret_hex, sources, ok=True, rtt=40, deep=False):
    p = Proxy(server, 443, Secret.from_link(secret_hex), frozenset(sources))
    r = Record(p, ip=ip, targets=[(ip, 443, p.secret)])
    r.rounds = [ProbeResult("dc", None, 5, rtt)] if ok else [ProbeResult("tcp", "tcp:timeout", 5, None)]
    r.deep_ok = deep
    return r


def test_build_feed_groups_aliases_and_counts_dependency():
    st = State()
    rows = [
        rec("a.example", "1.1.1.1", "ab" * 16, {"radikal"}),
        rec("b.example", "1.1.1.1", "cd" * 16, {"radikal", "tgmtproxy"}),  # alias of same server
        rec("c.example", "2.2.2.2", "ef" * 16, {"tgmtproxy"}),
        rec("d.example", "3.3.3.3", "ab" * 16, {"radikal"}, ok=False),     # unverified: excluded
    ]
    for r in rows:
        st.record(r.sid, r.verified, 1000, r.rtt)
    feed, exclusive = build_feed(rows, st)
    assert feed["schema"] == "tgpool/1"
    assert len(feed["proxies"]) == 2
    server1 = next(p for p in feed["proxies"] if p["ip"] == "1.1.1.1")
    assert server1["origins"] == ["radikal", "tgmtproxy"]
    assert server1["checks"] == 2  # two aliases recorded under one server id
    # no server is radikal-ONLY (server 1 also came from tgmtproxy) -> no exclusives
    assert exclusive["radikal"] == 0
    assert exclusive["tgmtproxy"] == 1


def test_weak_run_thresholds():
    assert weak_run(400, 754, 0.51) is True    # the 2026-11-04 weak runs
    assert weak_run(484, 754, 0.59) is True
    assert weak_run(714, 754, 0.95) is False   # healthy run, count holds
    assert weak_run(400, 754, 0.97) is False   # deep healthy: genuine shrink publishes
    assert weak_run(10, 50, 0.10) is False     # baseline too small to judge
    assert weak_run(400, 0, 0.10) is False     # no baseline at all
    assert weak_run(400, 754, None) is True    # deep disabled + collapse still trips


def _result(records, deep_enabled=True):
    rep = SourceReport(id="s1", url="https://example.invalid", found=len(records))
    return RunResult(records=records, reports=[rep], timings={}, per_round_ok=[],
                     targets=len(records), started=0, deep_enabled=deep_enabled)


def _records(n, deep_n):
    return [rec(f"s{i}.example", f"1.2.{i // 256}.{i % 256}", "ab" * 16, {"s1"},
                deep=i < deep_n) for i in range(n)]


def _prev_feed(tmp_path, count, updated=111):
    p = tmp_path / "prev" / "feed.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"schema": "tgpool/1", "updated_unix": updated,
                             "source": "proxiv3-pipeline",
                             "proxies": [{"server": str(i)} for i in range(count)]}))
    return str(p)


def test_publish_guard_keeps_previous_feed(tmp_path):
    prev = _prev_feed(tmp_path, 120)
    out = str(tmp_path / "out")
    # weak run: 150 verified links, only 60 survive deep -> 60 < 70% of 120, rate 0.40
    index = publish(_result(_records(150, 60)), State(), out, prev_feed_path=prev)
    assert index["guard"]["tripped"] is True
    assert index["guard"]["prev_servers"] == 120
    assert index["guard"]["new_servers"] == 60
    assert index["funnel"]["verified_servers"] == 60  # run report stays honest
    kept = json.loads(Path(out, "feed.json").read_text())
    assert kept["updated_unix"] == 111
    assert len(kept["proxies"]) == 120
    assert len(json.loads(Path(out, "proxies.json").read_text())) == 120
    assert Path(out, "state.json").exists()


def test_publish_healthy_run_replaces_feed(tmp_path):
    prev = _prev_feed(tmp_path, 120)
    out = str(tmp_path / "out")
    index = publish(_result(_records(130, 130)), State(), out, prev_feed_path=prev)
    assert index["guard"]["tripped"] is False
    feed = json.loads(Path(out, "feed.json").read_text())
    assert len(feed["proxies"]) == 130
    assert feed["updated_unix"] != 111


def test_publish_genuine_shrink_still_publishes(tmp_path):
    prev = _prev_feed(tmp_path, 120)
    out = str(tmp_path / "out")
    # count collapses but every survivor passed deep (rate 1.0): a source
    # really died — the smaller feed must publish, not freeze on the old one
    index = publish(_result(_records(60, 60)), State(), out, prev_feed_path=prev)
    assert index["guard"]["tripped"] is False
    assert len(json.loads(Path(out, "feed.json").read_text())["proxies"]) == 60


def test_publish_without_prev_feed_never_trips(tmp_path):
    out = str(tmp_path / "out")
    index = publish(_result(_records(150, 60)), State(), out)
    assert index["guard"] == {"tripped": False}
    assert len(json.loads(Path(out, "feed.json").read_text())["proxies"]) == 60
