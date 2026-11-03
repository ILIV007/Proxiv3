import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pool.links import Proxy  # noqa: E402
from pool.probe import ProbeResult  # noqa: E402
from pool.publish import build_feed  # noqa: E402
from pool.run import Record  # noqa: E402
from pool.secret import Secret  # noqa: E402
from pool.state import State  # noqa: E402


def rec(server, ip, secret_hex, sources, ok=True, rtt=40):
    p = Proxy(server, 443, Secret.from_link(secret_hex), frozenset(sources))
    r = Record(p, ip=ip, targets=[(ip, 443, p.secret)])
    r.rounds = [ProbeResult("dc", None, 5, rtt)] if ok else [ProbeResult("tcp", "tcp:timeout", 5, None)]
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
