"""python -m pool --out DIR [--state state.json] [--rounds 3] [--gap 20]"""
from __future__ import annotations

import argparse
import os

from .netinfo import Geo
from .publish import publish
from .run import Config, run
from .state import State


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--state", default=None, help="previous state.json (read + republished)")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--gap", type=float, default=20.0)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--geo-dir", default=".cache", help="dir holding dbip-*.mmdb (optional)")
    a = ap.parse_args()

    state = State.load(a.state) if a.state else State()
    geo = Geo(
        os.path.join(a.geo_dir, "dbip-country-lite.mmdb") if os.path.isdir(a.geo_dir) else None,
        os.path.join(a.geo_dir, "dbip-asn-lite.mmdb") if os.path.isdir(a.geo_dir) else None,
    )
    result = run(Config(rounds=a.rounds, gap=a.gap, timeout=a.timeout), state=state, geo=geo)
    index = publish(result, state, a.out)
    f = index["funnel"]
    print(f"collected={f['links_collected']} unique={f['unique_links']} targets={f['targets_probed']} "
          f"verified_links={f['verified_links']} servers={f['verified_servers']} "
          f"dependency_radikal={index['dependency_radikal']:.2%} timings={result.timings}")


if __name__ == "__main__":
    main()
