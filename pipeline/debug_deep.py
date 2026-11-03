"""One-off diagnostic (workflow_dispatch only): run probe + probe_deep
against a few collected proxies and print the exact deep-stage errors."""
import asyncio
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pool.deep import probe_deep  # noqa: E402
from pool.fetch import fetch_all, merge  # noqa: E402
from pool.netinfo import resolve_all  # noqa: E402
from pool.probe import probe  # noqa: E402
from pool.run import select_addresses  # noqa: E402
from pool.sources import SOURCES  # noqa: E402


async def main():
    reports = fetch_all(SOURCES)
    pool = merge(reports)
    proxies = list(pool.values())
    resolved = resolve_all({p.server for p in proxies})
    picked, kinds = [], Counter()
    for p in proxies:
        addrs, reject = select_addresses(resolved.get(p.server, []))
        if reject or not addrs:
            continue
        if kinds[p.secret.kind] >= 4:
            continue
        kinds[p.secret.kind] += 1
        picked.append((p, addrs[0]))
        if len(picked) >= 12:
            break
    print("picked:", [(p.secret.kind, p.server, p.port) for p, _ in picked], flush=True)
    for p, ip in picked:
        base = await probe(ip, p.port, p.secret, dc=2, timeout=8, connect_host=ip)
        print(f"PQ   {p.secret.kind:8} {p.server}:{p.port} -> {base.level} err={base.error}", flush=True)
        if not base.ok:
            continue
        deep = await probe_deep(ip, p.port, p.secret, dc=2, timeout=12, connect_host=ip)
        print(f"DEEP {p.secret.kind:8} {p.server}:{p.port} -> {deep.level} "
              f"deep={deep.extra.get('deep')} err={deep.error}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
