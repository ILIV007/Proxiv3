#!/usr/bin/env python3
"""Diagnostic cross-check (temporary, not part of the pipeline).

Question: can Telethon — a production MTProto client — complete auth key
creation + an encrypted ping through the same public proxies our deep
probe (pool/deep.py) rejects with transport error -404 / silence?
Run both against the SAME sample from the radikal resilient feed:

  telethon OK + deep FAIL  -> our wire has a bug; diff against Telethon.
  both FAIL                -> these proxies really are session-broken.
  both OK                  -> deep regressed only under pipeline conditions.

Prints one line per proxy and a summary; always exits 0.
"""
from __future__ import annotations

import asyncio
import json
import logging
import urllib.request
from collections import Counter

from telethon.network import MTProtoSender
from telethon.network.connection import (
    ConnectionTcpMTProxyIntermediate,
    ConnectionTcpMTProxyRandomizedIntermediate,
)
from telethon.tl.functions import PingRequest

from pool.deep import probe_deep
from pool.secret import Secret

FEED = ("https://raw.githubusercontent.com/0xRadikal/"
        "Free-Telegram-Proxy/main/resilient/proxies.json")
PER_KIND = 10


class Loggers(dict):
    def __missing__(self, key):
        return logging.getLogger(key)


LOGGERS = Loggers()
logging.disable(logging.WARNING)


async def telethon_check(item) -> str:
    host, port, secret = item["server"], item["port"], item["secret"]
    cls = (ConnectionTcpMTProxyRandomizedIntermediate
           if secret.startswith("dd") else ConnectionTcpMTProxyIntermediate)
    conn = cls(item.get("ip") or host, port, 2,
               loggers=LOGGERS, proxy=(host, port, secret))
    sender = MTProtoSender(None, loggers=LOGGERS, retries=1, delay=0,
                           auto_reconnect=False, connect_timeout=20)
    try:
        await asyncio.wait_for(sender.connect(conn), 25)
        pong = await asyncio.wait_for(
            sender.send(PingRequest(ping_id=0x1122334455667788)), 10)
        return f"OK({type(pong).__name__})"
    except Exception as e:  # noqa: BLE001 — diagnostic: report, never raise
        return f"FAIL({type(e).__name__}: {str(e)[:60]})"
    finally:
        try:
            await sender.disconnect()
        except Exception:  # noqa: BLE001
            pass


async def deep_check(item) -> str:
    try:
        secret = Secret.from_link(item["secret"])
    except Exception as e:  # noqa: BLE001
        return f"FAIL(secret: {e})"
    res = await probe_deep(item["server"], item["port"], secret, dc=2,
                           timeout=20.0, connect_host=item.get("ip"))
    if res.extra.get("deep"):
        return "OK(pong)"
    return f"FAIL({res.error or 'unknown'})"


async def one(item, sem) -> str:
    async with sem:
        kind = ("ee" if item["secret"].startswith("ee")
                else "dd" if item["secret"].startswith("dd") else "classic")
        deep = await deep_check(item)
        tele = await telethon_check(item)
        line = (f"XCHECK {item['server']}:{item['port']} kind={kind} "
                f"deep={deep} telethon={tele}")
        print(line, flush=True)
        return line


async def main() -> None:
    with urllib.request.urlopen(FEED, timeout=30) as r:
        items = json.load(r)
    sample = []
    for prefix in ("ee", "dd", ""):
        bucket = [i for i in items
                  if (i["secret"].startswith(prefix) if prefix
                      else not i["secret"].startswith(("ee", "dd")))]
        bucket.sort(key=lambda i: (-(i.get("uptime") or 0),
                                   i.get("rtt_ms") or 9999))
        sample += bucket[:PER_KIND]
    print(f"sample: {len(sample)} proxies", flush=True)
    sem = asyncio.Semaphore(5)
    lines = await asyncio.gather(*(one(i, sem) for i in sample))
    tele_ok = sum(" telethon=OK" in ln for ln in lines)
    deep_ok = sum(" deep=OK" in ln for ln in lines)
    both_ok = sum(" deep=OK" in ln and " telethon=OK" in ln for ln in lines)
    print(f"XCHECK SUMMARY total={len(lines)} telethon_ok={tele_ok} "
          f"deep_ok={deep_ok} both_ok={both_ok}", flush=True)
    kinds = Counter()
    for ln in lines:
        k = ln.split("kind=")[1].split()[0]
        kinds[(k, "telethon=OK" in ln, "deep=OK" in ln)] += 1
    for k in sorted(kinds):
        print("XCHECK BYKIND", k, kinds[k], flush=True)


if __name__ == "__main__":
    asyncio.run(main())
