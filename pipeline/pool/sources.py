"""Proxiv3 source registry — OURS.

These are public third-party lists/channels (nobody owns them). The starting
set mirrors the public sources measured on 2026-11-03 (see docs/PLAN_FA.md
§1): ranked by exclusive verified servers, the top few carry the pool.
A source stays in this list only while its exclusive yield justifies it.

kind: "list" (raw text/JSON of links) | "telegram" (t.me/s public preview)
      | "feed" (a proxies.json-style JSON feed, parsed like any other JSON)
"""
from __future__ import annotations

from dataclasses import dataclass

GH = "https://raw.githubusercontent.com/"
TG = "https://t.me/s/"


@dataclass(frozen=True)
class Source:
    id: str
    url: str
    kind: str = "list"


SOURCES: tuple[Source, ...] = (
    # Highest exclusive yield first (measured 2026-11-03).
    Source("weltimistar-archive", GH + "weltimistar777-crypto/MTProxy/refs/heads/main/archives.txt"),
    Source("tgmtproxy", GH + "tgmtproxy/telegram-mtproto-proxy-list/main/proxies.txt"),
    Source("onlymeoneme", GH + "onlymeoneme/mtproto/refs/heads/main/all_proxies_list.txt"),
    Source("dubblebyte", GH + "dubblebyte/free-mtproto-proxies/main/all_proxies.txt"),
    Source("tgproxypink", GH + "tgproxypink/telegram-proxy-list/main/mtproto.txt"),
    Source("vestranet", GH + "MustafaBaqer/VestraNet-Nodes/main/protocols/mtproto.txt"),
    Source("therealwh-eu", GH + "Therealwh/MTPproxyLIST/refs/heads/main/verified/proxy_eu_verified.txt"),
    Source("shablin", GH + "shablin/mtproto-proxy/refs/heads/main/data/valid_proxy.txt"),
    Source("solispirit", GH + "SoliSpirit/mtproto/master/all_proxies.txt"),
    Source("argh94", GH + "Argh94/Proxy-List/main/MTProto.txt"),
    Source("argh94-scraper", GH + "Argh94/telegram-proxy-scraper/refs/heads/main/proxy.txt"),
    Source("surfboard", GH + "Surfboardv2ray/TGProto/refs/heads/main/proxies.txt"),
    Source("ryazhapov", GH + "ryazhapov/tg-proxy-list/main/proxy.txt"),
    Source("airuop", GH + "Airuop/MTProtoCollector/main/proxy/mtproto.json"),
    Source("whitegram", GH + "whitegramseo/mtproxy-list/main/mtproto_proxies.json"),
    Source("weltimistar", GH + "weltimistar777-crypto/MTProxy/refs/heads/main/proxy.txt"),
    # Telegram channels (public web preview, no login).
    Source("tg-proxy_telegramt", TG + "proxy_telegramt", "telegram"),
    Source("tg-ProxyMTProto", TG + "ProxyMTProto", "telegram"),
    Source("tg-proxy_mtm", TG + "proxy_mtm", "telegram"),
    Source("tg-TelMTProto", TG + "TelMTProto", "telegram"),
    Source("tg-TProxyRU", TG + "TProxyRU", "telegram"),
    Source("tg-mtp4tg", TG + "mtp4tg", "telegram"),
    # The radikal project itself: ONE ordinary source among many (plan D8).
    # Its links enter our funnel and must pass OUR prober like everyone else's.
    Source("radikal", GH + "0xRadikal/Free-Telegram-Proxy/main/resilient/proxies.json", "feed"),
)
