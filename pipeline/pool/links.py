"""FORKED from 0xRadikal/Free-Telegram-Proxy (MIT) — tgproxy/links.py, 2026-11-03.
See NOTICE. Original docstring follows.

Proxy-link extraction and canonical link building.

Query parsing mirrors TDLib so that what we accept is exactly what a tap on
the link would accept in the official app:

  tdutils/td/utils/HttpUrl.cpp  parse_url_query: split on '&', split(k, '=')
                                 at the first '=', url_decode(.., plus_as_space)
                                 first occurrence of a key wins (find_if)
  tdutils/td/utils/misc.cpp     url_decode: '%XY' only if both hex digits
                                 exist, otherwise the '%' is kept literally
  tdutils/td/utils/misc.h       to_integer<int32>: optional '-', then leading
                                 digits; trailing garbage is ignored
  td/telegram/LinkManager.cpp   proxy?server=&port=&secret=  →
                                 is_valid_proxy_server (1..255 bytes, UTF-8)
                                 0 < port < 65536, ProxySecret::from_link ok
"""
from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field

from .secret import Secret, SecretError

# Any of the three proxy URL forms TDLib recognises for MTProto.
_LINK_RE = re.compile(
    r"(?:tg://proxy|(?:https?://)?(?:www\.)?(?:t\.me|telegram\.me|telegram\.dog)/proxy)\?"
    r"[^\s\"'<>`\\\]\[(){}|]+",
    re.IGNORECASE,
)
_HEX = "0123456789abcdefABCDEF"


def url_encode(s: str) -> str:
    """td::url_encode — keep ASCII alnum and `-._~`, percent-encode every other
    UTF-8 byte. TDLib's own get_proxy_link encodes the server this way, so a
    server containing `&`, `#`, `%`, space or a newline still round-trips."""
    out = []
    for b in s.encode("utf-8", "surrogateescape"):
        c = chr(b)
        if c.isascii() and (c.isalnum() or c in "-._~"):
            out.append(c)
        else:
            out.append(f"%{b:02X}")
    return "".join(out)


def url_decode(s: str, plus_as_space: bool = True) -> str:
    """td::url_decode, operating on UTF-8 bytes like the C++ does."""
    src = s.encode("utf-8", "surrogateescape")
    out = bytearray()
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        # C++: `from_i + 2 < n` — i.e. both hex digits must exist.
        if c == 0x25 and i + 2 < n and chr(src[i + 1]) in _HEX and chr(src[i + 2]) in _HEX:
            out.append(int(src[i + 1:i + 3], 16))
            i += 3
            continue
        out.append(0x20 if plus_as_space and c == 0x2B else c)
        i += 1
    return out.decode("utf-8", "surrogateescape")


def parse_query(query: str) -> dict[str, str]:
    """td::parse_url_query args; first key occurrence wins."""
    query = query.split("#", 1)[0]
    args: dict[str, str] = {}
    for part in query.split("&"):
        if part == "":
            continue
        k, _, v = part.partition("=")
        key = url_decode(k, True)
        if key and key not in args:
            args[key] = url_decode(v, True)
    return args


def to_int32(s: str) -> int:
    """td::to_integer<int32> for the values that matter (port).

    Leading digits only; wraps like the C++ unsigned arithmetic. Ports are
    validated with 0 < port < 65536 afterwards, so exotic wraps are rejected
    anyway — but we keep the semantics exact.
    """
    neg = s.startswith("-")
    i = 1 if neg else 0
    v = 0
    while i < len(s) and "0" <= s[i] <= "9":
        v = (v * 10 + ord(s[i]) - 48) & 0xFFFFFFFF
        i += 1
    if v > 0x7FFFFFFF:
        v = (~v + 1) & 0xFFFFFFFF
        neg = not neg
        if v > 0x7FFFFFFF:
            return -0x80000000
    return -v if neg else v


def _valid_server(server: str) -> bool:
    b = server.encode("utf-8", "surrogateescape")
    if not b or len(b) > 255:
        return False
    try:
        b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


@dataclass(frozen=True)
class Proxy:
    """One MTProxy endpoint, identity = (server, port, secret bytes)."""

    server: str
    port: int
    secret: Secret
    # where we saw it (source ids); not part of identity
    sources: frozenset = field(default=frozenset(), compare=False, hash=False)

    @property
    def key(self) -> tuple:
        return (self.server, self.port, self.secret.raw)

    def tg_link(self) -> str:
        return f"tg://proxy?server={url_encode(self.server)}&port={self.port}&secret={self.secret.hex()}"

    def tme_link(self) -> str:
        return f"https://t.me/proxy?server={url_encode(self.server)}&port={self.port}&secret={self.secret.hex()}"


def normalize_server(server: str) -> str:
    """Canonical host for dedup.

    DNS names are case-insensitive and a trailing dot is the FQDN root, so
    `Host.Example.` and `host.example` are the same server. IPv6 literals may
    arrive bracketed. Nothing else is altered (no IDNA guessing).
    """
    s = server.strip()
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    if s.endswith(".") and not s.endswith(".."):
        s = s[:-1]
    return s.lower()


def from_args(server: str | None, port, secret: str | None) -> Proxy | None:
    """Validate a (server, port, secret) triple the way LinkManager does."""
    if server is None or port is None or secret is None:
        return None
    server = str(server)
    p = port if isinstance(port, int) and not isinstance(port, bool) else to_int32(str(port))
    if not _valid_server(server) or not (0 < p < 65536):
        return None
    try:
        sec = Secret.from_link(str(secret))
    except SecretError:
        return None
    s = normalize_server(server)
    if not s:
        return None
    return Proxy(s, p, sec)


def parse_link(link: str) -> Proxy | None:
    if "?" not in link:
        return None
    a = parse_query(link.split("?", 1)[1])
    return from_args(a.get("server"), a.get("port"), a.get("secret"))


def _walk_json(root, out: list) -> None:
    """Depth-first, document order, iterative: a hostile source nesting
    100 000 arrays must not hit Python's recursion limit."""
    stack = [root]
    while stack:
        obj = stack.pop()
        if isinstance(obj, dict):
            q = obj.get("query") if isinstance(obj.get("query"), dict) else obj
            server = q.get("server", q.get("host"))
            if server is not None and q.get("port") is not None and q.get("secret") is not None:
                px = from_args(server, q.get("port"), q.get("secret"))
                if px:
                    out.append(px)
                    continue
            stack.extend(reversed(list(obj.values())))
        elif isinstance(obj, list):
            stack.extend(reversed(obj))
        elif isinstance(obj, str) and "proxy?" in obj:
            out.extend(extract_text(obj))


def extract_text(text: str) -> list[Proxy]:
    out = []
    # Telegram's web preview (t.me/s/) HTML-escapes '&' as '&amp;'
    for m in _LINK_RE.finditer(html.unescape(text)):
        px = parse_link(m.group(0))
        if px:
            out.append(px)
    return out


def extract(blob: str) -> list[Proxy]:
    """Pull every valid proxy out of text, HTML, or JSON."""
    s = blob.lstrip("\ufeff").strip()
    if s[:1] in "[{":
        try:
            out: list[Proxy] = []
            _walk_json(json.loads(s), out)
            return out
        except (ValueError, RecursionError):  # not JSON / nested past the C decoder limit
            pass
    return extract_text(s)
