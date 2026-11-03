"""FORKED from 0xRadikal/Free-Telegram-Proxy (MIT) — tgproxy/secret.py, 2026-11-03.
Kept byte-faithful to TDLib semantics; see NOTICE. Original docstring follows.

MTProxy secret parsing — a line-by-line port of TDLib's rules.

Why port instead of "be lenient": a secret that *we* accept but the official
client rejects would be published as working and then fail on every phone.
A secret that we reject but the client accepts is a lost proxy. Both are bugs,
so the only correct behaviour is to match the client byte for byte.

Ground truth (tdlib/td, master):
  td/mtproto/ProxySecret.cpp   from_link / from_binary
  td/mtproto/ProxySecret.h     MAX_DOMAIN_LENGTH = 182, emulate_tls, get_domain
  tdutils/td/utils/misc.cpp    hex_decode
  tdutils/td/utils/base64.cpp  base64_decode / base64url_decode (strict padding)

The test-suite cross-checks this module against the real TDLib binary
(tests/test_secret.py, `tdjson` oracle) on every secret we have ever collected.
"""
from __future__ import annotations

from dataclasses import dataclass

MAX_DOMAIN_LENGTH = 182  # ProxySecret.h

_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_TABLE = {False: {c: i for i, c in enumerate(_B64)}, True: {c: i for i, c in enumerate(_B64URL)}}


class SecretError(ValueError):
    """Raised exactly where TDLib returns an error Status."""


def _hex_decode(s: str) -> bytes:
    if len(s) % 2:
        raise SecretError("Wrong hex string length")
    try:
        # bytes.fromhex skips whitespace; TDLib does not — so reject it explicitly.
        if any(c not in "0123456789abcdefABCDEF" for c in s):
            raise ValueError
        return bytes.fromhex(s)
    except ValueError:
        raise SecretError("Wrong hex string") from None


def _base64_decode(s: str, is_url: bool) -> bytes:
    # base64_drop_padding<is_url>
    padding = 0
    while s.endswith("="):
        s = s[:-1]
        padding += 1
    if padding >= 3:
        raise SecretError("Wrong string padding")
    if (not is_url or padding > 0) and (len(s) + padding) & 3:
        raise SecretError("Wrong padding length")
    if is_url and (len(s) & 3) == 1:
        raise SecretError("Wrong string length")
    table = _TABLE[is_url]
    out = bytearray()
    i = 0
    while i < len(s):
        left = min(len(s) - i, 4)
        c = 0
        for t in range(left):
            v = table.get(s[i])
            i += 1
            if v is None:
                raise SecretError("Wrong character in the string")
            c |= v << ((3 - t) * 6)
        out.append((c >> 16) & 0xFF)
        if left == 2:
            if c & 0xFFFF:
                raise SecretError("Wrong padding in the string")
        else:
            out.append((c >> 8) & 0xFF)
            if left == 3:
                if c & 0xFF:
                    raise SecretError("Wrong padding in the string")
            else:
                out.append(c & 0xFF)
    return bytes(out)


def _base64url_encode(b: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


@dataclass(frozen=True)
class Secret:
    """A validated MTProxy secret.

    raw     the full binary secret (16 / 17 / 18..199 bytes)
    """

    raw: bytes

    # ------------------------------------------------------------ factories
    @classmethod
    def from_link(cls, encoded: str, truncate_if_needed: bool = False) -> "Secret":
        """ProxySecret::from_link — hex, then base64url, then base64."""
        for decode in (_hex_decode, lambda s: _base64_decode(s, True), lambda s: _base64_decode(s, False)):
            try:
                raw = decode(encoded)
                break
            except SecretError:
                continue
        else:
            raise SecretError("Wrong proxy secret")
        return cls.from_binary(raw, truncate_if_needed)

    @classmethod
    def from_binary(cls, raw: bytes, truncate_if_needed: bool = False) -> "Secret":
        if len(raw) > 17 + MAX_DOMAIN_LENGTH:
            if truncate_if_needed:
                raw = raw[: 17 + MAX_DOMAIN_LENGTH]
            else:
                raise SecretError("Too long secret")
        if len(raw) == 16 or (len(raw) == 17 and raw[0] == 0xDD) or (len(raw) >= 18 and raw[0] == 0xEE):
            return cls(raw)
        if len(raw) < 16:
            raise SecretError("Wrong proxy secret")
        raise SecretError("Unsupported proxy secret")

    # ------------------------------------------------------------ properties
    @property
    def key(self) -> bytes:
        """The 16-byte key used for obfuscation / FakeTLS HMAC."""
        return self.raw[1:17] if len(self.raw) >= 17 else self.raw

    @property
    def use_random_padding(self) -> bool:  # ProxySecret::use_random_padding
        return len(self.raw) >= 17

    @property
    def emulate_tls(self) -> bool:  # ProxySecret::emulate_tls
        return len(self.raw) >= 17 and self.raw[0] == 0xEE

    @property
    def domain(self) -> bytes:
        """FakeTLS SNI. Raw bytes — TDLib does not require ASCII (see docs)."""
        if not self.emulate_tls:
            raise SecretError("not a FakeTLS secret")
        return self.raw[17:]

    @property
    def kind(self) -> str:
        """'faketls' (ee) | 'secure' (dd) | 'classic' (16-byte)."""
        if self.emulate_tls:
            return "faketls"
        if self.use_random_padding:
            return "secure"
        return "classic"

    @property
    def domain_text(self) -> str | None:
        """Printable SNI for humans; None if the domain isn't clean ASCII."""
        if not self.emulate_tls:
            return None
        try:
            d = self.domain.decode("ascii")
        except UnicodeDecodeError:
            return None
        return d if d.isprintable() else None

    def encoded(self) -> str:
        """ProxySecret::get_encoded_secret — the canonical form clients emit."""
        if self.emulate_tls:
            return _base64url_encode(self.raw)
        return self.raw.hex()

    def hex(self) -> str:
        """Hex form — accepted by every client version, used in published links."""
        return self.raw.hex()
