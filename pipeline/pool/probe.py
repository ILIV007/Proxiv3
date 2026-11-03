"""FORKED from 0xRadikal/Free-Telegram-Proxy (MIT) — tgproxy/probe.py, 2026-11-03.
See NOTICE. Original docstring follows.

End-to-end MTProxy prober.

A proxy is only called *working* if it relays a real MTProto request to a real
Telegram datacenter and the datacenter's reply echoes a 128-bit nonce that we
generated a microsecond earlier. That cannot be faked by a generic TLS server,
an HTTP server, a port that merely accepts connections, or a proxy whose
secret we got wrong (each of these is an explicit negative control in tests/).

Proof levels (monotonic):
  tcp   TCP connection accepted
  tls   FakeTLS only: ServerHello HMAC verified with our secret
  dc    req_pq_multi relayed to DC, resPQ received with our nonce

Protocol ground truth:
  core.telegram.org/mtproto/mtproto-transports  (obfuscation, padded intermediate)
  tdlib  td/mtproto/TcpTransport.cpp            (init header, TLS record framing)
  tdlib  td/mtproto/TlsInit.cpp                 (hello padding to 517, HMAC check)
  alexbers/mtprotoproxy                          (server side, used in tests)
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .secret import Secret

REQ_PQ_MULTI = 0xBE7E8EF1
RES_PQ = 0x05162463
LEVELS = ("none", "tcp", "tls", "dc")

# First 4 bytes the obfuscated header must never start with (TcpTransport.cpp)
_BAD_FIRST_INT = {0x44414548, 0x54534F50, 0x20544547, 0x4954504F, 0xDDDDDDDD, 0xEEEEEEEE, 0x02010316}


def _ctr(key: bytes, iv: bytes):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def build_obfuscated_header(key16: bytes, padded: bool, dc: int, rnd=os.urandom):
    """Return (64-byte header, encryptor, decryptor) — TcpTransport.cpp init()."""
    while True:
        h = bytearray(rnd(64))
        if h[0] == 0xEF:
            continue
        if struct.unpack("<I", h[0:4])[0] in _BAD_FIRST_INT:
            continue
        if h[4:8] == b"\0\0\0\0":
            continue
        break
    h[56:60] = b"\xdd" * 4 if padded else b"\xee" * 4
    h[60:62] = struct.pack("<h", dc)
    rev = bytes(h[::-1])
    enc = _ctr(hashlib.sha256(bytes(h[8:40]) + key16).digest(), bytes(h[40:56]))
    dec = _ctr(hashlib.sha256(rev[8:40] + key16).digest(), rev[40:56])
    encrypted = enc.update(bytes(h))
    return bytes(h[:56]) + encrypted[56:64], enc, dec


def build_client_hello(key16: bytes, domain: bytes, unix_time: int | None = None, rnd=os.urandom):
    """FakeTLS ClientHello; random field = HMAC(secret, hello) ^ timestamp.

    Padded to a 517-byte record exactly like TlsInit.cpp (servers reject < 512).
    """
    def ext(t: int, data: bytes) -> bytes:
        return struct.pack(">HH", t, len(data)) + data

    exts = b"".join([
        ext(0x0000, struct.pack(">HBH", len(domain) + 3, 0, len(domain)) + domain),
        ext(0x0017, b""),
        ext(0xFF01, b"\x00"),
        ext(0x000A, bytes.fromhex("0006001d00170018")),
        ext(0x000B, b"\x01\x00"),
        ext(0x0010, bytes.fromhex("000c02683208687474702f312e31")),
        ext(0x000D, bytes.fromhex("000804030804040108070805")),
        ext(0x0033, struct.pack(">HHH", 36, 0x001D, 32) + rnd(32)),
        ext(0x002D, b"\x01\x01"),
        ext(0x002B, bytes.fromhex("0403040303")),
    ])
    ciphers = bytes.fromhex("130113021303c02bc02fc02cc030cca9cca8")
    head = b"\x03\x03" + b"\0" * 32 + b"\x20" + rnd(32) + struct.pack(">H", len(ciphers)) + ciphers + b"\x01\x00"
    # offset of the extensions block inside the full record:
    # 5 (record hdr) + 4 (handshake hdr) + len(head) + 2 (ext len)
    pad = 513 - (5 + 4 + len(head) + 2 + len(exts))
    if pad > 0:  # TlsInit.cpp: padding ext so that total size reaches 517
        exts += ext(0x0015, b"\0" * pad)
    body = head + struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    rec = b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs
    digest = bytearray(hmac.new(key16, rec, hashlib.sha256).digest())
    ts = struct.pack("<I", (int(time.time()) if unix_time is None else unix_time) & 0xFFFFFFFF)
    for i in range(4):
        digest[28 + i] ^= ts[i]
    return rec[:11] + bytes(digest) + rec[43:], bytes(digest)


def req_pq_multi(nonce: bytes) -> bytes:
    body = struct.pack("<I", REQ_PQ_MULTI) + nonce
    msg_id = (int(time.time() * 2**32) // 4) * 4
    return struct.pack("<qqi", 0, msg_id, len(body)) + body


@dataclass
class ProbeResult:
    level: str = "none"
    error: str | None = None
    tcp_ms: int | None = None
    rtt_ms: int | None = None  # request → resPQ through the proxy
    extra: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.level == "dc"


class _Fail(Exception):
    pass


async def _read_record(r: asyncio.StreamReader):
    hdr = await r.readexactly(5)
    return hdr, await r.readexactly(struct.unpack(">H", hdr[3:5])[0])


async def probe(host: str, port: int, secret: Secret, *, dc: int = 2, timeout: float = 8.0,
                connect_host: str | None = None) -> ProbeResult:
    """Probe one proxy. `connect_host` lets callers dial a pre-resolved IP."""
    res = ProbeResult()
    key = secret.key
    t0 = time.monotonic()
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(connect_host or host, port), timeout)
    except asyncio.TimeoutError:
        res.error = "tcp:timeout"
        return res
    except OSError as e:
        res.error = "tcp:" + (type(e).__name__)
        return res
    res.level = "tcp"
    res.tcp_ms = round((time.monotonic() - t0) * 1000)
    try:
        await asyncio.wait_for(_session(r, w, secret, key, dc, res), timeout)
    except asyncio.TimeoutError:
        res.error = f"timeout@{res.level}"
    except asyncio.IncompleteReadError:
        res.error = f"eof@{res.level}"
    except _Fail as e:
        res.error = str(e)
    except OSError as e:
        res.error = f"{type(e).__name__}@{res.level}"
    finally:
        w.close()
        try:
            await asyncio.wait_for(w.wait_closed(), 1)
        except Exception:  # noqa: BLE001 — closing is best-effort
            pass
    return res


async def _session(r, w, secret: Secret, key: bytes, dc: int, res: ProbeResult) -> None:
    tls = secret.emulate_tls
    if tls:
        hello, cdigest = build_client_hello(key, secret.domain)
        w.write(hello)
        await w.drain()
        # TlsInit::wait_hello_response — exact prefixes, then HMAC over all of it
        h1, p1 = await _read_record(r)
        if h1[:3] != b"\x16\x03\x03":
            raise _Fail("tls:bad-hello")
        h2, p2 = await _read_record(r)
        h3, p3 = await _read_record(r)
        if h2 + p2 != b"\x14\x03\x03\x00\x01\x01" or h3[:3] != b"\x17\x03\x03":
            raise _Fail("tls:bad-hello")
        resp = h1 + p1 + h2 + p2 + h3 + p3
        zeroed = resp[:11] + b"\0" * 32 + resp[43:]
        if not hmac.compare_digest(hmac.new(key, cdigest + zeroed, hashlib.sha256).digest(), resp[11:43]):
            raise _Fail("tls:hmac-mismatch")
        res.level = "tls"
    padded = secret.use_random_padding
    header, enc, dec = build_obfuscated_header(key, padded, dc)
    nonce = os.urandom(16)
    msg = req_pq_multi(nonce)
    pad = os.urandom(os.urandom(1)[0] % 16) if padded else b""
    payload = header + enc.update(struct.pack("<I", len(msg) + len(pad)) + msg + pad)
    if tls:
        w.write(b"\x14\x03\x03\x00\x01\x01\x17\x03\x03" + struct.pack(">H", len(payload)) + payload)
    else:
        w.write(payload)
    await w.drain()
    t1 = time.monotonic()
    buf = bytearray()

    async def need(n: int) -> bytes:
        nonlocal buf
        while len(buf) < n:
            if tls:
                h, p = await _read_record(r)
                if h[0] == 0x14:
                    continue
                if h[0] != 0x17:
                    raise _Fail("tls:unexpected-record")
                buf += dec.update(p)
            else:
                chunk = await r.read(4096)
                if not chunk:
                    raise asyncio.IncompleteReadError(b"", n)
                buf += dec.update(chunk)
        out, buf = bytes(buf[:n]), buf[n:]
        return out

    ln = struct.unpack("<I", await need(4))[0]
    if ln & 0x80000000 or ln < 4 or ln > 4096:
        raise _Fail("dc:bad-frame")
    data = await need(ln)
    if len(data) == 4:
        raise _Fail(f"dc:transport-error-{-struct.unpack('<i', data)[0]}")
    if len(data) < 40 or struct.unpack("<I", data[20:24])[0] != RES_PQ:
        raise _Fail("dc:unexpected-reply")
    if data[24:40] != nonce:
        raise _Fail("dc:nonce-mismatch")
    res.level = "dc"
    res.rtt_ms = round((time.monotonic() - t1) * 1000)
