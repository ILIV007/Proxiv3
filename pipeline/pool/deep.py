"""Deep session verification — Proxiv3's own code (not part of the MIT fork).

The forked prober (probe.py) proves a proxy relays one unauthenticated
req_pq to a real Telegram DC and echoes our nonce. Necessary, but not
sufficient: a handshake is not a working session (the lesson Aether's
prober is built on, and the root of Iliya's "half of them don't ping"
report). probe_deep() continues on the SAME connection and performs the
full client bootstrap:

    req_pq -> factorize pq -> req_DH_params (RSA_PAD) ->
    server_DH_inner_data -> set_client_DH_params -> dh_gen_ok ->
    auth key -> first ENCRYPTED message (ping) -> pong with our ping_id.

Only a proxy that sustains a real encrypted MTProto session passes.

Ground truth: core.telegram.org/mtproto/auth_key and
/mtproto/description (fetched 2026-11-03). The RSA keys are Telegram's
published DC keys (the same table the official Android client ships,
via Telethon's crypto/rsa.py); fingerprints are computed from the keys
here and pinned by tests — never trusted from the wire.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import math
import os
import struct
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .probe import ProbeResult, _read_record, build_client_hello, build_obfuscated_header, req_pq_multi
from .secret import Secret

# ---------------------------------------------------------------- RSA keys
_PEMS = [
    """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""",
]


def _der_ints(der: bytes) -> tuple[int, int]:
    """Parse a PKCS#1 RSAPublicKey SEQUENCE of two INTEGERs (n, e)."""
    def read_len(b, i):
        n = b[i]; i += 1
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(b[i:i + k], "big"); i += k
        return n, i
    assert der[0] == 0x30
    _, i = read_len(der, 1)
    out = []
    for _ in range(2):
        assert der[i] == 0x02
        ln, i = read_len(der, i + 1)
        out.append(int.from_bytes(der[i:i + ln], "big"))
        i += ln
    return out[0], out[1]


def _tl_bytes(b: bytes) -> bytes:
    if len(b) < 254:
        s = bytes([len(b)]) + b
    else:
        s = b"\xfe" + len(b).to_bytes(3, "little") + b
    return s + b"\0" * (-len(s) % 4)


def fingerprint(n: int, e: int) -> int:
    """64 lower-order bits of SHA1 over the bare rsa_public_key TL form."""
    nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
    eb = e.to_bytes((e.bit_length() + 7) // 8, "big")
    return struct.unpack("<Q", hashlib.sha1(_tl_bytes(nb) + _tl_bytes(eb)).digest()[-8:])[0]


def _load_keys() -> dict[int, tuple[int, int]]:
    import base64
    keys = {}
    for pem in _PEMS:
        n, e = _der_ints(base64.b64decode("".join(pem.split())))
        keys[fingerprint(n, e)] = (n, e)
    return keys


SERVER_KEYS: dict[int, tuple[int, int]] = _load_keys()

# ---------------------------------------------------------------- TL helpers

def tl_string(b: bytes) -> bytes:
    return _tl_bytes(b)


def parse_tl_string(buf: bytes, off: int) -> tuple[bytes, int]:
    first = buf[off]
    if first == 0xFE:
        ln = int.from_bytes(buf[off + 1:off + 4], "little")
        start, hdr = off + 4, 4
    else:
        ln = first
        start, hdr = off + 1, 1
    data = buf[start:start + ln]
    if len(data) != ln:
        raise ValueError("short tl string")
    total = hdr + ln
    return data, off + total + (-total % 4)


def _msg_id() -> int:
    return (int(time.time() * 2**32) // 4) * 4


# ---------------------------------------------------------------- pq factor

def _pollard(n: int) -> int:
    if n % 2 == 0:
        return 2
    import random
    rnd = random.Random(n)
    while True:
        x = rnd.randrange(2, n)
        c = rnd.randrange(1, n)
        y, d = x, 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
        if d != n:
            return d


def factorize(pq: int) -> tuple[int, int]:
    """Split pq into (p, q) with p < q — the DH proof of work."""
    for small in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if pq % small == 0:
            p, q = small, pq // small
            return (p, q) if p < q else (q, p)
    d = _pollard(pq)
    p, q = d, pq // d
    return (p, q) if p < q else (q, p)


# ---------------------------------------------------------------- AES IGE

def _ecb(key: bytes):
    return Cipher(algorithms.AES(key), modes.ECB())


def aes_ige_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    assert len(data) % 16 == 0 and len(iv) == 32
    enc = _ecb(key).encryptor()
    x, y = iv[:16], iv[16:]
    out = bytearray()
    for i in range(0, len(data), 16):
        p = data[i:i + 16]
        c = bytes(a ^ b for a, b in zip(enc.update(bytes(a ^ b for a, b in zip(p, x))), y))
        out += c
        x, y = c, p
    return bytes(out)


def aes_ige_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    assert len(data) % 16 == 0 and len(iv) == 32
    dec = _ecb(key).decryptor()
    prev_c, prev_p = iv[:16], iv[16:]
    out = bytearray()
    for i in range(0, len(data), 16):
        c = data[i:i + 16]
        p = bytes(a ^ b for a, b in zip(dec.update(bytes(a ^ b for a, b in zip(c, prev_p))), prev_c))
        out += p
        prev_c, prev_p = c, p
    return bytes(out)


# ---------------------------------------------------------------- RSA_PAD

def rsa_pad(data: bytes, n: int, e: int, rnd=os.urandom) -> bytes:
    """RSA_PAD from the spec (§4.1): pad to 192, reverse, OAEP+-style
    AES-IGE wrap under a temp key, raw RSA. Retries while >= modulus."""
    if len(data) > 192:
        raise ValueError("data too long for RSA_PAD")
    while True:
        padded = data + rnd(192 - len(data))
        rev = padded[::-1]
        temp_key = rnd(32)
        data_with_hash = rev + hashlib.sha256(temp_key + padded).digest()
        aes_encrypted = aes_ige_encrypt(data_with_hash, temp_key, b"\0" * 32)
        temp_xor = bytes(a ^ b for a, b in zip(temp_key, hashlib.sha256(aes_encrypted).digest()))
        block = temp_xor + aes_encrypted
        if int.from_bytes(block, "big") < n:
            return pow(int.from_bytes(block, "big"), e, n).to_bytes(256, "big")


def rsa_encrypt_legacy(data: bytes, n: int, e: int, rnd=os.urandom) -> bytes:
    """The legacy req_DH_params padding (SHA1(data) + data + random to
    255 bytes, raw RSA) — what Telethon's production auth flow sends.
    Live A/B (2026-11-03): DCs answered the spec's RSA_PAD with -404
    through public proxies, so the deep probe uses this form."""
    if len(data) > 235:
        raise ValueError("data too long")
    payload = hashlib.sha1(data).digest() + data + rnd(235 - len(data))
    return pow(int.from_bytes(payload, "big"), e, n).to_bytes(256, "big")


def tmp_key_iv(new_nonce: bytes, server_nonce: bytes) -> tuple[bytes, bytes]:
    a = hashlib.sha1(new_nonce + server_nonce).digest()
    b = hashlib.sha1(server_nonce + new_nonce).digest()
    c = hashlib.sha1(new_nonce + new_nonce).digest()
    return a + b[:12], b[12:20] + c + new_nonce[:4]


# ---------------------------------------------------------------- DH messages

RES_PQ = 0x05162463
P_Q_INNER_DC = 0xA9F55F95  # p_q_inner_data_dc: names the DC explicitly
P_Q_INNER = 0x83C95AEC  # plain variant (no dc field): the _dc variant is
# rejected (-444) whenever the DC actually reached through the proxy is
# not the one named — and proxies route freely. Telethon's production
# auth flow uses this same variant; DCs accept it without a dc check.
REQ_DH_PARAMS = 0xD712E4BE
SERVER_DH_OK = 0xD0E8075C
SERVER_DH_FAIL = 0x79CB045D
SERVER_DH_INNER = 0xB5890DBA
CLIENT_DH_INNER = 0x6643B654
SET_CLIENT_DH = 0xF5045F1F
DH_GEN_OK = 0x3BCBF734
DH_GEN_RETRY = 0x46DC1FB9
DH_GEN_FAIL = 0xA69DAE02
PING = 0x7ABE77EC
PONG = 0x347773C5
NEW_SESSION_CREATED = 0x9EC20908
MSG_CONTAINER = 0x73F1F8DC


class DeepFail(Exception):
    pass


@dataclass
class ResPQ:
    nonce: bytes
    server_nonce: bytes
    pq_bytes: bytes
    fingerprints: list[int]


def parse_res_pq(body: bytes) -> ResPQ:
    if len(body) < 56 or struct.unpack("<I", body[0:4])[0] != RES_PQ:
        raise DeepFail("deep:bad-respq")
    nonce, server_nonce = body[4:20], body[20:36]
    try:
        pq_bytes, off = parse_tl_string(body, 36)
        if struct.unpack("<I", body[off:off + 4])[0] != 0x1CB5C415:
            raise DeepFail("deep:bad-respq-vector")
        count = struct.unpack("<i", body[off + 4:off + 8])[0]
        fps = [struct.unpack("<Q", body[off + 8 + 8 * i:off + 16 + 8 * i])[0] for i in range(count)]
    except (ValueError, struct.error, IndexError) as e:
        raise DeepFail("deep:bad-respq") from e
    return ResPQ(nonce, server_nonce, pq_bytes, fps)


@dataclass
class DHState:
    nonce: bytes
    server_nonce: bytes
    new_nonce: bytes
    dc: int
    server_time: int = 0
    auth_key: bytes = b""
    auth_key_id: bytes = b""
    salt: bytes = b""
    session_id: bytes = b""


def build_req_dh_params(rp: ResPQ, dc: int, rnd=os.urandom,
                        inner_dc_id: int | None = None) -> tuple[bytes, DHState]:
    pq = int.from_bytes(rp.pq_bytes, "big")
    p, q = factorize(pq)
    fp = next((f for f in rp.fingerprints if f in SERVER_KEYS), None)
    if fp is None:
        raise DeepFail("deep:no-known-rsa-key")
    n, e = SERVER_KEYS[fp]
    new_nonce = rnd(32)
    inner = (
        struct.pack("<I", P_Q_INNER_DC if inner_dc_id is not None else P_Q_INNER)
        + tl_string(rp.pq_bytes)
        + tl_string(p.to_bytes((p.bit_length() + 7) // 8, "big"))
        + tl_string(q.to_bytes((q.bit_length() + 7) // 8, "big"))
        + rp.nonce + rp.server_nonce + new_nonce
        + (struct.pack("<i", inner_dc_id) if inner_dc_id is not None else b"")
    )
    encrypted = rsa_encrypt_legacy(inner, n, e, rnd)
    body = (
        struct.pack("<I", REQ_DH_PARAMS)
        + rp.nonce + rp.server_nonce
        + tl_string(p.to_bytes((p.bit_length() + 7) // 8, "big"))
        + tl_string(q.to_bytes((q.bit_length() + 7) // 8, "big"))
        + struct.pack("<Q", fp)  # raw 8 bytes; the field is a signed int64 on the wire
        + tl_string(encrypted)
    )
    return body, DHState(rp.nonce, rp.server_nonce, new_nonce, dc)


def handle_server_dh_params(body: bytes, st: DHState, rnd=os.urandom) -> bytes:
    """Validate server_DH_params_ok; return the set_client_DH_params body."""
    ctor = struct.unpack("<I", body[0:4])[0] if len(body) >= 4 else 0
    if ctor == SERVER_DH_FAIL:
        raise DeepFail("deep:server-dh-fail")
    if ctor != SERVER_DH_OK:
        raise DeepFail("deep:bad-server-dh-params")
    if body[4:20] != st.nonce or body[20:36] != st.server_nonce:
        raise DeepFail("deep:nonce-mismatch")
    try:
        answer, _ = parse_tl_string(body, 36)
    except (ValueError, IndexError) as e:
        raise DeepFail("deep:bad-answer") from e
    key, iv = tmp_key_iv(st.new_nonce, st.server_nonce)
    plain = aes_ige_decrypt(answer, key, iv)
    inner = plain[20:]
    # inner runs to a 16-byte boundary with random padding behind it; its
    # exact length (and the SHA1 check) is settled after the field walk.
    if len(inner) < 24 or struct.unpack("<I", inner[0:4])[0] != SERVER_DH_INNER:
        raise DeepFail("deep:bad-inner")
    try:
        off = 4
        if inner[off:off + 16] != st.nonce or inner[off + 16:off + 32] != st.server_nonce:
            raise DeepFail("deep:inner-nonce-mismatch")
        off += 32
        g = struct.unpack("<i", inner[off:off + 4])[0]
        off += 4
        dh_prime_b, off = parse_tl_string(inner, off)
        g_a_b, off = parse_tl_string(inner, off)
        server_time = struct.unpack("<i", inner[off:off + 4])[0]
        off += 4
    except (ValueError, struct.error, IndexError) as e:
        raise DeepFail("deep:bad-inner") from e
    if hashlib.sha1(inner[:off]).digest() != plain[:20]:
        raise DeepFail("deep:inner-hash-mismatch")
    prime = int.from_bytes(dh_prime_b, "big")
    g_a = int.from_bytes(g_a_b, "big")
    if not (2 <= g <= 7):
        raise DeepFail("deep:bad-g")
    if not (2**2047 < prime < 2**2048):
        raise DeepFail("deep:bad-dh-prime")
    if not (1 < g_a < prime - 1):
        raise DeepFail("deep:bad-g-a")
    b = int.from_bytes(rnd(256), "big") % (prime - 2) + 1
    g_b = pow(g, b, prime)
    auth_key = pow(g_a, b, prime).to_bytes(256, "big")
    client_inner = (
        struct.pack("<I", CLIENT_DH_INNER)
        + st.nonce + st.server_nonce
        + struct.pack("<q", 0)
        + tl_string(g_b.to_bytes(256, "big"))
    )
    data_with_hash = hashlib.sha1(client_inner).digest() + client_inner
    data_with_hash += rnd(-len(data_with_hash) % 16)
    encrypted = aes_ige_encrypt(data_with_hash, key, iv)
    st.server_time = server_time
    st.auth_key = auth_key
    st.auth_key_id = hashlib.sha1(auth_key).digest()[12:20]
    st.salt = bytes(x ^ y for x, y in zip(st.new_nonce[:8], st.server_nonce[:8]))
    st.session_id = rnd(8)
    return struct.pack("<I", SET_CLIENT_DH) + st.nonce + st.server_nonce + tl_string(encrypted)


def check_dh_gen_ok(body: bytes, st: DHState) -> None:
    ctor = struct.unpack("<I", body[0:4])[0] if len(body) >= 4 else 0
    if ctor == DH_GEN_RETRY:
        raise DeepFail("deep:dh-gen-retry")
    if ctor != DH_GEN_OK:
        raise DeepFail("deep:dh-gen-fail")
    if body[4:20] != st.nonce or body[20:36] != st.server_nonce:
        raise DeepFail("deep:nonce-mismatch")
    aux = hashlib.sha1(st.auth_key).digest()[:8]
    expect = hashlib.sha1(st.new_nonce + b"\x01" + aux).digest()[4:20]
    if not hmac.compare_digest(body[36:52], expect):
        raise DeepFail("deep:nonce-hash-mismatch")


# ---------------------------------------------------------------- encryption

def _msg_key_aes(auth_key: bytes, msg_key: bytes, x: int) -> tuple[bytes, bytes]:
    a = hashlib.sha256(msg_key + auth_key[x:x + 36]).digest()
    b = hashlib.sha256(auth_key[x + 40:x + 40 + 36] + msg_key).digest()
    return a[:8] + b[8:24] + a[24:32], b[:8] + a[8:24] + b[24:32]


def build_ping_payload(st: DHState, rnd=os.urandom) -> tuple[bytes, bytes]:
    """First encrypted message: ping. Returns (wire payload, ping_id)."""
    ping_id = rnd(8)
    body = struct.pack("<I", PING) + ping_id
    msg_id = ((st.server_time + 1) << 32) | 4
    plain = st.salt + st.session_id + struct.pack("<q", msg_id) + struct.pack("<i", 0) \
        + struct.pack("<i", len(body)) + body
    pad = 12
    while (len(plain) + pad) % 16:
        pad += 1
    plain += rnd(pad)
    msg_key = hashlib.sha256(st.auth_key[88:120] + plain).digest()[8:24]
    key, iv = _msg_key_aes(st.auth_key, msg_key, 0)
    return st.auth_key_id + msg_key + aes_ige_encrypt(plain, key, iv), ping_id


def find_pong(payload: bytes, st: DHState, ping_id: bytes) -> bool:
    """Decrypt one server packet; True iff it carries our pong (possibly
    inside a msg_container). Other valid packets return False."""
    if len(payload) < 24 + 32:
        raise DeepFail(f"deep:short-packet:{len(payload)}:{payload[:16].hex()}")
    if payload[:8] == b"\0" * 8:
        # an unencrypted packet after the DH exchange: name its constructor
        ctor = payload[20:24].hex() if len(payload) >= 24 else "????"
        raise DeepFail(f"deep:unencrypted:{ctor}:{len(payload)}")
    if payload[:8] != st.auth_key_id:
        raise DeepFail(f"deep:bad-auth-key-id:{payload[:16].hex()}:{len(payload)}")
    msg_key = payload[8:24]
    key, iv = _msg_key_aes(st.auth_key, msg_key, 8)
    ct = payload[24:]
    if len(ct) % 16:
        ct = ct[:len(ct) - len(ct) % 16]
    plain = aes_ige_decrypt(ct, key, iv)
    expect = hashlib.sha256(st.auth_key[88 + 8:120 + 8] + plain).digest()[8:24]
    if not hmac.compare_digest(msg_key, expect):
        raise DeepFail("deep:bad-msg-key")
    ln = struct.unpack("<i", plain[28:32])[0]
    body = plain[32:32 + ln]
    if len(body) < 4:
        return False
    ctor = struct.unpack("<I", body[0:4])[0]
    if ctor == PONG:
        # pong = ctor + msg_id(8, of our ping) + ping_id(8) — the ping_id
        # is the SECOND long; comparing the first one cost us a full
        # evening (it can never equal a random ping_id).
        return len(body) >= 20 and body[12:20] == ping_id
    if ctor == MSG_CONTAINER:
        # inner messages: msg_id(8) + seq_no(4) + bytes(4) + body
        count = struct.unpack("<i", body[4:8])[0]
        off = 8
        for _ in range(min(count, 64)):
            if off + 16 > len(body):
                break
            ilen = struct.unpack("<i", body[off + 12:off + 16])[0]
            if ilen < 0 or off + 16 + ilen > len(body):
                break
            inner = body[off + 16:off + 16 + ilen]
            if len(inner) >= 20 and struct.unpack("<I", inner[0:4])[0] == PONG \
                    and inner[12:20] == ping_id:
                return True
            off += 16 + ilen
    return False


# ---------------------------------------------------------------- transport

class _Conn:
    """The proxy's obfuscated stream, framed exactly as in probe.py:
    packets are [len][payload][transport pad] inside the CTR stream;
    FakeTLS wraps the stream in 0x17 records (CCS once, up front)."""

    def __init__(self, r, w, header, enc, dec, tls, padded):
        self.r, self.w = r, w
        self.header, self.enc, self.dec = header, enc, dec
        self.tls, self.padded = tls, padded
        self.buf = bytearray()
        self.started = False
        self.last_msg_id = 0

    def wrap_msg(self, body: bytes) -> bytes:
        mid = max(_msg_id(), self.last_msg_id + 4)
        self.last_msg_id = mid
        return b"\0" * 8 + struct.pack("<q", mid) + struct.pack("<i", len(body)) + body

    def send_packet(self, payload: bytes, pad: bytes = b"") -> None:
        pkt = struct.pack("<I", len(payload) + len(pad)) + payload + pad
        stream = self.enc.update(pkt)
        if not self.started:
            stream = self.header + stream
            self.started = True
            if self.tls:
                self.w.write(b"\x14\x03\x03\x00\x01\x01")
        if self.tls:
            out = bytearray()
            for i in range(0, len(stream), 16000):
                chunk = stream[i:i + 16000]
                out += b"\x17\x03\x03" + struct.pack(">H", len(chunk)) + chunk
            self.w.write(bytes(out))
        else:
            self.w.write(stream)

    def send_plain(self, body: bytes) -> None:
        pad = os.urandom(os.urandom(1)[0] % 16) if self.padded else b""
        self.send_packet(self.wrap_msg(body), pad)

    async def _need(self, n: int) -> bytes:
        while len(self.buf) < n:
            if self.tls:
                h, p = await _read_record(self.r)
                if h[0] == 0x14:
                    continue
                if h[0] != 0x17:
                    raise DeepFail("deep:tls-unexpected-record")
                self.buf += self.dec.update(p)
            else:
                chunk = await self.r.read(4096)
                if not chunk:
                    raise asyncio.IncompleteReadError(b"", n)
                self.buf += self.dec.update(chunk)
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    async def read_packet(self) -> bytes:
        ln = struct.unpack("<I", await self._need(4))[0]
        if ln & 0x80000000 or ln < 4 or ln > 1 << 20:
            raise DeepFail("deep:bad-frame")
        return await self._need(ln)

    async def recv_body(self) -> bytes:
        msg = await self.read_packet()
        if len(msg) == 4:  # transport error: the value is the negative code
            raise DeepFail(f"deep:transport-error-{-struct.unpack('<i', msg)[0]}")
        if len(msg) < 20:
            raise DeepFail("deep:short-message")
        ln = struct.unpack("<i", msg[16:20])[0]
        return msg[20:20 + ln]


async def probe_deep(host: str, port: int, secret: Secret, *, dc: int = 2,
                     timeout: float = 12.0, connect_host: str | None = None) -> ProbeResult:
    """Full-session probe. Result.ok stays the probe.py contract (level
    'dc'); extra['deep'] is True only after a real encrypted pong."""
    res = ProbeResult()
    res.extra["deep"] = False
    key = secret.key
    t0 = time.monotonic()
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(connect_host or host, port), timeout)
    except asyncio.TimeoutError:
        res.error = "tcp:timeout"
        return res
    except OSError as e:
        res.error = "tcp:" + type(e).__name__
        return res
    res.level = "tcp"
    res.tcp_ms = round((time.monotonic() - t0) * 1000)
    try:
        await asyncio.wait_for(_deep_session(r, w, secret, key, dc, res), timeout)
    except asyncio.TimeoutError:
        res.error = f"timeout@{res.level}"
    except asyncio.IncompleteReadError:
        res.error = f"eof@{res.level}"
    except DeepFail as e:
        res.error = str(e)
    except OSError as e:
        res.error = f"{type(e).__name__}@{res.level}"
    except Exception as e:  # noqa: BLE001 — one weird proxy must never
        res.error = f"deep:{type(e).__name__}"  # crash the whole pipeline
    finally:
        w.close()
        try:
            await asyncio.wait_for(w.wait_closed(), 1)
        except Exception:  # noqa: BLE001
            pass
    return res


async def _deep_session(r, w, secret: Secret, key: bytes, dc: int, res: ProbeResult) -> None:
    tls = secret.emulate_tls
    if tls:
        hello, cdigest = build_client_hello(key, secret.domain)
        w.write(hello)
        await w.drain()
        h1, p1 = await _read_record(r)
        if h1[:3] != b"\x16\x03\x03":
            raise DeepFail("tls:bad-hello")
        h2, p2 = await _read_record(r)
        h3, p3 = await _read_record(r)
        if h2 + p2 != b"\x14\x03\x03\x00\x01\x01" or h3[:3] != b"\x17\x03\x03":
            raise DeepFail("tls:bad-hello")
        resp = h1 + p1 + h2 + p2 + h3 + p3
        zeroed = resp[:11] + b"\0" * 32 + resp[43:]
        if not hmac.compare_digest(hmac.new(key, cdigest + zeroed, hashlib.sha256).digest(), resp[11:43]):
            raise DeepFail("tls:hmac-mismatch")
        res.level = "tls"
    header, enc, dec = build_obfuscated_header(key, secret.use_random_padding, dc)
    conn = _Conn(r, w, header, enc, dec, tls, secret.use_random_padding)

    nonce = os.urandom(16)
    t1 = time.monotonic()
    conn.send_packet(req_pq_multi(nonce),
                     os.urandom(os.urandom(1)[0] % 16) if secret.use_random_padding else b"")
    await w.drain()
    body = await conn.recv_body()
    rp = parse_res_pq(body)
    if rp.nonce != nonce:
        raise DeepFail("deep:nonce-mismatch")
    res.level = "dc"
    res.rtt_ms = round((time.monotonic() - t1) * 1000)

    dh_body, st = build_req_dh_params(rp, dc)
    conn.send_plain(dh_body)
    await w.drain()
    set_client_body = handle_server_dh_params(await conn.recv_body(), st)
    conn.send_plain(set_client_body)
    await w.drain()
    check_dh_gen_ok(await conn.recv_body(), st)

    payload, ping_id = build_ping_payload(st)
    # No transport padding on the ENCRYPTED packet: MTG-fronted proxies
    # (dd/ee secrets) answer a padded first encrypted packet with
    # transport error -404 — the pad rides inside the packet length and
    # breaks the DC's auth-key lookup. Unencrypted packets keep their
    # padding (harmless: they carry their own length field).
    # Live A/B (2026-11-03): pad0 -> pong on every sampled dd/ee proxy.
    conn.send_packet(payload, b"")
    await w.drain()
    mismatch = None
    for _ in range(4):
        try:
            # per-read budget: the outer wait_for timeout used to mask the
            # first packet's diagnostic behind a bare timeout@dc
            pkt = await asyncio.wait_for(conn.read_packet(), 6)
        except (TimeoutError, asyncio.IncompleteReadError):
            break
        try:
            if find_pong(pkt, st, ping_id):
                res.extra["deep"] = True
                return
        except DeepFail as e:
            if mismatch is None and str(e).startswith(
                    ("deep:bad-auth-key-id", "deep:unencrypted", "deep:short-packet")):
                mismatch = e  # keep scanning: the pong may be in a later packet
                continue
            raise
    if mismatch is not None:
        raise mismatch
    raise DeepFail("deep:no-pong")
