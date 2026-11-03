#!/usr/bin/env python3
"""Diagnostic (temporary): WHY does the DC reject our first encrypted ping?

Runs the deep handshake against a small feed sample, then tries ping
variants on fresh connections — salt = XOR-of-nonces (spec) vs 0
(Telethon), auth_key = 256-byte padded vs minimal big-endian (Telethon),
msg_id from DH server_time vs local clock — and DUMPS every response
packet's constructor (pong / new_session_created / bad_server_salt /
bad_msg_notification / transport -404) so the rejection reason is read,
not guessed. Always exits 0.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import struct
import time
import urllib.request

from pool import deep
from pool.deep import (
    DeepFail, _Conn, build_ping_payload, build_req_dh_params,
    check_dh_gen_ok, handle_server_dh_params, parse_res_pq,
)
from pool.probe import _read_record, build_client_hello, build_obfuscated_header, req_pq_multi
from pool.secret import Secret

FEED = ("https://raw.githubusercontent.com/0xRadikal/"
        "Free-Telegram-Proxy/main/resilient/proxies.json")

CTORS = {
    0x347773C5: "pong", 0x9EC20908: "new_session_created",
    0xEDAB447B: "bad_server_salt", 0xA7EFF810: "bad_msg_notification",
    0x73F1F8DC: "msg_container", 0x62D6B459: "msgs_ack",
    0xF35C6D01: "rpc_result", 0x2144CA19: "future_salts",
}


def describe(pkt: bytes, st) -> str:
    if len(pkt) < 24:
        code = struct.unpack("<i", pkt[:4])[0] if len(pkt) >= 4 else None
        return f"SHORT len={len(pkt)} int32={code} hex={pkt[:16].hex()}"
    if pkt[:8] != st.auth_key_id:
        return f"FOREIGN-KEY len={len(pkt)} prefix={pkt[:16].hex()}"
    msg_key = pkt[8:24]
    key, iv = deep._msg_key_aes(st.auth_key, msg_key, 8)
    ct = pkt[24:]
    ct = ct[:len(ct) // 16 * 16]
    try:
        plain = deep.aes_ige_decrypt(ct, key, iv)
    except Exception as e:  # noqa: BLE001
        return f"DECRYPT-FAIL {e}"
    ln = struct.unpack("<i", plain[28:32])[0]
    body = plain[32:32 + ln]
    if len(body) < 4:
        return f"EMPTY-BODY len={len(pkt)}"
    ctor = struct.unpack("<I", body[:4])[0]
    s = f"{CTORS.get(ctor, hex(ctor))} len={len(pkt)}"
    if ctor in (0xEDAB447B, 0xA7EFF810) and len(body) >= 20:
        s += (f" bad_msg_id={struct.unpack('<q', body[4:12])[0]}"
              f" err={struct.unpack('<i', body[16:20])[0]}")
        if ctor == 0xEDAB447B and len(body) >= 28:
            s += f" new_salt={body[20:28].hex()}"
    if ctor == 0x73F1F8DC:
        count = struct.unpack("<i", body[4:8])[0]
        off, inners = 8, []
        for _ in range(min(count, 8)):
            if off + 16 > len(body):
                break
            ilen = struct.unpack("<i", body[off + 12:off + 16])[0]
            inner = body[off + 16:off + 16 + ilen]
            if len(inner) >= 4:
                ic = struct.unpack("<I", inner[:4])[0]
                inners.append(CTORS.get(ic, hex(ic)))
            off += 16 + ilen
        s += f" inners={inners}"
    return s


async def attempt(item, variant) -> str:
    name, salt_mode, key_mode, msgid_mode = variant
    secret = Secret.from_link(item["secret"])
    key16 = secret.key
    host = item.get("ip") or item["server"]
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, item["port"]), 8)
    except Exception as e:  # noqa: BLE001
        return f"{name}: connect {type(e).__name__}"
    try:
        return await asyncio.wait_for(
            _session(r, w, secret, key16, variant), 25)
    except DeepFail as e:
        return f"{name}: {e}"
    except Exception as e:  # noqa: BLE001
        return f"{name}: {type(e).__name__}@{e}"
    finally:
        w.close()


async def _session(r, w, secret, key16, variant) -> str:
    name, salt_mode, key_mode, msgid_mode = variant
    tls = secret.emulate_tls
    if tls:
        hello, cdigest = build_client_hello(key16, secret.domain)
        w.write(hello)
        await w.drain()
        import hmac as _hmac
        h1, p1 = await _read_record(r)
        h2, p2 = await _read_record(r)
        h3, p3 = await _read_record(r)
        resp = h1 + p1 + h2 + p2 + h3 + p3
        zeroed = resp[:11] + b"\0" * 32 + resp[43:]
        if not _hmac.compare_digest(
                _hmac.new(key16, cdigest + zeroed, hashlib.sha256).digest(),
                resp[11:43]):
            raise DeepFail("tls-hmac")
    header, enc, dec = build_obfuscated_header(
        key16, secret.use_random_padding, 2)
    conn = _Conn(r, w, header, enc, dec, tls, secret.use_random_padding)
    nonce = os.urandom(16)
    conn.send_packet(req_pq_multi(nonce),
                     os.urandom(os.urandom(1)[0] % 16)
                     if secret.use_random_padding else b"")
    await w.drain()
    rp = parse_res_pq(await conn.recv_body())
    dh_body, st = build_req_dh_params(rp, 2)
    conn.send_plain(dh_body)
    await w.drain()
    set_client_body = handle_server_dh_params(await conn.recv_body(), st)
    conn.send_plain(set_client_body)
    await w.drain()
    check_dh_gen_ok(await conn.recv_body(), st)
    # --- variant overrides (st is fully built by now) ---
    if key_mode == "minimal":
        st.auth_key = st.auth_key.lstrip(b"\0") or b"\0"
        st.auth_key_id = hashlib.sha1(st.auth_key).digest()[12:20]
    if salt_mode == "zero":
        st.salt = b"\0" * 8
    if msgid_mode == "local":
        st.server_time = int(time.time())
    payload, ping_id = build_ping_payload(st)
    conn.send_packet(payload,
                     os.urandom(16) if secret.use_random_padding else b"")
    await w.drain()
    seen = []
    for _ in range(4):
        try:
            pkt = await asyncio.wait_for(conn.read_packet(), 6)
        except Exception as e:  # noqa: BLE001
            seen.append(f"READ-END({type(e).__name__})")
            break
        d = describe(pkt, st)
        seen.append(d)
        if d.startswith("pong"):
            return f"{name}: PONG! after {seen}"
    return (f"{name}: keylen={len(st.auth_key)} salt={st.salt.hex()} "
            f"packets={seen}")


VARIANTS = [
    ("V1-spec", "xor", "padded", "server"),
    ("V2-salt0", "zero", "padded", "server"),
    ("V3-telethon", "zero", "minimal", "server"),
    ("V4-keymin", "xor", "minimal", "server"),
    ("V5-localtime", "zero", "minimal", "local"),
]


async def main() -> None:
    with urllib.request.urlopen(FEED, timeout=30) as r:
        items = json.load(r)
    sample = []
    for prefix, n in (("ee", 2), ("dd", 3), ("", 3)):
        bucket = [i for i in items
                  if (i["secret"].startswith(prefix) if prefix
                      else not i["secret"].startswith(("ee", "dd")))]
        bucket.sort(key=lambda i: (-(i.get("uptime") or 0),
                                   i.get("rtt_ms") or 9999))
        sample += bucket[:n]
    for item in sample:
        kind = ("ee" if item["secret"].startswith("ee")
                else "dd" if item["secret"].startswith("dd") else "classic")
        print(f"DIAG {item['server']}:{item['port']} kind={kind}", flush=True)
        for variant in VARIANTS:
            out = await attempt(item, variant)
            print(f"  {out}", flush=True)
            if "PONG!" in out:
                break


if __name__ == "__main__":
    asyncio.run(main())
