"""Deep-probe tests: the pure protocol math is validated end-to-end
against an in-process simulation of the DC side of the DH exchange,
written from core.telegram.org/mtproto/auth_key — no network needed.
(The live end-to-end check is the CI pipeline-smoke job, whose egress
can actually reach Telegram.)"""
import hashlib
import os
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pool import deep  # noqa: E402
from pool.deep import (  # noqa: E402
    DHState, aes_ige_decrypt, aes_ige_encrypt, build_ping_payload,
    build_req_dh_params, check_dh_gen_ok, factorize, find_pong,
    fingerprint, handle_server_dh_params, parse_res_pq, rsa_pad,
    tl_string, tmp_key_iv,
)

# Telegram's current DH prime, quoted verbatim in the official docs.
DH_PRIME = int(
    "C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F"
    "48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C37"
    "20FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F64"
    "2477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4"
    "A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754"
    "FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4"
    "E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F"
    "0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B", 16)


def test_factorize():
    assert factorize(2_147_483_647 * 4_294_967_291) == (2_147_483_647, 4_294_967_291)
    assert factorize(101 * 9_973) == (101, 9_973)


def test_embedded_keys_parse_with_distinct_fingerprints():
    assert len(deep.SERVER_KEYS) == 8
    for fp, (n, e) in deep.SERVER_KEYS.items():
        assert e == 65537
        assert n.bit_length() in (2047, 2048)
        assert fingerprint(n, e) == fp


def test_aes_ige_roundtrip():
    key, iv = os.urandom(32), os.urandom(32)
    data = os.urandom(160)
    assert aes_ige_decrypt(aes_ige_encrypt(data, key, iv), key, iv) == data


def _test_rsa_key():
    from cryptography.hazmat.primitives.asymmetric import rsa
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = k.private_numbers()
    return nums.public_numbers.n, nums.public_numbers.e, nums.d


def test_rsa_pad_roundtrip():
    n, e, d = _test_rsa_key()
    block = rsa_pad(b"hello mtproto", n, e)
    recovered = pow(int.from_bytes(block, "big"), d, n).to_bytes(256, "big")
    temp_xor, aes_enc = recovered[:32], recovered[32:]
    temp_key = bytes(a ^ b for a, b in zip(temp_xor, hashlib.sha256(aes_enc).digest()))
    plain = aes_ige_decrypt(aes_enc, temp_key, b"\0" * 32)
    padded = plain[:192][::-1]
    assert padded[:13] == b"hello mtproto"
    assert hashlib.sha256(temp_key + padded).digest() == plain[192:224]


def _server_side(rp, client_req_body, n, d, server_nonce, new_nonce_holder):
    """Play the DC: validate req_DH_params, answer server_DH_params_ok.
    Returns (answer_body, server_state)."""
    body = client_req_body
    assert struct.unpack("<I", body[0:4])[0] == deep.REQ_DH_PARAMS
    assert body[4:20] == rp.nonce and body[20:36] == server_nonce
    off = 36
    p_b, off = deep.parse_tl_string(body, off)
    q_b, off = deep.parse_tl_string(body, off)
    off += 8  # fingerprint
    enc, off = deep.parse_tl_string(body, off)
    block = pow(int.from_bytes(enc, "big"), d, n).to_bytes(256, "big")
    if block[0] == 0:  # the legacy payload is 255 bytes; drop the pad zero
        block = block[1:]
    # legacy padding: SHA1(inner) + inner + random tail
    digest, inner = block[:20], block[20:]
    assert struct.unpack("<I", inner[0:4])[0] == deep.P_Q_INNER
    o = 4
    pq_b, o = deep.parse_tl_string(inner, o)
    p2_b, o = deep.parse_tl_string(inner, o)
    q2_b, o = deep.parse_tl_string(inner, o)
    assert p2_b == p_b and q2_b == q_b
    assert inner[o:o + 16] == rp.nonce and inner[o + 16:o + 32] == server_nonce
    o += 32
    new_nonce = inner[o:o + 32]
    o += 32
    assert hashlib.sha1(inner[:o]).digest() == digest
    new_nonce_holder.append(new_nonce)

    a = int.from_bytes(os.urandom(256), "big") % (DH_PRIME - 2) + 1
    g, g_a = 2, pow(2, a, DH_PRIME)
    server_time = int(time.time())
    dh_inner = (
        struct.pack("<I", deep.SERVER_DH_INNER) + rp.nonce + server_nonce
        + struct.pack("<i", g)
        + tl_string(DH_PRIME.to_bytes(256, "big"))
        + tl_string(g_a.to_bytes(256, "big"))
        + struct.pack("<i", server_time)
    )
    with_hash = hashlib.sha1(dh_inner).digest() + dh_inner
    with_hash += os.urandom(-len(with_hash) % 16)
    key, iv = tmp_key_iv(new_nonce, server_nonce)
    answer = (
        struct.pack("<I", deep.SERVER_DH_OK) + rp.nonce + server_nonce
        + tl_string(aes_ige_encrypt(with_hash, key, iv))
    )
    return answer, {"a": a, "new_nonce": new_nonce, "server_time": server_time}


def test_full_deep_handshake_simulation():
    # Loop until the key's fingerprint has the top bit set: real Telegram
    # fingerprints are signed int64s, and packing one >= 2**63 once
    # crashed build_req_dh_params (regression coverage).
    while True:
        n, e, d = _test_rsa_key()
        fp = fingerprint(n, e)
        if fp >= 2**63:
            break
    deep.SERVER_KEYS[fp] = (n, e)
    try:
        nonce, server_nonce = os.urandom(16), os.urandom(16)
        p, q = 2_147_483_647, 4_294_967_291
        pq_bytes = (p * q).to_bytes(8, "big")
        res_pq_body = (
            struct.pack("<I", deep.RES_PQ if hasattr(deep, "RES_PQ") else 0x05162463)
            + nonce + server_nonce + tl_string(pq_bytes)
            + struct.pack("<I", 0x1CB5C415) + struct.pack("<i", 1) + struct.pack("<Q", fp)
        )
        rp = parse_res_pq(res_pq_body)
        req_body, st = build_req_dh_params(rp, dc=2)
        holder = []
        answer, srv = _server_side(rp, req_body, n, d, server_nonce, holder)

        set_client_body = handle_server_dh_params(answer, st)
        # --- server validates set_client_DH_params, replies dh_gen_ok
        body = set_client_body
        assert struct.unpack("<I", body[0:4])[0] == deep.SET_CLIENT_DH
        enc, _ = deep.parse_tl_string(body, 36)
        key, iv = tmp_key_iv(srv["new_nonce"], server_nonce)
        plain = aes_ige_decrypt(enc, key, iv)
        client_inner = plain[20:]
        o = 4
        assert client_inner[o:o + 16] == nonce
        o += 16 + 16 + 8  # server_nonce + retry_id
        g_b_b, o = deep.parse_tl_string(client_inner, o)
        assert hashlib.sha1(client_inner[:o]).digest() == plain[:20]
        auth_key_srv = pow(int.from_bytes(g_b_b, "big"), srv["a"], DH_PRIME).to_bytes(256, "big")
        assert auth_key_srv == st.auth_key
        hash1 = hashlib.sha1(srv["new_nonce"] + b"\x01" + hashlib.sha1(auth_key_srv).digest()[:8]).digest()[4:20]
        gen_ok = struct.pack("<I", deep.DH_GEN_OK) + nonce + server_nonce + hash1
        check_dh_gen_ok(gen_ok, st)

        # --- encrypted ping -> pong
        payload, ping_id = build_ping_payload(st)
        assert payload[:8] == st.auth_key_id
        msg_key = payload[8:24]
        k2, iv2 = deep._msg_key_aes(st.auth_key, msg_key, 0)
        plain = aes_ige_decrypt(payload[24:], k2, iv2)
        assert hashlib.sha256(st.auth_key[88:120] + plain).digest()[8:24] == msg_key
        salt, session = plain[:8], plain[8:16]
        assert salt == st.salt and session == st.session_id
        ln = struct.unpack("<i", plain[28:32])[0]
        ping_body = plain[32:32 + ln]
        assert struct.unpack("<I", ping_body[0:4])[0] == deep.PING
        assert ping_body[4:12] == ping_id

        # pong delivered inside a msg_container, like real DCs do;
        # pong body = ctor + msg_id of the ping (8) + ping_id (8) = 20 bytes
        inner_msg = struct.pack("<q", ((srv["server_time"] + 2) << 32) | 4) + struct.pack("<i", 1) \
            + struct.pack("<i", 20) + struct.pack("<I", deep.PONG) + plain[16:24] + ping_id
        pong_body = struct.pack("<I", deep.MSG_CONTAINER) + struct.pack("<i", 1) + inner_msg
        pplain = salt + session + struct.pack("<q", ((srv["server_time"] + 2) << 32) | 4) \
            + struct.pack("<i", 1) + struct.pack("<i", len(pong_body)) + pong_body
        pad = 12
        while (len(pplain) + pad) % 16:
            pad += 1
        pplain += os.urandom(pad)
        mk = hashlib.sha256(st.auth_key[96:128] + pplain).digest()[8:24]
        k3, iv3 = deep._msg_key_aes(st.auth_key, mk, 8)
        pong_payload = st.auth_key_id + mk + aes_ige_encrypt(pplain, k3, iv3)
        assert find_pong(pong_payload, st, ping_id) is True
        assert find_pong(pong_payload, st, os.urandom(8)) is False
    finally:
        deep.SERVER_KEYS.pop(fp, None)
