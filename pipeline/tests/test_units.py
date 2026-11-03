import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pool.links import extract, parse_link  # noqa: E402
from pool.probe import build_client_hello, build_obfuscated_header, req_pq_multi  # noqa: E402
from pool.secret import Secret, SecretError  # noqa: E402
from pool.state import State, server_id  # noqa: E402


def test_secret_kinds():
    classic = Secret.from_link("ab" * 16)
    assert classic.kind == "classic" and classic.key == bytes.fromhex("ab" * 16)
    secure = Secret.from_link("dd" + "ab" * 16)
    assert secure.kind == "secure" and secure.use_random_padding
    ee_hex = "ee" + "ab" * 16 + b"example.com".hex()
    faketls = Secret.from_link(ee_hex)
    assert faketls.kind == "faketls" and faketls.domain == b"example.com"
    # base64url form of the same ee secret parses identically
    assert Secret.from_link(faketls.encoded()).raw == faketls.raw


def test_secret_rejects():
    for bad in ["zz" * 16, "ab" * 8, "", "a" * 33]:
        try:
            Secret.from_link(bad)
            raise AssertionError(f"accepted {bad!r}")
        except SecretError:
            pass


def test_extract_text_and_json():
    text = (
        "junk https://t.me/proxy?server=1.2.3.4&amp;port=443&amp;secret=" + "dd" + "ab" * 16 + " tail\n"
        "tg://proxy?server=host.example&port=8080&secret=" + "ab" * 16 + "\n"
        "https://t.me/proxy?server=bad&port=99999&secret=" + "ab" * 16
    )
    got = extract(text)
    assert len(got) == 2
    assert got[0].server == "1.2.3.4" and got[0].secret.kind == "secure"
    blob = json.dumps([{"server": "5.6.7.8", "port": 443, "secret": "ab" * 16}])
    got = extract(blob)
    assert len(got) == 1 and got[0].server == "5.6.7.8"


def test_parse_link_roundtrip():
    p = parse_link("https://t.me/proxy?server=Host.Example.&port=443&secret=" + "ab" * 16)
    assert p.server == "host.example"  # normalized: case + trailing dot
    assert parse_link("https://t.me/proxy?server=x&port=443") is None


def test_state_uptime_and_prune():
    st = State()
    sid = server_id("1.2.3.4", 443)
    for ok in [True, True, False, True]:
        st.record(sid, ok, 1000, 50)
    assert st.stats(sid) == {"uptime": 0.75, "checks": 4}
    st.prune(1000 + 31 * 86400)
    assert st.stats(sid)["checks"] == 0


def test_req_pq_multi_layout():
    nonce = bytes(range(16))
    msg = req_pq_multi(nonce)
    auth, msg_id, ln = struct.unpack("<qqi", msg[:20])
    assert auth == 0 and ln == len(msg) - 20
    assert struct.unpack("<I", msg[20:24])[0] == 0xBE7E8EF1
    assert msg[24:40] == nonce


def test_obfuscated_header_roundtrip():
    # server-side check: decrypting the wire header with the reverse-derived
    # key must reveal the padded marker and the DC id in the plain header.
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    import hashlib
    key = bytes(range(16))
    wire, _enc, _dec = build_obfuscated_header(key, padded=True, dc=2, rnd=lambda n: b"\x07" * n)
    assert len(wire) == 64
    rev = bytes(wire[::-1])
    d = Cipher(algorithms.AES(hashlib.sha256(rev[8:40] + key).digest()), modes.CTR(rev[40:56])).decryptor()
    plain = d.update(wire)
    assert plain[56:60] == b"\xdd" * 4
    assert struct.unpack("<h", plain[60:62])[0] == 2


def test_client_hello_is_517_byte_record():
    key = bytes(range(16))
    rec, digest = build_client_hello(key, b"example.com", unix_time=1700000000, rnd=lambda n: b"\x01" * n)
    assert rec[:3] == b"\x16\x03\x01"
    assert len(rec) == 5 + struct.unpack(">H", rec[3:5])[0]
    assert len(rec) >= 517
