#!/usr/bin/env python3
"""Demo / test: fetch shared Bambu Studio app cert + CRL + private key.

Given ``client_auth_secret`` and ``server_wrap_key``
(embedded stock-plugin bootstrap secrets), calls:

  GET /v1/iot-service/api/user/applications/{enc_secret}/cert?aes256=…&ver=1

and unwraps the response ``key`` blob with the custom S-box AES-256-CTR cipher
(fixed key 00..1f, CTR starting at 2). Writes:

  slicer_cert.pem, slicer_crl.pem, slicer_key.pem, slicer_cert_id.txt

Algorithm: PR #67 discussion + BambuSlicerKeySaver commit ac097b62
(danielwoz). Docs: research/10.02-secrets.md.

Examples:
  python3 tools/fetch_slicer_credentials.py --self-test
  python3 tools/fetch_slicer_credentials.py \\
    --client-auth-secret ~/.config/BambuStudio/client_auth_secret.txt \\
    --server-wrap-key ~/.config/BambuStudio/server_wrap_key.pem \\
    --out-dir /tmp/obn_slicer_creds \\
    --compare-key ~/.config/BambuStudio/slicer_key.pem
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import struct
import sys
import urllib.error
import urllib.request
from pathlib import Path
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as e:  # pragma: no cover
    print("error: need the 'cryptography' package:", e, file=sys.stderr)
    sys.exit(2)

# ---------------------------------------------------------------------------
# Custom AES-256-CTR (non-standard S-box) — from appcert_cipher.h
# ---------------------------------------------------------------------------

SBOX = bytes(
    [
        0xC5, 0x57, 0x4D, 0x6C, 0x3A, 0x95, 0x05, 0xE0, 0xA3, 0xBA, 0x36, 0x1F, 0xEA, 0x51, 0x53, 0x3B,
        0x0E, 0x07, 0x4E, 0x64, 0x50, 0x04, 0x40, 0xE8, 0x62, 0x6E, 0x9F, 0x2D, 0x70, 0x8B, 0x28, 0x49,
        0xD5, 0xF9, 0x65, 0x8D, 0x74, 0x68, 0x7C, 0x6F, 0x0A, 0x6A, 0xB3, 0xAF, 0x38, 0xFE, 0x7E, 0x8A,
        0x47, 0x7F, 0xB0, 0x16, 0x00, 0xD4, 0x0F, 0x13, 0xC9, 0x80, 0x4A, 0xAC, 0x8C, 0x4F, 0xA7, 0x98,
        0x83, 0x94, 0x5D, 0x48, 0xB4, 0xE9, 0x30, 0x19, 0x03, 0x99, 0x25, 0xBF, 0x8E, 0x41, 0xA0, 0xE4,
        0xC3, 0xCF, 0x2C, 0xAB, 0xD2, 0x32, 0x1A, 0x0C, 0x11, 0xB5, 0x56, 0x63, 0x15, 0xA6, 0x69, 0x0B,
        0x88, 0xBB, 0x4C, 0x10, 0xCB, 0x75, 0xFA, 0x81, 0xF8, 0xCD, 0xA1, 0xD6, 0x97, 0xB7, 0x26, 0xC6,
        0x9E, 0xF1, 0x5F, 0xE5, 0xA9, 0x87, 0xC7, 0xDC, 0x8F, 0x7A, 0x86, 0x20, 0x9A, 0xD1, 0x08, 0xC2,
        0x84, 0x09, 0x33, 0x1B, 0xDD, 0x1E, 0xFD, 0x01, 0x71, 0xDA, 0x77, 0x0D, 0xD7, 0xDE, 0x93, 0xCA,
        0xA5, 0xD0, 0xE6, 0x60, 0x89, 0x37, 0xC8, 0x21, 0x59, 0x79, 0x96, 0xAD, 0x24, 0x34, 0xB9, 0x44,
        0xFC, 0xC1, 0xAE, 0xF3, 0x82, 0x46, 0x43, 0x31, 0xE3, 0x2E, 0x4B, 0xFB, 0x92, 0x55, 0xED, 0x45,
        0x76, 0x6D, 0xAA, 0x3F, 0xF5, 0x5A, 0x91, 0x78, 0x22, 0x06, 0xFF, 0xD9, 0x35, 0x7D, 0x7B, 0xDB,
        0x54, 0x12, 0x9C, 0xD8, 0xD3, 0xEE, 0x17, 0x42, 0x52, 0x3E, 0xA4, 0xE7, 0xDF, 0x9D, 0xF2, 0xF4,
        0xEF, 0x73, 0xF6, 0x5E, 0xB1, 0x5B, 0x18, 0xE2, 0x9B, 0x58, 0xA8, 0x2A, 0xE1, 0x3D, 0x90, 0xB6,
        0x1C, 0xBD, 0x61, 0xEB, 0x23, 0xA2, 0x67, 0x39, 0xF0, 0xBC, 0xB2, 0xF7, 0x85, 0x27, 0x72, 0xCC,
        0x29, 0xB8, 0x1D, 0xBE, 0x66, 0xC4, 0x2F, 0xCE, 0x14, 0x3C, 0x6B, 0xEC, 0x5C, 0x2B, 0xC0, 0x02,
    ]
)

APPCERT_KEY = bytes(range(32))  # 00 01 … 1f
RCON = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D])


def _xtime(a: int) -> int:
    return ((a << 1) ^ (0x1B if (a & 0x80) else 0)) & 0xFF


def _gmul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def key_expand(key: bytes) -> list[bytes]:
    """AES-256 key schedule with custom SBOX → 15 round keys of 16 bytes."""
    assert len(key) == 32
    w = [[0, 0, 0, 0] for _ in range(60)]
    for i in range(8):
        for j in range(4):
            w[i][j] = key[4 * i + j]
    for i in range(8, 60):
        t = w[i - 1][:]
        if i % 8 == 0:
            tmp = t[0]
            t[0] = SBOX[t[1]] ^ RCON[i // 8 - 1]
            t[1] = SBOX[t[2]]
            t[2] = SBOX[t[3]]
            t[3] = SBOX[tmp]
        elif i % 8 == 4:
            t = [SBOX[x] for x in t]
        for j in range(4):
            w[i][j] = w[i - 8][j] ^ t[j]
    rk: list[bytes] = []
    for r in range(15):
        block = bytearray(16)
        for c in range(4):
            for j in range(4):
                block[4 * c + j] = w[4 * r + c][j]
        rk.append(bytes(block))
    return rk


def aes_encrypt_block(block: bytes, rk: list[bytes]) -> bytes:
    """One AES-256 block encrypt; column-major state (state[4*col + row])."""
    s = bytearray(block[i] ^ rk[0][i] for i in range(16))
    for rnd in range(1, 15):
        s = bytearray(SBOX[x] for x in s)
        t = bytearray(16)
        for r in range(4):
            for c in range(4):
                t[4 * c + r] = s[4 * ((c + r) % 4) + r]
        s = t
        if rnd < 14:
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c : 4 * c + 4]
                s[4 * c + 0] = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
                s[4 * c + 1] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
                s[4 * c + 2] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
                s[4 * c + 3] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)
        for i in range(16):
            s[i] ^= rk[rnd][i]
    return bytes(s)


def ctr_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """CTR keystream XOR; block i uses counter (2 + i)."""
    assert len(key) == 32 and len(nonce) == 12
    rk = key_expand(key)
    out = bytearray(len(data))
    for i in range((len(data) + 15) // 16):
        ctr = bytearray(nonce) + struct.pack(">I", 2 + i)
        ks = aes_encrypt_block(bytes(ctr), rk)
        base = i * 16
        n = min(16, len(data) - base)
        for j in range(n):
            out[base + j] = data[base + j] ^ ks[j]
    return bytes(out)


# ---------------------------------------------------------------------------
# Blob framing + RSA rebuild
# ---------------------------------------------------------------------------

def b64decode_any(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    pad = (-len(s)) % 4
    return base64.b64decode(s + "=" * pad)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")  # keeps padding


def decode_key_blob(key_b64: str) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    """Return (p, q, dp, dq, qinv) big-endian 128-byte limbs from response key."""
    blob = b64decode_any(key_b64)
    if len(blob) < 32 + 288:
        raise ValueError(f"key blob too short: {len(blob)} bytes")
    nonce = blob[:12]
    ct_len = struct.unpack_from("<I", blob, 28)[0]
    if 32 + ct_len > len(blob):
        ct_len = len(blob) - 32
    pt = ctr_xor(APPCERT_KEY, nonce, blob[32 : 32 + ct_len])
    # Magic is little-endian uint32 0x534b4559 ("SKEY") → bytes 59 45 4b 53 ("YEKS").
    if pt[:4] != b"\x59\x45\x4b\x53":
        raise ValueError("SKEY magic missing (wrong cipher / framing)")
    h, limb = 32, 128
    if len(pt) < h + 5 * limb:
        raise ValueError(f"SKEY plaintext too short: {len(pt)}")
    parts = [pt[h + i * limb : h + (i + 1) * limb] for i in range(5)]
    return parts[0], parts[1], parts[2], parts[3], parts[4]


def rsa_from_crt(p_be: bytes, q_be: bytes, dp_be: bytes, dq_be: bytes, qinv_be: bytes):
    p = int.from_bytes(p_be, "big")
    q = int.from_bytes(q_be, "big")
    dmp1 = int.from_bytes(dp_be, "big")
    dmq1 = int.from_bytes(dq_be, "big")
    iqmp = int.from_bytes(qinv_be, "big")
    n = p * q
    e = 65537
    # d = e^{-1} mod lcm(p-1, q-1)
    from math import gcd

    p1, q1 = p - 1, q - 1
    lam = (p1 // gcd(p1, q1)) * q1
    d = pow(e, -1, lam)
    return rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=dmp1,
        dmq1=dmq1,
        iqmp=iqmp,
        public_numbers=rsa.RSAPublicNumbers(e, n),
    ).private_key()


def first_cert(pem_chain: str) -> x509.Certificate:
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    a = pem_chain.find(begin)
    b = pem_chain.find(end, a)
    if a < 0 or b < 0:
        raise ValueError("no certificate PEM in cert field")
    return x509.load_pem_x509_certificate(pem_chain[a : b + len(end)].encode())


def cert_id_for_leaf(leaf: x509.Certificate) -> str:
    """MQTT form: lowercase hex serial ‖ issuer RFC4514 (e.g. …fCN=…)."""
    serial = format(leaf.serial_number, "x")
    if len(serial) % 2:
        serial = "0" + serial
    issuer = leaf.issuer.rfc4514_string()
    return serial + issuer


def private_key_pem(key) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


# ---------------------------------------------------------------------------
# Cloud request
# ---------------------------------------------------------------------------

DEFAULT_API = "https://api.bambulab.com"
# Cert endpoint accepts any User-Agent string; X-BBL-* fingerprint headers are
# not required (live check 2026-07). urllib still needs some UA present.
REQUEST_HEADERS = {
    "User-Agent": "obn-demo",
}


def build_cert_url(client_auth_secret: bytes, server_wrap_pem: bytes, api_host: str) -> str:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    session_key = os.urandom(32)
    iv = os.urandom(12)
    ct_tag = AESGCM(session_key).encrypt(iv, client_auth_secret, None)
    enc_secret = b64url(iv + ct_tag)
    pub = load_pem_public_key(server_wrap_pem)
    wrapped = pub.encrypt(session_key, asym_padding.PKCS1v15())
    aes256 = b64url(wrapped)
    base = api_host.rstrip("/")
    return f"{base}/v1/iot-service/api/user/applications/{enc_secret}/cert?aes256={aes256}&ver=1"


def fetch_app_cert(url: str) -> dict:
    req = urllib.request.Request(url, headers=REQUEST_HEADERS, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        body = e.read()
        status = e.code
        raise RuntimeError(f"HTTP {status}: {body[:500]!r}") from e
    data = json.loads(body.decode())
    if data.get("code") not in (0, "0", None) and data.get("message") != "success":
        raise RuntimeError(f"API error: {data!r}")
    if not data.get("cert") or not data.get("key"):
        raise RuntimeError(f"missing cert/key in response: keys={list(data)}")
    return data


# ---------------------------------------------------------------------------
# Self-test (public KATs from appcert_decrypt_blob_test.cpp)
# ---------------------------------------------------------------------------

def self_test() -> None:
    fails = 0

    def expect(name: str, cond: bool) -> None:
        nonlocal fails
        if cond:
            print(f"  PASS {name}")
        else:
            fails += 1
            print(f"  FAIL {name}")

    seen = [False] * 256
    bij = True
    for b in SBOX:
        if seen[b]:
            bij = False
        seen[b] = True
    expect("S-box is a bijection", bij and all(seen))
    expect("S-box is not standard AES (SBOX[0] != 0x63)", SBOX[0] != 0x63)

    nonce = bytes.fromhex("303c8f522a171b9a40dc8901")
    rk = key_expand(APPCERT_KEY)

    def ks(ctr: int) -> bytes:
        return aes_encrypt_block(nonce + struct.pack(">I", ctr), rk)

    expect(
        "keystream block 0 (ctr=2)",
        ks(2) == bytes.fromhex("c6bf1cc1b40dcc16443034d6dabe7b81"),
    )
    expect(
        "keystream block 1 (ctr=3)",
        ks(3) == bytes.fromhex("a5dee6b960b56cf67aa24081f505a4b8"),
    )
    expect(
        "known-answer oracle (ctr=4)",
        ks(4) == bytes.fromhex("a155d92625a1eb00d8901fef52a8f105"),
    )

    ct32 = bytes.fromhex(
        "9ffa5792b50dcc16443834d65abe7b8125dee6b9e0b56cf6faa240817505a4b8"
    )
    pt32 = ctr_xor(APPCERT_KEY, nonce, ct32)
    expect(
        "decrypt(real ct[0:32]) == SKEY header",
        pt32
        == bytes.fromhex(
            "59454b5301000000000800008000000080000000800000008000000080000000"
        ),
    )
    expect("magic == LE SKEY (59 45 4b 53)", pt32[:4] == b"\x59\x45\x4b\x53")

    nonce2 = bytes.fromhex("000102030405060708090a0b")
    pt = bytearray(704)
    pt[0:4] = b"\x59\x45\x4b\x53"
    pt[4] = 1
    for i in range(32, 704):
        pt[i] = (i * 7 + 3) & 0xFF
    ct = ctr_xor(APPCERT_KEY, nonce2, bytes(pt))
    back = ctr_xor(APPCERT_KEY, nonce2, ct)
    expect("CTR round-trip is identity", back == bytes(pt))
    expect("ciphertext differs from plaintext", ct != bytes(pt))
    wrong = ctr_xor(APPCERT_KEY, nonce, ct)
    expect("wrong nonce does not recover SKEY", wrong[:4] != b"\x59\x45\x4b\x53")

    if fails:
        raise SystemExit(f"self-test: {fails} failure(s)")
    print("self-test: all passed")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def read_secret_file(path: Path) -> bytes:
    raw = path.read_bytes()
    # strip a single trailing newline common in text dumps
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if raw.endswith(b"\r"):
        raw = raw[:-1]
    return raw


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--self-test", action="store_true", help="run cipher KATs and exit")
    ap.add_argument("--client-auth-secret", type=Path, help="path to client_auth_secret.txt")
    ap.add_argument("--server-wrap-key", type=Path, help="path to server_wrap_key.pem")
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=Path("."),
        help="directory for slicer_*.pem / slicer_cert_id.txt (default: cwd)",
    )
    ap.add_argument("--api", default=DEFAULT_API, help=f"API host (default {DEFAULT_API})")
    ap.add_argument(
        "--compare-key",
        type=Path,
        help="optional existing slicer_key.pem to compare modulus against",
    )
    args = ap.parse_args(argv)

    if args.self_test:
        print("== cipher self-test ==")
        self_test()
        if not args.client_auth_secret:
            return 0

    if not args.client_auth_secret or not args.server_wrap_key:
        ap.error("need --client-auth-secret and --server-wrap-key (or --self-test alone)")

    secret = read_secret_file(args.client_auth_secret)
    wrap_pem = args.server_wrap_key.read_bytes()
    print(f"client_auth_secret: {len(secret)} bytes")
    print(f"building request against {args.api} …")
    url = build_cert_url(secret, wrap_pem, args.api)
    # Don't print full URL (contains encrypted secret material).
    print(f"GET …/applications/{{enc_secret}}/cert?aes256=…&ver=1")
    data = fetch_app_cert(url)
    cert_pem = data["cert"]
    if isinstance(cert_pem, list):
        cert_pem = "".join(cert_pem)
    crl_field = data.get("crl") or []
    if isinstance(crl_field, str):
        crl_pem = crl_field
    else:
        crl_pem = "".join(crl_field)

    print("decrypting key blob …")
    p, q, dp, dq, qinv = decode_key_blob(data["key"])
    key = rsa_from_crt(p, q, dp, dq, qinv)
    leaf = first_cert(cert_pem)
    pub_n = leaf.public_key().public_numbers().n
    priv_n = key.private_numbers().public_numbers.n
    if pub_n != priv_n:
        print("error: reconstructed key modulus does not match leaf certificate", file=sys.stderr)
        return 1
    print("OK: private key modulus matches leaf certificate")

    cert_id = cert_id_for_leaf(leaf)
    key_pem = private_key_pem(key)

    if args.compare_key and args.compare_key.is_file():
        old = serialization.load_pem_private_key(args.compare_key.read_bytes(), password=None)
        old_n = old.private_numbers().public_numbers.n
        if old_n == priv_n:
            print(f"OK: matches --compare-key {args.compare_key}")
        else:
            print(f"NOTE: modulus differs from --compare-key {args.compare_key} (rotated?)")

    out = args.out_dir
    out.mkdir(parents=True, exist_ok=True)
    (out / "slicer_cert.pem").write_text(cert_pem if cert_pem.endswith("\n") else cert_pem + "\n")
    (out / "slicer_crl.pem").write_text(crl_pem if crl_pem.endswith("\n") else crl_pem + "\n")
    (out / "slicer_key.pem").write_text(key_pem if key_pem.endswith("\n") else key_pem + "\n")
    (out / "slicer_cert_id.txt").write_text(cert_id + "\n")
    print(f"wrote:")
    for name in ("slicer_cert.pem", "slicer_crl.pem", "slicer_key.pem", "slicer_cert_id.txt"):
        print(f"  {out / name}")
    print(f"cert_id: {cert_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
