#!/usr/bin/env python3
"""Extract the shared Bambu app private key from a process memory dump.

Note while the slicer key is the critical thing to extract here, we might as well 
extract all the certificates, keys, secrets and crl in one go with no other deps.

The stock networking plugin keeps the app private key obfuscated at rest as the
raw AES-CTR ``key`` blob (the same 704-byte blob the cloud cert endpoint returns:
``nonce(12) ‖ tag(16) ‖ u32le(ct_len) ‖ ciphertext``). It is decrypted to a
transient ``br_rsa_private_key`` only at sign time, so a plain-bytes scan for the
RSA CRT limbs finds nothing -- but the encrypted blob itself is resident and can
be unwrapped offline with the fixed-key custom-S-box AES-256-CTR cipher recovered
in research/§10.7. See research/10.07-bearssl-crypto-island.md
("Recovering the shared app key from a dump").

This works on any dump format whose memory is stored contiguously in the file
(Windows minidump ``procdump -ma``, a raw memory dump, an ELF core, ...): the
704-byte blob is contiguous on disk, so we scan the file bytes directly -- no
minidump/ELF parsing required.

Usage:
    # capture (Windows, SysInternals): procdump -accepteula -ma <pid|name> studio.dmp
    python extract_key_from_dump.py studio.dmp
    python extract_key_from_dump.py studio.dmp --out-dir ./out --key-sizes 2048,3072

Writes into --out-dir (default: cwd):
    slicer_key.pem                 recovered RSA private key (PKCS#8)
    slicer_cert.pem                full app cert chain (leaf -> intermediate ->
                                   application_root), assembled from the resident
                                   certs by walking issuer links -- byte-for-byte
                                   the same 3-PEM chain the cloud `cert` field
                                   returns, so security.app_cert_install accepts it
    slicer_cert_id.txt             MQTT cert_id for the leaf (serial ‖ issuer RFC4514)
    slicer_client_auth_secret.txt  bootstrap secret (reuse with fetch_slicer_credentials.py)
    slicer_crl.pem                 app-chain CRL(s), for security.app_cert_install
"""
from __future__ import annotations

import argparse
import mmap
import struct
import sys
from pathlib import Path

# Reuse the cipher + key/rt helpers from the cloud-fetch tool (same directory).
sys.path.insert(0, str(Path(__file__).resolve().parent))
import fetch_slicer_credentials as F  # noqa: E402

# Blob/plaintext layout constants live in the crypto module (single source of truth,
# shared with its own decode_key_blob); import the ones the scan below needs.
from fetch_slicer_credentials import (  # noqa: E402
    BLOB_HEADER_LEN,
    CRT_LIMB_COUNT,
    CT_LEN_OFFSET,
    FIRST_CT_BLOCK_COUNTER,
    NONCE_LEN,
    PT_HEADER_LEN,
    SKEY,
    SKEY_LEN,
)

# Sanity bounds for the PEM/heap-string scans below, so a stray BEGIN marker without
# a nearby END doesn't make us slurp megabytes.
MAX_CERT_PEM_LEN = 8000     # an RSA leaf/intermediate PEM is well under this
MAX_CRL_PEM_LEN = 20000     # app-chain CRLs are larger but still bounded
CLIENT_AUTH_SECRET_HEX_LEN = 16  # hex chars following the leaf-CN prefix (§10.2)

DEFAULT_RSA_KEY_SIZES = (2048, 3072, 4096, 1024)  # app key is 2048; rest are probes
EXPECTED_APP_CHAIN_LEN = 3   # leaf -> intermediate -> application_root
TEST_SIGN_PAYLOAD = b"open-bamboo-networking"  # sign/verify roundtrip proof message


def ct_len_for(bits: int) -> int:
    """Ciphertext length carried in the blob's u32le field for an RSA-`bits` key.

    Each of the 5 CRT limbs is half the modulus, i.e. bits/2 bits == bits/16 bytes;
    CTR ciphertext is the same length as the plaintext.
    """
    return PT_HEADER_LEN + CRT_LIMB_COUNT * (bits // 16)


def find_key_blob(mem: mmap.mmap, key_sizes: list[int]) -> tuple[int, bytes] | None:
    """Locate the encrypted key blob. Returns (file_offset, blob_bytes) or None.

    Fast path: only the first CTR block (counter=2) is needed to test the SKEY
    magic, and the AES round keys are fixed, so we test one AES block per
    candidate. Candidates are found by searching for the blob's u32le length
    field at offset +28 for each plausible RSA key size.
    """
    rk = F.key_expand(F.APPCERT_KEY)
    counter = struct.pack(">I", FIRST_CT_BLOCK_COUNTER)  # fixed; same for every candidate
    for bits in key_sizes:
        ct_len = ct_len_for(bits)
        blob_len = BLOB_HEADER_LEN + ct_len
        marker = struct.pack("<I", ct_len)
        pos = 0
        while True:
            k = mem.find(marker, pos)
            if k < 0:
                break
            pos = k + 1
            start = k - CT_LEN_OFFSET  # rewind from the length field to the blob start
            if start < 0:
                continue
            if start + blob_len > len(mem):
                break  # matches only grow; the blob can no longer fit before EOF
            nonce = mem[start : start + NONCE_LEN]
            ct0 = mem[start + BLOB_HEADER_LEN : start + BLOB_HEADER_LEN + SKEY_LEN]
            ks0 = F.aes_encrypt_block(nonce + counter, rk)
            if bytes(a ^ b for a, b in zip(ct0, ks0[:SKEY_LEN])) == SKEY:
                return start, bytes(mem[start : start + blob_len])
    return None


def collect_resident_certs(mem: mmap.mmap) -> list:
    """Parse every resident PEM certificate in the dump.

    Returns a list of x509.Certificate, deduplicated by DER bytes. Empty if
    ``cryptography`` is unavailable. One full-file scan feeds both the leaf lookup
    and the chain assembly below.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        return []
    begin = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    out, seen = [], set()
    pos = 0
    while True:
        a = mem.find(begin, pos)
        if a < 0:
            break
        pos = a + 1
        b = mem.find(end, a)
        if b < 0 or b - a > MAX_CERT_PEM_LEN:
            continue
        try:
            cert = x509.load_pem_x509_certificate(bytes(mem[a : b + len(end)]))
            der = cert.public_bytes(serialization.Encoding.DER)
        except Exception:
            continue
        if der not in seen:
            seen.add(der)
            out.append(cert)
    return out


def _rsa_modulus(cert):
    """RSA modulus n for `cert`, or None if the key is not RSA."""
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        return None
    pk = cert.public_key()
    return pk.public_numbers().n if isinstance(pk, rsa.RSAPublicKey) else None


def _ext_key_id(cert, oid, attr):
    """SubjectKeyIdentifier.digest / AuthorityKeyIdentifier.key_identifier, or None."""
    try:
        return getattr(cert.extensions.get_extension_for_oid(oid).value, attr)
    except Exception:
        return None


def _signed_by(child, parent) -> bool:
    """True iff `parent`'s public key verifies `child`'s certificate signature."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError:
        return False
    pub = parent.public_key()
    if not isinstance(pub, rsa.RSAPublicKey):
        return False  # app chain is RSA end to end
    try:
        pub.verify(child.signature, child.tbs_certificate_bytes,
                   padding.PKCS1v15(), child.signature_hash_algorithm)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def build_app_chain(leaf, certs: list, include_root: bool = False) -> list:
    """Order the resident app certs into a chain starting at `leaf`.

    Walks issuer links upward: for each cert, the parent is the resident cert whose
    subject matches the issuer, preferring an AuthorityKeyId->SubjectKeyId match and
    a verifying signature when several share a subject. Stops at the top of what is
    resident. The self-signed root (``BBL CA``) is excluded unless ``include_root``,
    reproducing the 3-PEM chain (leaf -> ``*.bambulab.com`` intermediate ->
    ``application_root``) that the cloud ``cert`` field carries and that
    ``security.app_cert_install`` expects.
    """
    from cryptography.x509.oid import ExtensionOID as X

    def ski(c):
        return _ext_key_id(c, X.SUBJECT_KEY_IDENTIFIER, "digest")

    def aki(c):
        return _ext_key_id(c, X.AUTHORITY_KEY_IDENTIFIER, "key_identifier")

    chain = [leaf]
    used = {id(leaf)}
    cur = leaf
    while cur.subject != cur.issuer:  # not yet at a self-signed cert
        cand = [c for c in certs if id(c) not in used and c.subject == cur.issuer]
        want = aki(cur)
        if want is not None:
            narrowed = [c for c in cand if ski(c) == want]
            if narrowed:
                cand = narrowed
        verified = [c for c in cand if _signed_by(cur, c)]
        parent = (verified or cand or [None])[0]
        if parent is None:
            break
        if parent.subject == parent.issuer and not include_root:
            break  # self-signed root; matches stock's chain-minus-root
        chain.append(parent)
        used.add(id(parent))
        cur = parent
    return chain


def find_client_auth_secret(mem: mmap.mmap, leaf) -> str | None:
    """Recover client_auth_secret = leaf-CN prefix + 16 hex chars (a 43-byte string).

    The leaf's CN gives the prefix; the bootstrap secret is that prefix followed by
    16 hardcoded hex chars, stored as a standalone heap string (§10.2).
    """
    try:
        from cryptography.x509.oid import NameOID
    except ImportError:
        return None
    cn = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn:
        return None
    prefix = cn[0].value.encode()
    hexset = set(b"0123456789abcdefABCDEF")
    pos = 0
    while True:
        k = mem.find(prefix, pos)
        if k < 0:
            break
        pos = k + 1
        tstart = k + len(prefix)
        tail = mem[tstart : tstart + CLIENT_AUTH_SECRET_HEX_LEN]
        if len(tail) != CLIENT_AUTH_SECRET_HEX_LEN or not all(c in hexset for c in tail):
            continue
        # The secret is a fixed 16-hex-char field (null-terminated heap string); if the
        # next byte is also hex this is a longer token (hash/UUID), not our secret.
        nxt = tstart + CLIENT_AUTH_SECRET_HEX_LEN
        if nxt < len(mem) and mem[nxt] in hexset:
            continue
        return (prefix + bytes(tail)).decode()
    return None


def find_app_crls(mem: mmap.mmap) -> list[bytes]:
    """Resident app-chain CRLs (issuer under bambulab.com), PEM bytes."""
    try:
        from cryptography import x509
    except ImportError:
        return []
    out, seen = [], set()
    begin, end = b"-----BEGIN X509 CRL-----", b"-----END X509 CRL-----"
    pos = 0
    while True:
        a = mem.find(begin, pos)
        if a < 0:
            break
        pos = a + 1
        b = mem.find(end, a)
        if b < 0 or b - a > MAX_CRL_PEM_LEN:
            continue
        pem = bytes(mem[a : b + len(end)])
        try:
            crl = x509.load_pem_x509_crl(pem)
        except Exception:
            continue
        if "bambulab.com" in crl.issuer.rfc4514_string() and pem not in seen:
            seen.add(pem)
            out.append(pem)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dump", type=Path, help="memory dump file (procdump -ma / raw / core)")
    ap.add_argument("--out-dir", type=Path, default=Path("."), help="output directory")
    ap.add_argument("--key-sizes", default=",".join(map(str, DEFAULT_RSA_KEY_SIZES)),
                    help="comma-separated RSA sizes to look for (default covers all common)")
    ap.add_argument("--include-root", action="store_true",
                    help="also append the self-signed root (BBL CA) to slicer_cert.pem; "
                         "off by default to match stock's 3-PEM chain-minus-root")
    args = ap.parse_args()

    if not args.dump.is_file():
        ap.error(f"no such file: {args.dump}")
    key_sizes = [int(s) for s in args.key_sizes.split(",") if s.strip()]
    args.out_dir.mkdir(parents=True, exist_ok=True)

    with open(args.dump, "rb") as fh:
        mem = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        print(f"scanning {args.dump} ({len(mem)/1e6:.0f} MB) for the app key blob...")
        hit = find_key_blob(mem, key_sizes)
        if not hit:
            print("no key blob found. The key is only resident once the plugin has "
                  "fetched the app cert (cold-start update_cert); make sure Studio has "
                  "started fully, then re-dump. Nothing written.", file=sys.stderr)
            return 1

        off, blob = hit
        print(f"found encrypted key blob at file offset 0x{off:x} ({len(blob)} bytes)")
        p, q, dp, dq, qinv = F.decode_key_blob(blob)  # decode_key_blob takes raw bytes
        key = F.rsa_from_crt(p, q, dp, dq, qinv)
        n = key.private_numbers().public_numbers.n
        pi = int.from_bytes(p, "big")
        qi = int.from_bytes(q, "big")
        assert pi * qi == n, "internal error: p*q != n"
        print(f"recovered RSA-{n.bit_length()} private key (p*q == n verified)")

        key_pem = F.private_key_pem(key)
        (args.out_dir / "slicer_key.pem").write_text(key_pem, newline="\n")
        print(f"wrote {args.out_dir / 'slicer_key.pem'}")

        certs = collect_resident_certs(mem)
        leaf = next((c for c in certs if _rsa_modulus(c) == n), None)
        if leaf is not None:
            from cryptography.hazmat.primitives import serialization
            chain = build_app_chain(leaf, certs, include_root=args.include_root)
            pem = "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in chain)
            (args.out_dir / "slicer_cert.pem").write_text(pem, newline="\n")
            cert_id = F.cert_id_for_leaf(leaf)
            (args.out_dir / "slicer_cert_id.txt").write_text(cert_id, newline="\n")
            print(f"wrote {args.out_dir / 'slicer_cert.pem'} ({len(chain)} cert(s)):")
            for i, c in enumerate(chain):
                role = "leaf" if i == 0 else ("root" if c.subject == c.issuer else "intermediate")
                print(f"    [{i}] {role:12s} subject {c.subject.rfc4514_string()}")
            if len(chain) < EXPECTED_APP_CHAIN_LEN and not args.include_root:
                print("    note: expected leaf -> intermediate -> application_root (3 PEMs); "
                      "some chain certs were not resident. app_cert_install may reject a "
                      "partial chain -- re-dump after Studio has fetched the cert, or fill "
                      "the gap from fetch_slicer_credentials.py.")
            print(f"cert_id: {cert_id}")

            secret = find_client_auth_secret(mem, leaf)
            if secret:
                (args.out_dir / "slicer_client_auth_secret.txt").write_text(secret, newline="")
                print(f"wrote {args.out_dir / 'slicer_client_auth_secret.txt'} "
                      f"({len(secret)} bytes) -- reuse with fetch_slicer_credentials.py")
            else:
                print("note: client_auth_secret not found (needs the leaf CN prefix + 16 hex)")

            # end-to-end proof: sign with the recovered key, verify with the leaf
            try:
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import padding
                sig = key.sign(TEST_SIGN_PAYLOAD, padding.PKCS1v15(), hashes.SHA256())
                leaf.public_key().verify(sig, TEST_SIGN_PAYLOAD,
                                         padding.PKCS1v15(), hashes.SHA256())
                print("sign/verify roundtrip against leaf: OK")
            except Exception as e:  # pragma: no cover
                print(f"warning: sign/verify check failed: {e}", file=sys.stderr)
        else:
            print("note: no matching leaf cert found resident; wrote key only. "
                  "cert_id needs the leaf (fetch it or dump after cert install).")

        crls = find_app_crls(mem)
        if crls:
            (args.out_dir / "slicer_crl.pem").write_bytes(b"".join(crls))
            print(f"wrote {args.out_dir / 'slicer_crl.pem'} ({len(crls)} CRL(s)) "
                  "-- for security.app_cert_install")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
