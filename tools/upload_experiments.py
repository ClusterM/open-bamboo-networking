#!/usr/bin/env python3
"""Batch FILE_UPLOAD (cmdtype 5) experiments over TLS :6000.

Usage:
    python3 tools/upload_experiments.py HOST ACCESS_CODE /path/to/file.3mf
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sys
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bambu6000_repl import (  # noqa: E402
    MAGIC_CTRL,
    MAGIC_LOGIN,
    build_ctrl_setup_json,
    build_frame_header,
    build_login_payload,
    connect_tls,
    parse_frames,
    split_text_and_binary,
    wrap_ctrl_json,
)


@dataclass
class StepResult:
    label: str
    ok: bool
    detail: str


class UploadLab:
    def __init__(self, host: str, code: str, *, user: str = "bblp") -> None:
        self.host = host
        self.code = code
        self.user = user

    def _session(self):
        sock = connect_tls(self.host, 6000, verify_tls=False)
        seq = 1

        def send_frame(magic: int, payload: bytes) -> None:
            nonlocal seq
            hdr = build_frame_header(len(payload), magic, seq)
            seq += 1
            sock.sendall(hdr)
            if payload:
                sock.sendall(payload)

        send_frame(MAGIC_LOGIN, build_login_payload(self.user, self.code))
        sock.settimeout(3.0)
        try:
            sock.recv(4096)
        except socket.timeout:
            pass
        send_frame(MAGIC_CTRL, build_ctrl_setup_json(f"{seq:08x}"))
        try:
            sock.recv(4096)
        except socket.timeout:
            pass
        sock.settimeout(None)
        return sock, send_frame

    def _recv_json(self, sock: socket.socket, timeout: float = 30.0) -> Optional[dict[str, Any]]:
        sock.settimeout(timeout)
        buf = b""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            frames = parse_frames(buf)
            if frames:
                text, _ = split_text_and_binary(frames[0][3])
                if text:
                    try:
                        return json.loads(text)
                    except json.JSONDecodeError:
                        return None
        return None

    def _delete(self, send_frame, sock, seq: int, storage: str, name: str) -> None:
        req = {"delete": [name]}
        if storage:
            req["storage"] = storage
        send_frame(
            MAGIC_CTRL,
            wrap_ctrl_json({"cmdtype": 3, "sequence": seq, "req": req}),
        )
        self._recv_json(sock, 10.0)

    def _send_chunked(
        self,
        *,
        data: bytes,
        remote_name: str,
        storage: str,
        init_req_extra: Optional[dict[str, Any]] = None,
        chunk_scale: Callable[[int], int] = lambda kb: kb * 1024,
        separator: bytes = b"\n\n",
        frag_id_start: int = 0,
        chunk_req_extra: Optional[dict[str, Any]] = None,
        md5_lower: bool = True,
        do_delete: bool = False,
        init_builder: Optional[Callable[[], dict[str, Any]]] = None,
    ) -> StepResult:
        sock, send_frame = self._session()
        seq = 2
        try:
            if do_delete:
                self._delete(send_frame, sock, seq, storage, remote_name)
                seq += 1

            if init_builder:
                init_req = init_builder()
            else:
                init_req = {
                    "type": "model",
                    "storage": storage,
                    "path": remote_name,
                    "total": len(data),
                }
                if init_req_extra:
                    init_req.update(init_req_extra)

            send_frame(
                MAGIC_CTRL,
                wrap_ctrl_json({"cmdtype": 5, "sequence": seq, "req": init_req}),
            )
            init_reply = self._recv_json(sock, 30.0)
            if not init_reply:
                return StepResult("chunked", False, "no init reply")
            ir = init_reply.get("result")
            if ir not in (1, 19):
                return StepResult("chunked", False, f"init result={ir} {init_reply}")

            reply = init_reply.get("reply") or {}
            chunk_kb = int(reply.get("chunk_size") or 0)
            chunk_size = chunk_scale(chunk_kb)
            if chunk_size <= 0:
                return StepResult("chunked", False, f"bad chunk_size={chunk_kb}")

            md5 = hashlib.md5()
            offset = 0
            frag_id = frag_id_start
            parts: list[str] = [f"init={ir},cs={chunk_kb}->{chunk_size}"]

            while offset < len(data):
                end = min(offset + chunk_size, len(data))
                chunk = data[offset:end]
                md5.update(chunk)
                req: dict[str, Any] = {
                    "frag_id": frag_id,
                    "offset": offset,
                    "size": len(chunk),
                }
                if chunk_req_extra:
                    req.update(chunk_req_extra)
                if end >= len(data):
                    digest = md5.hexdigest()
                    req["file_md5"] = digest.lower() if md5_lower else digest.upper()

                body = wrap_ctrl_json({"cmdtype": 5, "sequence": seq, "req": req})
                send_frame(MAGIC_CTRL, body + separator + chunk)
                chunk_reply = self._recv_json(sock, 120.0)
                if not chunk_reply:
                    parts.append(f"c{frag_id}=timeout")
                    return StepResult("chunked", False, "; ".join(parts))

                cr = chunk_reply.get("result")
                prog = (chunk_reply.get("reply") or {}).get("progress")
                parts.append(f"c{frag_id}={cr}" + (f"@{prog}" if prog is not None else ""))
                if cr in (0, 19):
                    return StepResult("chunked", True, "; ".join(parts))
                if cr != 1:
                    return StepResult("chunked", False, "; ".join(parts))
                offset = end
                frag_id += 1

            return StepResult("chunked", False, "; ".join(parts) + "; no final ack")
        finally:
            sock.close()

    def _send_oneshot(
        self,
        *,
        data: bytes,
        remote_name: str,
        storage: str,
        req_extra: Optional[dict[str, Any]] = None,
        separator: bytes = b"\n\n",
        md5_upper: bool = True,
    ) -> StepResult:
        sock, send_frame = self._session()
        try:
            digest = hashlib.md5(data).hexdigest()
            req: dict[str, Any] = {
                "path": f"/{storage}/" if storage else "/",
                "file": remote_name,
                "size": len(data),
                "md5": digest.upper() if md5_upper else digest.lower(),
                "peer": "studio",
                "api_version": 3,
            }
            if storage:
                req["storage"] = storage
            if req_extra:
                req.update(req_extra)
            body = wrap_ctrl_json({"cmdtype": 5, "sequence": 3, "req": req})
            send_frame(MAGIC_CTRL, body + separator + data)
            reply = self._recv_json(sock, 180.0)
            if not reply:
                return StepResult("oneshot", False, "no reply")
            r = reply.get("result")
            ok = r in (0, 1, 19)
            return StepResult("oneshot", ok, f"result={r} {reply}")
        finally:
            sock.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("access_code")
    ap.add_argument("file_path")
    ap.add_argument("--storage", default="emmc")
    ap.add_argument("--max-tests", type=int, default=0, help="0 = all")
    args = ap.parse_args()

    with open(args.file_path, "rb") as fh:
        data = fh.read()

    lab = UploadLab(args.host, args.access_code)
    tag = uuid.uuid4().hex[:8]
    base = f"obn_{tag}"

    tests: list[tuple[str, Callable[[], StepResult]]] = []

    def add(name: str, fn: Callable[[], StepResult]) -> None:
        tests.append((name, fn))

    # --- small synthetic payloads (fast probes) ---
    small = data[:65536]
    tiny = data[:4096]

    add(
        "tiny_emmc_baseline",
        lambda: lab._send_chunked(
            data=tiny, remote_name=f"{base}_tiny.3mf", storage="emmc"
        ),
    )
    add(
        "small_emmc_baseline",
        lambda: lab._send_chunked(
            data=small, remote_name=f"{base}_64k.3mf", storage="emmc"
        ),
    )
    add(
        "full_emmc_baseline",
        lambda: lab._send_chunked(
            data=data, remote_name=f"{base}_full.3mf", storage="emmc"
        ),
    )
    add(
        "full_udisk_baseline",
        lambda: lab._send_chunked(
            data=data, remote_name=f"{base}_full.3mf", storage="udisk"
        ),
    )
    add(
        "full_emmc_delete_first",
        lambda: lab._send_chunked(
            data=data,
            remote_name=f"{base}_del.3mf",
            storage="emmc",
            do_delete=True,
        ),
    )
    add(
        "full_emmc_chunk_bytes_not_kb",
        lambda: lab._send_chunked(
            data=data,
            remote_name=f"{base}_cbytes.3mf",
            storage="emmc",
            chunk_scale=lambda kb: kb,
        ),
    )
    add(
        "full_emmc_api_v3_init",
        lambda: lab._send_chunked(
            data=data,
            remote_name=f"{base}_api3.3mf",
            storage="emmc",
            init_req_extra={"peer": "studio", "api_version": 3},
        ),
    )
    add(
        "full_emmc_init_md5",
        lambda: lab._send_chunked(
            data=data,
            remote_name=f"{base}_imd5.3mf",
            storage="emmc",
            init_req_extra={
                "file_md5": hashlib.md5(data).hexdigest().lower(),
            },
        ),
    )
    add(
        "full_storage_internal",
        lambda: lab._send_chunked(
            data=data,
            remote_name=f"{base}_internal.3mf",
            storage="internal",
        ),
    )
    add(
        "full_emmc_frag_id_1",
        lambda: lab._send_chunked(
            data=data,
            remote_name=f"{base}_fid1.3mf",
            storage="emmc",
            frag_id_start=1,
        ),
    )
    add(
        "full_emmc_sep_nl",
        lambda: lab._send_chunked(
            data=data,
            remote_name=f"{base}_nl.3mf",
            storage="emmc",
            separator=b"\n",
        ),
    )
    add(
        "full_emmc_sep_none",
        lambda: lab._send_chunked(
            data=data,
            remote_name=f"{base}_nosep.3mf",
            storage="emmc",
            separator=b"",
        ),
    )
    add(
        "full_emmc_chunk_storage",
        lambda: lab._send_chunked(
            data=data,
            remote_name=f"{base}_cstor.3mf",
            storage="emmc",
            chunk_req_extra={"storage": "emmc"},
        ),
    )
    add(
        "full_emmc_md5_upper",
        lambda: lab._send_chunked(
            data=data,
            remote_name=f"{base}_m5u.3mf",
            storage="emmc",
            md5_lower=False,
        ),
    )
    add(
        "full_emmc_path_slash",
        lambda: lab._send_chunked(
            data=data,
            remote_name=f"{base}_path.3mf",
            storage="emmc",
            init_builder=lambda: {
                "type": "model",
                "storage": "emmc",
                "path": f"/emmc/{base}_path.3mf",
                "total": len(data),
            },
        ),
    )
    add(
        "oneshot_emmc_full",
        lambda: lab._send_oneshot(
            data=data, remote_name=f"{base}_1shot.3mf", storage="emmc"
        ),
    )
    add(
        "oneshot_udisk_full",
        lambda: lab._send_oneshot(
            data=data, remote_name=f"{base}_1shot.3mf", storage="udisk"
        ),
    )
    add(
        "oneshot_emmc_small",
        lambda: lab._send_oneshot(
            data=small, remote_name=f"{base}_1s64.3mf", storage="emmc"
        ),
    )
    add(
        "legacy_init_then_oneshot_body",
        lambda: lab._send_chunked(
            data=data,
            remote_name=f"{base}_leg.3mf",
            storage="emmc",
            init_builder=lambda: {
                "path": "/emmc/",
                "file": f"{base}_leg.3mf",
                "size": len(data),
                "md5": hashlib.md5(data).hexdigest().upper(),
                "storage": "emmc",
                "peer": "studio",
                "api_version": 3,
            },
            chunk_scale=lambda kb: len(data),  # force single "chunk" with all data
        ),
    )

    limit = args.max_tests or len(tests)
    print(f"file={args.file_path} size={len(data)} storage_default={args.storage}")
    print(f"running {min(limit, len(tests))}/{len(tests)} experiments\n")

    wins: list[str] = []
    for i, (name, fn) in enumerate(tests[:limit]):
        t0 = time.time()
        try:
            res = fn()
        except Exception as exc:
            res = StepResult(name, False, f"exception: {exc}")
        dt = time.time() - t0
        mark = "OK" if res.ok else "FAIL"
        print(f"[{i+1:02d}] {mark:4s} {name:30s} {dt:6.1f}s  {res.detail}")
        if res.ok:
            wins.append(name)

    print()
    if wins:
        print("SUCCESS:", ", ".join(wins))
    else:
        print("No successful upload variant found.")
    return 0 if wins else 1


if __name__ == "__main__":
    raise SystemExit(main())
