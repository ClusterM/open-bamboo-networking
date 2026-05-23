#!/usr/bin/env python3
"""Repeated pipeline upload tests (delete + init + pipeline chunks + one recv)."""
from __future__ import annotations

import hashlib
import json
import socket
import sys
import time
import uuid
from typing import Any, Optional

import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bambu6000_repl import (  # noqa: E402
    MAGIC_CTRL,
    MAGIC_LOGIN,
    MTYPE_CTRL_JSON,
    build_ctrl_setup_json,
    build_frame_header,
    build_login_payload,
    connect_tls,
    parse_frames,
    split_text_and_binary,
    wrap_ctrl_json,
)


def recv_json(sock: socket.socket, timeout: float = 30.0) -> Optional[dict[str, Any]]:
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
                    return {"_raw": text}
    return None


def send_frame(sock: socket.socket, frame_seq: list[int], magic: int, payload: bytes) -> None:
    hdr = build_frame_header(len(payload), magic, frame_seq[0])
    frame_seq[0] += 1
    sock.sendall(hdr)
    if payload:
        sock.sendall(payload)


def open_session(host: str, code: str, user: str = "bblp"):
    sock = connect_tls(host, 6000, verify_tls=False)
    fs = [1]
    send_frame(sock, fs, MAGIC_LOGIN, build_login_payload(user, code))
    sock.settimeout(3.0)
    try:
        sock.recv(4096)
    except socket.timeout:
        pass
    send_frame(sock, fs, MAGIC_CTRL, build_ctrl_setup_json(f"{fs[0]:08x}"))
    try:
        sock.recv(4096)
    except socket.timeout:
        pass
    sock.settimeout(None)
    return sock, fs


def pipeline_upload(
    sock: socket.socket,
    fs: list[int],
    data: bytes,
    storage: str,
    remote_name: str,
    *,
    do_delete: bool,
    wire_seq: int,
) -> tuple[bool, str]:
    seq = wire_seq
    if do_delete:
        req = {"delete": [remote_name], "storage": storage}
        send_frame(
            sock,
            fs,
            MAGIC_CTRL,
            wrap_ctrl_json({"cmdtype": 3, "sequence": seq, "req": req}),
        )
        del_reply = recv_json(sock, 15.0)
        if del_reply is None:
            return False, "delete: no reply"
        dr = del_reply.get("result")
        detail = f"delete seq={seq} result={dr} cmd={del_reply.get('cmdtype')}"
        if dr not in (0, 1, 19):
            return False, detail + f" body={del_reply}"
        seq += 1

    init_req = {
        "type": "model",
        "storage": storage,
        "path": remote_name,
        "total": len(data),
    }
    t0 = time.monotonic()
    send_frame(
        sock,
        fs,
        MAGIC_CTRL,
        wrap_ctrl_json({"cmdtype": 5, "sequence": seq, "req": init_req}),
    )
    init_reply = recv_json(sock, 30.0)
    if init_reply is None:
        return False, "init: no reply"
    ir = init_reply.get("result")
    detail = f"init seq={seq} result={ir} cmd={init_reply.get('cmdtype')}"
    if ir not in (1, 19):
        return False, detail + f" body={init_reply}"

    resp = init_reply.get("reply") or {}
    chunk_kb = int(resp.get("chunk_size") or 0)
    if chunk_kb <= 0:
        return False, detail + " missing chunk_size"
    chunk_size = chunk_kb * 1024
    offset = int(resp.get("offset") or 0)

    md5 = hashlib.md5()
    frag_id = 0
    send_t0 = time.monotonic()
    while offset < len(data):
        end = min(offset + chunk_size, len(data))
        chunk = data[offset:end]
        md5.update(chunk)
        req: dict[str, Any] = {
            "frag_id": frag_id,
            "offset": offset,
            "size": len(chunk),
        }
        if end >= len(data):
            req["file_md5"] = md5.hexdigest().lower()
        body = wrap_ctrl_json({"cmdtype": 5, "sequence": seq, "req": req})
        send_frame(sock, fs, MAGIC_CTRL, body + b"\n\n" + chunk)
        offset = end
        frag_id += 1

    send_dt = time.monotonic() - send_t0
    final = recv_json(sock, 180.0)
    total_dt = time.monotonic() - t0
    if final is None:
        return False, detail + f" chunks={frag_id} send={send_dt:.2f}s final=timeout"
    fr = final.get("result")
    ok = fr in (0, 19)
    return ok, (
        detail
        + f" chunks={frag_id} send={send_dt:.2f}s total={total_dt:.2f}s"
        + f" final result={fr} seq={final.get('sequence')} body={final}"
    )


def main() -> int:
    if len(sys.argv) < 4:
        print(f"usage: {sys.argv[0]} HOST CODE FILE [storage] [remote_name]", file=sys.stderr)
        return 2
    host, code, path = sys.argv[1], sys.argv[2], sys.argv[3]
    storage = sys.argv[4] if len(sys.argv) > 4 else "emmc"
    remote = sys.argv[5] if len(sys.argv) > 5 else os.path.basename(path)

    with open(path, "rb") as fh:
        data = fh.read()

    print(f"host={host} file={path} size={len(data)} storage={storage} name={remote}\n")

    # --- fresh connection, 5 consecutive uploads same name (Studio-like) ---
    print("=== same connection, delete each time, same remote name ===")
    sock, fs = open_session(host, code)
    wire_seq = 2
    for i in range(5):
        ok, msg = pipeline_upload(
            sock, fs, data, storage, remote, do_delete=True, wire_seq=wire_seq
        )
        wire_seq += 2  # delete + init share increment pattern like abi_ft wire_seq
        mark = "OK" if ok else "FAIL"
        print(f"  [{i+1}] {mark}: {msg}")
        time.sleep(0.5)
    sock.close()

    # --- fresh connection each attempt ---
    print("\n=== fresh connection per attempt ===")
    for i in range(3):
        sock, fs = open_session(host, code)
        ok, msg = pipeline_upload(
            sock, fs, data, storage, remote, do_delete=True, wire_seq=2
        )
        sock.close()
        mark = "OK" if ok else "FAIL"
        print(f"  [{i+1}] {mark}: {msg}")
        time.sleep(0.3)

    # --- udisk ---
    print("\n=== udisk, fresh each time ===")
    tag = uuid.uuid4().hex[:8]
    udisk_name = f"obn_{tag}.3mf"
    for i in range(2):
        sock, fs = open_session(host, code)
        ok, msg = pipeline_upload(
            sock, fs, data, "udisk", udisk_name, do_delete=True, wire_seq=2
        )
        sock.close()
        mark = "OK" if ok else "FAIL"
        print(f"  [{i+1}] {mark}: {msg}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
