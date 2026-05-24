#!/usr/bin/env python3
"""Interactive TLS :6000 REPL for reverse-engineering Bambu printer file browser.

Stock libBambuSource (BambuTunnelLocal, P2S Device -> Files) uses:

  TCP/TLS :6000
    -> subchannel 0x01: 16-byte hdr + 16-byte login (user[8] + access_code[8])
    -> subchannel 0x02: StartStreamEx JSON (mtype 12291) + framed CTRL JSON (mtype 12289)

This is **not** the 80-byte 0x3000 auth from OpenBambuAPI/video.md (MJPEG camera on A1/P1).

Frida tutk_third_SSL_write shows only channel-0x02 traffic after the session is up;
the login + 12291 handshake happen earlier inside Bambu_Open / Bambu_StartStreamEx.

Send to Printer uses libbambu_networking.so (ft_*), not BambuSource — sniff with
tools/frida_ft_attach.sh (stock plugin) or probe upload here with /upload.

Usage:
    python3 tools/bambu6000_repl.py 10.13.1.30 ABCD1234

Example LIST (External timelapse) — type one JSON line; framing is added automatically:
    {"cmdtype":1,"sequence":1,"req":{"type":"timelapse","api_version":2,"notify":"DETAIL"}}

REPL commands:
    /quit, /exit          — close session
    /ability              — REQUEST_MEDIA_ABILITY (cmdtype 7)
    /upload <local> <storage> <remote_name> — FILE_UPLOAD (cmdtype 5)
    /hex 404142...        — send raw bytes (even length hex string)
    /file path.bin        — send file contents
    /raw on|off           — send typed lines as raw bytes (no framing)
    /nl on|off            — append \\n to each typed line (default off)

Requires: Python 3.10+, stdlib only.
"""
from __future__ import annotations

import hashlib
import argparse
import json
import random
import socket
import ssl
import struct
import sys
import threading
import time
from contextlib import contextmanager
from typing import Any, Iterator, Optional

# Client -> printer (byte 7 of magic = 0x01). Server replies use 0x00.
MAGIC_LOGIN = 0x0101013F
MAGIC_CTRL = 0x0102013F

MTYPE_CTRL_SETUP = 12291  # 0x3003 — StartStreamEx handshake
MTYPE_CTRL_JSON = 12289   # 0x3001 — file browser RPC


def build_mjpeg_auth_packet(username: str, password: str) -> bytes:
    """80-byte MJPEG auth (type 0x3000) — camera path only, not file browser."""
    user = username.encode("ascii", errors="replace")[:32]
    pwd = password.encode("ascii", errors="replace")[:32]
    pkt = bytearray(80)
    struct.pack_into("<I", pkt, 0, 0x40)
    struct.pack_into("<I", pkt, 4, 0x3000)
    pkt[16 : 16 + len(user)] = user
    pkt[48 : 48 + len(pwd)] = pwd
    return bytes(pkt)


def build_frame_header(payload_len: int, magic: int, seq: int) -> bytes:
    hdr = bytearray(16)
    struct.pack_into("<I", hdr, 0, payload_len)
    struct.pack_into("<I", hdr, 4, magic)
    struct.pack_into("<I", hdr, 8, seq)
    return bytes(hdr)


def build_login_payload(username: str, access_code: str) -> bytes:
    user = username.encode("ascii", errors="replace")[:8].ljust(8, b"\0")
    code = access_code.encode("ascii", errors="replace")[:8].ljust(8, b"\0")
    return user + code


def build_ctrl_setup_json(pid: str, *, client_ver: str = "02.03.00.00") -> bytes:
    obj = {
        "sequence": 0,
        "mtype": MTYPE_CTRL_SETUP,
        "req": {
            "t_av": 1,
            "mtype": MTYPE_CTRL_JSON,
            "peer_t": 3,
            "pid": pid,
            "ver": client_ver,
        },
    }
    return json.dumps(obj, separators=(",", ":")).encode("ascii")


def wrap_ctrl_json(obj: dict[str, Any]) -> bytes:
    """Match stock wire format: prepend mtype 12289 to the ABI JSON body."""
    if "mtype" not in obj:
        obj = {"mtype": MTYPE_CTRL_JSON, **obj}
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def parse_frames(data: bytes) -> list[tuple[int, int, int, bytes]]:
    frames: list[tuple[int, int, int, bytes]] = []
    i = 0
    while i + 16 <= len(data):
        pl = struct.unpack_from("<I", data, i)[0]
        magic = struct.unpack_from("<I", data, i + 4)[0]
        seq = struct.unpack_from("<I", data, i + 8)[0]
        body = data[i + 16 : i + 16 + pl]
        frames.append((pl, magic, seq, body))
        i += 16 + pl
    return frames


def _json_prefix_end(data: bytes) -> Optional[int]:
    """Return byte index after the first top-level JSON object, or None."""
    if not data.startswith(b"{"):
        return None
    depth = 0
    in_str = False
    esc = False
    for i, b in enumerate(data):
        if in_str:
            if esc:
                esc = False
            elif b == ord("\\"):
                esc = True
            elif b == ord('"'):
                in_str = False
            continue
        if b == ord('"'):
            in_str = True
        elif b == ord("{"):
            depth += 1
        elif b == ord("}"):
            depth -= 1
            if depth == 0:
                return i + 1
    return None


def split_text_and_binary(data: bytes) -> tuple[Optional[str], bytes]:
    """Split payload into a leading text/JSON string and any trailing binary."""
    if not data:
        return None, b""

    jend = _json_prefix_end(data)
    if jend is not None:
        try:
            text = data[:jend].decode("utf-8")
        except UnicodeDecodeError:
            pass
        else:
            tail = data[jend:].lstrip(b"\r\n\t ")
            return text, tail

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None, data

    if text.isprintable() or all(c in "\n\r\t" for c in text):
        return text, b""
    return None, data


def format_hex(data: bytes, hex_limit: int = 512) -> list[str]:
    if not data:
        return []
    lines = [f"--- binary {len(data)} bytes ---"]
    show = min(len(data), hex_limit)
    for off in range(0, show, 16):
        row = data[off : off + 16]
        hex_part = " ".join(f"{b:02x}" for b in row)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{off:04x}  {hex_part:<47}  {asc}")
    if len(data) > show:
        lines.append(f"... ({len(data) - show} more bytes)")
    return lines


def format_payload(body: bytes, hex_limit: int = 512) -> list[str]:
    text, binary = split_text_and_binary(body)
    lines: list[str] = []
    if text is not None:
        lines.append(text)
    if binary:
        lines.extend(format_hex(binary, hex_limit))
    return lines


def format_recv(data: bytes, hex_limit: int = 512) -> str:
    lines: list[str] = [f"<< recv {len(data)} bytes"]
    frames = parse_frames(data)
    if frames:
        consumed = sum(16 + pl for pl, _, _, _ in frames)
        for _pl, _magic, _seq, body in frames:
            lines.extend(format_payload(body, hex_limit))
        tail = data[consumed:]
        if tail:
            lines.extend(format_payload(tail, hex_limit))
        return "\n".join(lines)

    lines.extend(format_payload(data, hex_limit))
    return "\n".join(lines)


class LocalCtrlSession:
    """BambuTunnelLocal file-browser session with auto framing."""

    def __init__(
        self,
        ssl_sock: ssl.SSLSocket,
        *,
        seq_base: Optional[int] = None,
        send_raw: bool = False,
        append_nl: bool = False,
        recv_hex_limit: int = 512,
    ) -> None:
        self._ssl = ssl_sock
        self._seq = seq_base if seq_base is not None else random.randint(1, 0x7FFFFFFF)
        self._send_raw = send_raw
        self._append_nl = append_nl
        self._recv_hex_limit = recv_hex_limit
        self._stop = threading.Event()
        self._sync_depth = 0
        self._rx_buf = bytearray()
        self._lock = threading.Lock()
        self._reader = threading.Thread(target=self._recv_loop, daemon=True)

    @property
    def pid(self) -> str:
        return f"{self._seq & 0xFFFFFFFF:08x}"

    def start(self) -> None:
        self._reader.start()

    def close(self) -> None:
        self._stop.set()
        try:
            self._ssl.close()
        except OSError:
            pass

    def _next_seq(self) -> int:
        s = self._seq
        self._seq += 1
        return s

    def _send_frame(self, magic: int, payload: bytes) -> None:
        hdr = build_frame_header(len(payload), magic, self._next_seq())
        with self._lock:
            self._ssl.sendall(hdr)
            if payload:
                self._ssl.sendall(payload)
        print(
            f">> frame magic=0x{magic:08x} payload={len(payload)} bytes",
            flush=True,
        )

    def _recv_once(self, timeout: float = 5.0) -> bytes:
        self._ssl.settimeout(timeout)
        chunks: list[bytes] = []
        try:
            while True:
                chunk = self._ssl.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except socket.timeout:
            pass
        finally:
            # Handshake uses short timeouts; the background reader blocks until data.
            self._ssl.settimeout(None)
        return b"".join(chunks)

    @contextmanager
    def _sync_recv(self) -> Iterator[None]:
        self._sync_depth += 1
        try:
            yield
        finally:
            self._sync_depth -= 1

    def _pop_json_frame(self, timeout: float) -> Optional[dict[str, Any]]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                frames = parse_frames(bytes(self._rx_buf))
                if frames:
                    pl, _magic, _seq, body = frames[0]
                    del self._rx_buf[: 16 + pl]
                    text, _bin = split_text_and_binary(body)
                    if text:
                        try:
                            obj = json.loads(text)
                        except json.JSONDecodeError:
                            return None
                        if isinstance(obj, dict):
                            return obj
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            with self._lock:
                self._ssl.settimeout(min(1.0, remaining))
                try:
                    chunk = self._ssl.recv(65536)
                except socket.timeout:
                    chunk = b""
                finally:
                    self._ssl.settimeout(None)
            if chunk:
                self._rx_buf.extend(chunk)
        return None

    def handshake(self, username: str, access_code: str) -> None:
        login = build_login_payload(username, access_code)
        self._send_frame(MAGIC_LOGIN, login)
        r1 = self._recv_once(2.0)
        if r1:
            print(format_recv(r1, self._recv_hex_limit), flush=True)

        setup = build_ctrl_setup_json(self.pid)
        self._send_frame(MAGIC_CTRL, setup)
        r2 = self._recv_once(3.0)
        if r2:
            print(format_recv(r2, self._recv_hex_limit), flush=True)
        print("CTRL session ready (channel 0x02).", flush=True)

    def send_bytes(self, payload: bytes) -> None:
        with self._lock:
            self._ssl.sendall(payload)
        print(f">> sent {len(payload)} raw bytes", flush=True)

    def send_ctrl_json(self, obj: dict[str, Any]) -> None:
        body = wrap_ctrl_json(obj)
        self._send_frame(MAGIC_CTRL, body)

    def _recv_loop(self) -> None:
        # Do not hold _lock across recv: handshake/send paths need the same lock.
        self._ssl.settimeout(1.0)
        while not self._stop.is_set():
            if self._sync_depth > 0:
                time.sleep(0.02)
                continue
            try:
                data = self._ssl.recv(65536)
            except ssl.SSLWantReadError:
                continue
            except socket.timeout:
                continue
            except OSError as exc:
                if not self._stop.is_set():
                    print(f"<< recv error: {exc}", flush=True)
                break
            if not data:
                print("<< connection closed by peer", flush=True)
                self._stop.set()
                break
            print(format_recv(data, self._recv_hex_limit), flush=True)

    def send_ability(self) -> None:
        self.send_ctrl_json({
            "cmdtype": 7,
            "sequence": 1,
            "req": {"peer": "studio", "api_version": 2},
        })

    def send_upload(self, local_path: str, storage: str, remote_name: str) -> None:
        with open(local_path, "rb") as fh:
            data = fh.read()
        with self._sync_recv():
            seq = 2
            init_req = {
                "type": "model",
                "storage": storage,
                "path": remote_name,
                "total": len(data),
            }
            self.send_ctrl_json({"cmdtype": 5, "sequence": seq, "req": init_req})
            reply = self._pop_json_frame(30.0)
            if reply is None:
                raise OSError("no init reply")
            print(f"init reply: {reply}", flush=True)
            result = reply.get("result")
            if result not in (1, 19):
                raise OSError(f"init failed result={result}")
            resp = reply.get("reply") or {}
            chunk_kb = int(resp.get("chunk_size") or 0)
            offset = int(resp.get("offset") or 0)
            if chunk_kb <= 0:
                raise OSError("missing chunk_size in init reply")
            chunk_size = chunk_kb * 1024
            md5 = hashlib.md5()
            frag_id = 0
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
                payload = body + b"\n\n" + chunk
                self._send_frame(MAGIC_CTRL, payload)
                offset = end
                frag_id += 1
            # P2S expects all chunks on the wire before reading replies.
            chunk_reply = self._pop_json_frame(180.0)
            if chunk_reply is None:
                raise OSError("no reply after pipelined upload")
            print(f"upload reply: {chunk_reply}", flush=True)
            cr = chunk_reply.get("result")
            if cr in (0, 19):
                print("upload done", flush=True)
                return
            raise OSError(f"upload failed result={cr}")

    def run_interactive(self) -> None:
        mode = "raw" if self._send_raw else "framed JSON (mtype 12289)"
        print(f"Connected. Mode: {mode}.  /raw /hex /quit", flush=True)
        while not self._stop.is_set():
            try:
                line = input(">> ")
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            cmd = line.strip()
            low = cmd.lower()
            if low in ("/quit", "/exit", "/q"):
                break
            if low.startswith("/raw "):
                arg = low.split(maxsplit=1)[-1]
                self._send_raw = arg in ("on", "1", "true", "yes")
                print(f"raw mode: {self._send_raw}", flush=True)
                continue
            if low.startswith("/nl "):
                arg = low.split(maxsplit=1)[-1]
                self._append_nl = arg in ("on", "1", "true", "yes")
                print(f"append newline: {self._append_nl}", flush=True)
                continue
            if low.startswith("/upload "):
                parts = cmd.split(maxsplit=3)
                if len(parts) < 4:
                    print("usage: /upload <local_path> <storage> <remote_name>", flush=True)
                    continue
                try:
                    self.send_upload(parts[1], parts[2], parts[3])
                except OSError as exc:
                    print(f"upload failed: {exc}", flush=True)
                continue
            if low == "/ability":
                self.send_ability()
                continue
            if low.startswith("/hex "):
                hex_str = "".join(cmd.split(maxsplit=1)[1].split())
                try:
                    payload = bytes.fromhex(hex_str)
                except ValueError as exc:
                    print(f"bad hex: {exc}", flush=True)
                    continue
                self.send_bytes(payload)
                continue
            if low.startswith("/file "):
                path = cmd.split(maxsplit=1)[1]
                try:
                    with open(path, "rb") as fh:
                        payload = fh.read()
                except OSError as exc:
                    print(f"read failed: {exc}", flush=True)
                    continue
                self.send_bytes(payload)
                continue
            if self._send_raw:
                payload = line.encode("utf-8")
                if self._append_nl:
                    payload += b"\n"
                self.send_bytes(payload)
                continue
            if not cmd.startswith("{"):
                print("expected JSON line, /hex, or /raw on", flush=True)
                continue
            try:
                obj = json.loads(cmd)
            except json.JSONDecodeError as exc:
                print(f"bad json: {exc}", flush=True)
                continue
            if not isinstance(obj, dict):
                print("expected JSON object", flush=True)
                continue
            self.send_ctrl_json(obj)


def connect_tls(
    host: str,
    port: int,
    *,
    serial: Optional[str] = None,
    verify_tls: bool = False,
    ca_file: Optional[str] = None,
    timeout: float = 10.0,
) -> ssl.SSLSocket:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    sni = serial or host
    if verify_tls:
        if ca_file:
            ctx.load_verify_locations(cafile=ca_file)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    raw = socket.create_connection((host, port), timeout=timeout)
    return ctx.wrap_socket(raw, server_hostname=sni)


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Interactive TLS :6000 REPL (BambuTunnelLocal file browser)",
    )
    p.add_argument("host", help="printer LAN IP")
    p.add_argument("access_code", help="8-char printer access code")
    p.add_argument("--port", type=int, default=6000, help="TCP port (default 6000)")
    p.add_argument("--user", default="bblp", help="login username (default bblp)")
    p.add_argument("--serial", help="printer serial for TLS SNI / verify")
    p.add_argument("--verify", action="store_true", help="verify printer TLS")
    p.add_argument(
        "--ca-file",
        help="BBL CA bundle PEM for --verify",
    )
    p.add_argument(
        "--mjpeg-auth",
        action="store_true",
        help="send legacy 80-byte 0x3000 auth (MJPEG camera) instead of Local login",
    )
    p.add_argument(
        "--no-handshake",
        action="store_true",
        help="skip login + mtype-12291 setup (for /hex experiments)",
    )
    p.add_argument("--init-hex", help="hex bytes to send after handshake")
    p.add_argument("--init-file", help="file to send after handshake")
    p.add_argument("--append-nl", action="store_true", help="append newline in /raw mode")
    p.add_argument("--raw", action="store_true", help="start in raw byte mode (no JSON framing)")
    p.add_argument("--recv-hex-limit", type=int, default=512)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        ssl_sock = connect_tls(
            args.host,
            args.port,
            serial=args.serial,
            verify_tls=args.verify,
            ca_file=args.ca_file,
        )
    except OSError as exc:
        print(f"connect failed: {exc}", file=sys.stderr)
        return 1

    print(f"TLS ok, cipher={ssl_sock.cipher()[0]}", flush=True)

    if args.mjpeg_auth:
        auth = build_mjpeg_auth_packet(args.user, args.access_code)
        ssl_sock.sendall(auth)
        print("sent 80-byte MJPEG auth (0x3000) — not the file-browser path", flush=True)
        repl = LocalCtrlSession(
            ssl_sock,
            send_raw=True,
            append_nl=args.append_nl,
            recv_hex_limit=args.recv_hex_limit,
        )
    else:
        repl = LocalCtrlSession(
            ssl_sock,
            send_raw=args.raw,
            append_nl=args.append_nl,
            recv_hex_limit=args.recv_hex_limit,
        )
        if not args.no_handshake:
            repl.handshake(args.user, args.access_code)

    repl.start()

    if args.init_hex:
        try:
            repl.send_bytes(bytes.fromhex("".join(args.init_hex.split())))
        except ValueError as exc:
            print(f"bad --init-hex: {exc}", file=sys.stderr)
            repl.close()
            return 1
    if args.init_file:
        try:
            with open(args.init_file, "rb") as fh:
                repl.send_bytes(fh.read())
        except OSError as exc:
            print(f"--init-file: {exc}", file=sys.stderr)
            repl.close()
            return 1

    try:
        repl.run_interactive()
    finally:
        repl.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
