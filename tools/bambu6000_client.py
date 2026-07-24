#!/usr/bin/env python3
"""Shared TLS :6000 client (BambuTunnelLocal file-browser wire).

Used by bambu6000_repl.py and bambu6000_ftp_proxy.py. Stdlib only.
"""
from __future__ import annotations

import hashlib
import errno
import json
import random
import socket
import ssl
import struct
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Iterator, Optional

# Client -> printer (byte 7 of magic = 0x01). Server replies use 0x00.
MAGIC_LOGIN = 0x0101013F
MAGIC_CTRL = 0x0102013F

MTYPE_CTRL_SETUP = 12291
MTYPE_CTRL_JSON = 12289

RESULT_CONTINUE = 1
RESULT_OK = 0


class Printer6000Error(OSError):
    """Raised when the :6000 session is unusable."""


@dataclass(frozen=True)
class FileEntry:
    name: str
    path: str
    size: int
    time: int = 0
    date: str = ""
    storage: str = ""


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
    if "mtype" not in obj:
        obj = {"mtype": MTYPE_CTRL_JSON, **obj}
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def consume_frames(data: bytes) -> tuple[list[bytes], int]:
    bodies: list[bytes] = []
    i = 0
    while i + 16 <= len(data):
        pl = struct.unpack_from("<I", data, i)[0]
        frame_len = 16 + pl
        if i + frame_len > len(data):
            break
        bodies.append(data[i + 16 : i + 16 + pl])
        i += frame_len
    return bodies, i


def parse_frames(data: bytes) -> list[tuple[int, int, int, bytes]]:
    out: list[tuple[int, int, int, bytes]] = []
    i = 0
    while i + 16 <= len(data):
        pl = struct.unpack_from("<I", data, i)[0]
        magic = struct.unpack_from("<I", data, i + 4)[0]
        seq = struct.unpack_from("<I", data, i + 8)[0]
        frame_len = 16 + pl
        if i + frame_len > len(data):
            break
        out.append((pl, magic, seq, data[i + 16 : i + 16 + pl]))
        i += frame_len
    return out


def _json_prefix_end(data: bytes) -> Optional[int]:
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
    if not data:
        return None, b""

    jend = _json_prefix_end(data)
    if jend is not None:
        try:
            text = data[:jend].decode("utf-8")
        except UnicodeDecodeError:
            pass
        else:
            # Match tunnel_local::split_json_prefix — only skip explicit
            # "\n\n" or "\r\n\r\n". Do not strip spaces/newlines from file data.
            i = jend
            if i + 1 < len(data) and data[i : i + 2] == b"\n\n":
                i += 2
            elif i + 3 < len(data) and data[i : i + 4] == b"\r\n\r\n":
                i += 4
            return text, data[i:]

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


def _parse_file_entries(reply: dict[str, Any]) -> list[FileEntry]:
    resp = reply.get("reply") or {}
    raw = resp.get("file_lists")
    if not isinstance(raw, list):
        return []
    out: list[FileEntry] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        path = str(item.get("path") or "")
        size = int(item.get("size") or 0)
        mtime = int(item.get("time") or 0)
        date = str(item.get("date") or "")
        out.append(FileEntry(name=name, path=path, size=size, time=mtime, date=date))
    return out


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
        quiet: bool = False,
        log: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._ssl = ssl_sock
        self._frame_seq = seq_base if seq_base is not None else random.randint(1, 0x7FFFFFFF)
        self._cmd_seq = 1
        self._send_raw = send_raw
        self._append_nl = append_nl
        self._recv_hex_limit = recv_hex_limit
        self._quiet = quiet
        self._log = log or (lambda msg: print(msg, flush=True))
        self._stop = threading.Event()
        self._sync_depth = 0
        self._rx_buf = bytearray()
        self._lock = threading.Lock()
        self._rx_cv = threading.Condition(self._lock)
        self._reader = threading.Thread(target=self._recv_loop, daemon=True)

    @property
    def pid(self) -> str:
        return f"{self._frame_seq & 0xFFFFFFFF:08x}"

    def start(self) -> None:
        self._reader.start()

    def close(self) -> None:
        self._stop.set()
        try:
            self._ssl.close()
        except OSError:
            pass

    def _next_frame_seq(self) -> int:
        s = self._frame_seq
        self._frame_seq += 1
        return s

    def _next_cmd_seq(self) -> int:
        s = self._cmd_seq
        self._cmd_seq += 1
        return s

    def _emit(self, msg: str) -> None:
        if not self._quiet:
            self._log(msg)

    def _send_frame(self, magic: int, payload: bytes) -> None:
        hdr = build_frame_header(len(payload), magic, self._next_frame_seq())
        with self._lock:
            self._ssl.sendall(hdr)
            if payload:
                self._ssl.sendall(payload)
        self._emit(f">> frame magic=0x{magic:08x} payload={len(payload)} bytes")

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
            self._ssl.settimeout(None)
        return b"".join(chunks)

    @contextmanager
    def _sync_recv(self) -> Iterator[None]:
        with self._lock:
            self._sync_depth += 1
        try:
            yield
        finally:
            with self._lock:
                self._sync_depth -= 1

    def _pop_json_frame(self, timeout: float) -> Optional[dict[str, Any]]:
        obj, _bin = self._pop_body_frame(timeout)
        return obj

    def _pop_body_frame(self, timeout: float) -> tuple[Optional[dict[str, Any]], bytes]:
        deadline = time.monotonic() + timeout
        with self._rx_cv:
            while time.monotonic() < deadline:
                if len(self._rx_buf) >= 16:
                    pl = struct.unpack_from("<I", self._rx_buf, 0)[0]
                    frame_len = 16 + pl
                    if len(self._rx_buf) >= frame_len:
                        body = bytes(self._rx_buf[16:frame_len])
                        del self._rx_buf[:frame_len]
                        text, binary = split_text_and_binary(body)
                        if text:
                            try:
                                obj = json.loads(text)
                            except json.JSONDecodeError:
                                return None, binary
                            if isinstance(obj, dict):
                                return obj, binary
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._rx_cv.wait(timeout=min(1.0, remaining))
        return None, b""

    def handshake(self, username: str, access_code: str) -> None:
        login = build_login_payload(username, access_code)
        self._send_frame(MAGIC_LOGIN, login)
        r1 = self._recv_once(2.0)
        if r1:
            self._emit(format_recv(r1, self._recv_hex_limit))

        setup = build_ctrl_setup_json(self.pid)
        self._send_frame(MAGIC_CTRL, setup)
        r2 = self._recv_once(3.0)
        if r2:
            self._emit(format_recv(r2, self._recv_hex_limit))
        self._emit("CTRL session ready (channel 0x02).")

    def send_bytes(self, payload: bytes) -> None:
        with self._lock:
            self._ssl.sendall(payload)
        self._emit(f">> sent {len(payload)} raw bytes")

    def send_ctrl_json(self, obj: dict[str, Any]) -> None:
        body = wrap_ctrl_json(obj)
        self._send_frame(MAGIC_CTRL, body)

    def _recv_loop(self) -> None:
        self._ssl.settimeout(1.0)
        while not self._stop.is_set():
            try:
                data = self._ssl.recv(65536)
            except ssl.SSLWantReadError:
                continue
            except BlockingIOError:
                continue
            except socket.timeout:
                continue
            except OSError as exc:
                if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    continue
                if not self._stop.is_set():
                    self._emit(f"<< recv error: {exc}")
                break
            if not data:
                self._emit("<< connection closed by peer")
                self._stop.set()
                break
            with self._rx_cv:
                sync_active = self._sync_depth > 0
                if sync_active:
                    self._rx_buf.extend(data)
                    self._rx_cv.notify_all()
            if not sync_active and not self._quiet:
                self._emit(format_recv(data, self._recv_hex_limit))

    def media_ability(self) -> dict[str, Any]:
        with self._sync_recv():
            seq = self._next_cmd_seq()
            self.send_ctrl_json({
                "cmdtype": 7,
                "sequence": seq,
                "req": {"peer": "studio", "api_version": 2},
            })
            reply = self._pop_json_frame(15.0)
            if reply is None:
                raise Printer6000Error("media_ability: no reply")
            return reply

    def list_info(self, file_type: str, storage: str = "") -> list[FileEntry]:
        req: dict[str, Any] = {
            "type": file_type,
            "api_version": 2,
            "notify": "DETAIL",
        }
        if storage:
            req["storage"] = storage
        with self._sync_recv():
            seq = self._next_cmd_seq()
            self.send_ctrl_json({"cmdtype": 1, "sequence": seq, "req": req})
            reply = self._pop_json_frame(30.0)
            if reply is None:
                raise Printer6000Error("list_info: no reply")
            result = reply.get("result")
            if result not in (RESULT_OK, RESULT_CONTINUE):
                raise Printer6000Error(f"list_info failed result={result}")
            return _parse_file_entries(reply)

    def list_info_with_fallbacks(
        self, file_type: str, storages: list[str]
    ) -> list[FileEntry]:
        last_err: Optional[Exception] = None
        for storage in storages:
            try:
                entries = self.list_info(file_type, storage)
                tagged = [
                    FileEntry(
                        e.name, e.path, e.size, e.time, e.date, storage=storage
                    )
                    for e in entries
                ]
                if tagged or storage == storages[-1]:
                    return tagged
            except Printer6000Error as exc:
                last_err = exc
        if last_err:
            raise last_err
        return []

    @staticmethod
    def build_download_req(entry: FileEntry) -> dict[str, Any]:
        """Match PrinterFileSystem::DownloadNextFile (path vs file).

        mem: scheme paths (e.g. ``mem:/26``) must use ``{"path": ...}``
        with the full scheme URI, not ``{"file": ...}`` — see
        ../research/06.14-file-transfer.md §6.14.4 and issue #52.
        """
        if entry.path.startswith("/") or entry.path.startswith("mem:"):
            return {"path": entry.path, "offset": 0}
        return {"file": entry.name, "offset": 0}

    @staticmethod
    def build_delete_req(entry: FileEntry, storage: str = "") -> dict[str, Any]:
        """Match PrinterFileSystem::DeleteFilesContinue (paths vs delete[])."""
        if entry.path.startswith("/"):
            return {"paths": [entry.path]}
        req: dict[str, Any] = {"delete": [entry.name]}
        if storage:
            req["storage"] = storage
        return req

    def download_entry(self, entry: FileEntry) -> bytes:
        req = self.build_download_req(entry)
        with self._sync_recv():
            seq = self._next_cmd_seq()
            self.send_ctrl_json({"cmdtype": 4, "sequence": seq, "req": req})
            data = bytearray()
            md5 = hashlib.md5()
            while True:
                reply, chunk = self._pop_body_frame(120.0)
                if reply is None:
                    raise Printer6000Error("download: no reply")
                self._emit(f"download reply: {reply}")
                resp = reply.get("reply") or {}
                if chunk and not resp.get("mem_dl_param_size"):
                    md5.update(chunk)
                    data.extend(chunk)
                result = reply.get("result")
                if result == RESULT_CONTINUE:
                    continue
                if result == RESULT_OK:
                    expect_total = resp.get("total")
                    if expect_total is not None and len(data) != int(expect_total):
                        raise Printer6000Error(
                            f"download size mismatch: got {len(data)} want {expect_total}"
                        )
                    expect_md5 = (resp.get("file_md5") or "").lower()
                    got_md5 = md5.hexdigest().lower()
                    if expect_md5 and got_md5 != expect_md5:
                        raise Printer6000Error(
                            f"download md5 mismatch: got {got_md5} want {expect_md5}"
                        )
                    return bytes(data)
                raise Printer6000Error(f"download failed result={result}")

    def delete_entry(self, entry: FileEntry, storage: str = "") -> None:
        req = self.build_delete_req(entry, storage)
        with self._sync_recv():
            seq = self._next_cmd_seq()
            self.send_ctrl_json({"cmdtype": 3, "sequence": seq, "req": req})
            reply = self._pop_json_frame(30.0)
            if reply is None:
                raise Printer6000Error("delete: no reply")
            result = reply.get("result")
            if result not in (RESULT_OK, RESULT_CONTINUE, 19):
                raise Printer6000Error(f"delete failed result={result}")

    def upload_bytes(self, data: bytes, storage: str, remote_name: str) -> None:
        with self._sync_recv():
            seq = self._next_cmd_seq()
            init_req = {
                "type": "model",
                "storage": storage,
                "path": remote_name,
                "total": len(data),
            }
            self.send_ctrl_json({"cmdtype": 5, "sequence": seq, "req": init_req})
            reply = self._pop_json_frame(30.0)
            if reply is None:
                raise Printer6000Error("upload: no init reply")
            self._emit(f"init reply: {reply}")
            result = reply.get("result")
            if result not in (RESULT_CONTINUE, 19):
                raise Printer6000Error(f"upload init failed result={result}")
            resp = reply.get("reply") or {}
            chunk_kb = int(resp.get("chunk_size") or 0)
            offset = int(resp.get("offset") or 0)
            if chunk_kb <= 0:
                raise Printer6000Error("upload: missing chunk_size")
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
            chunk_reply = self._pop_json_frame(180.0)
            if chunk_reply is None:
                raise Printer6000Error("upload: no reply after chunks")
            self._emit(f"upload reply: {chunk_reply}")
            cr = chunk_reply.get("result")
            if cr in (RESULT_OK, 19):
                return
            raise Printer6000Error(f"upload failed result={cr}")

    def upload_file(self, local_path: str, storage: str, remote_name: str) -> None:
        with open(local_path, "rb") as fh:
            data = fh.read()
        self.upload_bytes(data, storage, remote_name)

    def delete_files(self, paths: list[str], storage: str = "") -> None:
        if not paths:
            return
        req: dict[str, Any] = {"paths": paths}
        if storage:
            req["storage"] = storage
        with self._sync_recv():
            seq = self._next_cmd_seq()
            self.send_ctrl_json({"cmdtype": 3, "sequence": seq, "req": req})
            reply = self._pop_json_frame(30.0)
            if reply is None:
                raise Printer6000Error("delete: no reply")
            result = reply.get("result")
            if result not in (RESULT_OK, RESULT_CONTINUE, 19):
                raise Printer6000Error(f"delete failed result={result}")

    def download_file(self, printer_path: str) -> bytes:
        return self.download_entry(
            FileEntry(name=printer_path.rsplit("/", 1)[-1], path=printer_path, size=0)
        )

    def delete_by_name(self, remote_name: str, storage: str) -> None:
        req: dict[str, Any] = {"delete": [remote_name], "storage": storage}
        with self._sync_recv():
            seq = self._next_cmd_seq()
            self.send_ctrl_json({"cmdtype": 3, "sequence": seq, "req": req})
            reply = self._pop_json_frame(30.0)
            if reply is None:
                raise Printer6000Error("delete: no reply")
            result = reply.get("result")
            if result not in (RESULT_OK, RESULT_CONTINUE, 19):
                raise Printer6000Error(f"delete failed result={result}")

    # REPL compatibility aliases
    def send_ability(self) -> None:
        self.media_ability()

    def send_upload(self, local_path: str, storage: str, remote_name: str) -> None:
        self.upload_file(local_path, storage, remote_name)

    def send_download_mem(self, mem_path: str, out_path: str) -> None:
        data = self.download_file(mem_path)
        with open(out_path, "wb") as fh:
            fh.write(data)
        got_md5 = hashlib.md5(data).hexdigest().lower()
        magic = data[:4].hex(" ") if len(data) >= 4 else "(short)"
        self._emit(
            f"download done: {len(data)} bytes md5={got_md5} -> {out_path} magic={magic}"
        )


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


def connect_session(
    host: str,
    access_code: str,
    *,
    port: int = 6000,
    username: str = "bblp",
    serial: Optional[str] = None,
    verify_tls: bool = False,
    ca_file: Optional[str] = None,
    quiet: bool = True,
) -> LocalCtrlSession:
    ssl_sock = connect_tls(
        host,
        port,
        serial=serial,
        verify_tls=verify_tls,
        ca_file=ca_file,
    )
    session = LocalCtrlSession(ssl_sock, quiet=quiet)
    session.handshake(username, access_code)
    session.start()
    return session


def format_ls_line(entry: FileEntry, *, directory: bool = False) -> str:
    """Unix ls -l line for FTP LIST responses."""
    if directory:
        size = 4096
        name = entry.name.rstrip("/")
    else:
        size = entry.size
        name = entry.name
    if entry.date:
        parts = entry.date.split()
        if len(parts) >= 2:
            date_part = parts[0]
            time_part = parts[1][:5] if len(parts) > 1 else "00:00"
            try:
                dt = datetime.strptime(f"{date_part} {time_part}", "%Y-%m-%d %H:%M")
                stamp = dt.strftime("%b %d %H:%M")
            except ValueError:
                stamp = entry.date[:12]
        else:
            stamp = "Jan  1 00:00"
    elif entry.time > 0:
        stamp = datetime.utcfromtimestamp(entry.time).strftime("%b %d %H:%M")
    else:
        stamp = "Jan  1 00:00"
    mode = "drwxr-xr-x" if directory else "-rwxr-xr-x"
    return f"{mode}  1 0 0 {size:>8} {stamp} {name}"
