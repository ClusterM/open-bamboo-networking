'use strict';

// Frida logger for libbambu_networking.so (Send to Printer / ft_*).
//
// Modes (env FRIDA_FT_WIRE):
//   1 (default) — ABI hooks + filtered SSL_write/SSL_read (plaintext :6000)
//   0           — ABI only (safest if Studio crashes)
//
// Attach: ./tools/frida_ft_attach.sh [--wire|--safe] [--spawn [studio]]
//
// Wire filters (reduce crashes vs blind global SSL hooks):
//   - return address in libbambu_networking.so
//   - peer TCP port == FRIDA_FT_PORT (default 6000)
//   - copy + async format queue (no hexdump/console inside SSL stack)

const MOD_NAME = 'libbambu_networking.so';
const WIRE_LOG = '/tmp/ft_wire.log';
const MAX_PREVIEW = 4096;
const MAX_CHUNK = 512 * 1024;
const QUEUE_CAP = 256;

// Frida JS has no Node "process"; attach.sh injects globals via -e before -l.
function fridaEnv(name, fallback) {
  try {
    if (typeof globalThis !== 'undefined' && globalThis[name] != null) {
      return String(globalThis[name]);
    }
  } catch (e) { /* ignore */ }
  return fallback;
}

const TARGET_PORT = parseInt(fridaEnv('FRIDA_FT_PORT', '6000'), 10) || 6000;
const WIRE_ENABLED = fridaEnv('FRIDA_FT_WIRE', '1') !== '0';
// Syscall read/write capture is TLS ciphertext for stock (static OpenSSL). Default off.
const SYSCALL_WIRE = fridaEnv('FRIDA_FT_SYSCALL', '0') === '1';
const TLS_RAW = fridaEnv('FRIDA_FT_TLS_RAW', '0') === '1';

const ANSI = {
  reset: '\x1b[0m',
  tag: '\x1b[96m',
  out: '\x1b[91m',
  in: '\x1b[92m',
};

let installed = false;
let wireInstalled = false;
const wrappedCallbacks = new Set();
const wireQueue = [];
let wireFile = null;
let pluginRange = null; // { lo: NativePointer, hi: NativePointer }
const trackedFds = new Set();
const fdPortCache = new Map();

function globalExport(name) {
  if (typeof Module.getGlobalExportByName === 'function') {
    try {
      return Module.getGlobalExportByName(name);
    } catch (e) {
      return null;
    }
  }
  if (typeof Module.findExportByName === 'function') {
    return Module.findExportByName(null, name);
  }
  return null;
}

function emit(line) {
  console.log(line);
}

function emitTag(line) {
  console.log(ANSI.tag + line + ANSI.reset);
}

function logAbi(line) {
  emitTag(line);
  writeWireFile('[ABI] ' + line);
}

function emitWire(line, dir) {
  const color = dir === 'out' ? ANSI.out : ANSI.in;
  const prefix = dir === 'out' ? '> ' : '< ';
  console.log(color + prefix + line + ANSI.reset);
  writeWireFile(prefix + line);
}

function openWireFile() {
  if (wireFile) return;
  try {
    wireFile = new File(WIRE_LOG, 'a');
    wireFile.write('\n--- wire session ' + new Date().toISOString() + ' ---\n');
    wireFile.flush();
  } catch (e) {
    emit('[!] cannot open ' + WIRE_LOG + ': ' + e);
  }
}

function writeWireFile(line) {
  openWireFile();
  if (!wireFile) return;
  try {
    wireFile.write(line + '\n');
    wireFile.flush();
  } catch (e) { /* ignore */ }
}

function readCString(ptr) {
  if (ptr.isNull()) return '';
  try {
    return ptr.readUtf8String() || '';
  } catch (e) {
    return '<unreadable>';
  }
}

function moduleForAddress(addr) {
  try {
    return Process.findModuleByAddress(addr);
  } catch (e) {
    return null;
  }
}

function setPluginRange(mod) {
  pluginRange = {
    lo: mod.base,
    hi: mod.base.add(mod.size),
  };
}

function retaddrInMod(ret, name) {
  if (pluginRange) {
    return ret.compare(pluginRange.lo) >= 0 && ret.compare(pluginRange.hi) < 0;
  }
  const mod = moduleForAddress(ret);
  return mod && mod.name === name;
}

function sockaddrPort(sa, len) {
  if (sa.isNull() || len < 4) return -1;
  try {
    const family = sa.readU16();
    if (family === 2 && len >= 8) {
      return (sa.add(2).readU8() << 8) | sa.add(3).readU8();
    }
    if (family === 10 && len >= 8) {
      return (sa.add(2).readU8() << 8) | sa.add(3).readU8();
    }
  } catch (e) { /* ignore */ }
  return -1;
}

function rememberFdPort(fd, port) {
  if (fd >= 0 && port > 0) fdPortCache.set(fd, port);
}

function fdMatchesTarget(fd) {
  if (fd < 0) return true;
  if (trackedFds.has(fd)) return true;
  const cached = fdPortCache.get(fd);
  if (cached !== undefined) return cached === TARGET_PORT;
  return true;
}

function hookConnectTracking() {
  const addr = globalExport('connect');
  if (!addr) return;
  Interceptor.attach(addr, {
    onEnter(args) {
      try {
        if (!retaddrInMod(this.returnAddress, MOD_NAME)) return;
        this.fd = args[0].toInt32();
        this.port = sockaddrPort(args[1], args[2].toInt32());
      } catch (e) {
        this.port = -1;
      }
    },
    onLeave(retval) {
      try {
        if (this.port < 0) return;
        rememberFdPort(this.fd, this.port);
        if (retval.toInt32() === 0 && this.port === TARGET_PORT) {
          trackedFds.add(this.fd);
        }
      } catch (e) { /* ignore */ }
    },
  });
  emit('[+] wire hook connect (track :' + TARGET_PORT + ' fds)');
}

function hookGetpeernameCache() {
  const addr = globalExport('getpeername');
  if (!addr) return;
  Interceptor.attach(addr, {
    onEnter(args) {
      try {
        if (!retaddrInMod(this.returnAddress, MOD_NAME)) return;
        this.fd = args[0].toInt32();
        this.sa = args[1];
      } catch (e) {
        this.fd = -1;
      }
    },
    onLeave(retval) {
      try {
        if (this.fd < 0 || retval.toInt32() !== 0) return;
        const port = sockaddrPort(this.sa, 128);
        if (port > 0) rememberFdPort(this.fd, port);
      } catch (e) { /* ignore */ }
    },
  });
}

function isTlsCiphertext(data) {
  if (data.length < 3) return false;
  // TLS application / handshake record (0x17 / 0x16) + version 0x0301/0x0303
  const typ = data[0];
  if (typ !== 0x16 && typ !== 0x17) return false;
  return data[1] === 0x03 && (data[2] === 0x01 || data[2] === 0x03 || data[2] === 0x04);
}

function isPlainWire(data) {
  if (!data.length) return false;
  if (isTlsCiphertext(data)) return TLS_RAW;
  if (data[0] === 0x7b) return true; // JSON
  if (data.length >= 16) {
    const pl = readU32LE(data, 0);
    const magic = readU32LE(data, 4);
    if (pl > 0 && pl < 16 * 1024 * 1024 && (magic & 0xffff) === 0x013f) return true;
  }
  return false;
}

function shouldQueueWire(data) {
  if (!data || !data.length) return false;
  if (isTlsCiphertext(data)) return TLS_RAW;
  return isPlainWire(data);
}

function resolveSslSymbol(mod, name) {
  if (!mod) return null;
  try {
    const exp = mod.findExportByName(name);
    if (exp) return exp;
  } catch (e) { /* ignore */ }
  try {
    const off = fridaEnv('FRIDA_FT_' + name.toUpperCase() + '_OFF', '');
    if (off) {
      const delta = parseInt(off, 0);
      if (!isNaN(delta)) return mod.base.add(delta);
    }
  } catch (e) { /* ignore */ }
  try {
    if (typeof ApiResolver === 'function') {
      const resolver = new ApiResolver('module');
      const q = 'exports:' + mod.name + '!' + name;
      const hits = resolver.enumerateMatches(q);
      if (hits.length) return hits[0].address;
    }
  } catch (e) { /* ignore */ }
  try {
    const syms = mod.enumerateSymbols();
    for (let i = 0; i < syms.length; i++) {
      const s = syms[i];
      if (s.name === name || s.name.endsWith('!' + name) || s.name.endsWith(name)) {
        return s.address;
      }
    }
  } catch (e) { /* ignore */ }
  return globalExport(name);
}

let tlsBacktraceOnce = false;

function logTlsBacktrace(ctx, tag) {
  if (tlsBacktraceOnce || !ctx) return;
  tlsBacktraceOnce = true;
  try {
    const lines = Thread.backtrace(ctx, Backtracer.ACCURATE).map(function (addr) {
      return '  ' + DebugSymbol.fromAddress(addr);
    });
    writeWireFile('[discover] first TLS ' + tag + ' backtrace (find internal SSL_* offsets):');
    lines.forEach(function (l) { writeWireFile(l); });
    emit('[*] TLS backtrace written to ' + WIRE_LOG + ' — use for FRIDA_FT_SSL_WRITE_OFF');
  } catch (e) { /* ignore */ }
}

function readU32LE(data, off) {
  return (
    (data[off] |
      (data[off + 1] << 8) |
      (data[off + 2] << 16) |
      (data[off + 3] << 24)) >>> 0
  );
}

function jsonPrefixEnd(data) {
  if (!data.length || data[0] !== 0x7b) return -1;
  let depth = 0;
  let inStr = false;
  let esc = false;
  for (let i = 0; i < data.length; i++) {
    const b = data[i];
    if (inStr) {
      if (esc) esc = false;
      else if (b === 0x5c) esc = true;
      else if (b === 0x22) inStr = false;
      continue;
    }
    if (b === 0x22) inStr = true;
    else if (b === 0x7b) depth++;
    else if (b === 0x7d) {
      depth--;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

function bytesToLatin1(data) {
  let s = '';
  for (let i = 0; i < data.length; i++) {
    s += String.fromCharCode(data[i]);
  }
  return s;
}

function splitTextAndBinary(data) {
  if (!data.length) return { text: null, binary: new Uint8Array(0) };
  const jend = jsonPrefixEnd(data);
  if (jend > 0) {
    const text = bytesToLatin1(data.subarray(0, jend));
    let tailStart = jend;
    if (jend + 1 < data.length && data[jend] === 0x0a && data[jend + 1] === 0x0a) {
      tailStart = jend + 2;
    } else {
      while (tailStart < data.length &&
             (data[tailStart] === 0x0a || data[tailStart] === 0x0d ||
              data[tailStart] === 0x09 || data[tailStart] === 0x20)) {
        tailStart++;
      }
    }
    return { text: text, binary: data.subarray(tailStart) };
  }
  return { text: null, binary: data };
}

function formatHexPreview(data, limit) {
  const show = Math.min(data.length, limit);
  const lines = ['--- binary ' + data.length + ' bytes ---'];
  for (let off = 0; off < show; off += 16) {
    let hex = '';
    let asc = '';
    for (let i = 0; i < 16 && off + i < show; i++) {
      const b = data[off + i];
      hex += (b < 16 ? '0' : '') + b.toString(16) + ' ';
      asc += (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
    }
    lines.push(('0000' + off.toString(16)).slice(-4) + '  ' + hex.padEnd(48) + ' ' + asc);
  }
  if (data.length > show) {
    lines.push('... (' + (data.length - show) + ' more bytes)');
  }
  return lines;
}

function parseFrames(data) {
  const frames = [];
  let i = 0;
  while (i + 16 <= data.length) {
    const pl = readU32LE(data, i);
    const end = i + 16 + pl;
    if (end > data.length) break;
    frames.push(data.subarray(i + 16, end));
    i = end;
  }
  return { frames: frames, tail: data.subarray(i) };
}

function formatPayload(data) {
  const lines = [];
  const parsed = parseFrames(data);
  const bodies = parsed.frames.length ? parsed.frames : [data];
  for (const body of bodies) {
    const parts = splitTextAndBinary(body);
    if (parts.text !== null) lines.push(parts.text);
    if (parts.binary.length) {
      formatHexPreview(parts.binary, MAX_PREVIEW).forEach(function (l) {
        lines.push(l);
      });
    }
  }
  if (parsed.frames.length && parsed.tail.length) {
    formatPayload(parsed.tail).forEach(function (l) { lines.push(l); });
  }
  return lines;
}

function drainWireQueue() {
  while (wireQueue.length) {
    const item = wireQueue[0];
    if (item.lines === null) {
      try {
        item.lines = formatPayload(item.data);
      } catch (e) {
        item.lines = ['<format error: ' + e + '>'];
      }
      item.data = null;
    }
    wireQueue.shift();
    try {
      emit('[' + item.tag + '] ' + item.len + ' bytes');
      item.lines.forEach(function (line) {
        emitWire(line, item.dir);
      });
    } catch (e) { /* ignore */ }
  }
}

setInterval(drainWireQueue, 50);

function queueWireRaw(tag, dir, data) {
  if (wireQueue.length >= QUEUE_CAP) return;
  wireQueue.push({
    tag: tag,
    dir: dir,
    len: data.length,
    lines: null,
    data: data,
  });
}

let sslGetFdFn = null;

function sslFd(ssl) {
  if (ssl.isNull()) return -1;
  try {
    if (!sslGetFdFn) {
      const fn = globalExport('SSL_get_fd');
      if (!fn) return -1;
      sslGetFdFn = new NativeFunction(fn, 'int', ['pointer']);
    }
    return sslGetFdFn(ssl);
  } catch (e) {
    return -1;
  }
}

function shouldCaptureSyscall(retaddr, fd) {
  if (!retaddrInMod(retaddr, MOD_NAME)) return false;
  if (fd < 0) return false;
  return fdMatchesTarget(fd);
}

function copyBytes(ptr, len) {
  if (len <= 0 || len > MAX_CHUNK || ptr.isNull()) return null;
  try {
    return new Uint8Array(ptr.readByteArray(len));
  } catch (e) {
    return null;
  }
}

function hookGlobalSsl(mod) {
  if (wireInstalled) return;
  hookConnectTracking();
  hookGetpeernameCache();

  let sslHookCount = 0;
  const writeNames = ['SSL_write', 'SSL_write_ex'];
  const readNames = ['SSL_read', 'SSL_read_ex'];

  for (const name of writeNames) {
    const addr = resolveSslSymbol(mod, name);
    if (!addr) continue;
    const isEx = name.indexOf('_ex') >= 0;
    Interceptor.attach(addr, {
      onEnter(args) {
        try {
          if (!retaddrInMod(this.returnAddress, MOD_NAME)) return;
          this.isEx = isEx;
          this.buf = args[1];
          this.ssl = args[0];
          if (this.isEx) {
            this.written = args[3];
            this.reqLen = args[2].toInt32();
          } else {
            this.reqLen = args[2].toInt32();
          }
        } catch (e) {
          this.buf = null;
        }
      },
      onLeave(retval) {
        try {
          if (!this.buf) return;
          const fd = sslFd(this.ssl);
          if (!fdMatchesTarget(fd)) return;
          let n = this.reqLen || 0;
          if (this.isEx) {
            if (retval.toInt32() !== 1 || !this.written || this.written.isNull()) return;
            n = this.written.readUInt();
          } else {
            n = retval.toInt32();
            if (n <= 0) return;
          }
          const data = copyBytes(this.buf, n);
          if (data && shouldQueueWire(data)) queueWireRaw('SSL_' + name, 'out', data);
        } catch (e) { /* ignore */ }
      },
    });
    sslHookCount++;
    emit('[+] wire hook ' + name + ' @ ' + addr + ' (caller=' + MOD_NAME + ')');
  }

  for (const name of readNames) {
    const addr = resolveSslSymbol(mod, name);
    if (!addr) continue;
    const isEx = name.indexOf('_ex') >= 0;
    Interceptor.attach(addr, {
      onEnter(args) {
        try {
          if (!retaddrInMod(this.returnAddress, MOD_NAME)) return;
          this.capture = true;
          this.buf = args[1];
          this.ssl = args[0];
          this.isEx = isEx;
          if (this.isEx) this.readLen = args[3];
        } catch (e) {
          this.capture = false;
        }
      },
      onLeave(retval) {
        try {
          if (!this.capture) return;
          const fd = sslFd(this.ssl);
          if (!fdMatchesTarget(fd)) return;
          let n = 0;
          if (this.isEx) {
            if (retval.toInt32() !== 1 || !this.readLen || this.readLen.isNull()) return;
            n = this.readLen.readUInt();
          } else {
            n = retval.toInt32();
            if (n <= 0) return;
          }
          const data = copyBytes(this.buf, n);
          if (data && shouldQueueWire(data)) queueWireRaw('SSL_' + name, 'in', data);
        } catch (e) { /* ignore */ }
      },
    });
    sslHookCount++;
    emit('[+] wire hook ' + name + ' @ ' + addr + ' (caller=' + MOD_NAME + ')');
  }

  wireInstalled = true;
  return sslHookCount;
}

function hookGlobalWrite() {
  if (!SYSCALL_WIRE) {
    emit('[*] syscall read/write OFF (stock static OpenSSL = TLS ciphertext only)');
    emit('[*] set FRIDA_FT_SYSCALL=1 to log syscalls; FRIDA_FT_TLS_RAW=1 to dump TLS bytes');
    return;
  }

  const names = [
    { fn: 'write', fdIdx: 0, bufIdx: 1, lenIdx: 2 },
    { fn: 'send', fdIdx: 0, bufIdx: 1, lenIdx: 2 },
  ];
  for (const spec of names) {
    const addr = globalExport(spec.fn);
    if (!addr) continue;
    Interceptor.attach(addr, {
      onEnter(args) {
        try {
          const fd = args[spec.fdIdx].toInt32();
          if (!shouldCaptureSyscall(this.returnAddress, fd)) return;
          this.buf = args[spec.bufIdx];
          this.len = args[spec.lenIdx].toInt32();
          this.tag = spec.fn;
        } catch (e) {
          this.buf = null;
        }
      },
      onLeave(retval) {
        try {
          if (!this.buf) return;
          let n = this.len;
          const rc = retval.toInt32();
          if (rc >= 0) n = rc;
          if (n <= 0) return;
          const data = copyBytes(this.buf, n);
          if (!data || !shouldQueueWire(data)) {
            if (data && isTlsCiphertext(data)) logTlsBacktrace(this.context, this.tag);
            return;
          }
          queueWireRaw(this.tag, 'out', data);
        } catch (e) { /* ignore */ }
      },
    });
    emit('[+] wire hook ' + spec.fn + ' (syscall, port=' + TARGET_PORT + ')');
  }

  const readAddr = globalExport('read');
  if (readAddr) {
    Interceptor.attach(readAddr, {
      onEnter(args) {
        try {
          const fd = args[0].toInt32();
          this.capture = shouldCaptureSyscall(this.returnAddress, fd);
          if (this.capture) this.buf = args[1];
        } catch (e) {
          this.capture = false;
        }
      },
      onLeave(retval) {
        try {
          if (!this.capture) return;
          const n = retval.toInt32();
          if (n <= 0) return;
          const data = copyBytes(this.buf, n);
          if (!data || !shouldQueueWire(data)) {
            if (data && isTlsCiphertext(data)) logTlsBacktrace(this.context, 'read');
            return;
          }
          queueWireRaw('read', 'in', data);
        } catch (e) { /* ignore */ }
      },
    });
    emit('[+] wire hook read (syscall, port=' + TARGET_PORT + ')');
  }
}

function wrapCallbackPtr(label, ptr, onFire) {
  if (ptr.isNull()) return;
  const key = ptr.toString();
  if (wrappedCallbacks.has(key)) return;
  wrappedCallbacks.add(key);
  Interceptor.attach(ptr, {
    onEnter(args) {
      try {
        onFire(args);
      } catch (e) { /* ignore */ }
    },
  });
  emit('[+] wrap ' + label + ' cb=' + ptr);
}

function readJobResult(arg) {
  const p = arg;
  const ec = p.readS32();
  const respEc = p.add(4).readS32();
  const jsonPtr = p.add(8).readPointer();
  const binSize = p.add(24).readU32();
  return {
    ec: ec,
    respEc: respEc,
    json: readCString(jsonPtr),
    binSize: binSize,
  };
}

function readJobMsg(cbArgs) {
  try {
    const kind = cbArgs[1].toInt32();
    const json = readCString(cbArgs[2]);
    if (json) return { kind: kind, json: json };
  } catch (e) { /* fall through */ }
  try {
    const p = cbArgs[1];
    const kind = p.readS32();
    const json = readCString(p.add(8).readPointer());
    return { kind: kind, json: json };
  } catch (e) { /* ignore */ }
  return { kind: -1, json: '' };
}

function safeHook(mod, name, callbacks) {
  const addr = mod.findExportByName(name);
  if (!addr) {
    emit('[!] missing export ' + name);
    return false;
  }
  Interceptor.attach(addr, callbacks);
  emit('[+] hook ' + name);
  return true;
}

function hookFtAbi(mod) {
  safeHook(mod, 'ft_tunnel_create', {
    onEnter(args) {
      try {
        logAbi('[ft] ft_tunnel_create url=' + readCString(args[0]));
      } catch (e) { /* ignore */ }
    },
  });

  safeHook(mod, 'ft_tunnel_start_connect', {
    onEnter() {
      logAbi('[ft] ft_tunnel_start_connect');
    },
  });

  safeHook(mod, 'ft_tunnel_sync_connect', {
    onEnter() {
      logAbi('[ft] ft_tunnel_sync_connect');
    },
  });

  safeHook(mod, 'ft_job_create', {
    onEnter(args) {
      try {
        logAbi('[ft] ft_job_create params=' + readCString(args[0]));
      } catch (e) { /* ignore */ }
    },
  });

  safeHook(mod, 'ft_job_set_result_cb', {
    onEnter(args) {
      const cb = args[1];
      logAbi('[ft] ft_job_set_result_cb job=' + args[0] + ' cb=' + cb);
      wrapCallbackPtr('result', cb, function (cbArgs) {
        const r = readJobResult(cbArgs[1]);
        logAbi('[ft] result_cb ec=' + r.ec + ' resp_ec=' + r.respEc +
                ' json=' + r.json + (r.binSize ? ' bin=' + r.binSize + 'B' : ''));
      });
    },
  });

  safeHook(mod, 'ft_job_set_msg_cb', {
    onEnter(args) {
      const cb = args[1];
      logAbi('[ft] ft_job_set_msg_cb job=' + args[0] + ' cb=' + cb);
      wrapCallbackPtr('msg', cb, function (cbArgs) {
        const m = readJobMsg(cbArgs);
        logAbi('[ft] msg_cb kind=' + m.kind + ' json=' + m.json);
      });
    },
  });

  safeHook(mod, 'ft_tunnel_start_job', {
    onEnter(args) {
      logAbi('[ft] ft_tunnel_start_job tunnel=' + args[0] + ' job=' + args[1]);
    },
  });

  safeHook(mod, 'ft_job_cancel', {
    onEnter(args) {
      logAbi('[ft] ft_job_cancel job=' + args[0]);
    },
  });

  safeHook(mod, 'ft_job_get_result', {
    onEnter(args) {
      this.out = args[2];
    },
    onLeave(retval) {
      try {
        if (retval.toInt32() !== 0 || this.out.isNull()) return;
        const ec = this.out.readS32();
        const respEc = this.out.add(4).readS32();
        const jsonPtr = this.out.add(8).readPointer();
        const binSize = this.out.add(24).readU32();
        const json = readCString(jsonPtr);
        logAbi('[ft] ft_job_get_result ec=' + ec + ' resp_ec=' + respEc +
                ' json=' + json + (binSize ? ' bin=' + binSize + 'B' : ''));
      } catch (e) { /* ignore */ }
    },
  });

  safeHook(mod, 'ft_job_try_get_msg', {
    onEnter(args) {
      this.out = args[1];
    },
    onLeave(retval) {
      try {
        if (retval.toInt32() !== 0 || this.out.isNull()) return;
        const kind = this.out.readS32();
        const jsonPtr = this.out.add(8).readPointer();
        logAbi('[ft] ft_job_try_get_msg kind=' + kind +
                ' json=' + readCString(jsonPtr));
      } catch (e) { /* ignore */ }
    },
  });

  safeHook(mod, 'ft_job_get_msg', {
    onEnter(args) {
      this.out = args[2];
    },
    onLeave(retval) {
      try {
        if (retval.toInt32() !== 0 || this.out.isNull()) return;
        const kind = this.out.readS32();
        const jsonPtr = this.out.add(8).readPointer();
        logAbi('[ft] ft_job_get_msg kind=' + kind +
                ' json=' + readCString(jsonPtr));
      } catch (e) { /* ignore */ }
    },
  });
}

function installHooks() {
  if (installed) return true;
  const mod = Process.findModuleByName(MOD_NAME);
  if (!mod) return false;

  installed = true;
  setPluginRange(mod);
  emit('[+] module ' + MOD_NAME + ' base=' + mod.base + ' size=' + mod.size);
  hookFtAbi(mod);

  if (WIRE_ENABLED) {
    emit('[*] wire capture ON (port ' + TARGET_PORT + ', log ' + WIRE_LOG + ')');
    emit('[*] ABI JSON -> ' + WIRE_LOG + ' ; disable wire: --safe');
    try {
      const sslN = hookGlobalSsl(mod);
      if (!sslN) {
        emit('[!] SSL_write/SSL_read not found — stock plugin uses static stripped OpenSSL');
        emit('[!] syscall hooks see TLS ciphertext (17 03 03), not JSON plaintext');
        emit('[*] options: SSLKEYLOGFILE + Wireshark, or FRIDA_FT_SSL_WRITE_OFF=0x... after RE');
      }
      hookGlobalWrite();
    } catch (e) {
      emit('[!] wire hooks failed: ' + e);
    }
  } else {
    emit('[*] wire capture OFF (--safe / FRIDA_FT_WIRE=0)');
  }

  emit('[*] Send to Printer -> Cache/External (not Device -> Files)');
  return true;
}

function waitForModule() {
  if (installHooks()) return;
  emit('[*] waiting for ' + MOD_NAME + '...');
  const timer = setInterval(function () {
    if (installHooks()) clearInterval(timer);
  }, 1000);
}

waitForModule();
