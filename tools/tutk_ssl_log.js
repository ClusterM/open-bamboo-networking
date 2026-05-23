'use strict';

// Log stock libBambuSource traffic for Device -> Files RE.
// Send to Printer (ft_*) is libbambu_networking.so — see tools/frida_ft_upload.js
//
// Primary hooks: Bambu_SendMessage / Bambu_ReadSample (JSON plaintext at ABI).
// Secondary: tutk_third_SSL_* and TUTKSSL_* (wire encryption layer).
//
// Payload data only: > bright red (C->P), < bright green (P->C). Tags and frame hdr stay plain.
//
// Attach: ./tools/frida_tutk_attach.sh

const MOD_NAME = 'libBambuSource.so';
const LOG_PATH = '/tmp/tutk_ssl.log';
const MAX_HEX_CONSOLE = 2048;

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

const ANSI = {
  reset: '\x1b[0m',
  out: '\x1b[91m',  // bright red — client -> printer
  in: '\x1b[92m',   // bright green — printer -> client
};

let logFile = null;
const hooked = new Set();

function openLog() {
  if (logFile) return;
  try {
    logFile = new File(LOG_PATH, 'a');
    logFile.write('\n--- session ' + new Date().toISOString() + ' ---\n');
    logFile.flush();
  } catch (e) {
    console.error('cannot open ' + LOG_PATH + ': ' + e);
  }
}

function emit(line) {
  console.log(line);
  writeLog(line);
}

function emitData(line, dir) {
  const prefix = dir === 'out' ? '> ' : '< ';
  const plain = prefix + line;
  const color = dir === 'out' ? ANSI.out : ANSI.in;
  console.log(color + plain + ANSI.reset);
  writeLog(plain);
}

function writeLog(line) {
  openLog();
  if (logFile) {
    logFile.write(line + '\n');
    logFile.flush();
  }
}

function readBytes(ptr, len) {
  if (len <= 0 || ptr.isNull()) return null;
  return new Uint8Array(ptr.readByteArray(len));
}

function readU32LE(data, off) {
  return (
    data[off] |
    (data[off + 1] << 8) |
    (data[off + 2] << 16) |
    (data[off + 3] << 24)
  ) >>> 0;
}

function parseFrames(data) {
  const frames = [];
  let i = 0;
  while (i + 16 <= data.length) {
    const pl = readU32LE(data, i);
    const magic = readU32LE(data, i + 4);
    const seq = readU32LE(data, i + 8);
    const end = i + 16 + pl;
    if (end > data.length) break;
    frames.push({
      pl: pl,
      magic: magic,
      seq: seq,
      body: data.subarray(i + 16, end),
    });
    i = end;
  }
  return { frames: frames, tail: data.subarray(i) };
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


const MAGIC_MARKER = 0x013f;

function frameHeaderLabel(magic) {
  const sub = (magic >>> 16) & 0xff;
  const dir = (magic >>> 24) & 0xff;
  let subName;
  if (sub === 0x01) subName = 'LOGIN';
  else if (sub === 0x02) subName = 'CTRL';
  else subName = 'sub=0x' + sub.toString(16);
  const dirName = dir === 0x01 ? 'C->P' : dir === 0x00 ? 'P->C' : 'dir=0x' + dir.toString(16);
  return subName + ' ' + dirName;
}

function isFrameHeader(data) {
  return data.length === 16 && (readU32LE(data, 4) & 0xffff) === MAGIC_MARKER;
}

function hexU32(v) {
  let s = v.toString(16);
  while (s.length < 8) s = '0' + s;
  return '0x' + s;
}

function formatFrameHeader(data) {
  if (!isFrameHeader(data)) return null;
  const pl = readU32LE(data, 0);
  const magic = readU32LE(data, 4);
  const seq = readU32LE(data, 8);
  return (
    'frame hdr: payload_len=' + pl + ' ' + frameHeaderLabel(magic) +
    ' seq=' + hexU32(seq) + ' magic=' + hexU32(magic)
  );
}

function bytesToLatin1(data) {
  let s = '';
  for (let i = 0; i < data.length; i++) {
    s += String.fromCharCode(data[i]);
  }
  return s;
}

function isLatin1Printable(data) {
  for (let i = 0; i < data.length; i++) {
    const b = data[i];
    if (b === 0x0a || b === 0x0d || b === 0x09) continue;
    if (b < 0x20 || b > 0x7e) return false;
  }
  return true;
}

function splitTextAndBinary(data) {
  if (!data.length) return { text: null, binary: new Uint8Array(0) };

  const jend = jsonPrefixEnd(data);
  if (jend > 0) {
    const text = bytesToLatin1(data.subarray(0, jend));
    let tailStart = jend;
    // Studio envelope: json\n\n<binary blob>
    if (jend + 1 < data.length && data[jend] === 0x0a && data[jend + 1] === 0x0a) {
      tailStart = jend + 2;
    } else {
      tailStart = jend;
      while (tailStart < data.length &&
             (data[tailStart] === 0x0a || data[tailStart] === 0x0d ||
              data[tailStart] === 0x09 || data[tailStart] === 0x20)) {
        tailStart++;
      }
    }
    return { text: text, binary: data.subarray(tailStart) };
  }

  if (isLatin1Printable(data)) {
    return { text: bytesToLatin1(data), binary: new Uint8Array(0) };
  }
  return { text: null, binary: data };
}

function formatHex(data, hexLimit) {
  if (!data.length) return [];
  const lines = ['--- binary ' + data.length + ' bytes ---'];
  const show = Math.min(data.length, hexLimit);
  const buf = Memory.alloc(show);
  buf.writeByteArray(data.subarray(0, show));
  const dump = hexdump(buf, { length: show, ansi: false });
  dump.split('\n').forEach(function (line) {
    if (line.length) lines.push(line);
  });
  if (data.length > show) {
    lines.push('... (' + (data.length - show) + ' more bytes)');
  }
  return lines;
}

function formatPayload(data, hexLimit) {
  const parts = splitTextAndBinary(data);
  const lines = [];
  if (parts.text !== null) lines.push(parts.text);
  if (parts.binary.length) {
    formatHex(parts.binary, hexLimit).forEach(function (line) {
      lines.push(line);
    });
  }
  return lines;
}

function formatBytes(data, hexLimit) {
  const meta = [];
  const payload = [];

  if (data.length === 16) {
    const hdr = formatFrameHeader(data);
    if (hdr !== null) {
      meta.push(hdr);
      return { meta: meta, data: payload };
    }
  }

  const parsed = parseFrames(data);
  if (parsed.frames.length) {
    parsed.frames.forEach(function (f) {
      formatPayload(f.body, hexLimit).forEach(function (line) {
        payload.push(line);
      });
    });
    if (parsed.tail.length) {
      formatPayload(parsed.tail, hexLimit).forEach(function (line) {
        payload.push(line);
      });
    }
  } else {
    formatPayload(data, hexLimit).forEach(function (line) {
      payload.push(line);
    });
  }
  return { meta: meta, data: payload };
}

function logBytes(tag, ptr, len, dir) {
  const data = readBytes(ptr, len);
  if (!data) return;
  emit('[' + new Date().toISOString() + '] ' + tag + ' ' + len + ' bytes');
  const parts = formatBytes(data, MAX_HEX_CONSOLE);
  parts.meta.forEach(function (line) {
    emit(line);
  });
  parts.data.forEach(function (line) {
    emitData(line, dir);
  });
}

function hookExport(mod, name, callbacks) {
  const key = mod.name + '!' + name;
  if (hooked.has(key)) return true;
  const addr = mod.findExportByName(name);
  if (!addr) return false;
  Interceptor.attach(addr, callbacks);
  hooked.add(key);
  emit('[+] hook ' + name);
  return true;
}

function hookSslIo(mod) {
  const names = [
    'TUTKSSL_write', 'TUTKSSL_read',
    'tutk_third_SSL_write', 'tutk_third_SSL_read',
    'tutk_third_SSL_write_ex', 'tutk_third_SSL_read_ex',
  ];
  for (const name of names) {
    if (name.indexOf('write') >= 0) {
      hookExport(mod, name, {
        onEnter(args) {
          const len = args[2].toInt32();
          if (len > 0) logBytes('SSL ' + name + ' C->P', args[1], len, 'out');
        },
      });
    } else {
      hookExport(mod, name, {
        onEnter(args) {
          this.buf = args[1];
        },
        onLeave(retval) {
          const n = retval.toInt32();
          if (n > 0) logBytes('SSL ' + name + ' P->C', this.buf, n, 'in');
        },
      });
    }
  }
}

function hookBambuAbi(mod) {
  hookExport(mod, 'Bambu_SendMessage', {
    onEnter(args) {
      const ctrl = args[1].toInt32();
      const data = args[2];
      const len = args[3].toInt32();
      emit('[ABI] Bambu_SendMessage ctrl=0x' + ctrl.toString(16) + ' len=' + len);
      if (len > 0) logBytes('ABI SendMessage', data, len, 'out');
    },
  });

  hookExport(mod, 'Bambu_ReadSample', {
    onEnter(args) {
      this.sample = args[1];
    },
    onLeave(retval) {
      const rc = retval.toInt32();
      if (rc !== 0 || this.sample.isNull()) return;
      // struct Bambu_Sample { int itrack; int size; int flags; const uchar* buffer; ull decode_time; }
      const size = this.sample.add(4).readS32();
      const bufPtr = this.sample.add(16).readPointer();
      emit('[ABI] Bambu_ReadSample rc=' + rc + ' size=' + size);
      if (size > 0 && !bufPtr.isNull()) {
        logBytes('ABI ReadSample', bufPtr, size, 'in');
      }
    },
  });

  hookExport(mod, 'Bambu_Open', {
    onEnter() {
      emit('[ABI] Bambu_Open');
    },
  });

  hookExport(mod, 'Bambu_StartStreamEx', {
    onEnter(args) {
      emit('[ABI] Bambu_StartStreamEx type=0x' + args[1].toInt32().toString(16));
    },
  });
}

function installHooks() {
  const mod = Process.findModuleByName(MOD_NAME);
  if (!mod) return false;
  if (hooked.has(MOD_NAME + '!installed')) return true;

  emit('[+] module ' + MOD_NAME + ' base=' + mod.base);
  hookBambuAbi(mod);
  hookSslIo(mod);
  hooked.add(MOD_NAME + '!installed');
  emit('[*] ready — switch External / Internal in Device -> Files now');
  return true;
}

function waitForModule() {
  if (installHooks()) return;
  emit('[*] waiting for ' + MOD_NAME + ' (open Device tab)...');

  const dlopen = globalExport('dlopen');
  if (dlopen) {
    Interceptor.attach(dlopen, {
      onLeave() {
        installHooks();
      },
    });
  }

  const timer = setInterval(function () {
    if (installHooks()) clearInterval(timer);
  }, 500);
}

waitForModule();
