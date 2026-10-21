'use strict';

// Log the plaintext TLS :6000 traffic of the stock BambuSource library
// (Device -> Storage file browser, BambuTunnelLocal) on Windows or Linux.
//
// Hooks the exported LocalTunnel_Open/Write/Read, which frame messages on
// top of the library's own TLS, so no key logging or symbol search is
// needed. Also logs Bambu_Create / Bambu_StartStreamEx / Bambu_SendMessage
// (the slicer side) and, on Windows, the TLS record sizes on :6000.
//
// Windows:  frida -n orca-slicer.exe -l frida_localtunnel_log.js -o frida.log
// Linux:    frida -p <pid> -l tools/frida_localtunnel_log.js -o /tmp/frida.log
//
// The login frame carries the printer's access code in clear text.

const MODULE_NAMES = ['BambuSource.dll', 'libBambuSource.so'];
const MAX_DUMP = 4096;

function log(line) {
  console.log(new Date().toISOString().substr(11, 12) + ' ' + line);
}

function hex(p, n) {
  const bytes = new Uint8Array(p.readByteArray(n));
  let s = '';
  for (const b of bytes) s += (b < 16 ? '0' : '') + b.toString(16);
  return s;
}

function text(p, n) {
  const bytes = new Uint8Array(p.readByteArray(n));
  let s = '';
  for (const b of bytes) s += (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.';
  return s;
}

// One frame: 16-byte header (payload length, magic, sequence, 0) + payload.
function frame(dir, hdr, payload) {
  const len = hdr.readU32();
  const magic = hdr.add(4).readU32();
  const seq = hdr.add(8).readU32();
  const n = Math.min(len, MAX_DUMP);
  log(dir + ' frame magic=0x' + magic.toString(16).padStart(8, '0') + ' seq=' + seq +
      ' len=' + len + ' hdr=' + hex(hdr, 16));
  if (n > 0 && !payload.isNull()) {
    log(dir + '   hex:  ' + hex(payload, n) + (len > n ? '...' : ''));
    log(dir + '   text: ' + text(payload, n) + (len > n ? '...' : ''));
  }
}

function hookBambuSource(m) {
  log('hooking ' + m.name + ' at ' + m.base);
  const exp = (name) => m.findExportByName(name);

  const open = exp('LocalTunnel_Open');
  if (open) {
    Interceptor.attach(open, {
      onEnter(args) {
        this.t = args[0];
        log('LocalTunnel_Open t=' + args[0] + ' ' + args[1].readCString() + ':' + args[2].toInt32());
      },
      onLeave(ret) { log('LocalTunnel_Open t=' + this.t + ' -> ' + ret.toInt32()); },
    });
  }

  // Write(t, hdr, payload) returns 1 or 2 while the TLS socket would block;
  // the caller then repeats the call with the same message.
  const pendingWrite = {};
  const write = exp('LocalTunnel_Write');
  if (write) {
    Interceptor.attach(write, {
      onEnter(args) {
        this.t = args[0].toString();
        this.key = args[1].toString() + '/' + args[2].toString() + '/' + hex(args[1], 16);
        if (pendingWrite[this.t] !== this.key) frame('>>', args[1], args[2]);
      },
      onLeave(ret) {
        const r = ret.toInt32();
        if (r === 1 || r === 2) pendingWrite[this.t] = this.key;
        else delete pendingWrite[this.t];
        if (r !== 0 && r !== 1 && r !== 2) log('LocalTunnel_Write t=' + this.t + ' -> ' + r);
      },
    });
  }

  // Read(t, hdr_out, buf) returns 0 once a whole frame is in hdr_out/buf,
  // 1 or 2 while waiting for data.
  const read = exp('LocalTunnel_Read');
  if (read) {
    Interceptor.attach(read, {
      onEnter(args) { this.t = args[0]; this.hdr = args[1]; this.buf = args[2]; },
      onLeave(ret) {
        const r = ret.toInt32();
        if (r === 0) frame('<<', this.hdr, this.buf);
        else if (r !== 1 && r !== 2) log('LocalTunnel_Read t=' + this.t + ' -> ' + r);
      },
    });
  }

  const close = exp('LocalTunnel_Close');
  if (close) {
    Interceptor.attach(close, { onEnter(args) { log('LocalTunnel_Close t=' + args[0]); } });
  }

  const create = exp('Bambu_Create');
  if (create) {
    Interceptor.attach(create, {
      onEnter(args) {
        const url = args[1].readUtf8String().replace(/passwd=[^&]*/, 'passwd=***');
        log('Bambu_Create ' + url);
      },
    });
  }

  let lastStart = null;
  const startEx = exp('Bambu_StartStreamEx');
  if (startEx) {
    Interceptor.attach(startEx, {
      onEnter(args) { this.type = args[1].toInt32(); },
      onLeave(ret) {
        const s = '0x' + this.type.toString(16) + ' -> ' + ret.toInt32() +
                  (ret.toInt32() === 2 ? ' (would block)' : '');
        if (s !== lastStart) log('Bambu_StartStreamEx ' + s);
        lastStart = s;
      },
    });
  }

  const send = exp('Bambu_SendMessage');
  if (send) {
    Interceptor.attach(send, {
      onEnter(args) {
        const n = args[3].toInt32();
        log('Bambu_SendMessage 0x' + args[1].toInt32().toString(16) + ' ' +
            text(args[2], Math.min(n, MAX_DUMP)));
      },
    });
  }
}

// TLS record sizes on :6000 / :990, in case the LocalTunnel hooks stay silent.
function hookWinsock() {
  const ws = Process.findModuleByName('ws2_32.dll') || Process.findModuleByName('WS2_32.dll');
  if (!ws) return;
  const watched = {};
  Interceptor.attach(ws.findExportByName('connect'), {
    onEnter(args) {
      const sa = args[1];
      if (sa.readU16() !== 2) return; // AF_INET
      const port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
      if (port !== 6000 && port !== 990) return;
      const ip = [4, 5, 6, 7].map((i) => sa.add(i).readU8()).join('.');
      watched[args[0].toString()] = port;
      log('connect socket=' + args[0] + ' ' + ip + ':' + port);
    },
  });
  for (const name of ['send', 'recv']) {
    Interceptor.attach(ws.findExportByName(name), {
      onEnter(args) { this.s = args[0].toString(); },
      onLeave(ret) {
        const port = watched[this.s];
        const n = ret.toInt32();
        if (port && n > 0) log((name === 'send' ? 'tls>> ' : 'tls<< ') + ':' + port + ' ' + n + ' bytes');
      },
    });
  }
  Interceptor.attach(ws.findExportByName('closesocket'), {
    onEnter(args) {
      const s = args[0].toString();
      if (watched[s]) log('closesocket socket=' + s);
      delete watched[s];
    },
  });
  log('hooked ws2_32');
}

hookWinsock();

// The slicer loads BambuSource on first use (Storage tab, camera) and logs
// in right away, so hook from the load notification (Frida 17+).
let hooked = false;
function maybeHook(m) {
  if (hooked || MODULE_NAMES.indexOf(m.name) < 0) return;
  hooked = true;
  hookBambuSource(m);
}
Process.enumerateModules().forEach(maybeHook);
if (!hooked) {
  Process.attachModuleObserver({ onAdded: maybeHook });
  log('waiting for BambuSource to load (open Device -> Storage)');
}
