# bambu_extract_d

Extracts the RSA private key (`d`) from Bambu Lab's `libbambu_networking.so`
plugin so that `print.*` MQTT commands can be signed natively, without the
proprietary plugin being present at print time.

## How it works

The tool launches a minimal daemon binary in a sandboxed environment, injects an
LD_PRELOAD shim to defeat the watchdog timer, and redirects the daemon's printer
connection to a local fake TLS MQTT broker. When the daemon's signing thread
fires, the tool captures the RSA CRT intermediate values (`d_p`, `d_q`) via a
hardware breakpoint (DR0), reconstructs the full private key offline, and writes
it as a PKCS#1 PEM file.

No real printer is required. No network traffic leaves the machine. Feel free to
run it in a VM or container, particularly if your worried about what Bambu's
network plugin might be doing to your computer.

Only linux is supported at this point for extraction, but using the key works on
windows. This is one slicer key across all instances BambuStudio, I just don't
want to distribute a key because I don't understand the legality of such a
thing.

Since this is a oppositional environment, I've only included exactly how to
extract it, (the cheat answer at the end) not the real mechanism for
determining how to do it. No need to give Bambu a test case to code against.

## Output files

| File | Contents | Permissions |
|---|---|---|
| `slicer_key.pem` | PKCS#1 RSA-2048 private key | 0600 |
| `slicer_pubkey.pem` | RSA public key (SubjectPublicKeyInfo) | 0644 |
| `slicer_cert_id.txt` | Certificate ID string for envelope signing | 0644 |

Place `slicer_key.pem` and `slicer_cert_id.txt` at:
- Linux/macOS: `~/.config/BambuStudio/slicer_key.pem`
- Windows: `%APPDATA%\BambuStudio\slicer_key.pem`

Or set `BBL_SLICER_KEY_PEM` / `BBL_SLICER_CERT_ID` environment variables.

## Quick start

```bash
# Build (requires libssl-dev, zlib1g-dev — see Makefile)
make -C tools/bambu_extract_d

# Run (takes ~15s; requires CAP_SYS_PTRACE)
sudo tools/bambu_extract_d/bambu_extract_d --out ~/.config/BambuStudio/slicer_key.pem
```

## Build prerequisites

```bash
apt install build-essential libssl-dev zlib1g-dev
```

The three embed headers (`daemon_embed.h`, `watchdog_defeat_embed.h`,
`slicer_cert_embed.h`) must be generated from pre-compiled binaries before
building `bambu_extract_d`. See comments inside each header for details.

## Security note

`slicer_key.pem` is the slicer's actual RSA-2048 private key — treat it like a
`.p12` certificate. Do not share it, commit it to git, or store it with
world-readable permissions.
