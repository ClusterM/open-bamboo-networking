# bambu_extract_d

Extracts the slicer RSA-2048 private key from a Bambu Lab network plugin and
writes it as a PKCS#1 PEM file. The extracted key is used by
`open-bamboo-networking`'s signing implementation.

## Build

Dependencies: gcc, libssl-dev, zlib1g-dev

```bash
cd tools/bambu_extract_d
make
```

## Usage

### No-printer mode (recommended — no real printer needed)

```bash
./bambu_extract_d --no-printer --out ~/.config/BambuStudio/slicer_key.pem
```

The tool auto-downloads the latest plugin if none is installed, starts a
minimal bridge daemon internally, and ptraces it to capture the key material.
Requires `--cap-add SYS_PTRACE` when running inside Docker.

### With a real printer on LAN

```bash
./bambu_extract_d --access-code <code> \
                  --out ~/.config/BambuStudio/slicer_key.pem
```

`--dev-id` and `--lan-ip` are auto-discovered via SSDP if omitted.

## Output formats

| Extension | Contents |
|-----------|----------|
| `.pem`    | PKCS#1 RSA private key — directly consumed by `signing.cpp` |
| `.json`   | JSON with hex fields: `p_hex`, `q_hex`, `dp_hex`, `dq_hex`, `d_hex`, `N_hex` |

Default output is `.json` if the extension is not `.pem`.

## Output file location

Place the PEM at one of:

- `~/.config/BambuStudio/slicer_key.pem` (Linux — default search path)
- `%APPDATA%\BambuStudio\slicer_key.pem` (Windows)
- Any path set via `BBL_SLICER_KEY_PEM` environment variable

The plugin reads the key at first signing call and caches it for the process
lifetime. Mode 0600 is enforced on write; keep the file private.

## Security note

The output file contains a private RSA key. Treat it like a `.p12` certificate:
do not share it, do not commit it to version control, and do not push it to
any public system.

## Embedded components

`daemon_embed.h` and `watchdog_defeat_embed.h` are auto-generated C arrays
embedding the minimal bridge daemon binary and a ptrace-watchdog shim,
respectively. Regenerate them with `xxd -i` from the corresponding built
binaries when updating those components.
