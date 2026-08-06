# Building Open Bamboo Networking from source

This document covers building the plugin yourself and installing it manually.
Most users do **not** need this — grab a pre-built archive and run the bundled
installer instead (see [README — Installation](README.md#installation)). Build
from source if you are developing, packaging for a distribution, or targeting a
platform / ABI we do not ship binaries for.

## Table of contents

- [How to build](#how-to-build)
  - [Linux](#linux)
    - [Prerequisites](#prerequisites-linux)
    - [Linux: configure, build and install](#linux-configure-build-and-install)
    - [`./configure` options](#configure-options)
  - [macOS](#macos)
  - [Windows](#windows)
    - [Prerequisites](#prerequisites-windows)
    - [Windows: configure, build and install](#windows-configure-build-and-install)
- [Manual installation](#manual-installation)

## How to build

### Linux

#### Prerequisites (Linux)

You need **CMake ≥ 3.20**, a **C++17** compiler, **pkg-config**, and development
headers for everything the project links against:

| Component                           | Debian / Ubuntu packages                                                                             | Fedora-style packages                                                             |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| Toolchain                           | `build-essential`, `cmake`, `pkg-config`                                                             | `gcc-c++`, `cmake`, `pkgconf-pkg-config`                                          |
| MQTT / HTTP / TLS / zlib              | `git`, `uthash-dev`, `libcurl4-openssl-dev`, `libssl-dev`, `zlib1g-dev` | `git`, `uthash-devel`, `libcurl-devel`, `openssl-devel`, `zlib-devel` |

> Note  
> libmosquitto is **always vendored** via FetchContent at configure time (needs `git` + network). `uthash-dev` supplies `utlist.h`; cJSON is bundled automatically.

One-shot install examples:

```sh
# Debian / Ubuntu
sudo apt install build-essential cmake pkg-config git \
  uthash-dev libcurl4-openssl-dev libssl-dev zlib1g-dev
```

```sh
# Fedora
sudo dnf install gcc-c++ cmake pkgconf-pkg-config git \
  uthash-devel libcurl-devel openssl-devel zlib-devel
```

#### Linux: configure, build and install

From the repository root, the usual three commands:

```sh
./configure
make
make install
```

For Orca Slicer (it uses the same binaries; only the installation process is different):
```
./configure --client-type=orca_slicer
make
make install
```

No `sudo` needed — the default install prefix is inside your home directory.

That's it. `./configure` is a thin wrapper around CMake that writes the build
tree into `build/` and by default this script autodetects the Bambu Studio version
and the config location, then picks sensible defaults for a typical user.

`make install` runs the automated install. For the manual steps (copy paths, conf keys), see [Manual installation](#manual-installation) below.

`make uninstall` walks the install manifest and removes whatever was put
down; `make clean` / `make distclean` drop build artefacts; `make test`
runs the smoke tests via `ctest`.

#### `./configure` options

`./configure --help` prints the full list; the most useful ones:

| Flag                      | Default                                                        | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ------------------------- | -------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--client-type=TYPE`      | `bambu_studio`                                                 | Which slicer the plugin is being installed for: `bambu_studio` or `orca_slicer`. Drives the default `--prefix`, the auto-detected version source and the installation procedure                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `--prefix=DIR`            | per-client native config dir on Linux, with a Flatpak fallback | Where `make install` copies the shared objects and the OTA manifest. For both clients, `./configure` prefers the native config dir and only falls back to the Flatpak config dir when the native one is missing AND the Flatpak one exists: Studio: `~/.config/BambuStudio` → `~/.var/app/com.bambulab.BambuStudio/config/BambuStudio/`. Orca: `~/.config/OrcaSlicer` → `~/.var/app/com.orcaslicer.OrcaSlicer/config/OrcaSlicer/`. When this does not point at one of the two known dirs for the selected `--client-type`, the conf-file patch is skipped automatically — you are clearly building into a staging tree.                                                                                     |
| `--build-type=TYPE`       | `Release`                                                      | `Release`, `Debug`, `RelWithDebInfo`, `MinSizeRel`. Maps to `-DCMAKE_BUILD_TYPE=…`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `--with-version=VER`      | auto (see **Version auto-detection** below)                    | Overrides automatic `OBN_VERSION`. The slicer compares only the **first 8 characters** (`MAJOR.MINOR.PATCH`), so e.g. AppImage `v02.05.02.51` wants `02.05.02.*`. Maps to `-DOBN_VERSION=…`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `--enable-tests`          | disabled                                                       | Build `probe_plugin`, `ftps_parse_test`, and `*_live_test` smoke tests. Default is off for regular user builds; CI enables it explicitly. Maps to `-DOBN_BUILD_TESTS=ON`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `--no-conf-patch`         | patch enabled                                                  | Do not edit the slicer's conf file (`BambuStudio.conf` / `OrcaSlicer.conf`) during `make install`. Handy when you want to inspect it yourself first or if you manage it through some other means. Maps to `-DOBN_PATCH_CLIENT_CONF=OFF`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `--build-dir=DIR`         | `build`                                                        | Where CMake writes its build tree. Only relevant if you want to keep several builds side by side.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `--cmake-arg=ARG`         | none                                                           | Pass an arbitrary flag through to CMake (e.g. `--cmake-arg=-GNinja`). Repeatable.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |

**Version auto-detection** (omit `--with-version`):

- **Bambu Studio** — baseline comes from the slicer’s own build id: the `"version"` field inside the `"app"` object of `<prefix>/BambuStudio.conf` (written after you launch Studio at least once). That is the tag Studio and its bundled agent advertise; the plugin must match the **first eight characters** (`MAJOR.MINOR.PATCH`).
- **Orca Slicer** — baseline comes from `"network_plugin_version"` in the `"app"` object of `<prefix>/OrcaSlicer.conf`, because Orca tracks plugin ABI separately from the Orca app version. If that key is still missing (fresh Orca install, no plugin installed yet), both scripts fall back to **`02.03.00`**.

The detected `W.X.Y.Z` or `W.X.Y` is turned into a **four-component** `OBN_VERSION` with the **last component set to `99`** (e.g. `02.06.01.55` → `02.06.01.99`, `02.03.00` → `02.03.00.99`) so the replacement plugin always wins the “newer than the bundled agent” check.

`./configure --help` also lists less common flags (including Mosquitto linking
options). Driving **CMake** directly works the same way; see `OBN_`* and
other cache variables in `CMakeLists.txt`.

### macOS

macOS builds **statically embed** OpenSSL and libcurl into the plugin dylibs
(`OBN_MACOS_STATIC_DEPS=ON` by default). Homebrew is needed only at **build**
time for `openssl@3` (static `.a` archives); the installed plugin does **not**
require `brew install curl` / a Homebrew OpenSSL at runtime
([issue #60](https://github.com/ClusterM/open-bamboo-networking/issues/60)).
libcurl itself is vendored from source via FetchContent (minimal OpenSSL +
system zlib build).

#### Prerequisites (macOS)

```sh
brew install cmake pkg-config openssl@3 uthash
```

`./configure` auto-detects `OPENSSL_ROOT_DIR` from `brew --prefix openssl@3`
when unset. Opt out of the static embed with
`--cmake-arg=-DOBN_MACOS_STATIC_DEPS=OFF` (then you need a pkg-config
`libcurl` as on Linux).

#### macOS: configure, build and install

```sh
./configure
make
make install
```

Default `--prefix` is `~/Library/Application Support/BambuStudio` (or
`…/OrcaSlicer` with `--client-type=orca_slicer`).

### Windows

Bambu Studio for Windows is a 64-bit MSVC build (Visual Studio 2019, see
`3rd_party/BambuStudio/build_win.bat`). The plugin ABI passes
`std::string`, `std::map` and `std::function` across the DLL boundary, so
**the plugin must be built with the same compiler and STL Studio uses** —
i.e. MSVC from Visual Studio 2019 (toolset v142). MinGW or any libstdc++
flavour will silently mangle types and crash on the first `bambu_network_*`
call. C++ libraries (OpenSSL, libcurl, zlib) come from
[vcpkg](https://github.com/microsoft/vcpkg) in manifest mode (`vcpkg.json`).
libmosquitto is always vendored via FetchContent (same as Linux).

#### Prerequisites (Windows)

- Visual Studio 2019 with the *Desktop development with C++* workload
  (toolset v142). Newer toolsets *may* work but the std::string layout
  across the DLL boundary is not guaranteed.
- CMake ≥ 3.20 (the one bundled with VS 2019 works).
- vcpkg checked out somewhere on disk; export `VCPKG_ROOT` so PowerShell
  can find it. The vcpkg shipped with Visual Studio 2022 (under
  `…\VC\vcpkg\`) works as well — `vcpkg.json` pins a `builtin-baseline`
  SHA so modern, strict-manifest vcpkg installations are happy out of
  the box.

#### Windows: configure, build and install

Recommended path through the supplied PowerShell wrapper (mirrors the POSIX
`./configure`):

For Bambu Studio:
```powershell
$env:VCPKG_ROOT = "C:\path\to\vcpkg"
.\configure.ps1
cmake --build   build --config Release
cmake --install build --config Release
```

For Orca Slicer:
```powershell
$env:VCPKG_ROOT = "C:\path\to\vcpkg"
.\configure.ps1 -ClientType orca_slicer
cmake --build   build --config Release
cmake --install build --config Release
```

The wrapper's full option list is `Get-Help .\configure.ps1 -Detailed`; the
useful ones:

| Flag                                  | Default                                    | Equivalent `./configure` flag                           |
| ------------------------------------- | ------------------------------------------ | ------------------------------------------------------- |
| `-ClientType bambu_studio`            | `bambu_studio`                             | `--client-type=bambu_studio` (or `orca_slicer`)         |
| `-Prefix C:\Foo\BambuStudio`          | `%APPDATA%\<client>`                       | `--prefix=DIR`                                          |
| `-WithVersion 02.06.01.99`            | auto-detected (see below)                  | `--with-version=VER`                                    |
| `-EnableTests:$true`                  | `$false`                                   | `--enable-tests` (builds `probe_plugin.exe` on Windows) |
| `-PatchConf:$false`                   | `$true`                                    | `--no-conf-patch`                                       |

Windows-only options (no POSIX `./configure` equivalent — MSVC + vcpkg path only):

| Flag                                  | Default                                    | What it does                                                                                                                                                                                                                                                                                                                                                                                 |
| ------------------------------------- | ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-VcpkgTriplet x64-windows-static-md` | static deps + dynamic CRT (matches Studio) | Selects the **vcpkg triplet** CMake uses (`VCPKG_TARGET_TRIPLET`): which variants of OpenSSL, zlib, curl, mosquitto, etc. get linked. The default **static libs + `/MD` runtime** matches typical Bambu Studio builds so you do not mix CRT modes across the DLL boundary. Use **`x64-windows`** if you want **shared** vcpkg DLLs (often quicker rebuilds, different deployment trade-off). |
| `-VcpkgRoot C:\vcpkg`                 | `$env:VCPKG_ROOT`                          | **Path to your vcpkg checkout.** The script feeds CMake `…/scripts/buildsystems/vcpkg.cmake` from here so manifest mode can resolve `vcpkg.json`. Set the env var globally or pass this when vcpkg lives outside `%VCPKG_ROOT%` / you use several trees.                                                                                                                                     |
| `-RegisterDShowFilter:$false`         | `$true`                                    | When **on** (default), `cmake --install` runs **`regsvr32`** on `BambuSource.dll` so the **DirectShow** source filter is **COM-registered** — needed for **Orca / `wxMediaCtrl2` / Windows Media Player** camera playback. Turn **off** for portable or staged installs, CI, or if you register the DLL yourself (`regsvr32 /s` / `/u`) after copying plugins by hand.                       |

**Version auto-detection** (omit `-WithVersion`; same intent as Linux, different primary source):

- **Bambu Studio** — `configure.ps1` first tries the **installed application binary**, not the conf file alone. It scans the **Add/Remove Programs** uninstall registry (`HKLM\…\Uninstall`, `HKLM\…\Wow6432Node\…\Uninstall`, `HKCU\…\Uninstall`) for an entry whose **DisplayName** is **`Bambu Studio`**, resolves the real **`bambu-studio.exe`** from **`DisplayIcon`** (or **`InstallLocation`** + `bambu-studio.exe`), and reads the PE **`FileVersion`** string. That matches what Studio uses internally as **`SLIC3R_VERSION`** and what the About box shows. Only if that path fails does it fall back to the **`"version"`** field under **`"app"`** in **`<Prefix>\BambuStudio.conf`** (default prefix is **`%APPDATA%\BambuStudio`**). The binary wins when both exist because the conf can **lag the `.exe`** after a patch, and Studio’s plugin gate compares against the **running build**, not the stale JSON line — picking only the conf can make Studio reject the DLL every launch. If **neither** `FileVersion` nor conf **`version`** is available, the script **errors** and asks for **`-WithVersion`** (same “no silent guess” idea as Linux).
- **Orca Slicer** — the same registry walk for **DisplayName `OrcaSlicer`**, then **`FileVersion`** of the Orca executable; if that fails, **`"network_plugin_version"`** under **`"app"`** in **`<Prefix>\OrcaSlicer.conf`**. If that key is still absent (never installed a plugin), fall back to **`02.03.00`** — the newest network version Orca advertises upstream (see **`AVAILABLE_NETWORK_VERSIONS`** in Orca’s `bambu_networking.hpp`), so a pristine Orca profile still configures. When **FileVersion** and the conf disagree, the script prints a note and keeps the **binary** value.

Identical to Linux: the chosen `W.X.Y.Z` or `W.X.Y` is normalized to **four** dotted components with the **last set to `99`** so the plugin passes the “newer than bundled agent” check.

Driving CMake directly is also fine:

```powershell
cmake -S . -B build -G "Visual Studio 16 2019" -A x64 `
    -DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake `
    -DVCPKG_TARGET_TRIPLET=x64-windows-static-md `
    -DOBN_VERSION=02.06.01.99 -DOBN_CLIENT_TYPE=bambu_studio
cmake --build   build --config Release
cmake --install build --config Release
```

`cmake --install` runs the automated install. For the manual steps (copy paths, conf keys), see [Manual installation](#manual-installation) below.

## Manual installation

First, copy the plugin binaries themselves: `*.so` on Linux and `*.dll` on Windows.
For both Bambu Studio and Orca Slicer, put them in the `plugins` directory under the application’s data / config directory:

  - `~/.config/<client_name>/plugins` — Linux
  - `~/.var/app/<namespace>/config/<client_name>/plugins` — Linux (Flatpak install)
  - `%APPDATA%\<client_name>\plugins` — Windows

Here `client_name` is `BambuStudio` or `OrcaSlicer`, and `namespace` is `com.bambulab.BambuStudio` or `com.orcaslicer.OrcaSlicer` respectively.

- **Bambu Studio:** also place `network_plugins.json` in `ota/plugins` (alongside the `plugins` directory).
- **Orca Slicer:** rename `libbambu_networking.so` (or `bambu_networking.dll` on Windows) so the filename includes the plugin version, e.g. `libbambu_networking_02.03.00.99.so`.

Then edit the configuration file.

**Bambu Studio** — `BambuStudio.conf` (under the `app` object):

  - set `"installed_networking"` to `"1"` (mark the plugin as installed)
  - set `"update_network_plugin"` to `"false"` (avoid auto-update replacing it with the stock plugin)
  - on **Windows** and **macOS**, set `ignore_module_cert` to `"1"` to skip publisher / certificate validation for the plugin

**Orca Slicer** — `OrcaSlicer.conf` (under the `app` object):

  - set `"installed_networking"` to `"true"`
  - set `"network_plugin_version"` to your built plugin version, e.g. `02.03.00.99`
  - set `"network_plugin_remind_later"` to `"true"` to suppress “newer plugin available” prompts
  - remove your plugin version from `"network_plugin_skipped_versions"` if it appears there

---

Back to the [main README](README.md).
