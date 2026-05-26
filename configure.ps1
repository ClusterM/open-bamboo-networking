# PowerShell wrapper around CMake for the Windows build, mirroring what
# ./configure does on Linux. Drops a ready-to-build tree under -BuildDir
# (default ./build) and writes a tiny config.ps1 that records the build
# directory for downstream helpers.
#
# Every parameter below maps 1:1 to a CMake cache variable; run cmake
# directly if you want something this script does not expose.
#
# Typical use:
#   .\configure.ps1                                    # bambu_studio, x64-windows-static
#   .\configure.ps1 -ClientType orca_slicer
#   .\configure.ps1 -BuildType Debug -EnableTests:$false
#   .\configure.ps1 -VcpkgRoot C:\vcpkg -VcpkgTriplet x64-windows
#   .\configure.ps1 -Generator "Visual Studio 17 2022"   # pin a VS version
#
# If -Generator is omitted, it is not passed to CMake and CMake picks its
# platform default (on Windows with VS installed, typically the newest
# Visual Studio). VCPKG_ROOT does not imply a compiler/VS version; use
# -Generator when you must match a specific toolset (e.g. VS 2019 / v142).
#
# Requirements:
#   - Visual Studio 2019 (toolset v142) -- matches the MSVC ABI Bambu Studio
#     itself ships with. Newer toolsets *may* work but the std::string layout
#     across the DLL boundary is not guaranteed.
#   - vcpkg (manifest mode picks up vcpkg.json automatically).
#   - cmake on PATH (3.16+).

[CmdletBinding()]
param(
    [string]   $Prefix       = "",
    [string]   $BuildDir     = "build",
    [ValidateSet("Release","Debug","RelWithDebInfo","MinSizeRel")]
    [string]   $BuildType    = "Release",
    [string]   $WithVersion  = "",
    [ValidateSet("bambu_studio","orca_slicer")]
    [string]   $ClientType   = "bambu_studio",
    [bool]     $Workarounds   = $true,
    [bool]     $EnableTests   = $false,
    [bool]     $PatchConf     = $true,
    # On Windows install the DirectShow source filter (HKCU CLSID +
    # bambu: URL handler) so wxMediaCtrl2 can stream live camera. The
    # CMake side runs `regsvr32 /s BambuSource.dll`. Set $false to
    # skip if the user prefers to register manually.
    [bool]     $RegisterDShowFilter = $true,
    [string]   $VcpkgRoot    = "",
    # Default triplet: x64-windows-static-md = static deps + dynamic CRT (/MD).
    # Bambu Studio is /MD (dynamic CRT), and a /MT-built DLL would emit a
    # LIBCMT-vs-MSVCRT mismatch warning (LNK4098) and -- worse -- run two
    # copies of the C runtime side by side with diverging stdio and heap
    # state. -static (without -md) is left as an option for users who want
    # the older default.
    [ValidateSet("x64-windows","x64-windows-static","x64-windows-static-md","x86-windows","x86-windows-static")]
    [string]   $VcpkgTriplet = "x64-windows-static-md",
    # Empty = let CMake choose (-G omitted). Pass an explicit name to pin
    # a Visual Studio version (e.g. "Visual Studio 16 2019").
    [string]   $Generator    = "",
    [string]   $Architecture = "x64",
    # Cloud endpoint overrides baked in at build time. Empty = keep Bambu
    # defaults. The matching OBN_CLOUD_* environment variable wins at
    # runtime, so the same DLL can be redirected without rebuilding.
    #   -CloudApiUrl       : REST API base, no trailing slash
    #                        (e.g. https://api.example.com).
    #   -CloudWebUrl       : web portal base, WITH trailing slash
    #                        (e.g. https://example.com/).
    #   -CloudMqttHostname : MQTT broker hostname, no scheme, no port.
    [string]   $CloudApiUrl      = "",
    [string]   $CloudWebUrl      = "",
    [string]   $CloudMqttHostname = "",
    [string[]] $CMakeArg     = @()
)

$ErrorActionPreference = "Stop"

function Write-Note {
    param([string]$msg)
    Write-Host "configure: $msg"
}

function Write-Err {
    param([string]$msg)
    Write-Host "configure: $msg" -ForegroundColor Red
}

# ----- prerequisites -----------------------------------------------------

if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    Write-Err "cmake is required but was not found on PATH"
    exit 1
}

# Resolve vcpkg root, in this order: -VcpkgRoot, $env:VCPKG_ROOT, vcpkg.exe
# on PATH (its parent directory). If none are usable we error out -- vcpkg
# is mandatory for the Windows build because dependency resolution in
# CMakeLists relies on the vcpkg.cmake toolchain.
if ([string]::IsNullOrEmpty($VcpkgRoot) -and $env:VCPKG_ROOT) {
    $VcpkgRoot = $env:VCPKG_ROOT
}
if ([string]::IsNullOrEmpty($VcpkgRoot)) {
    $vcpkgExe = Get-Command vcpkg.exe -ErrorAction SilentlyContinue
    if ($vcpkgExe) {
        $VcpkgRoot = Split-Path -Parent $vcpkgExe.Source
    }
}
if ([string]::IsNullOrEmpty($VcpkgRoot) -or
    -not (Test-Path (Join-Path $VcpkgRoot "scripts\buildsystems\vcpkg.cmake"))) {
    Write-Err "vcpkg is required for the Windows build."
    Write-Err "  Install it from https://github.com/microsoft/vcpkg, set"
    Write-Err "  `$env:VCPKG_ROOT (or pass -VcpkgRoot), and re-run."
    exit 1
}
$ToolchainFile = Join-Path $VcpkgRoot "scripts\buildsystems\vcpkg.cmake"

# ----- per-client defaults ----------------------------------------------

# AppData\Roaming -- matches wxStandardPaths::Get().GetUserDataDir() in
# Bambu Studio's Windows build. CMakeLists / Clients.cmake compute the same
# default; we recompute it here so we can also surface the version detected
# from the slicer's existing .conf file before we even invoke cmake.
$Appdata = $env:APPDATA
$ClientLabel = ""
$ClientDir   = ""
$ConfName    = ""
$JsonKey     = ""
switch ($ClientType) {
    "bambu_studio" {
        $ClientLabel = "Bambu Studio"
        $ClientDir   = Join-Path $Appdata "BambuStudio"
        $ConfName    = "BambuStudio.conf"
        $JsonKey     = "version"
    }
    "orca_slicer"  {
        $ClientLabel = "Orca Slicer"
        $ClientDir   = Join-Path $Appdata "OrcaSlicer"
        $ConfName    = "OrcaSlicer.conf"
        $JsonKey     = "network_plugin_version"
    }
}

if ([string]::IsNullOrEmpty($Prefix)) {
    $Prefix = $ClientDir
}

# ----- version auto-detection -------------------------------------------

# Mirrors the Linux ./configure logic: read "app.<json_key>" from the
# slicer's conf file, bump the last component to .99 so our plugin always
# wins the slicer's compatibility gate (Studio compares the first 8 chars
# == "MAJOR.MINOR.PATCH"; .99 keeps us ahead).
function Detect-VersionFromConf {
    param([string]$ConfPath, [string]$Key)
    if (-not (Test-Path $ConfPath)) { return "" }
    $line = Select-String -Path $ConfPath -Pattern "`"$Key`"\s*:\s*`"([0-9][0-9.]*)`"" -ErrorAction SilentlyContinue |
            Select-Object -First 1
    if (-not $line) { return "" }
    if ($line.Matches.Count -gt 0 -and $line.Matches[0].Groups.Count -ge 2) {
        return $line.Matches[0].Groups[1].Value
    }
    return ""
}

# Resolve <ExeName>.exe to a four-component FileVersion via the
# Windows registry's Uninstall keys. The registry's DisplayVersion can
# lag behind the actual binary (it is set at install time and not
# refreshed on minor patches), so we read the running binary's
# FileVersion resource directly. That is the same string Studio reports
# in the About dialog and uses internally as SLIC3R_VERSION on Windows.
function Detect-VersionFromExe {
    param([string]$DisplayName)
    $regPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $entries = Get-ItemProperty -Path $regPaths -ErrorAction SilentlyContinue |
               Where-Object { $_.DisplayName -eq $DisplayName }
    foreach ($e in $entries) {
        # DisplayIcon usually points at the launcher exe, even when
        # InstallLocation is empty (and many installers leave it empty).
        $exe = $null
        if ($e.DisplayIcon) {
            $candidate = ($e.DisplayIcon -split ',')[0].Trim('"')
            if (Test-Path $candidate) { $exe = $candidate }
        }
        if (-not $exe -and $e.InstallLocation) {
            $base = ([System.IO.Path]::GetFileNameWithoutExtension($DisplayName).ToLower() -replace ' ','-')
            $candidate = Join-Path $e.InstallLocation ($base + '.exe')
            if (Test-Path $candidate) { $exe = $candidate }
        }
        if ($exe) {
            $fv = (Get-Item $exe).VersionInfo.FileVersion
            if ($fv -match '^\d+(\.\d+){2,3}$') {
                return [PSCustomObject]@{ Version = $fv; Path = $exe }
            }
        }
    }
    return $null
}

if ([string]::IsNullOrEmpty($WithVersion)) {
    $confPath = Join-Path $Prefix $ConfName
    $confVersion = Detect-VersionFromConf -ConfPath $confPath -Key $JsonKey

    $exeVersion = ""
    $exePath    = ""
    $exeInfo = $null
    if ($ClientType -eq "bambu_studio") {
        $exeInfo = Detect-VersionFromExe -DisplayName "Bambu Studio"
    } else {
        # Orca's Add/Remove name has historically been just "OrcaSlicer".
        $exeInfo = Detect-VersionFromExe -DisplayName "OrcaSlicer"
    }
    if ($exeInfo) {
        $exeVersion = $exeInfo.Version
        $exePath    = $exeInfo.Path
    }

    # Prefer the binary's FileVersion over the conf -- Windows Studio
    # ships .exe v02.06.01.55 against a conf still saying 02.06.00.51
    # right after a minor patch, and Studio compares the first 8 chars
    # of OUR plugin version against its own SLIC3R_VERSION. Picking the
    # conf there would silently fail the gate and Studio would fall back
    # to the stock backup at every launch.
    $detected = ""
    $source   = ""
    if (-not [string]::IsNullOrEmpty($exeVersion)) {
        $detected = $exeVersion
        $source   = "exe FileVersion of $exePath"
    } elseif (-not [string]::IsNullOrEmpty($confVersion)) {
        $detected = $confVersion
        $source   = "conf $confPath"
    } elseif ($ClientType -eq "orca_slicer") {
        # Orca only writes network_plugin_version after it has installed a
        # plugin at least once. A pristine Orca install has no key at all,
        # so fall back to the latest version Orca knows about. See
        # AVAILABLE_NETWORK_VERSIONS in
        # 3rd_party/OrcaSlicer/src/slic3r/Utils/bambu_networking.hpp.
        $detected = "02.03.00"
        $source   = "(default for orca_slicer; no $JsonKey in $confPath)"
    }

    if ([string]::IsNullOrEmpty($detected)) {
        Write-Err "cannot determine the plugin version automatically."
        Write-Err "  Tried to read `"$JsonKey`" from: $confPath"
        Write-Err "  Tried to read FileVersion via the Add/Remove Programs registry."
        if (-not (Test-Path $confPath)) {
            Write-Err "  (conf file does not exist)"
        }
        Write-Err "  Launch $ClientLabel at least once so it writes its config,"
        Write-Err "  or pass the version explicitly:"
        Write-Err "      .\configure.ps1 -WithVersion 02.06.01.99"
        exit 1
    }

    # Helpful sanity warning when the two sources disagree -- keeps the
    # user from being surprised when their conf-driven build gets
    # silently swapped out by Studio for a /lower/ stock version.
    if (-not [string]::IsNullOrEmpty($exeVersion) -and
        -not [string]::IsNullOrEmpty($confVersion) -and
        $exeVersion -ne $confVersion) {
        Write-Note "note: $ClientLabel binary FileVersion is $exeVersion but conf reports $confVersion"
        Write-Note "      using the binary version (Studio uses it for plugin compatibility check)"
    }

    # CMake's OBN_VERSION regex requires exactly four dotted components.
    if ($detected -match '^\d+(\.\d+){3}$') {
        $WithVersion = ($detected -replace '\.\d+$', '.99')
    } elseif ($detected -match '^\d+(\.\d+){2}$') {
        $WithVersion = "$detected.99"
    } else {
        Write-Err "cannot bump version `"$detected`": expected 3 or 4 dotted components."
        exit 1
    }
    Write-Note "detected $ClientLabel baseline $detected (source: $source)"
    Write-Note "plugin version set to $WithVersion (override with -WithVersion ...)"
}

# ----- assemble cmake command line --------------------------------------

# x86 builds usually want "Win32" as the architecture, x64 builds use "x64".
# If the user picked an x86 triplet without flipping -Architecture, normalize
# automatically so the generator string lines up with the deps vcpkg builds.
if ($VcpkgTriplet -like "x86-*" -and $Architecture -eq "x64") {
    Write-Note "x86 triplet selected; switching architecture to Win32"
    $Architecture = "Win32"
}

# Convert booleans to ON/OFF first; if we inline the ternary into the
# array literal, PowerShell's comma-vs-plus operator precedence ends up
# splitting "-DFOO=" and "ON" into two adjacent elements.
$workaroundsVal      = if ($Workarounds)        { "ON" } else { "OFF" }
$enableTestsVal      = if ($EnableTests)        { "ON" } else { "OFF" }
$patchConfVal        = if ($PatchConf)          { "ON" } else { "OFF" }
$registerDshowVal    = if ($RegisterDShowFilter){ "ON" } else { "OFF" }

$cmakeArgs = @(
    "-S", ".",
    "-B", $BuildDir
)
if (-not [string]::IsNullOrWhiteSpace($Generator)) {
    $cmakeArgs += "-G", $Generator
}
$cmakeArgs += @(
    "-A", $Architecture,
    "-DCMAKE_TOOLCHAIN_FILE=$ToolchainFile",
    "-DVCPKG_TARGET_TRIPLET=$VcpkgTriplet",
    "-DCMAKE_BUILD_TYPE=$BuildType",
    "-DCMAKE_INSTALL_PREFIX=$Prefix",
    "-DOBN_VERSION=$WithVersion",
    "-DOBN_CLIENT_TYPE=$ClientType",
    "-DOBN_ENABLE_WORKAROUNDS=$workaroundsVal",
    "-DOBN_BUILD_TESTS=$enableTestsVal",
    "-DOBN_PATCH_CLIENT_CONF=$patchConfVal",
    "-DOBN_REGISTER_DSHOW_FILTER=$registerDshowVal"
)
$cmakeArgs += "-DOBN_CLOUD_API_URL=$CloudApiUrl"
$cmakeArgs += "-DOBN_CLOUD_WEB_URL=$CloudWebUrl"
$cmakeArgs += "-DOBN_CLOUD_MQTT_HOSTNAME=$CloudMqttHostname"
if ($CMakeArg.Count -gt 0) { $cmakeArgs += $CMakeArg }

Write-Note ("cmake " + ($cmakeArgs -join " "))
& cmake @cmakeArgs
if ($LASTEXITCODE -ne 0) {
    Write-Err "cmake exited with $LASTEXITCODE"
    exit $LASTEXITCODE
}

# When -Generator was omitted, report the generator CMake actually selected.
$resolvedGenerator = $Generator
if ([string]::IsNullOrWhiteSpace($resolvedGenerator)) {
    $cacheFile = Join-Path $BuildDir "CMakeCache.txt"
    if (Test-Path $cacheFile) {
        $gLine = Select-String -LiteralPath $cacheFile -Pattern '^CMAKE_GENERATOR:INTERNAL=' -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($gLine) {
            $resolvedGenerator = ($gLine.Line -replace '^CMAKE_GENERATOR:INTERNAL=', '')
        }
    }
    if ([string]::IsNullOrWhiteSpace($resolvedGenerator)) {
        $resolvedGenerator = "(CMake default; see CMakeCache.txt)"
    }
}

# Persist the build dir so a future helper script (or the user) can reuse it
# without retyping it. POSIX side does the same with config.mk; ours is just
# a one-liner ps1 sourced via dot-source.
@(
    "# Generated by configure.ps1. Re-run it to refresh.",
    "`$BuildDir = '$BuildDir'"
) | Set-Content -Path "config.ps1" -Encoding ASCII

$patchTargetConf = Join-Path $ClientDir $ConfName

@"
configure: done.

Selected client: $ClientType
Install prefix : $Prefix
Plugin version : $WithVersion
Build dir      : $BuildDir
Generator      : $resolvedGenerator $Architecture
vcpkg toolchain: $ToolchainFile  ($VcpkgTriplet)

Next steps:
  cmake --build   $BuildDir --config $BuildType
  cmake --install $BuildDir --config $BuildType

The install step copies bambu_networking.dll, BambuSource.dll and
live555.dll into:
    $Prefix\plugins\

and (when -PatchConf is on, the default) sets installed_networking,
update_network_plugin and ignore_module_cert under "app" in:
    $patchTargetConf

so Bambu Studio loads our DLL on next launch.

When -RegisterDShowFilter is on (the default) the install step also
runs:
    regsvr32 /s "$Prefix\plugins\BambuSource.dll"
to register the DirectShow Source Filter (HKCU only, no admin needed)
that Studio's wxMediaCtrl2 needs for live camera view. To uninstall:
    regsvr32 /u "$Prefix\plugins\BambuSource.dll"
"@
