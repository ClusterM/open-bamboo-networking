#!/usr/bin/env python3
"""One-shot helper: rewrite research/*.md Studio/Orca path citations to GitHub permalinks.

Already applied for Studio 12f17b06f4f537f9c03162d08bb70cf733c42839 /
Orca 11fdb472d6193312bc6c78b7703ad2c1222502b7 (2026-07-26). Do not re-run on
pinned docs without restoring bare `src/slic3r/...` citations first — bare
path replace corrupts URLs if links already exist.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESEARCH = ROOT / "research"

STUDIO_SHA = "12f17b06f4f537f9c03162d08bb70cf733c42839"
ORCA_SHA = "11fdb472d6193312bc6c78b7703ad2c1222502b7"
STUDIO_BASE = f"https://github.com/bambulab/BambuStudio/blob/{STUDIO_SHA}"
ORCA_BASE = f"https://github.com/SoftFever/OrcaSlicer/blob/{ORCA_SHA}"

ORCA_ONLY = {
    "src/slic3r/Utils/BBLNetworkPlugin.cpp",
}


def base_for(path: str) -> str:
    return ORCA_BASE if path in ORCA_ONLY else STUDIO_BASE


def link(path: str, start: int | None = None, end: int | None = None, label: str | None = None) -> str:
    url = f"{base_for(path)}/{path}"
    if start is not None:
        url += f"#L{start}" if end is None or end == start else f"#L{start}-L{end}"
    if label is None:
        name = Path(path).name
        if start is None:
            label = name if not path.endswith(("{cpp,h}", "{c,h}", "{hpp,cpp}")) else path.split("/")[-1]
        elif end is None or end == start:
            label = f"{name}:{start}"
        else:
            label = f"{name}:{start}-{end}"
    return f"[{label}]({url})"


def link_brace(path_prefix: str, exts: str) -> str:
    """path like src/.../foo.{cpp,h} → two links."""
    stem = path_prefix  # includes src/.../foo
    parts = [e.strip() for e in exts.split(",")]
    return ", ".join(link(f"{stem}.{ext}", label=f"{Path(stem).name}.{ext}") for ext in parts)


# Exact old backtick citations → new markdown (longest keys first when applying)
# Values are the full replacement including brackets.
EXACT: dict[str, str] = {}


def add(old: str, path: str, start: int | None = None, end: int | None = None, label: str | None = None) -> None:
    EXACT[old] = link(path, start, end, label)


def add_file(old: str, path: str, label: str | None = None) -> None:
    EXACT[old] = link(path, label=label or Path(path).name)


def add_brace(old: str, stem: str, exts: str) -> None:
    EXACT[old] = link_brace(stem, exts)


# --- source-map / common ranges (updated) ---
add("src/slic3r/GUI/DeviceManager.cpp:2067-2074, 3548-3553",
    "src/slic3r/GUI/DeviceManager.cpp", 2145, 2145,
    label="DeviceManager.cpp:2145")  # will special-case dual below

# Fix dual ranges manually in rewrite_source_map instead.

# Single-range maps used across files
RANGES: list[tuple[str, str, int | None, int | None]] = [
    # DeviceManager
    ("src/slic3r/GUI/DeviceManager.cpp:1744-2090", "src/slic3r/GUI/DeviceManager.cpp", 1759, 2094),
    ("src/slic3r/GUI/DeviceManager.cpp:1537-1775", "src/slic3r/GUI/DeviceManager.cpp", 1615, 1842),
    ("src/slic3r/GUI/DeviceManager.cpp:3764", "src/slic3r/GUI/DeviceManager.cpp", 3988, None),
    # DevCalib / Fila
    ("src/slic3r/GUI/DeviceCore/DevCalib.cpp:45-324", "src/slic3r/GUI/DeviceCore/DevCalib.cpp", 45, 324),
    ("src/slic3r/GUI/DeviceCore/DevCalib.cpp:54-80", "src/slic3r/GUI/DeviceCore/DevCalib.cpp", 56, 80),
    ("src/slic3r/GUI/DeviceCore/DevFilaSystemCtrl.cpp:11-57", "src/slic3r/GUI/DeviceCore/DevFilaSystemCtrl.cpp", 11, 57),
    ("src/libslic3r/Calib.hpp:114-181", "src/libslic3r/Calib.hpp", 114, 181),

    # NetworkAgent
    ("src/slic3r/Utils/NetworkAgent.cpp:279-382", "src/slic3r/Utils/NetworkAgent.cpp", 285, 394),
    ("src/slic3r/Utils/NetworkAgent.cpp:523-575", "src/slic3r/Utils/NetworkAgent.cpp", 529, 580),
    ("src/slic3r/Utils/NetworkAgent.cpp:1363-1425", "src/slic3r/Utils/NetworkAgent.cpp", 1158, 1195),
    ("src/slic3r/Utils/NetworkAgent.cpp:368", "src/slic3r/Utils/NetworkAgent.cpp", 378, 379),
    ("src/slic3r/Utils/NetworkAgent.cpp:276", "src/slic3r/Utils/NetworkAgent.cpp", 272, None),
    ("src/slic3r/Utils/NetworkAgent.hpp:10-115", "src/slic3r/Utils/NetworkAgent.hpp", 10, 123),
    # bambu_networking.hpp
    ("src/slic3r/Utils/bambu_networking.hpp:97-100", "src/slic3r/Utils/bambu_networking.hpp", 105, 107),
    ("src/slic3r/Utils/bambu_networking.hpp:13-94", "src/slic3r/Utils/bambu_networking.hpp", 14, 101),
    ("src/slic3r/Utils/bambu_networking.hpp:152-241", "src/slic3r/Utils/bambu_networking.hpp", 152, 250),
    ("src/slic3r/Utils/bambu_networking.hpp:180-275", "src/slic3r/Utils/bambu_networking.hpp", 187, 250),
    ("src/slic3r/Utils/bambu_networking.hpp:180-189", "src/slic3r/Utils/bambu_networking.hpp", 187, 196),
    ("src/slic3r/Utils/bambu_networking.hpp:192-241", "src/slic3r/Utils/bambu_networking.hpp", 199, 250),
    ("src/slic3r/Utils/bambu_networking.hpp:100", "src/slic3r/Utils/bambu_networking.hpp", 107, None),
    ("src/slic3r/Utils/bambu_networking.hpp:97", "src/slic3r/Utils/bambu_networking.hpp", 105, None),
    ("src/slic3r/Utils/bambu_networking.hpp:29", "src/slic3r/Utils/bambu_networking.hpp", 29, None),
    # Jobs
    ("src/slic3r/GUI/Jobs/PrintJob.cpp:149-624", "src/slic3r/GUI/Jobs/PrintJob.cpp", 149, 681),
    ("src/slic3r/GUI/Jobs/SendJob.cpp:111-347", "src/slic3r/GUI/Jobs/SendJob.cpp", 111, 392),
    ("src/slic3r/GUI/Jobs/UpgradeNetworkJob.cpp:16-146", "src/slic3r/GUI/Jobs/UpgradeNetworkJob.cpp", 16, 146),
    ("src/slic3r/GUI/Jobs/UpgradeNetworkJob.cpp:19-20", "src/slic3r/GUI/Jobs/UpgradeNetworkJob.cpp", 19, 20),
    ("src/slic3r/GUI/SelectMachine.cpp:2931-3157", "src/slic3r/GUI/SelectMachine.cpp", 3013, 3241),
    ("src/slic3r/GUI/SendToPrinter.cpp:1700-1995", "src/slic3r/GUI/SendToPrinter.cpp", 1746, 2025),
    # File transfer
    ("src/slic3r/Utils/FileTransferUtils.hpp:239-253", "src/slic3r/Utils/FileTransferUtils.hpp", 239, 253),
    ("src/slic3r/Utils/FileTransferUtils.cpp:12-37", "src/slic3r/Utils/FileTransferUtils.cpp", 12, 40),
    ("src/slic3r/Utils/CertificateVerify.cpp:289-300", "src/slic3r/Utils/CertificateVerify.cpp", 291, 300),
    # GUI_App
    ("src/slic3r/GUI/GUI_App.cpp:1469-1556", "src/slic3r/GUI/GUI_App.cpp", 1569, 1595),
    ("src/slic3r/GUI/GUI_App.cpp:1573-1761", "src/slic3r/GUI/GUI_App.cpp", 1597, 1785),
    ("src/slic3r/GUI/GUI_App.cpp:1763-1912", "src/slic3r/GUI/GUI_App.cpp", 1787, 1936),
    ("src/slic3r/GUI/GUI_App.cpp:1914-1957", "src/slic3r/GUI/GUI_App.cpp", 1938, 1942),
    ("src/slic3r/GUI/GUI_App.cpp:1959-1973", "src/slic3r/GUI/GUI_App.cpp", 1983, 2004),
    ("src/slic3r/GUI/GUI_App.cpp:1982-1998", "src/slic3r/GUI/GUI_App.cpp", 2006, 2022),
    ("src/slic3r/GUI/GUI_App.cpp:3359-3419", "src/slic3r/GUI/GUI_App.cpp", 3575, 3635),
    ("src/slic3r/GUI/GUI_App.cpp:3421-3519", "src/slic3r/GUI/GUI_App.cpp", 3637, 3756),
    ("src/slic3r/GUI/GUI_App.cpp:3423", "src/slic3r/GUI/GUI_App.cpp", 3639, None),
    ("src/slic3r/GUI/GUI_App.cpp:3461-3510", "src/slic3r/GUI/GUI_App.cpp", 3682, 3750),
    ("src/slic3r/GUI/GUI_App.cpp:3430-3437", "src/slic3r/GUI/GUI_App.cpp", 3639, 3639),
    ("src/slic3r/GUI/GUI_App.cpp:1906-1909", "src/slic3r/GUI/GUI_App.cpp", 1906, 1909),
    # PresetUpdater
    ("src/slic3r/Utils/PresetUpdater.cpp:1165-1253", "src/slic3r/Utils/PresetUpdater.cpp", 1165, 1253),
    ("src/slic3r/Utils/PresetUpdater.cpp:561-737", "src/slic3r/Utils/PresetUpdater.cpp", 561, 737),
    ("src/slic3r/Utils/PresetUpdater.cpp:1131-1163", "src/slic3r/Utils/PresetUpdater.cpp", 1131, 1163),
    # BambuSource / media
    ("src/slic3r/GUI/Printer/PrinterFileSystem.cpp:1831-1877", "src/slic3r/GUI/Printer/PrinterFileSystem.cpp", 1840, 1879),
    ("src/slic3r/GUI/Printer/PrinterFileSystem.cpp:1431-1458", "src/slic3r/GUI/Printer/PrinterFileSystem.cpp", 1439, 1478),
    ("src/slic3r/GUI/Printer/PrinterFileSystem.cpp:1567-1595", "src/slic3r/GUI/Printer/PrinterFileSystem.cpp", 1567, 1606),
    ("src/slic3r/GUI/Printer/PrinterFileSystem.cpp:1567-1596", "src/slic3r/GUI/Printer/PrinterFileSystem.cpp", 1567, 1606),
    ("src/slic3r/GUI/Printer/PrinterFileSystem.cpp:1747-1748", "src/slic3r/GUI/Printer/PrinterFileSystem.cpp", 1756, 1756),
    ("src/slic3r/GUI/Printer/PrinterFileSystem.h:32-72", "src/slic3r/GUI/Printer/PrinterFileSystem.h", 32, 72),
    ("src/slic3r/GUI/Printer/PrinterFileSystem.h:32", "src/slic3r/GUI/Printer/PrinterFileSystem.h", 32, None),
    ("src/slic3r/GUI/Printer/PrinterFileSystem.h:34-45", "src/slic3r/GUI/Printer/PrinterFileSystem.h", 34, 45),
    ("src/slic3r/GUI/Printer/PrinterFileSystem.h:48-72", "src/slic3r/GUI/Printer/PrinterFileSystem.h", 48, 72),
    ("src/slic3r/GUI/MediaPlayCtrl.cpp:307-318, 551-559", "src/slic3r/GUI/MediaPlayCtrl.cpp", 444, 455),
    ("src/slic3r/GUI/MediaPlayCtrl.cpp:307-318", "src/slic3r/GUI/MediaPlayCtrl.cpp", 444, 455),
    ("src/slic3r/GUI/MediaPlayCtrl.cpp:49", "src/slic3r/GUI/MediaPlayCtrl.cpp", 67, None),
    ("src/slic3r/GUI/wxMediaCtrl2.cpp:44-68", "src/slic3r/GUI/wxMediaCtrl2.cpp", 42, 52),
    ("src/slic3r/GUI/wxMediaCtrl2.cpp:71-138", "src/slic3r/GUI/wxMediaCtrl2.cpp", 55, 138),
    ("src/slic3r/GUI/wxMediaCtrl2.cpp:95-138", "src/slic3r/GUI/wxMediaCtrl2.cpp", 94, 138),
    ("src/slic3r/GUI/wxMediaCtrl2.mm:67-141", "src/slic3r/GUI/wxMediaCtrl2.mm", 245, 289),
    ("src/slic3r/GUI/wxMediaCtrl2.mm:67-85", "src/slic3r/GUI/wxMediaCtrl2.mm", 245, 269),
    ("src/slic3r/GUI/BambuPlayer/BambuPlayer.h:14-28", "src/slic3r/GUI/BambuPlayer/BambuPlayer.h", 36, 58),
    ("src/slic3r/GUI/Printer/gstbambusrc.c", "src/slic3r/GUI/Printer/gstbambusrc.c", None, None),
    ("src/slic3r/Utils/BBLNetworkPlugin.cpp", "src/slic3r/Utils/BBLNetworkPlugin.cpp", 286, 325),
]

FILE_ONLY = [
    "src/slic3r/Utils/NetworkAgent.hpp",
    "src/slic3r/Utils/NetworkAgent.cpp",
    "src/slic3r/Utils/bambu_networking.hpp",
    "src/slic3r/Utils/PresetUpdater.cpp",
    "src/slic3r/Utils/CertificateVerify.cpp",
    "src/slic3r/Utils/FileTransferUtils.hpp",
    "src/slic3r/Utils/FileTransferObject.cpp",
    "src/slic3r/GUI/GUI_App.cpp",
    "src/slic3r/GUI/DownloadProgressDialog.cpp",
    "src/slic3r/GUI/Jobs/UpgradeNetworkJob.cpp",
    "src/slic3r/GUI/Printer/BambuTunnel.h",
    "src/slic3r/GUI/Printer/PrinterFileSystem.cpp",
    "src/slic3r/GUI/Printer/PrinterFileSystem.h",
    "src/slic3r/GUI/MediaPlayCtrl.cpp",
    "src/slic3r/GUI/BambuPlayer/BambuPlayer.h",
    "src/slic3r/GUI/wxMediaCtrl2.mm",
    "src/slic3r/GUI/wxMediaCtrl2.cpp",
    "src/slic3r/GUI/fila_manager/wgtFilaManagerCloudClient.cpp",
    "src/slic3r/GUI/fila_manager/wgtFilaManagerCloudSync.cpp",
    "src/slic3r/GUI/DeviceCore/DevAxisCtrl.cpp",
]

BRACES = [
    ("src/slic3r/Utils/FileTransferUtils.{hpp,cpp}", "src/slic3r/Utils/FileTransferUtils", "hpp,cpp"),
    ("src/slic3r/Utils/CertificateVerify.{hpp,cpp}", "src/slic3r/Utils/CertificateVerify", "hpp,cpp"),
    ("src/slic3r/GUI/Jobs/UpgradeNetworkJob.{hpp,cpp}", "src/slic3r/GUI/Jobs/UpgradeNetworkJob", "hpp,cpp"),
    ("src/slic3r/GUI/Printer/gstbambusrc.{c,h}", "src/slic3r/GUI/Printer/gstbambusrc", "c,h"),
    ("src/slic3r/GUI/Printer/PrinterFileSystem.{cpp,h}", "src/slic3r/GUI/Printer/PrinterFileSystem", "cpp,h"),
    ("src/slic3r/GUI/MediaPlayCtrl.{cpp,h}", "src/slic3r/GUI/MediaPlayCtrl", "cpp,h"),
    ("src/slic3r/GUI/MediaFilePanel.{cpp,h}", "src/slic3r/GUI/MediaFilePanel", "cpp,h"),
    ("src/slic3r/GUI/wxMediaCtrl2.{cpp,h}", "src/slic3r/GUI/wxMediaCtrl2", "cpp,h"),
    ("src/slic3r/GUI/wxMediaCtrl3.{cpp,h}", "src/slic3r/GUI/wxMediaCtrl3", "cpp,h"),
    ("src/slic3r/GUI/AVVideoDecoder.{cpp,h}", "src/slic3r/GUI/AVVideoDecoder", "cpp,h"),
]

for old, path, start, end in RANGES:
    add(old, path, start, end)

for path in FILE_ONLY:
    add_file(path, path)

for old, stem, exts in BRACES:
    add_brace(old, stem, exts)

# Special dual-range citations
EXACT["src/slic3r/GUI/DeviceManager.cpp:2067-2074, 3548-3553"] = (
    f"{link('src/slic3r/GUI/DeviceManager.cpp', 2145, 2145)}, "
    f"{link('src/slic3r/GUI/DeviceManager.cpp', 3628, 3628, label='DeviceManager.cpp:3628')}"
)
EXACT["src/slic3r/GUI/DeviceCore/DevFilaSystem.cpp:344-385, 522-555"] = (
    f"{link('src/slic3r/GUI/DeviceCore/DevFilaSystem.cpp', 340, 382)}, "
    f"{link('src/slic3r/GUI/DeviceCore/DevFilaSystem.cpp', 522, 561, label='DevFilaSystem.cpp:522-561')}"
)
EXACT["src/slic3r/GUI/MediaPlayCtrl.cpp:307-318, 551-559"] = (
    f"{link('src/slic3r/GUI/MediaPlayCtrl.cpp', 444, 455)}, "
    f"{link('src/slic3r/GUI/MediaPlayCtrl.cpp', 742, 760, label='MediaPlayCtrl.cpp:742-760')}"
)
# Relative BambuPlayer path in source-map
EXACT["BambuPlayer/BambuPlayer.h"] = link("src/slic3r/GUI/BambuPlayer/BambuPlayer.h")
EXACT["AVVideoDecoder.{cpp,h}"] = link_brace("src/slic3r/GUI/AVVideoDecoder", "cpp,h")

# Floating master URLs in 08.14
EXACT["https://github.com/bambulab/BambuStudio/blob/master/src/slic3r/Utils/FileTransferObject.cpp"] = (
    f"{STUDIO_BASE}/src/slic3r/Utils/FileTransferObject.cpp"
)
EXACT["https://github.com/bambulab/BambuStudio/blob/master/src/slic3r/GUI/MediaPlayCtrl.cpp"] = (
    f"{STUDIO_BASE}/src/slic3r/GUI/MediaPlayCtrl.cpp"
)

# Fence line updates: (path, old_start, old_end) -> (new_start, new_end)
FENCE_UPDATES: dict[tuple[str, int, int], tuple[int, int]] = {
    ("src/slic3r/Utils/NetworkAgent.cpp", 523, 575): (529, 580),
    ("src/slic3r/GUI/Printer/PrinterFileSystem.cpp", 1831, 1867): (1840, 1879),
    ("src/slic3r/GUI/MediaPlayCtrl.cpp", 307, 318): (444, 455),
    ("src/slic3r/GUI/wxMediaCtrl2.cpp", 44, 68): (42, 52),
    ("src/slic3r/GUI/Printer/gstbambusrc.c", 67, 67): (67, 67),
    ("src/slic3r/GUI/Printer/PrinterFileSystem.cpp", 1883, 1884): (1895, 1896),
    ("src/slic3r/GUI/wxMediaCtrl2.cpp", 95, 138): (94, 138),
    ("src/slic3r/GUI/wxMediaCtrl2.mm", 67, 85): (245, 269),
    ("src/slic3r/GUI/BambuPlayer/BambuPlayer.h", 14, 28): (36, 58),
    ("src/slic3r/GUI/Printer/PrinterFileSystem.h", 32, 32): (32, 32),
    ("src/slic3r/GUI/Printer/PrinterFileSystem.cpp", 1747, 1758): (1756, 1771),
    ("src/slic3r/GUI/Printer/PrinterFileSystem.cpp", 1431, 1458): (1439, 1478),
    ("src/slic3r/GUI/Printer/PrinterFileSystem.h", 34, 45): (34, 45),
    ("src/slic3r/Utils/FileTransferUtils.hpp", 71, 95): (71, 95),
    ("src/slic3r/Utils/FileTransferUtils.hpp", 27, 40): (27, 40),
}

FENCE_RE = re.compile(r"^```(\d+):(\d+):(src/(?:slic3r|libslic3r)/[^\n]+)\n", re.M)


def rewrite_text(text: str) -> str:
    # Fences first: update line numbers and prepend permalink
    def fence_sub(m: re.Match[str]) -> str:
        a, b, path = int(m.group(1)), int(m.group(2)), m.group(3)
        na, nb = FENCE_UPDATES.get((path, a, b), (a, b))
        permalink = link(path, na, nb)
        return f"Source: {permalink}\n\n```{na}:{nb}:{path}\n"

    text = FENCE_RE.sub(fence_sub, text)

    # Protect existing GitHub blob URLs from further path substitution
    placeholders: list[str] = []

    def protect(m: re.Match[str]) -> str:
        placeholders.append(m.group(0))
        return f"\x00URL{len(placeholders) - 1}\x00"

    text = re.sub(r"https://github\.com/[^\s\)\]]+", protect, text)

    # Exact replacements, longest first (backtick form first, then bare)
    for old in sorted(EXACT.keys(), key=len, reverse=True):
        new = EXACT[old]
        if old.startswith("http"):
            # already protected; handle via direct replace on placeholders restored later — skip
            continue
        text = text.replace(f"`{old}`", new)
        text = text.replace(old, new)

    # Restore URLs, then apply floating-master → pin rewrites
    for i, url in enumerate(placeholders):
        text = text.replace(f"\x00URL{i}\x00", url)
    for old, new in EXACT.items():
        if old.startswith("http"):
            text = text.replace(old, new)

    # Comment path in 10.03
    text = text.replace(
        "// 3rd_party/BambuStudio/src/slic3r/GUI/DeviceCore/DevAxisCtrl.cpp",
        f"// {STUDIO_BASE}/src/slic3r/GUI/DeviceCore/DevAxisCtrl.cpp",
    )
    text = text.replace(
        "3rd_party/BambuStudio/src/slic3r/GUI/DeviceCore/DevAxisCtrl.cpp",
        f"{STUDIO_BASE}/src/slic3r/GUI/DeviceCore/DevAxisCtrl.cpp",
    )

    # Soften MediaPlayCtrl ~line 834
    text = text.replace(
        "(~line 834)",
        f"({link('src/slic3r/GUI/MediaPlayCtrl.cpp', 860, 860, label='MediaPlayCtrl.cpp:860')})",
    )

    return text


def rewrite_source_map() -> None:
    ipcam = (
        f"{link('src/slic3r/GUI/DeviceManager.cpp', 2145, 2145)}, "
        f"{link('src/slic3r/GUI/DeviceManager.cpp', 3628, 3628, label='DeviceManager.cpp:3628')}"
    )
    ams_tray = (
        f"{link('src/slic3r/GUI/DeviceCore/DevFilaSystem.cpp', 340, 382)}, "
        f"{link('src/slic3r/GUI/DeviceCore/DevFilaSystem.cpp', 522, 561, label='DevFilaSystem.cpp:522-561')}"
    )
    media = (
        f"{link('src/slic3r/GUI/MediaPlayCtrl.cpp', 444, 455)}, "
        f"{link('src/slic3r/GUI/MediaPlayCtrl.cpp', 742, 760, label='MediaPlayCtrl.cpp:742-760')}"
    )
    content = f"""## 15. Map of key source locations

Studio citations are permalinks into [bambulab/BambuStudio](https://github.com/bambulab/BambuStudio) at `{STUDIO_SHA}` (2026-07-26). Orca-only paths use [SoftFever/OrcaSlicer](https://github.com/SoftFever/OrcaSlicer) at `{ORCA_SHA}`.

| Topic | File:lines |
|-------|------------|
| Timelapse storage preflight (`ipcam_get_media_info`) | {ipcam} |
| PA calibration commands (`extrusion_cali_*`, `flowrate_*`) | {link('src/slic3r/GUI/DeviceManager.cpp', 1759, 2094)}, {link('src/slic3r/GUI/DeviceCore/DevCalib.cpp', 45, 324)} |
| AMS MQTT commands (`ams_*`, `print_option`) | {link('src/slic3r/GUI/DeviceManager.cpp', 1615, 1842)}, {link('src/slic3r/GUI/DeviceCore/DevFilaSystemCtrl.cpp', 11, 57)} |
| AMS status / tray indexing | {ams_tray} |
| `PACalibResult` / `FlowRatioCalibResult` schemas | {link('src/libslic3r/Calib.hpp', 114, 181)}, {link('src/slic3r/GUI/DeviceCore/DevCalib.cpp', 56, 80)} |
| Resolution of all 100+ symbols | {link('src/slic3r/Utils/NetworkAgent.cpp', 285, 394)} |
| API typedefs | {link('src/slic3r/Utils/NetworkAgent.hpp', 10, 123)} |
| Name constants | {link('src/slic3r/Utils/bambu_networking.hpp', 105, 107)} |
| Error codes | {link('src/slic3r/Utils/bambu_networking.hpp', 14, 101)} |
| Print-job stage enum + `PrintParams` | {link('src/slic3r/Utils/bambu_networking.hpp', 152, 250)} |
| Studio print orchestration (decision tree) | {link('src/slic3r/GUI/Jobs/PrintJob.cpp', 149, 681)} |
| Upload-only job (`SendJob`) | {link('src/slic3r/GUI/Jobs/SendJob.cpp', 111, 392)} |
| Select-machine dialog → `PrintJob` | {link('src/slic3r/GUI/SelectMachine.cpp', 3013, 3241)} |
| Send-to-Printer dialog → `ft_*` | {link('src/slic3r/GUI/SendToPrinter.cpp', 1746, 2025)} |
| `NetworkAgent` wrappers for `start_*` | {link('src/slic3r/Utils/NetworkAgent.cpp', 1158, 1195)} |
| Data structures | {link('src/slic3r/Utils/bambu_networking.hpp', 187, 250)} |
| `InitFTModule` / `UnloadFTModule` | {link('src/slic3r/Utils/FileTransferUtils.hpp', 239, 253)} |
| `ft_*` symbol resolution | {link('src/slic3r/Utils/FileTransferUtils.cpp', 12, 40)} |
| Signature verification | {link('src/slic3r/Utils/CertificateVerify.cpp', 291, 300)} |
| Signature bypass | `app_config → ignore_module_cert`; {link('src/slic3r/GUI/GUI_App.cpp', 3639, 3639)} |
| Request URL | {link('src/slic3r/GUI/GUI_App.cpp', 1569, 1595)} |
| Plugin download | {link('src/slic3r/GUI/GUI_App.cpp', 1597, 1785)} |
| Extraction / installation | {link('src/slic3r/GUI/GUI_App.cpp', 1787, 1936)} |
| Version check | {link('src/slic3r/GUI/GUI_App.cpp', 2006, 2022)} |
| Restart networking | {link('src/slic3r/GUI/GUI_App.cpp', 1938, 1942)} |
| Removal | {link('src/slic3r/GUI/GUI_App.cpp', 1983, 2004)} |
| OTA copy-in | {link('src/slic3r/GUI/GUI_App.cpp', 3575, 3635)} |
| Agent initialization | {link('src/slic3r/GUI/GUI_App.cpp', 3637, 3756)} |
| OTA `sync_plugins` | {link('src/slic3r/Utils/PresetUpdater.cpp', 1165, 1253)} |
| `sync_resources` (shared engine) | {link('src/slic3r/Utils/PresetUpdater.cpp', 561, 737)} |
| OTA cache validation | {link('src/slic3r/Utils/PresetUpdater.cpp', 1131, 1163)} |
| UI install job | {link('src/slic3r/GUI/Jobs/UpgradeNetworkJob.cpp', 16, 146)} |
| "Downloading Bambu Network Plug-in" dialog | {link('src/slic3r/GUI/DownloadProgressDialog.cpp')} |
| `libBambuSource` C ABI | {link('src/slic3r/GUI/Printer/BambuTunnel.h')} |
| `libBambuSource` loader | {link('src/slic3r/GUI/Printer/PrinterFileSystem.cpp', 1840, 1879)} |
| `libBambuSource` `dlopen`/`LoadLibrary` | {link('src/slic3r/Utils/NetworkAgent.cpp', 529, 580)} |
| Camera URL formats | {media} |
| File-browser CTRL command set | {link('src/slic3r/GUI/Printer/PrinterFileSystem.h', 32, 72)} |
| File-browser CTRL JSON envelope | {link('src/slic3r/GUI/Printer/PrinterFileSystem.cpp', 1439, 1478)} |
| Linux camera back-end (gstbambusrc — Orca / legacy Studio) | {link_brace('src/slic3r/GUI/Printer/gstbambusrc', 'c,h')} |
| Windows / Linux camera widget — current Studio (FFmpeg, C ABI) | {link_brace('src/slic3r/GUI/wxMediaCtrl3', 'cpp,h')}, {link_brace('src/slic3r/GUI/AVVideoDecoder', 'cpp,h')} |
| Windows camera back-end (DirectShow CLSID — Orca / legacy Studio only) | {link('src/slic3r/GUI/wxMediaCtrl2.cpp', 55, 138)} |
| macOS camera (`BambuPlayer` Objective-C class) | {link('src/slic3r/GUI/wxMediaCtrl2.mm', 245, 289)}, {link('src/slic3r/GUI/BambuPlayer/BambuPlayer.h')} |

---

"""
    (RESEARCH / "15-source-map.md").write_text(content)


def main() -> None:
    rewrite_source_map()
    for path in sorted(RESEARCH.glob("*.md")):
        if path.name == "15-source-map.md":
            continue
        orig = path.read_text()
        new = rewrite_text(orig)
        if new != orig:
            path.write_text(new)
            print(f"updated {path.name}")
        else:
            print(f"unchanged {path.name}")


if __name__ == "__main__":
    main()
