#!/usr/bin/env python3
"""Validate internal Markdown links to .md files (and #anchors) in this repo."""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Build / vendor / VCS noise — not project documentation
SKIP_DIR_NAMES = {
    "third_party",
    "3rd_party",
    ".git",
    ".vcpkg",
    "vcpkg",
    "vcpkg_installed",
    "node_modules",
    "build",
    "cmake-build-debug",
    "cmake-build-release",
    ".cache",
    "__pycache__",
}
# Also skip top-level build-* trees (FetchContent / local test builds)
SKIP_DIR_PREFIXES = ("build-",)

# [text](target) — skip images ![text](target)
LINK_RE = re.compile(r"(?<!!)\[([^\]]*)\]\(([^)]+)\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$", re.M)

# github-slugger punctuation class (underscore is kept)
# github-slugger-ish: drop punctuation / symbols; keep letters, digits, underscore, space, hyphen
_PUNCT_RE = re.compile(
    r"[^\w\s\-]",
    flags=re.UNICODE,
)


def iter_md_files() -> list[Path]:
    out: list[Path] = []
    for p in ROOT.rglob("*.md"):
        rel_parts = p.relative_to(ROOT).parts
        if any(part in SKIP_DIR_NAMES for part in rel_parts):
            continue
        if any(part.startswith(SKIP_DIR_PREFIXES) for part in rel_parts):
            continue
        out.append(p)
    return sorted(out)


def github_slug(heading: str) -> str:
    """GFM / github-slugger-compatible heading id."""
    s = heading.strip().lower()
    s = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)
    s = re.sub(r"<[^>]+>", "", s)
    # Unwrap code / *bold* / *italic*; keep `_` inside identifiers (GitHub keeps them)
    s = s.replace("`", "")
    s = re.sub(r"\*\*([^*]+)\*\*", r"\1", s)
    s = re.sub(r"\*([^*]+)\*", r"\1", s)
    s = _PUNCT_RE.sub("", s)
    s = re.sub(r"\s+", "-", s.strip())
    s = re.sub(r"-+", "-", s).strip("-")
    return s


def heading_slugs(text: str) -> set[str]:
    slugs: set[str] = set()
    counts: dict[str, int] = defaultdict(int)
    for m in HEADING_RE.finditer(text):
        base = github_slug(m.group(2))
        if not base:
            continue
        n = counts[base]
        counts[base] = n + 1
        slugs.add(base if n == 0 else f"{base}-{n}")
    return slugs


def is_external(target: str) -> bool:
    t = target.strip()
    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", t))


def main() -> int:
    files = iter_md_files()
    slug_cache: dict[Path, set[str]] = {}
    errors: list[str] = []
    checked = 0

    for src in files:
        text = src.read_text(encoding="utf-8", errors="replace")
        for m in LINK_RE.finditer(text):
            target = m.group(2).strip()
            # Trim optional title: url "title"
            if target.startswith("<") and ">" in target:
                target = target[1 : target.index(">")].strip()
            else:
                target = target.split()[0] if target else target

            if not target or is_external(target):
                continue

            path_part, frag = (target.split("#", 1) + [None])[:2] if "#" in target else (target, None)
            if frag == "":
                frag = None

            # Same-file anchor
            if path_part == "":
                dest = src
            else:
                # Only care about .md destinations (and same-file # handled above)
                if not path_part.endswith(".md"):
                    continue
                dest = (src.parent / path_part).resolve()
                try:
                    dest.relative_to(ROOT)
                except ValueError:
                    errors.append(f"{src.relative_to(ROOT)}:{text.count(chr(10), 0, m.start()) + 1} → {target} (outside repo)")
                    checked += 1
                    continue

            line = text.count("\n", 0, m.start()) + 1
            checked += 1

            if not dest.is_file():
                errors.append(f"{src.relative_to(ROOT)}:{line} → {target} (missing file)")
                continue

            if frag is not None:
                if dest not in slug_cache:
                    slug_cache[dest] = heading_slugs(
                        dest.read_text(encoding="utf-8", errors="replace")
                    )
                if frag not in slug_cache[dest]:
                    errors.append(
                        f"{src.relative_to(ROOT)}:{line} → {target} (missing anchor #{frag})"
                    )

    print(f"Checked {checked} internal .md / # links in {len(files)} files.")
    if errors:
        print(f"\n{len(errors)} broken:")
        for e in errors:
            print(f"  {e}")
        return 1
    print("OK — no broken internal .md links.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
