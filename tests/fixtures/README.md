# Vendored Fixtures — doomspork/PandaSpy (MIT)

These files are unmodified, verbatim copies of fixture recordings from
[doomspork/PandaSpy](https://github.com/doomspork/PandaSpy), licensed under the
MIT License — Copyright (c) 2026 Sean Callan.

- Source repo: https://github.com/doomspork/PandaSpy
- License: MIT (see upstream `LICENSE`)
- Raw SSDP source: https://raw.githubusercontent.com/doomspork/PandaSpy/main/fixtures/ssdp/
- Raw sequence source: https://raw.githubusercontent.com/doomspork/PandaSpy/main/fixtures/sequences/p1s-print-lifecycle/

## SSDP inventory (12 files — live GitHub API listing of upstream `fixtures/ssdp/`, 2026-09-29)

- synthetic-msearch-echo.txt
- synthetic-not-ssdp.txt
- synthetic-notify-colonless-header.txt
- synthetic-notify-https-location.txt
- synthetic-notify-lf-lowercase-a1mini.txt
- synthetic-notify-names-nothing.txt
- synthetic-notify-no-location-h2d.txt
- synthetic-notify-unknown-model.txt
- synthetic-notify-url-location.txt
- synthetic-notify-x1c.txt
- synthetic-search-response-404.txt
- synthetic-search-response-p1s.txt

Upstream serves **12** SSDP fixtures; our survey notes (INTERESTING_REPOS.md:53,
decision D-02) said **13** — the 13-vs-12 count discrepancy is recorded here
deliberately (OQ-2). No 13th fixture is ever invented.

## Sequence inventory (7 files, `p1s-print-lifecycle/`)

The delta-merge test (02-03) replays these in the order below:

1. `00-pushall.json`
2. `01-delta-temps.json`
3. `02-delta-progress.json`
4. `03-delta-tray-switch.json`
5. `04-delta-null-clears-wifi.json`
6. `05-delta-pause.json`
7. `06-delta-finish.json`

All fixture bytes are guarded by `.gitattributes` (`tests/fixtures/** -text`)
so git never converts line endings — the LF-only case stays LF-only.