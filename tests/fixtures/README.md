# Vendored Fixtures — doomspork/PandaSpy (MIT)

These files are unmodified, verbatim copies of fixture recordings from
[doomspork/PandaSpy](https://github.com/doomspork/PandaSpy), licensed under the
MIT License — Copyright (c) 2026 Sean Callan.

- Source repo: https://github.com/doomspork/PandaSpy
- License: MIT — full text vendored at [LICENSE.PandaSpy](LICENSE.PandaSpy)
- Raw SSDP source: https://raw.githubusercontent.com/doomspork/PandaSpy/main/fixtures/ssdp/
- Raw sequence source: https://raw.githubusercontent.com/doomspork/PandaSpy/main/fixtures/sequences/p1s-print-lifecycle/

## SHA-256 manifest

Every fixture byte is pinned here; the SSDP suite reads fixtures at runtime
and fails loudly on a missing file (D-08), while this manifest guards
against silent content edits. Regenerate with `sha256sum` over the two
directories and diff against this block.

```
# ssdp/
d8c25b0be7ea457d8b56ea2537d6f0bb0c8b69e1a04be41892d25ff9bc846140  ssdp/synthetic-msearch-echo.txt
3bef7752b26eb388d62c5bbcb7681f01e1be0658ca82e827b8e24bd5372253aa  ssdp/synthetic-not-ssdp.txt
fe3025744ef2654f80db90de2f782b54e107fb5856c8ab5ba7207fc6d3f23afe  ssdp/synthetic-notify-colonless-header.txt
cbe3587a31ab5ab8eb0cb0e6be713d1a7297ad53681eea05b96ec368fc91493a  ssdp/synthetic-notify-https-location.txt
7601dc2ac5d04cce68790f0a81ad32e3512c9720850eb613bf77ee7fd97785f7  ssdp/synthetic-notify-lf-lowercase-a1mini.txt
b94b8b6553f7f586d1834a080e2f08f106b7a20a4f1ef58dbb1bcdd5fa934bb1  ssdp/synthetic-notify-names-nothing.txt
5f39294f3abeb7bd623314b28f523dd931ad5071ec31eee95ccd400b49203a73  ssdp/synthetic-notify-no-location-h2d.txt
b59b5e57a489d40ce1d96135baf5a526f155af2e34a3578a256916363864f916  ssdp/synthetic-notify-unknown-model.txt
a1c82766646f95b9cb911130f9241fa336b6903e1d4726ded3ac37912328d530  ssdp/synthetic-notify-url-location.txt
60581210ef84806f97f7d0d1e5cd43a69bd24c566063028565e488108f65c059  ssdp/synthetic-notify-x1c.txt
0954b4e49067bf34083684feedf8e0009a28af3aba5d77b1c47e07d30601b2a6  ssdp/synthetic-search-response-404.txt
4b674821d6d99b9f5001260dbb9466eb2475eb220e0f9b763a694aaadf2fadd2  ssdp/synthetic-search-response-p1s.txt
# sequences/p1s-print-lifecycle/
67a495afec3a7015eca2e22f8b80a81c92f5dd1a650c30f1d1649a1d6365a416  sequences/p1s-print-lifecycle/00-pushall.json
acff29c28f7f20897f2c1078bd7b450e756dceb417f7aa76d8a02dd2ff9dcac2  sequences/p1s-print-lifecycle/01-delta-temps.json
e5e6593bcb5dc73b3b0c3bd811baf87a4e42561d4c8e48a338fab19dd5682dad  sequences/p1s-print-lifecycle/02-delta-progress.json
e4253394710a98f75cd3c95addf7d2a142bb4df0b2ac98c165887215cc55673e  sequences/p1s-print-lifecycle/03-delta-tray-switch.json
d512d7fceabb9b89265f1e053856de3ea9101f6b3f4c3860df7e564469dce1e1  sequences/p1s-print-lifecycle/04-delta-null-clears-wifi.json
cb33381a4026304cff97a7f0e0cec3e473b9b6de765fdfebf825f09a3d175eb6  sequences/p1s-print-lifecycle/05-delta-pause.json
85c475686240bbc0616459535113e6e3cc98dce41d467de6670c464e8668622a  sequences/p1s-print-lifecycle/06-delta-finish.json
```

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

Raw material for a future `push_status` delta-merge test — the repo has no
push_status accumulator to call yet, so no test drives them today (they are
kept for the day one exists):

1. `00-pushall.json`
2. `01-delta-temps.json`
3. `02-delta-progress.json`
4. `03-delta-tray-switch.json`
5. `04-delta-null-clears-wifi.json`
6. `05-delta-pause.json`
7. `06-delta-finish.json`

All fixture bytes are guarded by `.gitattributes` (`tests/fixtures/** -text`)
so git never converts line endings — the LF-only case stays LF-only.
