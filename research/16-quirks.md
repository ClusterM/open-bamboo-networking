## 16. Community quirk index

Facts-only index of firmware/model-specific traps documented in the community issue tracker (bambuddy, AGPL — facts and links only, never code). Two-way linked: each row points at the chapter that owns the topic; those chapters link back here.

| Issue | Firmware / model | Trap (one sentence) | Research page | Source |
|---|---|---|---|---|
| #1618 | all (detect flow) | Slicers/plugins stall after TCP `:3000` detect — an undocumented post-detect step is expected | [§6.1](06.01-ssdp.md) / [§8.4](08.04-lan.md) | INTERESTING_REPOS.md §4 |
| #2834 | all (detect flow) | Same detect-stall family as #1618 — a separate report of the post-detect stall | [§6.1](06.01-ssdp.md) / [§8.4](08.04-lan.md) | INTERESTING_REPOS.md §4 |
| #3014 | all (detect flow) | Same detect-stall family as #1618 — a separate report of the post-detect stall | [§6.1](06.01-ssdp.md) / [§8.4](08.04-lan.md) | INTERESTING_REPOS.md §4 |
| #2732 | fw 01.10.00.00, 2×AMS | `ams_mapping` needs 8 elements; shorter array → `project_file` silently ignored → 270 s timeout | [§8.8](08.08-print-abi.md) | INTERESTING_REPOS.md §9 |
| #2757 | P1S | port 6000 accepts max 2 concurrent camera streams; 3rd accepted-but-stalled | [§6.4](06.04-port-6000.md) / [§12.1.5](12.01.05-fields-camera-ai.md) | INTERESTING_REPOS.md §9 |
| #2762 | H2-series | FTPS `:990` exposes external storage only; Studio uploads via two TLS conns to `:6000` to reach internal eMMC | [§6.3](06.03-ftps.md) / [§8.14](08.14-file-transfer.md) | INTERESTING_REPOS.md §9 |
| #2856 | — | printer reports project file as `brtc://emmc/<file>` → internal-storage class | [§12.1.5](12.01.05-fields-camera-ai.md) | INTERESTING_REPOS.md §9 |
| #1170 | P2S | FTPS `550` on all probe dirs | [§6.3](06.03-ftps.md) / [§8.14](08.14-file-transfer.md) | INTERESTING_REPOS.md §9 |
| #2931 | H2 | `subtask_name` may be a MakerWorld profile title; real file at `/data/Metadata/plate_1.gcode` | [§6.3](06.03-ftps.md) / [§8.14](08.14-file-transfer.md) | INTERESTING_REPOS.md §9 |

Footnote (draft PRs, not traps): #1200 (dual-UID `tray_uuid` e2e), #2803 (`ams_mapping` re-validation, 38 tests), #1185 (macro whitelist — Bambu ignores `G91`).

Source: INTERESTING_REPOS.md §9
