#pragma once

// COVER-01: pick the cover listing key for a push_status frame.
//
// The wire chain keys the FTPS/LAN listing match on one name
// (cover_cache -> fetch_model_tile_thumbnail -> find_model_entry ->
// name_matches_model, src/tunnel_upload.cpp). For a print started from
// a MakerWorld profile that name is the *profile title* — a prose
// string that can never equal a listing filename — while the frame also
// carries the real file path. Measured facts (bambuddy PR
// #2931, https://github.com/maziggy/bambuddy/pull/2931 — AGPL, facts
// only; no upstream code or wording is copied here):
//
//   subtask_name  = "PETG 0.2mm layer, 2 walls, 15% infill"
//   gcode_file    = "/data/Metadata/plate_1.gcode"
//
// Contract (research OQ1 recommended default):
//
//   primary   : `gcode_file` present and non-empty ->
//               basename after the last '/', trailing ".gcode" stripped
//               ("/data/Metadata/plate_1.gcode" -> "plate_1"; the
//               listing matcher accepts plate_1.gcode.3mf via its
//               model_name + ".gcode.3mf" branch).
//   fallback  : `gcode_file` absent or empty -> `subtask_name` verbatim
//               (the profile-title case; best effort, byte-exact — this
//               is today's behavior, so nothing regresses).
//   empty     : neither field present/usable -> "".
//
// Byte-exact by design: no normalization, no lowercasing, '/' is the
// only path separator considered. Identity (subtask_name gate, synthetic
// ids, cache paths, Studio URLs) is untouched by this helper — the key
// selects the LISTING MATCH only.
//
// Reads the fields from the parsed frame (obn::json, json_lite): both
// the root object and the `print.*` block are consulted, because
// push_status frames arrive as {"print":{...}} while bare payloads may
// carry the fields at top level.

#include <string>

namespace obn {

// Pure: frame text in, cover listing key out. No I/O, no globals, no
// dependencies beyond json_lite — deliberately linkable from a small
// block-1 test.
std::string cover_model_key(const std::string& payload_json);

} // namespace obn
