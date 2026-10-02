#pragma once

// Cover-image cache for the "currently printing" thumbnail in Studio's
// Device tab.
//
// Sources, best first: for LAN prints this plugin uploaded itself, the
// image staged from their .3mf (stage_from_3mf); otherwise the printer's
// copy via tunnel_upload::fetch_model_tile_thumbnail, the same
// LIST_INFO + SUB_FILE path as Device → Storage → Model.

#include <cstdint>
#include <string>
#include <vector>

namespace obn::cover_cache {

std::string temp_dir();

std::string path_for(const std::string& subtask_name,
                     int                plate_idx,
                     const std::string& version = {});

// Plate image of a local .3mf: Metadata/plate_N.png, else
// plate_no_light_N.png, as the :6000 fetch; never another plate's image.
// `*entry` (optional) gets the archive entry that was used.
bool read_local_thumbnail(const std::string&         path_3mf,
                          int                        plate_idx,
                          std::vector<std::uint8_t>* png,
                          std::string*               entry = nullptr,
                          std::string*               err = nullptr);

// Keeps the plate image of a .3mf this plugin uploads for a few hours; a
// cover fetch for that printer, name and plate writes it before trying :6000.
// The next call for the name and plate replaces it, or removes it when
// that archive has no plate image. True when an image was staged.
bool stage_from_3mf(const std::string& dev_id,
                    const std::string& subtask_name,
                    const std::string& path_3mf,
                    int                plate_idx);

// Drops the staged image again when the print it was staged for never
// started (project_file could not be published).
void unstage(const std::string& dev_id,
             const std::string& subtask_name,
             int                plate_idx);

// Background fetcher: if path_for(...) is missing, spawn a thread that
// connects on TLS :6000, reuses the file-browser wire path, writes PNG.
//
// COVER-01: `subtask_name` remains the IDENTITY (gate, inflight/neg-cache
// key, path_for, Studio url_for) while `model_key` is the LISTING-MATCH
// key handed to fetch_model_tile_thumbnail — gcode_file basename when the
// frame carried one, empty when it didn't (fetch then matches on
// subtask_name, i.e. pre-COVER-01 behavior).
void ensure(const std::string& host,
            const std::string& dev_id,
            const std::string& user,
            const std::string& password,
            const std::string& subtask_name,
            const std::string& model_key,
            int                plate_idx,
            const std::string& version = {});

} // namespace obn::cover_cache
