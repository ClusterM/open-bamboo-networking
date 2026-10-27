#pragma once

// Cover-image cache for the "currently printing" thumbnail in Studio's
// Device tab.
//
// Fetches via tunnel_upload::fetch_model_tile_thumbnail — the same
// LIST_INFO + SUB_FILE #thumbnail path as Device → Storage → Model.
// When that fails, LAN prints this plugin uploaded itself fall back to the
// image staged from their .3mf (stage_from_3mf).

#include <cstdint>
#include <string>
#include <vector>

namespace obn::cover_cache {

std::string temp_dir();

std::string path_for(const std::string& subtask_name,
                     int                plate_idx,
                     const std::string& version = {});

// Plate image of a local .3mf: Metadata/plate_N.png, then the same
// fallbacks as the :6000 fetch (plate_no_light_N, then plate 1 when
// N != 1). `*entry` (optional) gets the archive entry that was used.
bool read_local_thumbnail(const std::string&         path_3mf,
                          int                        plate_idx,
                          std::vector<std::uint8_t>* png,
                          std::string*               entry = nullptr,
                          std::string*               err = nullptr);

// Keeps the plate image of a .3mf this plugin uploads for a few hours; a
// failed :6000 fetch for that printer, name and plate writes it instead.
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
void ensure(const std::string& host,
            const std::string& dev_id,
            const std::string& user,
            const std::string& password,
            const std::string& subtask_name,
            int                plate_idx,
            const std::string& version = {});

} // namespace obn::cover_cache
