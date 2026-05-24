#pragma once

// Cover-image cache for the "currently printing" thumbnail in Studio's
// Device tab.
//
// Fetches via tunnel_upload::fetch_model_tile_thumbnail — the same
// LIST_INFO + SUB_FILE #thumbnail path as Device → Storage → Model.

#include <string>

namespace obn::cover_cache {

std::string temp_dir();

std::string path_for(const std::string& subtask_name,
                     int                plate_idx,
                     const std::string& version = {});

// Background fetcher: if path_for(...) is missing, spawn a thread that
// connects on TLS :6000, reuses the file-browser wire path, writes PNG.
void ensure(const std::string& host,
            const std::string& dev_id,
            const std::string& user,
            const std::string& password,
            const std::string& ca_file,
            const std::string& subtask_name,
            int                plate_idx,
            const std::string& version = {});

} // namespace obn::cover_cache
