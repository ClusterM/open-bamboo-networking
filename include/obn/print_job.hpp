#pragma once

// Shared helpers for LAN-FTPS + project_file MQTT print submission.
//
// The LAN `run_local_print_job` and the cloud `run_cloud_print_job`
// pipelines both need to (a) pick a printer-friendly remote filename,
// (b) push the .3mf over FTPS to /cache/ on the printer, and (c) build
// a `{"print":{"command":"project_file", ...}}` payload for MQTT. We
// keep those three concerns here so both pipelines stay in sync.

#include <cstdint>
#include <functional>
#include <string>

#include "obn/bambu_networking.hpp"

namespace obn::print_job {

// Computes the printer-side filename we upload and later reference in
// the project_file MQTT payload. Uses project_name/task_name when
// possible and falls back to the basename of params.filename.
std::string pick_remote_name(const BBL::PrintParams& p);

// Remote STOR basename for start_send_gcode_to_sdcard: sanitized
// project_name verbatim (no .gcode.3mf suffix). Empty when project_name
// is unset — stock libbambu_networking.so fails the upload in that case.
std::string dest_name_for_send_gcode(const BBL::PrintParams& p);

// Performs the actual FTPS STOR of params.filename to remote_path,
// streaming progress through update_fn as PrintingStageUpload. Obeys
// cancel_fn. Returns 0 on success or a BAMBU_NETWORK_ERR_* code
// (err_code_on_failure is used for generic transport/upload errors; a
// cancellation is always reported as BAMBU_NETWORK_ERR_CANCELED).
//
// When `remote_path` starts with `/sdcard/` or `/usb/`, we transparently
// probe the printer with CWD across `{sdcard, usb, root}` and rewrite
// the directory portion to whichever mount actually answers - the same
// auto-detection logic `abi_ft.cpp` and the BambuSource CTRL bridge
// already apply (matters on A1 / A1 mini / P2S firmware variants where
// the FTPS root is the storage mount and `/sdcard` / `/usb` 550s). The
// caller can read the final path via `*selected_remote_path` (when
// non-null) to keep its `project_file` MQTT payload in sync.
int ftp_upload(const BBL::PrintParams& p,
               const std::string&      remote_path,
               const std::string&      ca_file,
               BBL::OnUpdateStatusFn   update_fn,
               BBL::WasCancelledFn     cancel_fn,
               int                     err_code_on_failure,
               std::uint64_t&          total_bytes_out,
               std::string*            selected_remote_path = nullptr);

// Options controlling the project_file payload we publish over MQTT.
// Cloud print fills in the real ids/url; LAN print uses "0" for ids
// and ftp://<file> for url.
struct ProjectFileOpts {
    std::string file_path;    // leading-slash path on the printer FS ("/cache/x.gcode.3mf")
    std::string url;          // "ftp://<file_path>" for LAN, or a presigned HTTPS URL for cloud
    std::string md5;          // hex MD5 of the uploaded file; "" if unknown
    std::string project_id{"0"};
    std::string profile_id{"0"};
    std::string task_id{"0"};
    std::string subtask_id{"0"};
};

std::string build_project_file_json(const BBL::PrintParams& p,
                                    const ProjectFileOpts&  opts);

} // namespace obn::print_job
