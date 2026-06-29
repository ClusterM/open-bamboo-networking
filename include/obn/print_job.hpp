#pragma once

// Shared helpers for LAN print submission (FTPS legacy + :6000/brtc).
//
// The LAN `run_local_print_job` and the cloud `run_cloud_print_job`
// pipelines both need to (a) pick a printer-friendly remote filename,
// (b) push the .3mf to the printer (FTPS or :6000 cache upload), and
// (c) build a `{"print":{"command":"project_file", ...}}` payload for MQTT.

#include <cstdint>
#include <functional>
#include <string>

#include "obn/bambu_networking.hpp"

namespace obn::print_job {

// Strip path, normalise plate_0→plate_1 in the name, ensure .gcode.3mf
// extension. Used to compute the remote STOR filename and the
// project_file url= field so the printer sees plate_1 even when Orca
// Slicer wrote a plate_0 file.
std::string to_print_basename(std::string fname);

// Rewrite a 3MF ZIP archive in-place: rename Metadata/plate_0.* entries
// to Metadata/plate_1.*, patch model_settings.config path references,
// and bump plater_id "0"→"1". No-op when the archive already contains
// plate_1.gcode or lacks plate_0.gcode (BBS-style spools pass through
// unchanged). Returns false only on I/O or ZIP errors — the caller
// should treat false as fatal and refuse the print.
bool normalise_to_plate_one(const std::string& threemf_path);

// Computes the printer-side filename we upload and later reference in
// the project_file MQTT payload. Uses project_name/task_name when
// possible and falls back to the basename of params.filename.
std::string pick_remote_name(const BBL::PrintParams& p);

// Remote STOR basename for start_send_gcode_to_sdcard: sanitized
// project_name verbatim (no .gcode.3mf suffix). Empty when project_name
// is unset — stock libbambu_networking.so fails the upload in that case.
std::string dest_name_for_send_gcode(const BBL::PrintParams& p);

// True when the print job should upload via :6000 + MQTT brtc:// (P2S/emmc).
bool use_brtc_cache_upload(const BBL::PrintParams& p);

// MQTT url for model-cache print-start after :6000 upload.
std::string build_brtc_emmc_url(const std::string& remote_name);

// MQTT url for print-from-device (absolute path on printer storage).
std::string build_file_url(const std::string& absolute_path);

// MQTT url for legacy LAN print after FTPS upload.
std::string build_ftp_url(const std::string& stored_path);

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
// and brtc://emmc/, file://, or ftp:// for url.
struct ProjectFileOpts {
    std::string file_path;    // basename or absolute path on printer FS
    std::string url;          // brtc://emmc/, file://, ftp://, or presigned https
    std::string md5;          // hex MD5 of the uploaded file; "" if unknown
    std::string project_id{"0"};
    std::string profile_id{"0"};
    std::string task_id{"0"};
    std::string subtask_id{"0"};
};

std::string build_project_file_json(const BBL::PrintParams& p,
                                    const ProjectFileOpts&  opts);

// Cloud-print variant: emits `url_enc` and `param_enc` (RSA-PKCS#1 v1.5
// encrypted, base64-encoded) instead of the plaintext `url` / `param` fields.
// The caller is responsible for encrypting the values before calling this
// function (see cloud_print.cpp: rsa_pkcs1v15_encrypt_b64).
struct CloudProjectFileOpts {
    std::string url_enc;      // base64(RSA-PKCS1v1.5-encrypt(url))
    std::string param_enc;    // base64(RSA-PKCS1v1.5-encrypt("Metadata/plate_N.gcode"))
    std::string file_path;    // basename / absolute path on printer FS
    std::string md5;
    std::string project_id{"0"};
    std::string profile_id{"0"};
    std::string task_id{"0"};
    std::string subtask_id{"0"};
};

std::string build_cloud_project_file_json(const BBL::PrintParams&    p,
                                          const CloudProjectFileOpts& opts);

} // namespace obn::print_job
