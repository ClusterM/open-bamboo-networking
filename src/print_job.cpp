// LAN print pipeline.
//
// The flow we implement mirrors what Studio's original plugin does on the
// `connection_type == "lan"` branch of PrintJob::process():
//
//   1. Tell Studio we started (PrintingStageCreate).
//   2. Upload the .3mf to the printer (:6000 emmc cache when
//      try_emmc_print, else FTPS STOR on N7-class hardware).
//      Progress is streamed back as PrintingStageUpload with code=percent.
//   3. Publish a `{"print":{"command":"project_file",...}}` MQTT message
//      to the existing LanSession (PrintingStageSending).
//   4. Notify the user that we're done (PrintingStageFinished).
//
// We deliberately keep this synchronous: Studio invokes
// start_local_print() from its own PrintJob worker thread, so spawning
// yet another thread here would just complicate cancellation without
// buying us anything.

#include "obn/agent.hpp"
#include "obn/print_job.hpp"

#include "obn/bambu_networking.hpp"
#include "obn/config.hpp"
#include "obn/ftps.hpp"
#include "obn/log.hpp"
#include "obn/print_params_ftp_prefs.hpp"
#include "obn/tunnel_upload.hpp"

extern "C" {
#include "miniz/miniz.h"
#include "miniz/miniz_zip.h"
}

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <system_error>

#include <openssl/evp.h>

namespace obn::print_job {

// ---------------------------------------------------------------------------
// Plate normalisation (plate_0 → plate_1 rename + ZIP rewrite)
// ---------------------------------------------------------------------------

std::string to_print_basename(std::string fname)
{
    {
        auto slash = fname.find_last_of("/\\");
        if (slash != std::string::npos)
            fname = fname.substr(slash + 1);
    }
    if (fname.empty()) return "print.gcode.3mf";
    {
        const std::string needle = "plate_0";
        auto pos = fname.find(needle);
        if (pos != std::string::npos)
            fname.replace(pos, needle.size(), "plate_1");
    }
    auto ends_with_ci = [](const std::string& s, const char* suf) {
        std::size_t n = std::strlen(suf);
        if (s.size() < n) return false;
        for (std::size_t i = 0; i < n; ++i) {
            char a = s[s.size() - n + i];
            if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
            if (a != suf[i]) return false;
        }
        return true;
    };
    if (ends_with_ci(fname, ".gcode.3mf")) return fname;
    if (ends_with_ci(fname, ".3mf"))
        fname.erase(fname.size() - 4);
    return fname + ".gcode.3mf";
}

namespace {

// Increments the last _N decimal suffix in a ZIP entry name.
// "Metadata/plate_0.gcode" → "Metadata/plate_1.gcode"
// Returns nm unchanged when no such suffix is found.
static std::string bump_plate_index(const std::string& nm)
{
    auto under = nm.rfind('_');
    if (under == std::string::npos) return nm;
    std::size_t di = under + 1, de = di;
    while (de < nm.size() && std::isdigit(static_cast<unsigned char>(nm[de]))) ++de;
    if (de == di) return nm;
    int n;
    try {
        n = std::stoi(nm.substr(di, de - di));
    } catch (const std::exception&) {
        return nm; // out_of_range / invalid_argument: leave name untouched
    }
    return nm.substr(0, di) + std::to_string(n + 1) + nm.substr(de);
}

// Applies bump_plate_index to every Metadata/ path found in the config body,
// and increments numeric plater_id attribute values.
static std::string bump_config_body(std::string body)
{
    std::string out;
    out.reserve(body.size() + 32);
    for (std::size_t i = 0; i < body.size(); ) {
        auto pos = body.find("Metadata/", i);
        if (pos == std::string::npos) { out.append(body, i, std::string::npos); break; }
        out.append(body, i, pos - i);
        std::size_t end = pos + 9;
        while (end < body.size() && body[end] != '"' && body[end] != '<' &&
               body[end] != '>' && body[end] != '\n' && body[end] != ' ')
            ++end;
        out += bump_plate_index(body.substr(pos, end - pos));
        i = end;
    }
    const std::string kPV = "key=\"plater_id\" value=\"";
    for (std::size_t i = 0; (i = out.find(kPV, i)) != std::string::npos; ) {
        std::size_t vi = i + kPV.size(), ve = vi;
        while (ve < out.size() && std::isdigit(static_cast<unsigned char>(out[ve]))) ++ve;
        if (ve > vi) {
            try {
                int n = std::stoi(out.substr(vi, ve - vi));
                out.replace(vi, ve - vi, std::to_string(n + 1));
            } catch (const std::exception&) {
                // out_of_range / invalid_argument: leave value untouched
            }
        }
        i = ve;
    }
    return out;
}

} // namespace

bool normalise_to_plate_one(const std::string& in_path)
{
    // Only process .3mf archives; other file types (e.g. check_access_code.txt
    // sent by Studio to verify access codes) pass through unchanged.
    {
        auto dot = in_path.rfind('.');
        if (dot == std::string::npos) return true;
        std::string ext = in_path.substr(dot);
        for (auto& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (ext != ".3mf") return true;
    }

    mz_zip_archive in{};
    if (!mz_zip_reader_init_file(&in, in_path.c_str(), 0)) {
        OBN_ERROR("plate_norm: open failed: %s", in_path.c_str());
        return false;
    }

    bool has_plate_0 = false;
    bool has_plate_1 = false;
    const mz_uint n_in = mz_zip_reader_get_num_files(&in);
    char name[512];
    for (mz_uint i = 0; i < n_in && !(has_plate_0 && has_plate_1); ++i) {
        if (mz_zip_reader_get_filename(&in, i, name, sizeof(name)) == 0) continue;
        const std::string nm(name);
        if (nm.rfind("Metadata/plate_0", 0) == 0) has_plate_0 = true;
        if (nm.rfind("Metadata/plate_1", 0) == 0) has_plate_1 = true;
    }
    if (!has_plate_0) {
        mz_zip_reader_end(&in);
        return true;
    }
    if (has_plate_1) {
        mz_zip_reader_end(&in);
        return true;
    }

    const std::string out_path = in_path + ".normalised";
    std::error_code ec;
    std::filesystem::remove(out_path, ec);
    mz_zip_archive out{};
    if (!mz_zip_writer_init_file(&out, out_path.c_str(), 0)) {
        OBN_ERROR("plate_norm: create temp failed: %s", out_path.c_str());
        mz_zip_reader_end(&in);
        return false;
    }

    bool ok = true;
    int  n_renamed = 0;
    for (mz_uint i = 0; i < n_in && ok; ++i) {
        if (mz_zip_reader_get_filename(&in, i, name, sizeof(name)) == 0) continue;
        const std::string in_name(name);
        if (in_name == "Metadata/model_settings.config") {
            std::size_t sz = 0;
            void* data = mz_zip_reader_extract_to_heap(&in, i, &sz, 0);
            if (!data) { ok = false; break; }
            std::string body = bump_config_body(
                std::string(static_cast<const char*>(data), sz));
            mz_free(data);
            if (!mz_zip_writer_add_mem(&out, in_name.c_str(), body.data(), body.size(),
                                       MZ_DEFAULT_COMPRESSION)) {
                ok = false; break;
            }
        } else {
            const std::string out_name = bump_plate_index(in_name);
            if (out_name != in_name) {
                std::size_t sz = 0;
                void* data = mz_zip_reader_extract_to_heap(&in, i, &sz, 0);
                if (!data) { ok = false; break; }
                bool added = mz_zip_writer_add_mem(&out, out_name.c_str(), data, sz,
                                                   MZ_DEFAULT_COMPRESSION);
                mz_free(data);
                if (!added) { ok = false; break; }
                ++n_renamed;
            } else {
                if (!mz_zip_writer_add_from_zip_reader(&out, &in, i)) { ok = false; break; }
            }
        }
    }

    if (ok && !mz_zip_writer_finalize_archive(&out)) ok = false;
    if (!mz_zip_writer_end(&out))                    ok = false;
    mz_zip_reader_end(&in);

    if (!ok) {
        std::filesystem::remove(out_path, ec);
        OBN_ERROR("plate_norm: rewrite failed: %s", in_path.c_str());
        return false;
    }
    std::filesystem::rename(out_path, in_path, ec);
    if (ec) {
        OBN_ERROR("plate_norm: rename failed (%s): %s", ec.message().c_str(), in_path.c_str());
        std::filesystem::remove(out_path, ec);
        return false;
    }
    OBN_INFO("plate_norm: rewrote %s (entries renamed=%d)", in_path.c_str(), n_renamed);
    return true;
}

namespace {

// Strict-enough JSON string escaper. The printer firmware's parser is
// lenient but we still need to handle quotes/backslashes/control bytes
// so that, e.g., project names containing quotes don't break the wire
// format. UTF-8 bytes pass through unchanged.
std::string json_escape(const std::string& in)
{
    std::string out;
    out.reserve(in.size() + 2);
    out.push_back('"');
    for (unsigned char c : in) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    out.push_back('"');
    return out;
}

std::string to_bool(bool v) { return v ? "true" : "false"; }

// Returns a millisecond-resolution epoch timestamp string suitable for
// use as a sequence_id; matches the Bambu plugin's style.
std::string now_seq_id()
{
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::system_clock::now().time_since_epoch()).count();
    return std::to_string(ms);
}

// Studio's SelectMachineDialog::get_ams_mapping_result serializes the
// mapping into `params.ams_mapping` as a JSON array string, e.g.
// "[0,-1,-1,-1]". We must not wrap it again - the firmware's parser
// accepts the array as-is. When there's no AMS involved we leave the
// field as an empty array; that matches what the original plugin does
// and the firmware treats it the same as "not provided".
// Compute the uppercase-hex MD5 of a local file. Stock plugin parity:
// the Bambu firmware cross-checks the uploaded 3mf against `print.md5`,
// and the stock libbambu_networking.so always populates that field
// itself (Studio leaves `params.ftp_file_md5` empty). We mirror that
// so callers don't have to pre-hash. Returns empty on I/O failure —
// the firmware will then refuse the job rather than printing garbage.
std::string md5_of_file(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};

    std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)> ctx(
        EVP_MD_CTX_new(),
        [](EVP_MD_CTX* c){ if (c) EVP_MD_CTX_free(c); });
    if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_md5(), nullptr) != 1)
        return {};

    std::array<char, 64 * 1024> buf{};
    while (f.read(buf.data(), buf.size()) || f.gcount() > 0) {
        if (EVP_DigestUpdate(ctx.get(), buf.data(),
                             static_cast<size_t>(f.gcount())) != 1)
            return {};
    }

    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned      len = 0;
    if (EVP_DigestFinal_ex(ctx.get(), digest, &len) != 1) return {};

    static const char kHex[] = "0123456789ABCDEF";
    std::string hex(len * 2, '\0');
    for (unsigned i = 0; i < len; ++i) {
        hex[2 * i    ] = kHex[(digest[i] >> 4) & 0xF];
        hex[2 * i + 1] = kHex[ digest[i]       & 0xF];
    }
    return hex;
}

// Trim a single leading '/' from `s`. Stock plugin parity: when the
// upload landed in the FTPS root the `print.file` and `print.url`
// fields are bare names (`"foo.gcode.3mf"` and `"ftp://foo.gcode.3mf"`),
// not `"/foo.gcode.3mf"` / `"ftp:///foo..."`. Internally we keep the
// absolute path for FTP I/O — only the wire form drops the slash.
std::string strip_leading_slash(const std::string& s)
{
    if (!s.empty() && s.front() == '/') return s.substr(1);
    return s;
}

std::string format_ams_mapping(const std::string& mapping, bool use_ams)
{
    std::string s = mapping;
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' ||
                          s.front() == '\r' || s.front() == '\n')) s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' ||
                          s.back() == '\r' || s.back() == '\n')) s.pop_back();
    if (s.empty()) return use_ams ? "[0]" : "[]";
    if (s.front() == '[') return s; // already a JSON array
    std::string arr = "[";
    std::size_t start = 0;
    while (start <= s.size()) {
        std::size_t end = s.find(',', start);
        std::string tok = s.substr(start,
                                   end == std::string::npos ? std::string::npos : end - start);
        while (!tok.empty() && (tok.front() == ' ' || tok.front() == '\t')) tok.erase(tok.begin());
        while (!tok.empty() && (tok.back() == ' ' || tok.back() == '\t'))  tok.pop_back();
        if (!tok.empty()) {
            if (arr.size() > 1) arr += ',';
            arr += tok;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    arr += "]";
    return arr;
}

} // namespace

namespace {

// True when `path` starts with `prefix` followed by `/`. Used to detect
// `/sdcard/...` and `/usb/...` paths that we want to auto-correct
// against the printer's actual FTPS layout.
bool path_under(const std::string& path, const char* prefix)
{
    std::size_t plen = std::strlen(prefix);
    return path.size() > plen + 1 &&
           std::equal(path.begin(), path.begin() + plen, prefix) &&
           path[plen] == '/';
}

// Picks the actual storage prefix to STOR under by CWD-probing the
// printer. Mirrors the auto-detection in `abi_ft.cpp` (Send-to-Printer
// fastpath) and `BambuSource.cpp` (PrinterFileSystem CTRL bridge):
// firmware on A1 / A1 mini / P2S exposes the storage mount either as
// `/sdcard`, `/usb`, or as the FTPS root itself - we pick whichever
// answers and rewrite the directory portion of `remote_path` to match.
//
// Probe order keeps the caller-supplied prefix first so X1 / P1 (where
// `/sdcard` really exists) take the fast path with no extra round-trip
// cost beyond the CWD itself. If every probe 550s we leave the path
// untouched so the original STOR error reaches the upper layer with
// the path the caller asked for.
std::string adjust_storage_path(obn::ftps::Client& cli,
                                const std::string& remote_path)
{
    const bool under_sdcard = path_under(remote_path, "/sdcard");
    const bool under_usb    = path_under(remote_path, "/usb");
    if (!under_sdcard && !under_usb) return remote_path;

    auto slash = remote_path.find('/', 1);
    std::string filename = (slash == std::string::npos)
                               ? std::string{}
                               : remote_path.substr(slash + 1);
    if (filename.empty()) return remote_path;

    static const std::array<const char*, 3> kCandidatesSdcard = {"/sdcard", "/usb", "/"};
    static const std::array<const char*, 3> kCandidatesUsb    = {"/usb", "/sdcard", "/"};
    const auto& candidates = under_sdcard ? kCandidatesSdcard : kCandidatesUsb;

    for (const char* cand : candidates) {
        if (!cli.cwd(cand).empty()) continue;
        std::string adjusted =
            (std::strcmp(cand, "/") == 0) ? ("/" + filename)
                                          : (std::string{cand} + "/" + filename);
        if (adjusted != remote_path) {
            OBN_DEBUG("print_job: storage probe rewrote '%s' -> '%s'",
                     remote_path.c_str(), adjusted.c_str());
        }
        return adjusted;
    }
    OBN_WARN("print_job: storage probe found neither /sdcard, /usb nor /; "
             "falling back to the caller-supplied path '%s'",
             remote_path.c_str());
    return remote_path;
}

} // namespace

int ftp_upload(const BBL::PrintParams&    p,
               const std::string&         remote_path,
               const std::string&         ca_file,
               BBL::OnUpdateStatusFn      update_fn,
               BBL::WasCancelledFn        cancel_fn,
               int                        err_code_on_failure,
               std::uint64_t&             total_bytes_out,
               std::string*               selected_remote_path)
{
    std::error_code ec;
    auto sz = std::filesystem::file_size(p.filename, ec);
    if (ec) {
        OBN_ERROR("print_job: stat %s failed: %s", p.filename.c_str(), ec.message().c_str());
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_FILE_NOT_EXIST,
                                 "file not found");
        return BAMBU_NETWORK_ERR_FILE_NOT_EXIST;
    }
    total_bytes_out = sz;
    constexpr std::uint64_t kOneGB = 1ull * 1024 * 1024 * 1024;
    if (sz > kOneGB) {
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_PRINT_LP_FILE_OVER_SIZE,
                                 "file over 1 GB");
        return BAMBU_NETWORK_ERR_PRINT_LP_FILE_OVER_SIZE;
    }

    obn::ftps::ConnectConfig cfg;
    cfg.host     = p.dev_ip;
    cfg.port     = p.use_ssl_for_ftp ? 990 : 21;
    cfg.username = p.username.empty() ? std::string{"bblp"} : p.username;
    cfg.password = p.password;
    cfg.ca_file              = ca_file;
    cfg.tls_verify_hostname  = p.dev_id;
    cfg.use_tls              = p.use_ssl_for_ftp;

    obn::ftps::Client cli;
    if (std::string err = cli.connect(cfg); !err.empty()) {
        OBN_ERROR("print_job: ftps connect %s: %s", p.dev_ip.c_str(), err.c_str());
        if (update_fn) update_fn(BBL::PrintingStageERROR, err_code_on_failure, err);
        return err_code_on_failure;
    }

    std::string effective_path = adjust_storage_path(cli, remote_path);
    if (selected_remote_path) *selected_remote_path = effective_path;

    auto progress = [&](std::uint64_t sent, std::uint64_t total) {
        if (cancel_fn && cancel_fn()) return false;
        if (update_fn) {
            int pct = total > 0 ? static_cast<int>(sent * 100 / total) : 0;
            if (pct > 100) pct = 100;
            update_fn(BBL::PrintingStageUpload, pct,
                      std::to_string(pct) + "%");
        }
        return true;
    };

    std::string err = cli.stor(p.filename, effective_path, progress);
    cli.quit();
    if (!err.empty()) {
        OBN_ERROR("print_job: STOR %s failed: %s", effective_path.c_str(), err.c_str());
        int code = err == "upload cancelled" ? BAMBU_NETWORK_ERR_CANCELED
                                             : err_code_on_failure;
        if (update_fn) update_fn(BBL::PrintingStageERROR, code, err);
        return code;
    }
    return 0;
}

namespace {

// Shared body for both the LAN (`build_project_file_json`) and cloud
// (`build_cloud_project_file_json`) variants of the `project_file` MQTT
// command. The two variants differ only in two slots:
//   * the "param"/"param_enc" field (plaintext plate path vs RSA-encrypted)
//   * the "url"/"url_enc"     field (plaintext fetch URL vs RSA-encrypted)
// The caller passes those two slots fully formed (key + value, including the
// leading comma) so the rest of the payload — and its exact field ordering —
// stays byte-identical between the two. `Opts` is duck-typed: both
// ProjectFileOpts and CloudProjectFileOpts expose project_id / profile_id /
// task_id / subtask_id / file_path / md5.
template <typename Opts>
std::string build_project_file_json_impl(const BBL::PrintParams& p,
                                         const Opts&             opts,
                                         const std::string&      param_field,
                                         const std::string&      url_field)
{
    std::string subtask     = p.project_name.empty() ? p.task_name : p.project_name;
    std::string bed_type    = p.task_bed_type.empty() ? "auto" : p.task_bed_type;
    std::string ams_mapping = format_ams_mapping(p.ams_mapping, p.task_use_ams);

    std::ostringstream os;
    os << "{\"print\":{";
    os << "\"sequence_id\":" << json_escape(now_seq_id());
    os << ",\"command\":\"project_file\"";
    os << param_field;
    os << ",\"project_id\":" << json_escape(opts.project_id);
    os << ",\"profile_id\":" << json_escape(opts.profile_id);
    os << ",\"task_id\":"    << json_escape(opts.task_id);
    os << ",\"subtask_id\":" << json_escape(opts.subtask_id);
    os << ",\"subtask_name\":" << json_escape(subtask);
    os << ",\"file\":" << json_escape(strip_leading_slash(opts.file_path));
    os << url_field;
    os << ",\"md5\":"  << json_escape(opts.md5);
    os << ",\"bed_type\":" << json_escape(bed_type);
    os << ",\"bed_leveling\":"      << to_bool(p.task_bed_leveling);
    os << ",\"flow_cali\":"         << to_bool(p.task_flow_cali);
    os << ",\"vibration_cali\":"    << to_bool(p.task_vibration_cali);
    os << ",\"layer_inspect\":"     << to_bool(p.task_layer_inspect);
    os << ",\"timelapse\":"         << to_bool(p.task_record_timelapse);
    os << ",\"use_ams\":"           << to_bool(p.task_use_ams);
    os << ",\"ams_mapping\":"       << ams_mapping;

    // Field name mapping (Studio C++ -> firmware JSON) is intentionally
    // asymmetric in the upstream; preserved verbatim here so wireshark
    // diffs against the stock plugin stay clean:
    //   PrintParams::ams_mapping2              -> "ams_mapping2"
    //   PrintParams::auto_bed_leveling         -> "auto_bed_leveling"
    //   PrintParams::auto_offset_cali          -> "nozzle_offset_cali"
    //   PrintParams::extruder_cali_manual_mode -> "extrude_cali_manual_mode"
    // Stock plugin parity: `ams_mapping2` is emitted **unconditionally**
    // — even when AMS isn't in use the field appears as an empty array
    // (`"ams_mapping2": []`). Confirmed via `tools/plugin_runner` against
    // the stock libbambu_networking.so on N7 (see NETWORK_PLUGIN.md
    // §6.8.2 "Per-PrintParams-field mapping" matrix). We feed it
    // verbatim from `params.ams_mapping2` (a JSON-array string from
    // SelectMachineDialog::get_ams_mapping_result), defaulting to `[]`
    // when the caller didn't populate it.
    if (p.ams_mapping2.empty())
        os << ",\"ams_mapping2\":[]";
    else
        os << ",\"ams_mapping2\":" << p.ams_mapping2;
    if (!p.nozzle_mapping.empty()) {
        // It's already a JSON array
        os << ",\"nozzle_mapping\":" << p.nozzle_mapping;
    }
    os << ",\"auto_bed_leveling\":"  << p.auto_bed_leveling;
    os << ",\"nozzle_offset_cali\":" << p.auto_offset_cali;
    #if ABI_VERSION >= 0x020400
        // Studio leaves -1 when set_print_config() was never called (e.g.
        // headless / SDK paths). Skip the field in that case rather than
        // forwarding the sentinel; the firmware then keeps its default PA mode.
        if (p.extruder_cali_manual_mode >= 0) {
            os << ",\"extrude_cali_manual_mode\":" << p.extruder_cali_manual_mode;
        }
    #endif

    // `cfg` is a string-encoded bitmask the stock plugin builds from
    // PrintParams flags that don't have a dedicated MQTT field. So far
    // only one bit is known:
    //   bit 2 (value 4) = use internal storage for timelapse.
    // Driven by `task_timelapse_use_internal` (added to PrintParams in
    // ABI 02.05.03). All other bits stay 0 in every captured stock
    // frame; if more flags surface later, OR them into `cfg_bits` here.
    // See NETWORK_PLUGIN.md §6.8.2.
    //
    // Wire-level parity: the cross-ABI `tools/plugin_runner` matrix
    // (02.05.00 -> 02.06.01) showed the stock plugin emits `cfg` in
    // `project_file` for **every** ABI we tested — older builds simply
    // hardcode `"0"` because the underlying field doesn't exist yet.
    // So we emit unconditionally and gate only the *value* on the ABI
    // bound that introduced `task_timelapse_use_internal`.
    int cfg_bits = 0;
#if ABI_VERSION >= 0x020503
    if (p.task_timelapse_use_internal &&
        !obn::config::current().force_timelapse_external)
        cfg_bits |= 4;
#endif
    os << ",\"cfg\":\"" << cfg_bits << "\"";

    // `extrude_cali_flag` is the wire mirror of `auto_flow_cali`:
    // confirmed via `tools/plugin_runner` overlay (`auto_flow_cali=1`
    // flipped the field from 0 to 1 across both 02.05.00 and 02.06.01).
    // Studio populates this from the user's "Flow dynamics calibration"
    // dropdown; the firmware uses it to short-circuit redundant PA
    // cali runs. See NETWORK_PLUGIN.md §6.8.2.
    os << ",\"extrude_cali_flag\":" << p.auto_flow_cali;

    os << "}}";
    return os.str();
}

} // namespace

std::string build_project_file_json(const BBL::PrintParams& p,
                                    const ProjectFileOpts&  opts)
{
    std::string plate_param = "Metadata/plate_" +
                              std::to_string(p.plate_index <= 0 ? 1 : p.plate_index) +
                              ".gcode";
    return build_project_file_json_impl(
        p, opts,
        ",\"param\":" + json_escape(plate_param),
        ",\"url\":"   + json_escape(opts.url));
}

// Cloud-print variant of build_project_file_json.
//
// Identical to the LAN variant except:
//   * "param" is replaced by "param_enc" (RSA-PKCS#1 v1.5 encrypted,
//     base64-encoded).  The plaintext would be "Metadata/plate_N.gcode".
//   * "url"   is replaced by "url_enc"   (RSA-PKCS#1 v1.5 encrypted,
//     base64-encoded).  The plaintext is the raw fetch URL (ftp:///, brtc://,
//     or presigned HTTPS).
//
// Both encrypted values must be pre-computed by the caller (see
// rsa_pkcs1v15_encrypt_b64 in cloud_print.cpp) using the printer's RSA
// public key extracted from its TLS leaf certificate.
std::string build_cloud_project_file_json(const BBL::PrintParams&    p,
                                          const CloudProjectFileOpts& opts)
{
    return build_project_file_json_impl(
        p, opts,
        ",\"param_enc\":" + json_escape(opts.param_enc),
        ",\"url_enc\":"   + json_escape(opts.url_enc));
}

} // namespace obn::print_job

namespace obn {

int Agent::run_local_print_job(const BBL::PrintParams&   params,
                               BBL::OnUpdateStatusFn     update_fn,
                               BBL::WasCancelledFn       cancel_fn)
{
    OBN_INFO("local_print dev=%s ip=%s plate=%d file=%s project=%s use_ams=%d",
             params.dev_id.c_str(), params.dev_ip.c_str(), params.plate_index,
             params.filename.c_str(), params.project_name.c_str(),
             params.task_use_ams ? 1 : 0);

    print_params_set_use_ssl_for_ftp(params.use_ssl_for_ftp);

    if (params.dev_ip.empty() || params.password.empty()) {
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_CONNECTION_TO_PRINTER_FAILED,
                                 "no dev_ip/access_code");
        return BAMBU_NETWORK_ERR_CONNECTION_TO_PRINTER_FAILED;
    }
    if (params.filename.empty()) {
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_FILE_NOT_EXIST,
                                 "empty filename");
        return BAMBU_NETWORK_ERR_FILE_NOT_EXIST;
    }

    if (update_fn) update_fn(BBL::PrintingStageCreate, 0, "");
    if (cancel_fn && cancel_fn()) return BAMBU_NETWORK_ERR_CANCELED;

    // Protect the original .3mf: normalise a temporary copy, upload it,
    // then delete the copy. The original file is never modified.
    const std::string upload_path = params.filename + ".upload";
    {
        std::error_code cec;
        std::filesystem::copy_file(params.filename, upload_path,
                                   std::filesystem::copy_options::overwrite_existing, cec);
        if (cec) {
            OBN_ERROR("local_print: copy %s -> %s failed: %s",
                      params.filename.c_str(), upload_path.c_str(), cec.message().c_str());
            if (update_fn) update_fn(BBL::PrintingStageERROR,
                                     BAMBU_NETWORK_ERR_PRINT_LP_UPLOAD_FTP_FAILED,
                                     "failed to create upload copy");
            return BAMBU_NETWORK_ERR_PRINT_LP_UPLOAD_FTP_FAILED;
        }
    }
    auto upload_copy_guard = [&upload_path]() {
        std::error_code ec;
        std::filesystem::remove(upload_path, ec);
    };

    if (!print_job::normalise_to_plate_one(upload_path)) {
        upload_copy_guard();
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_PRINT_LP_UPLOAD_FTP_FAILED,
                                 "plate normalisation failed");
        return BAMBU_NETWORK_ERR_PRINT_LP_UPLOAD_FTP_FAILED;
    }

    BBL::PrintParams upload_params = params;
    upload_params.filename = upload_path;

    // Stock plugin parity: when `ftp_folder` is empty (which it always
    // is — Studio never assigns m_ftp_folder anywhere in the public
    // tree, see `3rd_party/BambuStudio/src/slic3r/GUI/Jobs/PrintJob.cpp`)
    // the stock plugin uploads the 3mf to the **FTPS root**, not to
    // `/cache/`. Confirmed by sniffing a real LAN print on N7 with the
    // stock libbambu_networking.so loaded via `tools/plugin_runner`:
    // the published `project_file` carries `"file":
    // "<project>.gcode.3mf"` (no `/cache/` prefix) and the firmware
    // happily accepts it. The `/cache/` path was an earlier guess that
    // matched no observed traffic; we keep `ftp_folder` honored
    // verbatim so a downstream caller can still target a specific
    // directory if needed (e.g. `"sdcard/"` for printers whose
    // firmware insists on it). See NETWORK_PLUGIN.md §6.8.2.
    std::string remote_folder = params.ftp_folder;
    if (!remote_folder.empty() && remote_folder.back() != '/') remote_folder += '/';
    if (!remote_folder.empty() && remote_folder.front() == '/') remote_folder.erase(0, 1);
    // Normalise plate_0→plate_1 in the remote filename so the STOR target
    // and the project_file url= field reference plate_1, matching the
    // rewritten archive entries.
    std::string remote_name = print_job::to_print_basename(
                                  print_job::pick_remote_name(params));
    std::string remote_path = "/" + remote_folder + remote_name;

    std::string ca_file = bambu_ca_bundle_path();

    std::uint64_t total = 0;
    std::string   stored_path;
    int rc = 0;

    const bool brtc = print_job::use_brtc_cache_upload(params);
    OBN_INFO("local_print: upload path=%s (try_emmc_print=%d, force_ftps=%d)",
             brtc ? "brtc :6000" : "ftps :990",
             params.try_emmc_print ? 1 : 0,
             obn::config::current().force_ftps ? 1 : 0);

    if (brtc) {
        obn::tunnel_upload::ConnectParams cp =
            obn::tunnel_upload::connect_params_from_print(
                params.dev_ip, params.dev_id, params.password);
        obn::tunnel_upload::UploadRequest ureq;
        ureq.local_path   = upload_path;
        ureq.dest_storage = "emmc";
        ureq.dest_name    = remote_name;

        obn::tunnel_upload::UploadCallbacks cb;
        cb.cancelled = [&]() {
            return cancel_fn && cancel_fn();
        };
        cb.progress = [&](int pct) {
            if (update_fn) update_fn(BBL::PrintingStageUpload, pct, "");
        };

        obn::tunnel_upload::UploadOutcome outcome;
        rc = obn::tunnel_upload::upload_file(
            cp, ureq, cb, &outcome,
            BAMBU_NETWORK_ERR_PRINT_LP_UPLOAD_FTP_FAILED);
        if (rc != 0) { upload_copy_guard(); return rc; }
        total = outcome.bytes;
        stored_path = remote_name;
        OBN_INFO("local_print: brtc upload %llu bytes to emmc/%s",
                 static_cast<unsigned long long>(total), remote_name.c_str());
    } else {
        rc = print_job::ftp_upload(upload_params, remote_path, ca_file, update_fn, cancel_fn,
                                   BAMBU_NETWORK_ERR_PRINT_LP_UPLOAD_FTP_FAILED, total,
                                   &stored_path);
        if (rc != 0) { upload_copy_guard(); return rc; }
    }

    upload_copy_guard();

    if (cancel_fn && cancel_fn()) {
        if (update_fn) update_fn(BBL::PrintingStageERROR, BAMBU_NETWORK_ERR_CANCELED, "cancelled");
        return BAMBU_NETWORK_ERR_CANCELED;
    }

    if (update_fn) update_fn(BBL::PrintingStageSending, 0, "");

    print_job::ProjectFileOpts opts;
    opts.file_path = stored_path;
    if (print_job::use_brtc_cache_upload(params)) {
        opts.url = print_job::build_brtc_emmc_url(remote_name);
    } else {
        opts.url = print_job::build_ftp_url(stored_path);
    }
    // Stock plugin parity: it always populates `print.md5` itself —
    // Studio's PrintJob never sets `params.ftp_file_md5`. Hash the
    // local 3mf if the caller didn't pre-compute one. Matters because
    // the firmware refuses the job on MD5 mismatch (and an empty
    // string trivially mismatches).
    opts.md5 = params.ftp_file_md5;
    if (opts.md5.empty()) {
        opts.md5 = print_job::md5_of_file(params.filename);
        if (opts.md5.empty()) {
            OBN_WARN("local_print: failed to MD5 %s — sending empty md5; "
                     "the printer will likely reject the job",
                     params.filename.c_str());
        }
    }
    std::string json = print_job::build_project_file_json(params, opts);
    OBN_DEBUG("local_print mqtt: %s", json.c_str());

    int pub = send_message_to_printer(params.dev_id, json, /*qos=*/0);
    if (pub != 0) {
        OBN_ERROR("local_print: publish project_file failed rc=%d", pub);
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_PRINT_LP_PUBLISH_MSG_FAILED,
                                 "MQTT publish failed");
        return BAMBU_NETWORK_ERR_PRINT_LP_PUBLISH_MSG_FAILED;
    }

    // Studio shows the countdown message before navigating to the device
    // page. "3" below is the number of seconds it displays; matches Bambu
    // plugin behaviour.
    if (update_fn) update_fn(BBL::PrintingStageFinished, 0, "3");
    OBN_INFO("local_print dev=%s: queued for printing (uploaded %llu bytes, plate=%d)",
             params.dev_id.c_str(), static_cast<unsigned long long>(total),
             params.plate_index);
    return 0;
}

int Agent::run_sdcard_print_job(const BBL::PrintParams& params,
                                BBL::OnUpdateStatusFn   update_fn,
                                BBL::WasCancelledFn     cancel_fn)
{
    // The file is already on the printer (we listed it via the
    // PrinterFileSystem CTRL channel); all we do is tell the printer
    // to start a print from that path. Studio routes this through
    // "cloud" by design, but Developer Mode printers have no cloud
    // route - the command has to go over LAN MQTT.
    OBN_INFO("sdcard_print dev=%s ip=%s dst_file=%s plate=%d use_ams=%d",
             params.dev_id.c_str(), params.dev_ip.c_str(),
             params.dst_file.c_str(), params.plate_index,
             params.task_use_ams ? 1 : 0);

    print_params_set_use_ssl_for_ftp(params.use_ssl_for_ftp);

    if (params.dev_id.empty()) {
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_CONNECTION_TO_PRINTER_FAILED,
                                 "no dev_id");
        return BAMBU_NETWORK_ERR_CONNECTION_TO_PRINTER_FAILED;
    }
    if (params.dst_file.empty()) {
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_FILE_NOT_EXIST,
                                 "no dst_file");
        return BAMBU_NETWORK_ERR_FILE_NOT_EXIST;
    }
    if (cancel_fn && cancel_fn()) return BAMBU_NETWORK_ERR_CANCELED;

    if (update_fn) update_fn(BBL::PrintingStageCreate, 0, "");

    // Studio's MediaFilePanel already stripped one leading slash when
    // building dst_file; re-normalise so the printer sees an absolute
    // path (it'll also accept a relative one, but this matches the
    // format FILE_DOWNLOAD traffic uses).
    std::string remote_path = params.dst_file;
    if (remote_path.empty() || remote_path.front() != '/')
        remote_path = "/" + remote_path;

    print_job::ProjectFileOpts opts;
    opts.file_path  = remote_path;
    opts.url        = print_job::build_file_url(remote_path);
    opts.md5        = "";  // not known for a pre-existing file on storage
    opts.project_id = "0";
    opts.profile_id = "0";
    opts.task_id    = "0";
    opts.subtask_id = "0";

    std::string json = print_job::build_project_file_json(params, opts);
    OBN_DEBUG("sdcard_print mqtt: %s", json.c_str());

    if (update_fn) update_fn(BBL::PrintingStageSending, 0, "");

    int pub = send_message_to_printer(params.dev_id, json, /*qos=*/0);
    if (pub != 0) {
        OBN_ERROR("sdcard_print: publish project_file failed rc=%d (no LAN session?)", pub);
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_PRINT_LP_PUBLISH_MSG_FAILED,
                                 "MQTT publish failed (no LAN session)");
        return BAMBU_NETWORK_ERR_PRINT_LP_PUBLISH_MSG_FAILED;
    }

    if (update_fn) update_fn(BBL::PrintingStageFinished, 0, "3");
    OBN_INFO("sdcard_print dev=%s: queued for printing (file=%s, plate=%d)",
             params.dev_id.c_str(), remote_path.c_str(), params.plate_index);
    return 0;
}

int Agent::run_send_gcode_to_sdcard(const BBL::PrintParams& params,
                                    BBL::OnUpdateStatusFn   update_fn,
                                    BBL::WasCancelledFn     cancel_fn)
{
    OBN_INFO("send_gcode_to_sdcard dev=%s ip=%s file=%s",
             params.dev_id.c_str(), params.dev_ip.c_str(), params.filename.c_str());

    print_params_set_use_ssl_for_ftp(params.use_ssl_for_ftp);

    if (params.dev_ip.empty() || params.password.empty()) {
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_CONNECTION_TO_PRINTER_FAILED,
                                 "no dev_ip/access_code");
        return BAMBU_NETWORK_ERR_CONNECTION_TO_PRINTER_FAILED;
    }

    if (update_fn) update_fn(BBL::PrintingStageCreate, 0, "");

    // Protect the original file: normalise a temporary copy, upload it,
    // then delete the copy.
    const std::string upload_path = params.filename.empty()
                                    ? std::string{} : params.filename + ".upload";
    auto sg_upload_guard = [&upload_path]() {
        if (upload_path.empty()) return;
        std::error_code ec;
        std::filesystem::remove(upload_path, ec);
    };

    if (!params.filename.empty()) {
        std::error_code cec;
        std::filesystem::copy_file(params.filename, upload_path,
                                   std::filesystem::copy_options::overwrite_existing, cec);
        if (cec) {
            OBN_ERROR("send_gcode: copy %s -> %s failed: %s",
                      params.filename.c_str(), upload_path.c_str(), cec.message().c_str());
            if (update_fn) update_fn(BBL::PrintingStageERROR,
                                     BAMBU_NETWORK_ERR_PRINT_SG_UPLOAD_FTP_FAILED,
                                     "failed to create upload copy");
            return BAMBU_NETWORK_ERR_PRINT_SG_UPLOAD_FTP_FAILED;
        }
        if (!print_job::normalise_to_plate_one(upload_path)) {
            sg_upload_guard();
            if (update_fn) update_fn(BBL::PrintingStageERROR,
                                     BAMBU_NETWORK_ERR_PRINT_SG_UPLOAD_FTP_FAILED,
                                     "plate normalisation failed");
            return BAMBU_NETWORK_ERR_PRINT_SG_UPLOAD_FTP_FAILED;
        }
    }

    BBL::PrintParams upload_params = params;
    if (!upload_path.empty()) upload_params.filename = upload_path;

    std::string remote_name = print_job::dest_name_for_send_gcode(params);
    if (remote_name.empty()) {
        sg_upload_guard();
        if (update_fn) update_fn(BBL::PrintingStageERROR,
                                 BAMBU_NETWORK_ERR_PRINT_SG_UPLOAD_FTP_FAILED,
                                 "empty project_name");
        return BAMBU_NETWORK_ERR_PRINT_SG_UPLOAD_FTP_FAILED;
    }

    std::string remote_folder = params.ftp_folder;
    if (!remote_folder.empty() && remote_folder.back() != '/') remote_folder += '/';
    if (!remote_folder.empty() && remote_folder.front() == '/') remote_folder.erase(0, 1);
    std::string remote_path = "/" + remote_folder + remote_name;

    std::string ca_file = bambu_ca_bundle_path();
    std::uint64_t total = 0;
    int rc = print_job::ftp_upload(upload_params, remote_path, ca_file, update_fn, cancel_fn,
                                   BAMBU_NETWORK_ERR_PRINT_SG_UPLOAD_FTP_FAILED, total);
    sg_upload_guard();
    if (rc != 0) return rc;
    if (update_fn) update_fn(BBL::PrintingStageFinished, 0, "3");
    return 0;
}

} // namespace obn
