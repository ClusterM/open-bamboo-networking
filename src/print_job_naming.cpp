#include "obn/print_job.hpp"

#include "obn/config.hpp"

#include <algorithm>
#include <cstring>
#include <string>

namespace obn::print_job {

namespace {

std::string basename_of(const std::string& path)
{
    auto slash = path.find_last_of("/\\");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::string sanitize_remote_name(std::string name)
{
    while (!name.empty() && (name.front() == '.' || name.front() == '/' ||
                             name.front() == '\\' || name.front() == ' '))
        name.erase(name.begin());
    while (!name.empty() && (name.back() == ' ' || name.back() == '.'))
        name.pop_back();
    for (char& c : name) {
        unsigned char u = static_cast<unsigned char>(c);
        if (u < 0x20 || c == '/' || c == '\\') c = '_';
    }
    return name;
}

std::string strip_3mf_extension(std::string name)
{
    auto ends_with = [](const std::string& s, const char* suf) {
        std::size_t n = std::strlen(suf);
        return s.size() >= n &&
               std::equal(suf, suf + n, s.end() - n);
    };
    if (ends_with(name, ".gcode.3mf"))
        name.resize(name.size() - std::strlen(".gcode.3mf"));
    else if (ends_with(name, ".3mf"))
        name.resize(name.size() - std::strlen(".3mf"));
    return name;
}

} // namespace

std::string pick_remote_name(const BBL::PrintParams& p)
{
    std::string project = p.project_name;
    if (project.empty()) project = p.task_name;
    project = sanitize_remote_name(project);
    project = strip_3mf_extension(project);

    if (!project.empty()) return project + ".gcode.3mf";

    std::string name = sanitize_remote_name(basename_of(p.filename));
    if (!name.empty()) return name;
    return "print.gcode.3mf";
}

std::string dest_name_for_send_gcode(const BBL::PrintParams& p)
{
    if (p.project_name.empty()) return {};
    return sanitize_remote_name(p.project_name);
}

std::string strip_leading_slash(const std::string& s)
{
    if (!s.empty() && s.front() == '/') return s.substr(1);
    return s;
}

bool use_brtc_cache_upload(const BBL::PrintParams& p)
{
    // force_ftps: the printer's native :6000 file transport is unusable, so
    // fall back to the legacy FTPS (:990) upload path (url=ftp://…) regardless
    // of try_emmc_print — this is how LAN print worked before the BRTC :6000
    // protocol was added.
    if (obn::config::current().force_ftps) return false;
    // LAN print with eMMC cache: upload .3mf via TLS :6000, then MQTT url=brtc://emmc/…
    return p.try_emmc_print;
}

std::string build_brtc_emmc_url(const std::string& remote_name)
{
    return "brtc://emmc/" + strip_leading_slash(remote_name);
}

std::string build_file_url(const std::string& absolute_path)
{
    std::string norm = absolute_path;
    if (norm.empty() || norm.front() != '/') norm = "/" + norm;
    return "file://" + norm;
}

std::string build_ftp_url(const std::string& stored_path)
{
    return "ftp://" + strip_leading_slash(stored_path);
}

std::string build_ftp_remote_path(const BBL::PrintParams& p,
                                  const std::string&      remote_name)
{
    std::string folder = p.ftp_folder;
    while (!folder.empty() && (folder.front() == '/' || folder.front() == '\\'))
        folder.erase(folder.begin());
    while (!folder.empty() && (folder.back() == '/' || folder.back() == '\\'))
        folder.pop_back();
    if (folder.empty()) return "/" + strip_leading_slash(remote_name);
    return "/" + folder + "/" + strip_leading_slash(remote_name);
}

} // namespace obn::print_job
