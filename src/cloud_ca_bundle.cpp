#include "obn/cloud_ca_bundle.hpp"

#include "obn/log.hpp"

#include <filesystem>
#include <fstream>
#include <system_error>

namespace obn::tls {

std::string ensure_cloud_ca_bundle_file(const std::string& config_dir)
{
    if (config_dir.empty()) return {};

    const std::filesystem::path dir(config_dir);
    const std::filesystem::path out = dir / "obn_cloud_ca.pem";
    const std::filesystem::path tmp = dir / "obn_cloud_ca.pem.tmp";

    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) {
            OBN_WARN("cloud_ca_bundle: failed to open %s for write",
                      tmp.string().c_str());
            return {};
        }
        f << kCloudCaBundlePem;
        if (!f) {
            OBN_WARN("cloud_ca_bundle: failed writing %s", tmp.string().c_str());
            return {};
        }
    }

    std::error_code ec;
    std::filesystem::rename(tmp, out, ec);
    if (ec) {
        OBN_WARN("cloud_ca_bundle: failed to install %s: %s",
                  out.string().c_str(), ec.message().c_str());
        std::filesystem::remove(tmp, ec);
        return {};
    }
    return out.string();
}

} // namespace obn::tls
