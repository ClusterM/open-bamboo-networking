// OssAgoraBambuSource — BambuSourceHandle backed by OssAgoraEngine + OssAgoraSignaling.

#pragma once

#include "../BambuSourceHandle.hpp"
#include "OssAgoraEngine.hpp"
#include "OssAgoraSignaling.hpp"
#include "../AgoraUrl.hpp"   // for AgoraUrl / AgoraRegion parsing

#include <memory>
#include <string>
#include <vector>

namespace bambu_net {
namespace camera {
namespace oss_agora {

class OssAgoraBambuSource : public BambuSourceHandle {
public:
    OssAgoraBambuSource();
    ~OssAgoraBambuSource() override;

    void set_test_mode(bool enabled);

    bool init() override;
    bool library_ready() const override;

    int  bambu_create(void** out_tunnel, const std::string& url) override;
    void bambu_destroy(void* tunnel) override;
    int  bambu_open(void* tunnel) override;
    void bambu_close(void* tunnel) override;
    int  bambu_start_stream(void* tunnel, bool video) override;
    int  bambu_start_stream_ex(void* tunnel, int type) override;
    int  bambu_send_message(void* tunnel, int ctrl,
                             const char* data, int len) override;
    void bambu_set_logger(void* tunnel, Logger logger, void* ctx) override;
    std::string bambu_get_last_error_msg() override;
    int  bambu_get_stream_count(void* tunnel) override;
    int  bambu_get_stream_info(void* tunnel, int index, void* info_out) override;
    int  bambu_read_sample(void* tunnel, void* sample_out) override;

private:
    bool m_test_mode = false;
};

} // namespace oss_agora
} // namespace camera
} // namespace bambu_net
