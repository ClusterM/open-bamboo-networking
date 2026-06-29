//
// Abstract interface to the proprietary `libBambuSource` library — same
// shape as BambuStudio-bridge/src/bambu_bridge/BambuSourceHandle.hpp but
// declared abstract so the OSS camera module compiles + tests without the
// proprietary library being present.
//
// Production path (host runs the slicer + has libBambuSource on disk):
//   the host instantiates a concrete subclass that dlopens libBambuSource,
//   then injects a `shared_ptr<BambuSourceHandle>` into LanCameraSource /
//   CloudCameraSource via `attach_source_handle(...)`. The OSS sources then
//   stream H.264 via the proprietary library.
//
// OSS-only path (no proprietary library):
//   no handle attached -> LanCameraSource::open() / CloudCameraSource::open()
//   fail fast and the factory falls back to JpegCameraSource (A1/P1) or
//   reports source-unavailable (X1/H2). JpegCameraSource needs no handle.
//
// Test path:
//   tests subclass BambuSourceHandle and override the virtuals (using
//   set_library_ready_for_test) to script the byte stream without ever
//   touching a real .so.

#ifndef BAMBU_NET_CAMERA_BAMBU_SOURCE_HANDLE_HPP
#define BAMBU_NET_CAMERA_BAMBU_SOURCE_HANDLE_HPP

#include <cstdint>
#include <memory>
#include <string>

namespace bambu_net {
namespace camera {

class BambuSourceHandle {
public:
    BambuSourceHandle()          = default;
    virtual ~BambuSourceHandle() = default;

    BambuSourceHandle(const BambuSourceHandle&)            = delete;
    BambuSourceHandle& operator=(const BambuSourceHandle&) = delete;

    // dlopen the library + resolve every export + call `Bambu_Init`.
    // Idempotent. Default impl is a no-op returning false (no proprietary
    // library); a host integration can subclass and override.
    virtual bool init() { return false; }
    virtual bool library_ready() const { return m_ready; }

    // 1:1 wrappers over the proprietary C ABI.
    // Default impls return -1 (library not loaded) — subclasses MUST
    // override when an actual library is present.
    virtual int  bambu_create(void** out_tunnel, const std::string& url) {
        (void)out_tunnel; (void)url; return -1;
    }
    virtual void bambu_destroy(void* tunnel) { (void)tunnel; }
    virtual int  bambu_open(void* tunnel) { (void)tunnel; return -1; }
    virtual void bambu_close(void* tunnel) { (void)tunnel; }
    virtual int  bambu_start_stream(void* tunnel, bool video) {
        (void)tunnel; (void)video; return -1;
    }
    virtual int  bambu_start_stream_ex(void* tunnel, int type) {
        (void)tunnel; (void)type; return -1;
    }
    virtual int  bambu_send_message(void* tunnel, int ctrl,
                                    const char* data, int len) {
        (void)tunnel; (void)ctrl; (void)data; (void)len; return -1;
    }

    typedef void (*Logger)(void* context, int level, const char* msg);
    virtual void bambu_set_logger(void* tunnel, Logger logger, void* ctx) {
        (void)tunnel; (void)logger; (void)ctx;
    }
    virtual void bambu_free_log_msg(const char* msg) { (void)msg; }
    virtual std::string bambu_get_last_error_msg() { return {}; }

    virtual int  bambu_get_stream_count(void* tunnel) {
        (void)tunnel; return 0;
    }
    virtual int  bambu_get_stream_info(void* tunnel, int index, void* info_out) {
        (void)tunnel; (void)index; (void)info_out; return -1;
    }
    virtual int  bambu_read_sample(void* tunnel, void* sample_out) {
        (void)tunnel; (void)sample_out; return -1;
    }

protected:
    void set_library_ready_for_test(bool ready) { m_ready = ready; }

private:
    bool m_ready = false;
};

// Proprietary plugin handle — same indirection as BambuSourceHandle for
// the `bambu_networking` C++-by-value ABI. CloudCameraSource needs only
// `get_camera_url` and a readiness probe; the rest of the surface is
// available for host integrations.
class BambuNetworkingPluginHandle {
public:
    BambuNetworkingPluginHandle()          = default;
    virtual ~BambuNetworkingPluginHandle() = default;

    BambuNetworkingPluginHandle(const BambuNetworkingPluginHandle&)            = delete;
    BambuNetworkingPluginHandle& operator=(const BambuNetworkingPluginHandle&) = delete;

    virtual bool agent_ready() const { return false; }

    // Resolve a camera URL. Default impl returns -1 (no agent). Host
    // subclass calls the proprietary `bambu_network_get_camera_url`
    // export and waits up to `timeout_ms` for the callback.
    virtual int  get_camera_url(const std::string& ask,
                                std::string* out_url, int timeout_ms) {
        (void)ask; (void)out_url; (void)timeout_ms; return -1;
    }
};

}  // namespace camera
}  // namespace bambu_net

#endif  // BAMBU_NET_CAMERA_BAMBU_SOURCE_HANDLE_HPP
