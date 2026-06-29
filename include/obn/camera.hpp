#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace obn::camera {

// Printer models that support native JPEG streaming on port 6000.
bool is_jpeg_model(const std::string& model);

// Configuration for the port-6000 TLS/MJPEG path (A1/P1/N1/N2S/C13/C14).
struct JpegConfig {
    std::string dev_id;
    std::string ip;
    std::string access_code;
    int port               = 6000;
    int connect_timeout_ms = 5000;
    int read_timeout_ms    = 10000;
};

// Full camera specification.  Fields used depend on source type:
//   - camera_url non-empty → Agora or TUTK relay (H.264)
//   - camera_url empty + is_jpeg_model(model) + !lan_ip.empty() → JPEG
struct CameraSpec {
    std::string dev_id;
    std::string camera_url;    // bambu:///agora?... or bambu:///tutk?... or empty
    std::string model;         // printer model string (for JPEG fallback)
    std::string lan_ip;        // printer LAN IP (for JPEG fallback)
    std::string access_code;   // printer access code
};

// Start a camera session.
// Returns the local MJPEG URL (http://127.0.0.1:PORT/cam) for JPEG cameras,
// the original camera_url for relay/cloud cameras, or empty string on failure.
std::string start_camera(const CameraSpec& spec);

// Backward-compat overload: wraps JpegConfig into a CameraSpec.
std::string start_camera(const JpegConfig& cfg);

// Stops the camera session for this dev_id.
void stop_camera(const std::string& dev_id);

// Returns the current stream URL for dev_id, or empty if not active.
std::string get_url(const std::string& dev_id);

} // namespace obn::camera
