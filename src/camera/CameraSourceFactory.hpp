//
// CameraSourceFactory — create the right ICameraSource for a CameraSpec.
//
// Selection order:
//   1. camera_url starts with "bambu:///agora?" → AgoraCameraSource
//      (OssAgoraSignaling relay, H.264 Annex-B)
//   2. camera_url starts with "bambu:///tutk?"  → OssTutkCameraSource
//      (TUTK relay via OssAgoraSignaling, H.264 Annex-B)
//   3. camera_url empty + is_jpeg_model(model) + !lan_ip.empty()
//      → JpegCameraSource (port-6000 TLS MJPEG)
//   4. nullptr — no source available

#pragma once

#include "ICameraSource.hpp"
#include <memory>

namespace obn {
namespace camera {

struct CameraSpec;   // defined in obn/camera.hpp

class CameraSourceFactory {
public:
    std::shared_ptr<bambu_net::camera::ICameraSource>
    make(const CameraSpec& spec) const;
};

}  // namespace camera
}  // namespace obn
