#pragma once

// Startup device-region request body. Stock 02.08.04.60 posts exactly one
// JSON key. Exposed so tests can pin it against the MITM capture.

#include "obn/bambu_networking.hpp"

#include <string>

namespace obn::detail {

#if ABI_VERSION >= 0x020804
// {"ClientType":"<value>"}. An empty ClientType is sent as the literal
// "slicer" — stock does that even when the X-BBL-Client-Type header is
// something else. DeviceId, country and XClientCountry are not serialized;
// stock 02.08.04.60 dropped them on the wire (UUID, "DE" and "FR" included).
std::string build_device_region_body(const BBL::DeviceRegionParams& params);
#endif

} // namespace obn::detail
