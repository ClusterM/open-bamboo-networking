#pragma once

#include <string>

namespace obn::hms {

// Removes every object entry whose "code" equals `target_code` from the
// "hms" array of a printer report frame, in place. No-op when the frame
// carries no HMS array, no matching code, or a malformed array. Entries
// that are not objects are preserved as-is.
void filter_hms_code(std::string& json, int target_code);

} // namespace obn::hms
