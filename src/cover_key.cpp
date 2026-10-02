// COVER-01 key selection — see the contract comment in obn/cover_key.hpp.

#include "obn/cover_key.hpp"

#include "obn/json_lite.hpp"

#include <optional>
#include <string>

namespace obn {

namespace {

// Reads one string field from a parsed frame: the root object first,
// then the print.* block (push_status frames are {"print":{...}}; the
// flat-text peek in agent.cpp matched either, so this helper keeps the
// same reach without hand-rolling a second parser).
std::string frame_string_field(const json::Value& root, const char* key)
{
    json::Value v = root.find(key);
    if (!v.is_string()) v = root.find(std::string("print.") + key);
    return v.is_string() ? v.as_string() : std::string{};
}

// Last '/'-separated component, then the trailing ".gcode" (and only
// that suffix) removed. No other normalization — byte-exact.
std::string gcode_file_to_key(const std::string& gcode_file)
{
    const std::size_t slash = gcode_file.rfind('/');
    std::string base = (slash == std::string::npos)
                           ? gcode_file
                           : gcode_file.substr(slash + 1);
    static constexpr char kSuffix[] = ".gcode";
    static constexpr std::size_t kSuffixLen = sizeof(kSuffix) - 1;
    if (base.size() >= kSuffixLen &&
        base.compare(base.size() - kSuffixLen, kSuffixLen, kSuffix) == 0) {
        base.resize(base.size() - kSuffixLen);
    }
    return base;
}

} // namespace

std::string cover_model_key(const std::string& payload_json)
{
    std::optional<json::Value> parsed = json::parse(payload_json);
    if (!parsed) return {};

    const std::string gcode_file = frame_string_field(*parsed, "gcode_file");
    if (!gcode_file.empty()) return gcode_file_to_key(gcode_file);

    // Primary key absent (or explicitly empty) — best-effort fallback:
    // subtask_name verbatim, profile title or not.
    return frame_string_field(*parsed, "subtask_name");
}

} // namespace obn
