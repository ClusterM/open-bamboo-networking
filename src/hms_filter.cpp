#include "obn/hms_filter.hpp"

#include "obn/json_lite.hpp"

#include <string>

namespace obn::hms {

void filter_hms_code(std::string& json, int target_code)
{
    if (json.find(std::to_string(target_code)) == std::string::npos ||
        json.find("\"hms\"") == std::string::npos) {
        return;
    }

    size_t hms_pos = json.find("\"hms\"");
    size_t arr_start = (hms_pos != std::string::npos) ? json.find('[', hms_pos) : std::string::npos;
    size_t arr_end = (arr_start != std::string::npos) ? json.find(']', arr_start) : std::string::npos;
    if (arr_start != std::string::npos && arr_end != std::string::npos) {
        std::string hms_str = json.substr(arr_start, arr_end - arr_start + 1);
        auto parsed = obn::json::parse(hms_str);
        if (parsed && parsed->is_array()) {
            obn::json::Array filtered_hms;
            for (const auto& item : parsed->as_array()) {
                if (item.is_object()) {
                    auto code_val = item.find("code");
                    if (code_val.is_number() && code_val.as_int() == target_code) {
                        continue;
                    }
                }
                filtered_hms.push_back(item);
            }
            std::string new_hms = obn::json::Value(std::move(filtered_hms)).dump();
            json.replace(arr_start, arr_end - arr_start + 1, new_hms);
        }
    }
}

} // namespace obn::hms
