#pragma once

// Minor-account restrictions (ABI 02.09.01): request query and response
// parsing for GET /v1/user-service/minors/decisions. Exposed so tests can
// pin both against the stock 02.09.01.54 capture (research/08.10-http.md).

#include "obn/bambu_networking.hpp"

#include <string>
#include <vector>

namespace obn::detail {

#if ABI_VERSION >= 0x020901
// Stock refuses an empty list or a repeated scene code before any request
// goes out. Unknown or lower-case codes are accepted; the server echoes them.
bool minors_scene_codes_valid(const std::vector<std::string>& scene_codes);

// "?sceneCodes=A&sceneCodes=B", one key per code in request order. Values
// are percent-encoded except RFC 3986 unreserved characters and '/', which
// stock leaves as is ("A B&c=d/é" -> "A%20B%26c%3Dd/%C3%A9").
std::string build_minors_decisions_query(const std::vector<std::string>& scene_codes);

// Strict, like stock: the body must be {"decisions":[...]} whose entries
// carry sceneCode (string), familyLinkEnable (bool), familyLinkDecision
// (string, copied verbatim) and decision ("ALLOW" / "DENY" / "NEED_IDV",
// case-sensitive). The returned scene codes must match the requested ones
// exactly: no missing, extra or repeated entry. On success `out` holds one
// result per requested code, in request order; on failure it is cleared.
bool parse_minors_decisions(const std::string& body,
                            const std::vector<std::string>& scene_codes,
                            std::vector<BBL::MinorsDecisionResult>* out);
#endif

} // namespace obn::detail
