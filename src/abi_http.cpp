#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "obn/abi_export.hpp"
#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/cloud_auth.hpp"
#include "obn/http_client.hpp"
#include "obn/json_lite.hpp"
#include "obn/log.hpp"

using obn::as_agent;

OBN_IGNORE_RETURN_CXX_IN_EXTERN_C_BEGIN
OBN_ABI std::string bambu_network_get_studio_info_url(void* /*agent*/)
{
    return {};
}
OBN_IGNORE_RETURN_CXX_IN_EXTERN_C_END

OBN_ABI int bambu_network_set_extra_http_header(void* agent,
                                                std::map<std::string, std::string> extra_headers)
{
    if (auto* a = as_agent(agent)) {
        a->set_extra_http_headers(std::move(extra_headers));
        return BAMBU_NETWORK_SUCCESS;
    }
    return BAMBU_NETWORK_ERR_INVALID_HANDLE;
}

OBN_ABI int bambu_network_get_my_message(void* /*agent*/,
                                         int /*type*/, int /*after*/, int /*limit*/,
                                         unsigned int* http_code, std::string* http_body)
{
    if (http_code) *http_code = 0;
    if (http_body) http_body->clear();
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_check_user_task_report(void* /*agent*/, int* task_id, bool* printable)
{
    if (task_id)   *task_id = 0;
    if (printable) *printable = false;
    return BAMBU_NETWORK_SUCCESS;
}

namespace {

// Serialize a json_lite value back to compact JSON text. We only need
// this for the pass-through "whatever was in the server's device
// entry" payload; json::Value::dump() does the heavy lifting for us.
std::string dump_or_null(const obn::json::Value& v)
{
    return v.is_null() ? std::string{"null"} : v.dump();
}

// The Bambu cloud returns device-bind info at
//   GET /v1/iot-service/api/user/bind
// with body shape:
//   { "devices":[{
//       "dev_id":"22E8BJ610801473",
//       "name":"3Д принтерик",
//       "online":true,
//       "print_status":"SUCCESS",
//       "dev_model_name":"N7-V2",
//       "dev_product_name":"P2S",
//       "dev_access_code":"03f06755",
//       ... }]}
// Studio's DeviceManager::parse_user_print_info however reads slightly
// different field names - {dev_name, dev_online, task_status}. We
// translate here so Studio's parser finds everything. Pass-through
// fields that Studio doesn't care about (print_job, nozzle_diameter,
// dev_structure...) are preserved verbatim in case anything else on
// the Studio side picks them up.
std::string remap_bind_payload(const std::string& raw_body,
                               std::vector<std::string>* out_dev_ids)
{
    std::string perr;
    auto root = obn::json::parse(raw_body, &perr);
    if (!root) {
        OBN_WARN("get_user_print_info: bad JSON from server: %s", perr.c_str());
        return R"({"devices":[]})";
    }

    std::ostringstream out;
    out << "{\"message\":\"success\",\"devices\":[";
    // Copy the devices array out of the temporary Value to avoid
    // dangling reference (as_array() returns a reference to storage
    // owned by the temporary returned from find()).
    auto devs_v = root->find("devices");
    const auto& devs = devs_v.as_array();
    bool first = true;
    for (const auto& d : devs) {
        if (!first) out << ',';
        first = false;
        out << '{';
        // Required by Studio's parser.
        const auto dev_id = d.find("dev_id").as_string();
        if (out_dev_ids && !dev_id.empty()) out_dev_ids->push_back(dev_id);
        out << "\"dev_id\":"          << obn::json::escape(dev_id) << ',';
        out << "\"dev_name\":"        << obn::json::escape(d.find("name").as_string()) << ',';
        out << "\"dev_online\":"      << (d.find("online").as_bool() ? "true" : "false") << ',';
        out << "\"dev_model_name\":"  << obn::json::escape(d.find("dev_model_name").as_string()) << ',';
        out << "\"task_status\":"     << obn::json::escape(d.find("print_status").as_string()) << ',';
        out << "\"dev_access_code\":" << obn::json::escape(d.find("dev_access_code").as_string());
        // Pass-through extras; Studio code paths occasionally look them up.
        if (auto v = d.find("dev_product_name"); !v.is_null())
            out << ",\"dev_product_name\":" << obn::json::escape(v.as_string());
        if (auto v = d.find("print_job"); !v.is_null())
            out << ",\"print_job\":" << dump_or_null(v);
        if (auto v = d.find("nozzle_diameter"); !v.is_null())
            out << ",\"nozzle_diameter\":" << dump_or_null(v);
        if (auto v = d.find("dev_structure"); !v.is_null())
            out << ",\"dev_structure\":" << obn::json::escape(v.as_string());
        out << '}';
    }
    out << "]}";
    return out.str();
}

} // namespace

OBN_ABI int bambu_network_get_user_print_info(void* agent,
                                              unsigned int* http_code, std::string* http_body)
{
    if (http_code) *http_code = 0;
    if (http_body) http_body->clear();

    auto* a = as_agent(agent);
    if (!a) return BAMBU_NETWORK_ERR_GET_USER_PRINTINFO_FAILED;
    auto s = a->user_session_snapshot();
    if (s.access_token.empty()) {
        OBN_WARN("get_user_print_info: no access token");
        return BAMBU_NETWORK_ERR_GET_USER_PRINTINFO_FAILED;
    }

    const std::string url = obn::cloud::api_host(a->cloud_region())
                          + "/v1/iot-service/api/user/bind";
    std::map<std::string, std::string> hdrs{
        {"Authorization", "Bearer " + s.access_token},
    };

    auto resp = obn::http::get_json(url, hdrs);
    if (http_code) *http_code = static_cast<unsigned int>(resp.status_code);

    if (!resp.error.empty()) {
        OBN_WARN("get_user_print_info: transport: %s", resp.error.c_str());
        if (http_body) *http_body = resp.body;
        return BAMBU_NETWORK_ERR_GET_USER_PRINTINFO_FAILED;
    }
    if (resp.status_code != 200) {
        OBN_WARN("get_user_print_info: HTTP %ld body=%s",
                 resp.status_code, resp.body.c_str());
        if (http_body) *http_body = resp.body;
        return BAMBU_NETWORK_ERR_GET_USER_PRINTINFO_FAILED;
    }

    std::vector<std::string> dev_ids;
    std::string mapped = remap_bind_payload(resp.body, &dev_ids);
    OBN_INFO("get_user_print_info: mapped %zu -> %zu bytes, %zu device(s)",
             resp.body.size(), mapped.size(), dev_ids.size());

    // Studio's DeviceManager never calls add_subscribe() for single-
    // machine cloud mode (the only call sites in GUI_App.cpp / DevManager
    // are either commented out or gated on the multi-machine flag), yet
    // the stock Bambu plugin still receives per-device pushes from the
    // cloud. We replicate that behaviour here: every device the /user/
    // bind endpoint returns becomes an implicit subscription to
    // device/<id>/report. Cloud MQTT connect may not have landed yet -
    // CloudSession buffers the desired set and re-applies it on the
    // next CONNACK, so ordering doesn't matter.
    if (!dev_ids.empty()) {
        a->cloud_add_subscribe(dev_ids);
    }

    if (http_body) *http_body = std::move(mapped);
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_get_user_tasks(void* /*agent*/,
                                         BBL::TaskQueryParams /*params*/,
                                         std::string* http_body)
{
    if (http_body) http_body->clear();
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_get_printer_firmware(void* agent,
                                               std::string dev_id,
                                               unsigned* http_code, std::string* http_body)
{
    // The stock plugin fetches this from Bambu Lab's cloud firmware
    // catalogue. We don't have cloud auth plumbed in, so we rebuild
    // the subset Studio actually reads from the MQTT frames the
    // printer already pushes through us: current versions come from
    // info.command=get_version, advertised-new versions come from
    // push_status.upgrade_state.new_ver_list. See Agent::render_
    // firmware_json for details.
    //
    // The Update tab stays blank until this call returns a JSON that
    // parses successfully AND whose devices[0].dev_id matches; an
    // empty body (the previous stub) made json::parse("") throw and
    // left m_firmware_valid=false forever.
    std::string body;
    if (auto* a = as_agent(agent)) {
        body = a->render_firmware_json(dev_id);
    } else {
        // No agent context yet - emit the minimal valid envelope so
        // Studio's json::parse doesn't throw. This path is only hit
        // on startup before a printer has connected.
        body.reserve(64);
        body.append(R"({"devices":[{"dev_id":")");
        for (char c : dev_id) {
            if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
                (c >= 'a' && c <= 'z') || c == '_' || c == '-')
                body.push_back(c);
        }
        body.append(R"(","firmware":[],"ams":[]}]})");
    }

    if (http_code) *http_code = 200;
    if (http_body) *http_body = std::move(body);
    OBN_DEBUG("get_printer_firmware dev=%s -> %zu bytes",
              dev_id.c_str(),
              http_body ? http_body->size() : size_t{0});
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_get_task_plate_index(void* /*agent*/,
                                               std::string /*task_id*/, int* plate_index)
{
    if (plate_index) *plate_index = -1;
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_get_subtask_info(void* agent,
                                           std::string subtask_id,
                                           std::string* task_json,
                                           unsigned int* http_code,
                                           std::string*  http_body)
{
    if (task_json) task_json->clear();
    if (http_code) *http_code = 0;
    if (http_body) http_body->clear();

#if OBN_ENABLE_WORKAROUNDS
    // Synthetic-subtask short-circuit. notify_local_message rewrites
    // zero ids in LAN push_status frames to "lan-<fnv>"; Studio then
    // calls us here to resolve that id. We hand back a minimal
    // "cloud subtask" JSON whose only interesting field is the
    // context.plates[0].thumbnail.url pointing at our local
    // cover_server, which in turn serves the PNG extracted from the
    // printer's /cache/<name>.3mf.
    auto* a = as_agent(agent);
    if (a) {
        obn::Agent::SubtaskCoverInfo info;
        if (a->lookup_synthetic_subtask(subtask_id, &info) &&
            !info.url.empty()) {
            using obn::json::Value;
            using obn::json::Object;
            using obn::json::Array;

            Object thumb{{"url", Value(info.url)}};
            Object plate{
                {"index",     Value(static_cast<double>(info.plate_idx))},
                {"thumbnail", Value(std::move(thumb))},
            };
            Array plates;
            plates.push_back(Value(std::move(plate)));
            Object context{{"plates", Value(std::move(plates))}};

            // DeviceManager.cpp parses `content` as a *string* holding
            // an embedded JSON object, then reads info.plate_idx out
            // of it to pick which plate entry to attach.
            Object inner_info{
                {"plate_idx", Value(static_cast<double>(info.plate_idx))},
            };
            Object inner{{"info", Value(std::move(inner_info))}};
            Value inner_v{std::move(inner)};

            Object root{
                {"context", Value(std::move(context))},
                {"content", Value(inner_v.dump())},
            };
            std::string body = Value(std::move(root)).dump();
            if (task_json) *task_json = body;
            if (http_code) *http_code = 200;
            if (http_body) *http_body = body;
            OBN_DEBUG("get_subtask_info: synthetic id=%s url=%s body=%s",
                      subtask_id.c_str(), info.url.c_str(), body.c_str());
            return BAMBU_NETWORK_SUCCESS;
        }
    }
#endif
    (void)agent;
    (void)subtask_id;
    return BAMBU_NETWORK_SUCCESS;
}

OBN_ABI int bambu_network_get_slice_info(void* /*agent*/,
                                         std::string /*project_id*/,
                                         std::string /*profile_id*/,
                                         int         /*plate_index*/,
                                         std::string* slice_json)
{
    if (slice_json) slice_json->clear();
    return BAMBU_NETWORK_SUCCESS;
}
