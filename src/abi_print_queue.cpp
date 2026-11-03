// Print Queue entry points (bambu_network_*_print_queue_*).
//
// Studio 02.09.01 resolves all 14 symbols but builds with
// STUDIO_ENABLE_PRINT_QUENE 0, so no UI path reaches them; the stock plugin
// has exported them since 02.08.02. These are documented stubs: no network,
// output strings cleared, callbacks never invoked, and each call returns its
// own "failed" code from the -36 … -59 block (a null agent still gets
// INVALID_HANDLE first). See research/08.16-errors.md §8.16.9.

#include <string>

#include "obn/abi_export.hpp"
#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"
#include "obn/log.hpp"

#if ABI_VERSION >= 0x020802

using obn::as_agent;

namespace {

int print_queue_stub(void* agent, std::string* out, int failed_code, const char* fn)
{
    if (out) out->clear();
    if (!as_agent(agent)) return BAMBU_NETWORK_ERR_INVALID_HANDLE;
    OBN_DEBUG("%s: Print Queue is not implemented (ret=%d)", fn, failed_code);
    return failed_code;
}

} // namespace

OBN_ABI int bambu_network_create_print_queue_project(void* agent,
                                                     BBL::PrintQueueProjectCreateParams /*params*/,
                                                     std::string* http_body)
{
    return print_queue_stub(agent, http_body, BAMBU_NETWORK_ERR_CREATE_PRINT_QUEUE_PROJECT_FAILED,
                            __func__);
}

OBN_ABI int bambu_network_get_print_queue_projects(void* agent,
                                                   BBL::PrintQueueProjectsQueryParams /*params*/,
                                                   std::string* http_body)
{
    return print_queue_stub(agent, http_body, BAMBU_NETWORK_ERR_GET_PRINT_QUEUE_PROJECTS_FAILED,
                            __func__);
}

OBN_ABI int bambu_network_update_print_queue_project(void* agent,
                                                     BBL::PrintQueueProjectUpdateParams /*params*/,
                                                     std::string* http_body)
{
    return print_queue_stub(agent, http_body, BAMBU_NETWORK_ERR_UPDATE_PRINT_QUEUE_PROJECT_FAILED,
                            __func__);
}

OBN_ABI int bambu_network_sort_print_queue_project(void* agent,
                                                   BBL::PrintQueueProjectSortParams /*params*/,
                                                   std::string* http_body)
{
    return print_queue_stub(agent, http_body, BAMBU_NETWORK_ERR_SORT_PRINT_QUEUE_PROJECT_FAILED,
                            __func__);
}

OBN_ABI int bambu_network_delete_print_queue_project(void* agent,
                                                     BBL::PrintQueueProjectDeleteParams /*params*/,
                                                     std::string* http_body)
{
    return print_queue_stub(agent, http_body, BAMBU_NETWORK_ERR_DELETE_PRINT_QUEUE_PROJECT_FAILED,
                            __func__);
}

OBN_ABI int bambu_network_update_print_queue_plate(void* agent,
                                                   BBL::PrintQueuePlateUpdateParams /*params*/,
                                                   std::string* http_body)
{
    return print_queue_stub(agent, http_body, BAMBU_NETWORK_ERR_UPDATE_PRINT_QUEUE_PLATE_FAILED,
                            __func__);
}

OBN_ABI int bambu_network_sort_print_queue_plate(void* agent,
                                                 BBL::PrintQueuePlateSortParams /*params*/,
                                                 std::string* http_body)
{
    return print_queue_stub(agent, http_body, BAMBU_NETWORK_ERR_SORT_PRINT_QUEUE_PLATE_FAILED,
                            __func__);
}

OBN_ABI int bambu_network_delete_print_queue_plate(void* agent,
                                                   BBL::PrintQueuePlateDeleteParams /*params*/,
                                                   std::string* http_body)
{
    return print_queue_stub(agent, http_body, BAMBU_NETWORK_ERR_DELETE_PRINT_QUEUE_PLATE_FAILED,
                            __func__);
}

OBN_ABI int bambu_network_extract_print_queue_plate(void* agent,
                                                    BBL::PrintQueuePlateExtractParams /*params*/,
                                                    std::string* http_body)
{
    return print_queue_stub(agent, http_body, BAMBU_NETWORK_ERR_EXTRACT_PRINT_QUEUE_PLATE_FAILED,
                            __func__);
}

OBN_ABI int bambu_network_delete_unavailable_print_queue_plates(
    void* agent,
    BBL::PrintQueueUnavailablePlatesDeleteParams /*params*/,
    std::string* http_body)
{
    return print_queue_stub(agent, http_body,
                            BAMBU_NETWORK_ERR_DELETE_UNAVAILABLE_PRINT_QUEUE_PLATES_FAILED, __func__);
}

OBN_ABI int bambu_network_get_print_queue_model_profile(void* agent,
                                                        BBL::PrintQueueModelProfileQueryParams /*params*/,
                                                        std::string* http_body)
{
    return print_queue_stub(agent, http_body, BAMBU_NETWORK_ERR_GET_PRINT_QUEUE_MODEL_PROFILE_FAILED,
                            __func__);
}

OBN_ABI int bambu_network_download_print_queue_config(void* agent,
                                                      BBL::PrintQueueConfigDownloadParams /*params*/,
                                                      std::string* http_body)
{
    return print_queue_stub(agent, http_body, BAMBU_NETWORK_ERR_DOWNLOAD_PRINT_QUEUE_CONFIG_FAILED,
                            __func__);
}

OBN_ABI int bambu_network_start_print_queue_task(void* agent,
                                                 BBL::PrintQueueTaskParams /*params*/,
                                                 BBL::OnUpdateStatusFn /*update_fn*/,
                                                 BBL::WasCancelledFn /*cancel_fn*/,
                                                 BBL::OnWaitFn /*wait_fn*/)
{
    return print_queue_stub(agent, nullptr, BAMBU_NETWORK_ERR_START_PRINT_QUEUE_TASK_FAILED,
                            __func__);
}

OBN_ABI int bambu_network_upload_print_queue_content(void* agent,
                                                     BBL::PrintParams /*params*/,
                                                     BBL::OnUpdateStatusFn /*update_fn*/,
                                                     BBL::WasCancelledFn /*cancel_fn*/,
                                                     std::string* response_body)
{
    return print_queue_stub(agent, response_body, BAMBU_NETWORK_ERR_PRINT_QUEUE_UPLOAD_ARCHIVE_FAILED,
                            __func__);
}

#endif
