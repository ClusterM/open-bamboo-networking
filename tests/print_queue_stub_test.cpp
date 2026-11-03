// The Print Queue exports are stubs: each returns its own "failed" code,
// clears the output string and never touches the network or the callbacks.

#include "obn/agent.hpp"
#include "obn/bambu_networking.hpp"

#include <cstdio>
#include <filesystem>
#include <string>

#if ABI_VERSION >= 0x020802
extern "C" {
int bambu_network_create_print_queue_project(void*, BBL::PrintQueueProjectCreateParams, std::string*);
int bambu_network_get_print_queue_projects(void*, BBL::PrintQueueProjectsQueryParams, std::string*);
int bambu_network_update_print_queue_project(void*, BBL::PrintQueueProjectUpdateParams, std::string*);
int bambu_network_sort_print_queue_project(void*, BBL::PrintQueueProjectSortParams, std::string*);
int bambu_network_delete_print_queue_project(void*, BBL::PrintQueueProjectDeleteParams, std::string*);
int bambu_network_update_print_queue_plate(void*, BBL::PrintQueuePlateUpdateParams, std::string*);
int bambu_network_sort_print_queue_plate(void*, BBL::PrintQueuePlateSortParams, std::string*);
int bambu_network_delete_print_queue_plate(void*, BBL::PrintQueuePlateDeleteParams, std::string*);
int bambu_network_extract_print_queue_plate(void*, BBL::PrintQueuePlateExtractParams, std::string*);
int bambu_network_delete_unavailable_print_queue_plates(void*, BBL::PrintQueueUnavailablePlatesDeleteParams,
                                                        std::string*);
int bambu_network_get_print_queue_model_profile(void*, BBL::PrintQueueModelProfileQueryParams, std::string*);
int bambu_network_download_print_queue_config(void*, BBL::PrintQueueConfigDownloadParams, std::string*);
int bambu_network_start_print_queue_task(void*, BBL::PrintQueueTaskParams, BBL::OnUpdateStatusFn,
                                         BBL::WasCancelledFn, BBL::OnWaitFn);
int bambu_network_upload_print_queue_content(void*, BBL::PrintParams, BBL::OnUpdateStatusFn,
                                             BBL::WasCancelledFn, std::string*);
}
#endif

static int fail_count = 0;

#define CHECK(cond)                                                         \
    do {                                                                    \
        if (!(cond)) {                                                      \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,    \
                         #cond);                                            \
            ++fail_count;                                                   \
        }                                                                   \
    } while (0)

#if ABI_VERSION >= 0x020802

template <typename Fn>
static void expect(Fn fn, void* agent, int want)
{
    std::string body = "stale";
    CHECK(fn(agent, &body) == want);
    CHECK(body.empty());
}

static void run_all(void* agent, bool null_agent)
{
    auto code = [null_agent](int failed) {
        return null_agent ? BAMBU_NETWORK_ERR_INVALID_HANDLE : failed;
    };
    expect([](void* a, std::string* b) { return bambu_network_create_print_queue_project(a, {}, b); },
           agent, code(BAMBU_NETWORK_ERR_CREATE_PRINT_QUEUE_PROJECT_FAILED));
    expect([](void* a, std::string* b) { return bambu_network_get_print_queue_projects(a, {}, b); },
           agent, code(BAMBU_NETWORK_ERR_GET_PRINT_QUEUE_PROJECTS_FAILED));
    expect([](void* a, std::string* b) { return bambu_network_update_print_queue_project(a, {}, b); },
           agent, code(BAMBU_NETWORK_ERR_UPDATE_PRINT_QUEUE_PROJECT_FAILED));
    expect([](void* a, std::string* b) { return bambu_network_sort_print_queue_project(a, {}, b); },
           agent, code(BAMBU_NETWORK_ERR_SORT_PRINT_QUEUE_PROJECT_FAILED));
    expect([](void* a, std::string* b) { return bambu_network_delete_print_queue_project(a, {}, b); },
           agent, code(BAMBU_NETWORK_ERR_DELETE_PRINT_QUEUE_PROJECT_FAILED));
    expect([](void* a, std::string* b) { return bambu_network_update_print_queue_plate(a, {}, b); },
           agent, code(BAMBU_NETWORK_ERR_UPDATE_PRINT_QUEUE_PLATE_FAILED));
    expect([](void* a, std::string* b) { return bambu_network_sort_print_queue_plate(a, {}, b); },
           agent, code(BAMBU_NETWORK_ERR_SORT_PRINT_QUEUE_PLATE_FAILED));
    expect([](void* a, std::string* b) { return bambu_network_delete_print_queue_plate(a, {}, b); },
           agent, code(BAMBU_NETWORK_ERR_DELETE_PRINT_QUEUE_PLATE_FAILED));
    expect([](void* a, std::string* b) { return bambu_network_extract_print_queue_plate(a, {}, b); },
           agent, code(BAMBU_NETWORK_ERR_EXTRACT_PRINT_QUEUE_PLATE_FAILED));
    expect([](void* a, std::string* b) {
               return bambu_network_delete_unavailable_print_queue_plates(a, {}, b);
           },
           agent, code(BAMBU_NETWORK_ERR_DELETE_UNAVAILABLE_PRINT_QUEUE_PLATES_FAILED));
    expect([](void* a, std::string* b) { return bambu_network_get_print_queue_model_profile(a, {}, b); },
           agent, code(BAMBU_NETWORK_ERR_GET_PRINT_QUEUE_MODEL_PROFILE_FAILED));
    expect([](void* a, std::string* b) { return bambu_network_download_print_queue_config(a, {}, b); },
           agent, code(BAMBU_NETWORK_ERR_DOWNLOAD_PRINT_QUEUE_CONFIG_FAILED));

    bool called = false;
    auto update = [&called](int, int, std::string) { called = true; };
    auto cancel = [&called]() { called = true; return false; };
    auto wait   = [&called](int, std::string) { called = true; return true; };
    CHECK(bambu_network_start_print_queue_task(agent, {}, update, cancel, wait) ==
          code(BAMBU_NETWORK_ERR_START_PRINT_QUEUE_TASK_FAILED));
    std::string body = "stale";
    CHECK(bambu_network_upload_print_queue_content(agent, {}, update, cancel, &body) ==
          code(BAMBU_NETWORK_ERR_PRINT_QUEUE_UPLOAD_ARCHIVE_FAILED));
    CHECK(body.empty());
    CHECK(!called);
}

#endif

int main()
{
#if ABI_VERSION >= 0x020802
    run_all(nullptr, true);
    {
        namespace fs = std::filesystem;
        const fs::path dir = fs::temp_directory_path() / "obn-print-queue-stub-test";
        fs::remove_all(dir);
        fs::create_directories(dir);
        obn::Agent agent(dir.string());
        run_all(&agent, false);
        fs::remove_all(dir);
    }
#endif
    if (fail_count) {
        std::fprintf(stderr, "print_queue_stub_test: %d failure(s)\n", fail_count);
        return 1;
    }
    std::puts("print_queue_stub_test: all checks passed");
    return 0;
}
