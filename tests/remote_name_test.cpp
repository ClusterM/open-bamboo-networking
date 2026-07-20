// Unit tests for pick_remote_name / dest_name_for_send_gcode.
// Ground-truth table: NETWORK_PLUGIN.md §6.14.3 "Stock plugin verification".

#include "obn/print_job.hpp"

#include <cstdio>
#include <string>

namespace {

int g_failed = 0;

void expect(const char* label, const std::string& got, const std::string& want)
{
    if (got != want) {
        std::printf("FAIL %s: got '%s' want '%s'\n",
                    label, got.c_str(), want.c_str());
        ++g_failed;
    }
}

BBL::PrintParams params(const char* project,
                        const char* task = "",
                        const char* file = "/tmp/plate.gcode.3mf")
{
    BBL::PrintParams p;
    p.project_name = project ? project : "";
    p.task_name    = task ? task : "";
    p.filename     = file ? file : "";
    return p;
}

} // namespace

int main()
{
    // --- start_send_gcode_to_sdcard (dest_name_for_send_gcode) ---
    expect("sg verify_job",
           obn::print_job::dest_name_for_send_gcode(params("verify_job")),
           "verify_job");
    expect("sg bare",
           obn::print_job::dest_name_for_send_gcode(params("obn_probe_bare")),
           "obn_probe_bare");
    expect("sg full ext",
           obn::print_job::dest_name_for_send_gcode(
               params("obn_probe_bare.gcode.3mf")),
           "obn_probe_bare.gcode.3mf");
    expect("sg empty project",
           obn::print_job::dest_name_for_send_gcode(params("")),
           "");
    expect("sg sanitize slash",
           obn::print_job::dest_name_for_send_gcode(params("foo/bar")),
           "foo_bar");

    // --- start_local_print / cloud FTPS leg (pick_remote_name) ---
    expect("lp bare project",
           obn::print_job::pick_remote_name(params("my-print")),
           "my-print.gcode.3mf");
    expect("lp task fallback",
           obn::print_job::pick_remote_name(params("", "task-only")),
           "task-only.gcode.3mf");
    expect("lp already has ext",
           obn::print_job::pick_remote_name(params("foo.gcode.3mf")),
           "foo.gcode.3mf");
    expect("lp filename fallback",
           obn::print_job::pick_remote_name(
               params("", "", "/path/to/export.gcode.3mf")),
           "export.gcode.3mf");
    expect("lp default",
           obn::print_job::pick_remote_name(params("", "", "")),
           "print.gcode.3mf");

    // --- build_ftp_remote_path (ftp_folder) ---
    {
        auto p = params("job");
        expect("ftp path root",
               obn::print_job::build_ftp_remote_path(p, "job.gcode.3mf"),
               "/job.gcode.3mf");
        p.ftp_folder = "cache";
        expect("ftp path folder",
               obn::print_job::build_ftp_remote_path(p, "job.gcode.3mf"),
               "/cache/job.gcode.3mf");
        p.ftp_folder = "/cache/";
        expect("ftp path normalize",
               obn::print_job::build_ftp_remote_path(p, "job.gcode.3mf"),
               "/cache/job.gcode.3mf");
    }

    std::printf("remote_name_test: %s\n", g_failed ? "FAILED" : "ok");
    return g_failed ? 1 : 0;
}
