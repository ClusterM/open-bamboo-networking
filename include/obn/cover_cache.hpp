#pragma once

// Cover-image cache for the "currently printing" thumbnail in Studio's
// Device tab.
//
// Fetches via tunnel_upload::fetch_model_tile_thumbnail — the same
// LIST_INFO + SUB_FILE #thumbnail path as Device → Storage → Model.
// LAN prints this plugin uploads itself take the image from that .3mf
// instead (stage_from_3mf).

#include <cstdint>
#include <string>
#include <vector>

namespace obn::cover_cache {

std::string temp_dir();

std::string path_for(const std::string& subtask_name,
                     int                plate_idx,
                     const std::string& version = {});

// Plate image of a local .3mf: Metadata/plate_N.png, then the same
// fallbacks as the :6000 fetch (plate_no_light_N, then plate 1 when
// N != 1). `*entry` (optional) gets the archive entry that was used.
bool read_local_thumbnail(const std::string&         path_3mf,
                          int                        plate_idx,
                          std::vector<std::uint8_t>* png,
                          std::string*               entry = nullptr,
                          std::string*               err = nullptr);

// Stages the cover of a LAN print this plugin is about to start, read
// from the .3mf it uploads, for the project_file with `sequence_id`. The
// cache file name depends on the print's task_id, which the printer
// assigns only after project_file, so the image is kept per (dev_id,
// subtask_name) until the job reports it: once activate_stage() has been
// called, the first task_id the printer reports that it had not reported
// before staging is the job's, and a report of that task_id with this name
// and plate takes the image and retires the stage. Returns false (and
// blocks the name, an earlier stage of it included, for two minutes from
// now) when the archive has no plate image or an earlier stage or block of
// the name still exists.
bool stage_from_3mf(const std::string& dev_id,
                    const std::string& subtask_name,
                    const std::string& path_3mf,
                    int                plate_idx,
                    const std::string& sequence_id);

// The project_file with `sequence_id` has been published. Activates its
// stage unless that was dropped meanwhile; drops it instead when the job
// cannot be told apart: no report with a task_id (a LAN one with an empty
// id included) in the last 10 s, or a new task_id, a report gap or a LAN
// disconnect since staging.
void activate_stage(const std::string& dev_id, const std::string& subtask_name,
                    const std::string& sequence_id);

// The project_file with `sequence_id` was refused by the printer or not
// submitted (cancel, publish failure): its job never starts, so its stage
// (active or not yet) must not go to another one. Other submissions'
// stages are left alone.
void drop_submission(const std::string& dev_id, const std::string& sequence_id);

// A project_file for `subtask_name` is being published (any path,
// including the generic send_message ABIs). Unless it is the submission a
// stage of that name was made for (same sequence_id), its job could take
// that stage, so the name is blocked for two minutes from now.
void note_project_file(const std::string& dev_id, const std::string& subtask_name,
                       const std::string& sequence_id);

// The LAN report stream of `dev_id` broke (MQTT disconnect): reports may
// have been missed, so a stage whose job has not reported yet is dropped,
// and the next one needs a report from after the disconnect.
void reports_interrupted(const std::string& dev_id);

// A task_id `dev_id` reported (print.task_id of every LAN and cloud
// report; "" is ignored). Earlier jobs for stages made later; the owner
// (or the end) of an active stage.
void note_task_id(const std::string& dev_id, const std::string& task_id);

// A LAN report of `dev_id` whose print.task_id is "" or "0": the printer
// has no job id right now (e.g. after a restart). A fresh report that adds
// no id to the baseline; never binds an owner; report-gap rules apply as
// for any report.
void note_no_task_id(const std::string& dev_id);

// If path_for(...) is missing: writes the staged cover for this printer
// and subtask name when there is one, otherwise spawns a thread that
// connects on TLS :6000, reuses the file-browser wire path, writes PNG.
// `task_id` is the report's print.task_id ("" when absent or "0"); it
// identifies the job a staged cover is for.
void ensure(const std::string& host,
            const std::string& dev_id,
            const std::string& user,
            const std::string& password,
            const std::string& subtask_name,
            int                plate_idx,
            const std::string& version = {},
            const std::string& task_id = {});

} // namespace obn::cover_cache
