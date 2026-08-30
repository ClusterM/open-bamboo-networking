#pragma once

// Small, non-sensitive plugin state that must survive slicer restarts.
//
// Bambu Studio / Orca ask the networking plugin for the last selected
// printer during startup. Keep that value in <config_dir>/obn.state.json;
// otherwise a newly-created Agent can only return an empty string and the
// Device tab falls back to "No printer".

#include <mutex>
#include <string>

namespace obn::state {

class Store {
public:
    // Empty path disables disk persistence (useful for tests).
    explicit Store(std::string path);

    // Load the state file if it exists. Missing or malformed files leave the
    // store at its safe default (no selected printer).
    void load();

    // Replace and persist the selected printer id. An empty id intentionally
    // persists deselection so an older value cannot reappear after restart.
    void set_selected_machine(std::string dev_id);

    std::string selected_machine() const;

private:
    void persist_locked() const;

    std::string        path_;
    mutable std::mutex mu_;
    std::string        selected_machine_;
};

} // namespace obn::state
