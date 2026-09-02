#pragma once

// Small, non-sensitive plugin state that must survive slicer restarts.
//
// Studio and Orca keep their own "last selected printer" in the slicer config
// and fall back to the plugin's answer only when that value is empty
// (DeviceManager::get_user_last_machine). Orca clears its own value on every
// startup while installing its printer agent, long before any printer shows up
// in the device list, so the plugin's copy is what decides whether the Device
// tab comes back selected (GitHub issue #78). Keep it in
// <config_dir>/obn.state.json.

#include <mutex>
#include <string>

namespace obn::state {

class Store {
public:
    // Empty path disables disk persistence (useful for tests).
    explicit Store(std::string path);

    // Load the state file if it exists. Missing or malformed files leave the
    // store at its safe default (nothing remembered).
    void load();

    // Remember and persist a printer id. An empty id is ignored on purpose:
    // the slicer deselects the current printer for reasons that have nothing
    // to do with user intent (startup agent install, logout, a refresh tick
    // that finds the printer temporarily missing), and persisting those would
    // wipe the only surviving copy of the selection.
    void remember_machine(const std::string& dev_id);

    std::string remembered_machine() const;

private:
    void persist_locked() const;

    std::string        path_;
    mutable std::mutex mu_;
    std::string        remembered_machine_;
};

} // namespace obn::state
