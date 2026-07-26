## 3. Where it is stored and how it is installed

### 3.1. Working directory (active plugin)

Studio loads the binary from **`<data_dir>/plugins/`**. The file name varies by OS:

| Platform | Path |
|----------|------|
| Windows  | `<data_dir>\plugins\bambu_networking.dll` |
| Windows  | `<data_dir>\plugins\BambuSource.dll` (optional, camera) |
| Windows  | `<data_dir>\plugins\live555.dll` (RTSP/media) |
| macOS    | `<data_dir>/plugins/libbambu_networking.dylib` |
| macOS    | `<data_dir>/plugins/libBambuSource.dylib` |
| macOS    | `<data_dir>/plugins/liblive555.dylib` |
| Linux    | `<data_dir>/plugins/libbambu_networking.so` |
| Linux    | `<data_dir>/plugins/libBambuSource.so` |
| Linux    | `<data_dir>/plugins/liblive555.so` |

On Linux `<data_dir>` is usually `~/.config/BambuStudio/` (wxWidgets XDG path), on macOS `~/Library/Application Support/BambuStudio/`, on Windows `%AppData%\BambuStudio\`.

The path is computed in `NetworkAgent::initialize_network_module`:

Source: [NetworkAgent.cpp:214-272](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/NetworkAgent.cpp#L214-L272)

```cpp
    auto plugin_folder = data_dir_path / "plugins";
    if (using_backup) plugin_folder = plugin_folder/"backup";
    ...
#if defined(_MSC_VER) || defined(_WIN32)
    library = plugin_folder.string() + "\\" + std::string(BAMBU_NETWORK_LIBRARY) + ".dll";
    ...
    networking_module = LoadLibrary(lib_wstr);
#else
    #if defined(__WXMAC__)
    library = plugin_folder.string() + "/" + std::string("lib") + std::string(BAMBU_NETWORK_LIBRARY) + ".dylib";
    #else
    library = plugin_folder.string() + "/" + std::string("lib") + std::string(BAMBU_NETWORK_LIBRARY) + ".so";
    #endif
    networking_module = dlopen(library.c_str(), RTLD_LAZY);
#endif
```

The constant `BAMBU_NETWORK_LIBRARY = "bambu_networking"` lives in [bambu_networking.hpp:105](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/bambu_networking.hpp#L105).

### 3.2. Backup copy

After a successful unpack `install_plugin` copies every top-level file from `<data_dir>/plugins/` into **`<data_dir>/plugins/backup/`**. If at startup the primary plugin fails to load or is version-incompatible, Studio makes a second attempt with `using_backup=true` — the path then becomes `<data_dir>/plugins/backup/`:

Source: [GUI_App.cpp:1787-1936](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/GUI_App.cpp#L1787-L1936)

```cpp
    fs::path dir_path(plugin_folder);
    if (fs::exists(dir_path) && fs::is_directory(dir_path)) {
        ...
        for (fs::directory_iterator it(dir_path); it != fs::directory_iterator(); ++it) {
            if (it->path().string() == backup_folder) continue;
            auto dest_path = backup_folder.string() + "/" + it->path().filename().string();
            if (fs::is_regular_file(it->status())) {
                ... CopyFileResult cfr = copy_file(it->path().string(), dest_path, error_message, false);
            } else {
                copy_framework(it->path().string(), dest_path);
            }
        }
    }
```

The retry logic is in `GUI_App::on_init_network` ([GUI_App.cpp:3637-3756](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/GUI_App.cpp#L3637-L3756)).

### 3.3. OTA cache (staging)

All background downloads land in **`<data_dir>/ota/plugins/`** (the constant `PLUGINS_SUBPATH` defined at `PresetUpdater.cpp:57`). That folder is expected to contain **all three** libraries plus a JSON manifest:

Source: [PresetUpdater.cpp:1131-1163](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/PresetUpdater.cpp#L1131-L1163)

```cpp
    network_library = cache_folder.string() + "/bambu_networking.dll";      // or .dylib / .so
    player_library  = cache_folder.string() + "/BambuSource.dll";
    live555_library = cache_folder.string() + "/live555.dll";
    std::string changelog_file = cache_folder.string() + "/network_plugins.json";
    if (fs::exists(network_library)
        && fs::exists(player_library)
        && fs::exists(live555_library)
        && fs::exists(changelog_file))
    {
        has_plugins = true;
        parse_ota_files(changelog_file, cached_version, force, description);
    }
```

If any of the files is missing, the cache is considered incomplete.

### 3.4. `network_plugins.json` format

The JSON is produced by `sync_resources` after unpacking the archive:

Source: [PresetUpdater.cpp:712-723](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/PresetUpdater.cpp#L712-L723)

```cpp
    json j;
    j["version"]     = resource_update->second.version;
    j["description"] = resource_update->second.description;
    j["force"]       = resource_update->second.force;
    boost::nowide::ofstream c;
    c.open(changelog_file, std::ios::out | std::ios::trunc);
    c << std::setw(4) << j << std::endl;
```

Minimal valid file:

```json
{
  "version": "02.06.00.50",
  "description": "…",
  "force": false
}
```

### 3.5. The "download -> install" flow

1. `UpgradeNetworkJob` (with `name="plugins"` and `package_name="networking_plugins.zip"`, [UpgradeNetworkJob.cpp:19-20](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Jobs/UpgradeNetworkJob.cpp#L19-L20)) calls:
   - `GUI_App::download_plugin("plugins", "networking_plugins.zip", ...)` — drops the ZIP into `temp_directory_path()/networking_plugins.zip` (a parallel branch in `WebDownPluginDlg` / `GuideFrame` uses the name `network_plugin.zip`).
   - `GUI_App::install_plugin("plugins", "networking_plugins.zip", ...)` — extracts the archive into **`<data_dir>/plugins/`** while preserving its internal directory hierarchy.
2. On success a flag is written: `app_config["app"]["installed_networking"] = "1"` ([GUI_App.cpp](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/GUI_App.cpp) 1906–1909).
3. `restart_networking()` ([GUI_App.cpp:1938-1942](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/GUI_App.cpp#L1938-L1942)) restarts the agent: it calls `on_init_network(try_backup=true)`, resets `StaticBambuLib`, re-registers callbacks and kicks off discovery.

### 3.6. Applying OTA at startup

If `update_network_plugin == "true"`, on the next launch — **before** network initialization — Studio copies the freshly downloaded libraries in:

Source: [GUI_App.cpp:3575-3635](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/GUI_App.cpp#L3575-L3635)

```cpp
void GUI_App::copy_network_if_available()
{
    if (app_config->get("update_network_plugin") != "true") return;
    auto plugin_folder = data_dir_path / "plugins";
    auto cache_folder  = data_dir_path / "ota" / "plugins";
#if defined(_MSC_VER) || defined(_WIN32)
    const char* library_ext = ".dll";
#elif defined(__WXMAC__)
    const char* library_ext = ".dylib";
#else
    const char* library_ext = ".so";
#endif
    for (auto& dir_entry : boost::filesystem::directory_iterator(cache_folder)) {
        if (boost::algorithm::iends_with(file_path, library_ext)) {
            copy_file(file_path, (plugin_folder / file_name).string(), error_message, false);
            fs::permissions(dest_path, fs::owner_read|fs::owner_write|fs::group_read|fs::others_read);
        }
    }
    fs::remove_all(cache_folder);
    app_config->set("update_network_plugin", "false");
}
```

Note: only **top-level files whose extension matches the library extension** are copied. Subdirectories and auxiliary files (e.g. certificates) are ignored. The shipped plugin must therefore be "flat" — just the library binary (`bambu_networking.{dll|so|dylib}`) plus, optionally, `BambuSource` and `live555`.

### 3.7. Removal

`GUI_App::remove_old_networking_plugins` wipes the **whole** `<data_dir>/plugins/` tree:

Source: [GUI_App.cpp:1983-2004](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/GUI_App.cpp#L1983-L2004)

```cpp
void GUI_App::remove_old_networking_plugins()
{
    auto plugin_folder = data_dir_path / "plugins";
    if (boost::filesystem::exists(plugin_folder)) {
        fs::remove_all(plugin_folder);
    }
}
```

---

