## 2. Where the plugin is downloaded from

### 2.1. Base API

The URL is built by `GUI_App::get_http_url` based on the `country_code` stored in `app_config`:

Source: [GUI_App.cpp:1569-1595](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/GUI_App.cpp#L1569-L1595)

```cpp
std::string GUI_App::get_http_url(std::string country_code, std::string path)
{
    std::string url;
    if (country_code == "US") {
        url = "https://api.bambulab.com/";
    }
    else if (country_code == "CN") {
        url = "https://api.bambulab.cn/";
    }
    // ENV_CN_DEV  -> https://api-dev.bambu-lab.com/
    // ENV_CN_QA   -> https://api-qa.bambu-lab.com/
    // ENV_CN_PRE  -> https://api-pre.bambu-lab.com/
    // NEW_ENV_DEV_HOST -> https://api-dev.bambulab.net/
    // NEW_ENV_QAT_HOST -> https://api-qa.bambulab.net/
    // NEW_ENV_PRE_HOST -> https://api-pre.bambulab.net/
    else {
        url = "https://api.bambulab.com/";
    }
    url += path.empty() ? "v1/iot-service/api/slicer/resource" : path;
    return url;
}
```

The resulting base is `https://api.bambulab.com/v1/iot-service/api/slicer/resource` (or its regional equivalent).

### 2.2. Manifest request

`GUI_App::get_plugin_url` assembles the query parameter `slicer/plugins/cloud=<ver>`:

Source: [GUI_App.cpp:1569-1595](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/GUI_App.cpp#L1569-L1595)

```cpp
std::string GUI_App::get_plugin_url(std::string name, std::string country_code)
{
    std::string url = get_http_url(country_code);
    std::string curr_version = SLIC3R_VERSION;
    std::string using_version = curr_version.substr(0, 9) + "00";
    if (name == "cameratools")
        using_version = curr_version.substr(0, 6) + "00.00";
    url += (boost::format("?slicer/%1%/cloud=%2%") % name % using_version).str();
    return url;
}
```

For the networking plugin the helper is called with `name == "plugins"`. For `SLIC3R_VERSION = "02.06.00.51"` the request becomes:

```
GET https://api.bambulab.com/v1/iot-service/api/slicer/resource?slicer/plugins/cloud=02.06.00.00
```

### 2.3. Response format (JSON manifest)

The response is parsed in `GUI_App::download_plugin` (see [GUI_App.cpp](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/GUI_App.cpp) around lines 1617–1649). The expected shape:

```json
{
  "message": "success",
  "resources": [
    {
      "type": "slicer/plugins/cloud",
      "version": "02.05.03.xx",
      "description": "…changelog…",
      "url": "https://<cdn>/<path>/plugin.zip",
      "force_update": false
    }
  ]
}
```

Studio consumes only `version`, `description`, `url` and `force_update`. `url` points at a ZIP archive that is fetched next.

### 2.4. Special HTTP headers

- **`X-BBL-OS-Type`** is temporarily set to `"windows_arm"` when downloading the plugin on Windows ARM64 and restored to `"windows"` after the request: [GUI_App.cpp](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/GUI_App.cpp) 1597–1605, 1665–1672 and [PresetUpdater.cpp](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/PresetUpdater.cpp) 1209–1237.
- All other "sticky" headers (User-Agent etc.) are registered through `Slic3r::Http::set_extra_headers` and forwarded into the plugin via `bambu_network_set_extra_http_header`.

### 2.5. Background synchronization (OTA)

`PresetUpdater::priv::sync_plugins` hits the same HTTP API, but its purpose is to populate the OTA cache rather than install the plugin immediately:

Source: [PresetUpdater.cpp:1165-1253](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/PresetUpdater.cpp#L1165-L1253)

```cpp
void PresetUpdater::priv::sync_plugins(std::string http_url, std::string plugin_version)
{
    ...
    std::string using_version = curr_version.substr(0, 9) + "00";
    auto cache_plugin_folder = cache_path / PLUGINS_SUBPATH;        // data_dir/ota/plugins
    ...
    std::map<std::string, Resource> resources {
        {"slicer/plugins/cloud", { using_version, "", "", "", false, cache_plugin_folder.string()}}
    };
    sync_resources(http_url, resources, true, plugin_version, "network_plugins.json");
    ...
    if (result) {
        if (force_upgrade) {
            app_config->set("update_network_plugin", "true");
        } else {
            // push notification BBLPluginUpdateAvailable
        }
    }
}
```

`sync_resources` builds the final URL like this:

Source: [PresetUpdater.cpp:581-583](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/PresetUpdater.cpp#L581-L583)

```cpp
    std::string url = http_url;
    url += query_params;
    Slic3r::Http http = Slic3r::Http::get(url);
```

i.e. identically to `get_plugin_url`.

### 2.6. Download entry points

- **Background**: `GUI_App::on_init` → `CallAfter` → `preset_updater->sync(http_url, lang, network_ver, ...)` ([GUI_App.cpp](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/GUI_App.cpp) 1333–1340).
- **"Download Bambu Network Plug-in" dialog**: `GUI_App::updating_bambu_networking()` ([GUI_App.cpp:1999](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/GUI_App.cpp#L1999)) → `DownloadProgressDialog` → `UpgradeNetworkJob::process()` ([UpgradeNetworkJob.cpp:48-132](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/Jobs/UpgradeNetworkJob.cpp#L48-L132)).
- **Manual trigger from the WebView**: event `begin_network_plugin_download` ([GUI_App.cpp](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/GUI_App.cpp) ~4078–4090) and `ShowDownNetPluginDlg`.
- User-facing wiki article shown on failure: `https://wiki.bambulab.com/en/software/bambu-studio/failed-to-get-network-plugin` ([DownloadProgressDialog.cpp](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/DownloadProgressDialog.cpp) 32–33).

---

