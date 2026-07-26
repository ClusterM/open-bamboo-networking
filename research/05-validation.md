## 5. Validation

### 5.1. Studio <-> plugin version compatibility

The main check is that the first **8 characters** of the version string match, i.e. `MAJOR.MINOR.PATCH` without the build suffix:

Source: [GUI_App.cpp:2006-2022](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/GUI_App.cpp#L2006-L2022)

```cpp
bool GUI_App::check_networking_version()
{
    std::string network_ver = Slic3r::NetworkAgent::get_version();
    std::string studio_ver = SLIC3R_VERSION;   // "02.06.00.51"
    if (network_ver.length() >= 8) {
        if (network_ver.substr(0,8) == studio_ver.substr(0,8)) {  // "02.06.00"
            m_networking_compatible = true;
            return true;
        }
    }
    m_networking_compatible = false;
    return false;
}
```

For `SLIC3R_VERSION = "02.06.00.51"` the plugin must return **a string starting with `"02.06.00"`** (e.g. `"02.06.00.50"`). Otherwise Studio marks it incompatible, sets `m_networking_need_update=true` and pops up the update dialog.

> Observation: on Linux this version check is effectively the **only** formal compatibility gate — see § 5.2, where the signature check is a no-op on that platform.

The plugin exposes its version through the symbol `bambu_network_get_version` (`func_get_version` typed as `std::string(*)(void)`). See `NetworkAgent::get_version`:

Source: [NetworkAgent.cpp:582-603](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/NetworkAgent.cpp#L582-L603)

```cpp
std::string NetworkAgent::get_version()
{
    bool consistent = true;
    if (check_debug_consistent_ptr) {
#if defined(NDEBUG)
        consistent = check_debug_consistent_ptr(false);
#else
        consistent = check_debug_consistent_ptr(true);
#endif
    }
    if (!consistent) return "00.00.00.00";
    if (get_version_ptr) return get_version_ptr();
    return "00.00.00.00";
}
```

A separate consistency check is `bambu_network_check_debug_consistent(bool is_debug)` — it lets the plugin reject a mismatched debug/release build. If it returns `false`, Studio treats the version as `"00.00.00.00"` and refuses to proceed.

### 5.2. Binary signature

Before calling `LoadLibrary`/`dlopen` Studio compares the module's publisher with Studio's own publisher:

Source: [NetworkAgent.cpp:214-272](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/NetworkAgent.cpp#L214-L272)

```cpp
    std::optional<SignerSummary> self_cert_summary, module_cert_summary;
    if (validate_cert) self_cert_summary = SummarizeSelf();
    ...
    if (self_cert_summary) {
        module_cert_summary = SummarizeModule(library);
        if (module_cert_summary) {
            if (IsSamePublisher(*self_cert_summary, *module_cert_summary))
                networking_module = LoadLibrary(lib_wstr);   // (or dlopen)
            else
                BOOST_LOG_TRIVIAL(info) << "module is from another publisher...";
        }
    } else {
        networking_module = LoadLibrary(lib_wstr);           // self cert unknown -> load as is
    }
```

`IsSamePublisher`:

Source: [CertificateVerify.cpp:294-300](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/CertificateVerify.cpp#L294-L300)

```cpp
bool IsSamePublisher(const SignerSummary& a, const SignerSummary& b)
{
    if (!a.team_id.empty() && a.team_id == b.team_id) return true;   // macOS TeamID
    if (a.spki_sha256 == b.spki_sha256) return true;                 // same SPKI
    if (a.cert_sha256 == b.cert_sha256) return true;                 // same certificate
    return false;
}
```

- **Windows**: the Authenticode signature of the main `bambu-studio.exe` and of `bambu_networking.dll` must share either an SPKI or a certificate. If the plugin is unsigned, `SummarizeModule` returns `nullopt`, the "error" branch is logged, `networking_module` stays `nullptr`, and the module **will not be loaded**.
- **macOS**: the comparison uses the `team_id` (Developer ID).
- **Linux**: `SummarizeSelf` / `SummarizeModule` **always return `std::nullopt`** — see:

Source: [CertificateVerify.cpp:291-291](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/CertificateVerify.cpp#L291-L291)

```cpp
#else
    std::optional<SignerSummary> SummarizeSelf() { return std::nullopt; }
    std::optional<SignerSummary> SummarizeModule(const std::string&) { return std::nullopt; }
#endif
```

Therefore on Linux `if (self_cert_summary)` is false and Studio takes the "load as is" branch — **the signature is effectively not verified on Linux**.

### 5.3. Bypassing the signature check

`AppConfig` exposes a flag **`ignore_module_cert`**, which is forwarded to the `validate_cert` parameter:

Source: [GUI_App.cpp:3639](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/GUI_App.cpp#L3639)

```cpp
    int load_agent_dll = Slic3r::NetworkAgent::initialize_network_module(false, !app_config->get_bool("ignore_module_cert"));
```

Setting `ignore_module_cert = 1` in `BambuStudio.conf` disables the publisher check on Windows/macOS entirely.

### 5.4. What "plugin installed" looks like to Studio

- A boolean **`installed_networking`** key in `app_config` (section `app`) — set to `"1"` after a successful `install_plugin` ([GUI_App.cpp:1906-1909](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/GUI_App.cpp#L1906-L1909)). This flag drives the "show install/update dialog" logic.
- The actual "the plugin works" check is this chain:
  1. `LoadLibrary`/`dlopen` returns non-null;
  2. `bambu_network_check_debug_consistent` returns `true` for the appropriate build flavor;
  3. `bambu_network_get_version` returns a string at least 8 chars long with the right version prefix;
  4. `BambuSource` also loaded successfully.

### 5.5. Archive integrity (MD5/SHA)

**Not checked.** There is no hash verification of the ZIP anywhere in `download_plugin` / `install_plugin` / `sync_resources` ([GUI_App.cpp](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/GUI/GUI_App.cpp), [PresetUpdater.cpp](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/PresetUpdater.cpp)). The only defense-in-depth measure is the binary's own signature.

Error codes of the form `BAMBU_NETWORK_ERR_CHECK_MD5_FAILED` (see `[bambu_networking.hpp:29](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/bambu_networking.hpp#L29), 54, 70`) belong to MD5 checks **inside the plugin** during print-job uploads, not to verification of the plugin itself.

---

