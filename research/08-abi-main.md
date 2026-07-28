## 8. The main module ABI contract

All symbols are resolved through `GetProcAddress` (Windows) / `dlsym` (Linux, macOS) in `NetworkAgent::get_network_function`:

Source: [NetworkAgent.cpp:529-580](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/NetworkAgent.cpp#L529-L580)

```cpp
void* NetworkAgent::get_network_function(const char* name)
{
    if (!networking_module) return nullptr;
#if defined(_MSC_VER) || defined(_WIN32)
    return GetProcAddress(networking_module, name);
#else
    return dlsym(networking_module, name);
#endif
}
```

Symbol names are not mangled — every function must be declared `extern "C"`.

> ABI note: even though this is a C-style interface, the signatures use C++ types (`std::string`, `std::vector`, `std::map`, `std::function`, and custom structs `PrintParams`/`BBLModelTask`/…). The plugin must therefore be built with the same compiler and libstdc++/libc++ standard-library ABI as Bambu Studio itself. It is **not** a pure C ABI — mixing compilers/linkers (e.g. GCC vs. MSVC) is not safe.

### Shared types by chapter

Structs / enums used by live `bambu_network_*` symbols are documented with their owning ABI chapter (`PrintParams` / `SendingPrintJobStage` → [§8.8](08.08-print-abi.md); `BindJobStage` / `detectResult` → [§8.6](08.06-bind.md); `MessageFlag` → [§8.3](08.03-cloud-mqtt.md); `TaskQueryParams` → [§8.10](08.10-http.md); MakerWorld / publish types → [§8.12](08.12-makerworld.md); filament / AMS → [§8.15](08.15-filament.md); `ConnectStatus` → [§8.2](08.02-callbacks.md); `ft_*` → [§8.14](08.14-file-transfer.md)).

### Header-only / unused typedefs

[`bambu_networking.hpp`](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/bambu_networking.hpp) also declares a few names that **no** `NetworkAgent` `dlsym` / wrapper uses on pin `12f17b06`. Keep them for header parity; do not invent plugin entry points around them.

**Orphan callback typedefs** ([bambu_networking.hpp:145-147](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/bambu_networking.hpp#L145-L147)):

| Typedef | Signature | Notes |
| --- | --- | --- |
| `LoginFn` | `std::function<void(int retcode, std::string info)>` | Not wired through `NetworkAgent`. Live login progress uses `OnUpdateStatusFn` / auth symbols ([§8.5](08.05-auth.md), [§8.6](08.06-bind.md)). |
| `ResultFn` | `std::function<void(int result, std::string info)>` | Same — unused by Studio’s network wrappers. |
| `CancelFn` | `std::function<bool()>` | Same shape as `WasCancelledFn`, but the **live** print/publish cancel typedef is `WasCancelledFn` ([§8.8](08.08-print-abi.md)). Unrelated GUI `CancelFn` aliases exist outside this header. |

**`CertificateInformation`** ([bambu_networking.hpp:311-317](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/src/slic3r/Utils/bambu_networking.hpp#L311-L317)) — present in the header, not referenced by any `NetworkAgent` typedef or Studio `dlsym` on this pin:

| Field | Type | Meaning (literal) |
| --- | --- | --- |
| `issuer` | `std::string` | Certificate issuer DN / label |
| `sub_name` | `std::string` | Subject name |
| `start_date` | `std::string` | Not-before |
| `end_date` | `std::string` | Not-after |
| `serial_number` | `std::string` | Certificate serial |

Live device / app cert flows use `update_cert` / `install_device_cert` ([§8.4](08.04-lan.md)) and the trust material in [§10.2](10.02-secrets.md), not this struct.

