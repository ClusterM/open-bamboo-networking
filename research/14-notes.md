## 14. Additional notes

1. **Sanity entry point for debugging**: immediately after `create_agent` Studio makes the exact sequence of calls documented in [§8.1.1](08.01-initialization.md) (common contract / sequence). Observing those in order is the shortest way to confirm that the ABI is wired correctly.
2. `QueueOnMainFn` ([§8.2.2](08.02-callbacks.md)) is the plugin's only safe path onto Studio's GUI thread (`CallAfter`). Studio's own inbound callback lambdas already marshal with `CallAfter` / `wxQueueEvent` — that does **not** replace `queue_on_main` for work the **plugin** initiates. wxWidgets is not thread-safe.
3. **Certificate files (`set_cert_file`)** — full detail in [§10.6](10.06-lan-tls-and-access-codes.md) / [§8.1.8](08.01-initialization.md). Studio passes `(<resources>/cert, slicer_base64.cer)`; both `slicer_base64.cer` (cloud) and `printer.cer` (BBL CA bundle) live in that folder. Stock plugin LAN trust behaviour is not documented here beyond the printer-side TLS observations in [§10.6](10.06-lan-tls-and-access-codes.md) / [§8.1.8](08.01-initialization.md).
4. **ABI/STL compatibility** is the single biggest foot-gun of this contract: the plugin has to be built with the exact same toolchain that built Bambu Studio (matching MSVC runtime on Windows, matching libstdc++ ABI on Linux, matching Xcode/libc++ on macOS). Any mismatch is undefined behaviour the moment a `std::string` / `std::map` crosses the library boundary.

---

