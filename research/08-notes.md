## 8. Additional notes

1. **Sanity entry point for debugging**: immediately after `create_agent` Studio makes the exact sequence of calls documented in § 6.1 ("Initialization sequence"). Observing those in order is the shortest way to confirm that the ABI is wired correctly.
2. `QueueOnMainFn` is critical: nearly every UI-touching callback must be dispatched through this lambda — wxWidgets is not thread-safe, and direct calls from the plugin's worker threads will race.
3. **Certificate files (`set_cert_file`)** — full detail in §6.1.1. Studio passes `(<resources>/cert, slicer_base64.cer)`; both `slicer_base64.cer` (cloud) and `printer.cer` (BBL CA bundle) live in that folder. Stock plugin LAN trust behaviour is not documented here beyond the printer-side TLS observations in §6.1.1.
4. **ABI/STL compatibility** is the single biggest foot-gun of this contract: the plugin has to be built with the exact same toolchain that built Bambu Studio (matching MSVC runtime on Windows, matching libstdc++ ABI on Linux, matching Xcode/libc++ on macOS). Any mismatch is undefined behaviour the moment a `std::string` / `std::map` crosses the library boundary.

---

