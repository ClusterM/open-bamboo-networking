# Bambu Studio Network Plugin — research index

Reverse-engineering reference for how Bambu Studio integrates with its proprietary **Network Plugin** (`bambu_networking`) and `libBambuSource`: download/install, validation, C ABI, cloud/LAN wire formats, and camera/file-browser CTRL.

Derived from BambuStudio / OrcaSlicer sources, MITM of the stock plugin, and cross-ABI matrix runs — not from binary disassembly. OBN implementation status lives in [STATUS.md](../STATUS.md), not here.

## Contents

- [Introduction](00-intro.md)
- [1. Architecture overview](01-architecture.md)
- [2. Where the plugin is downloaded from](02-download.md)
- [3. Where it is stored and how it is installed](03-install.md)
- [4. What the plugin is, physically](04-physical.md)
- [5. Validation](05-validation.md)
- [6. The full C ABI contract](06-abi-intro.md)
  - [6.1. Initialization and lifecycle](06.01-lifecycle.md)
  - [6.2. Callbacks (registration)](06.02-callbacks.md)
  - [6.3. Cloud — connection and subscriptions](06.03-cloud-mqtt.md)
  - [6.4. Local printer connection (LAN)](06.04-lan.md)
  - [6.5. Authentication and user](06.05-auth.md)
  - [6.6. Binding / bind](06.06-bind.md)
  - [6.7. Printer selection and metadata](06.07-printer-selection.md)
  - [6.8. Submitting a print job](06.08.0-print-flows.md)
    - [6.8.0. End-to-end print flows](06.08.0-print-flows.md)
    - [6.8.1. Cloud upload flow](06.08.1-cloud-upload.md)
    - [6.8.2. MQTT `project_file` wire format](06.08.2-project-file.md)
    - [6.8.3. Timelapse-storage preflight](06.08.3-timelapse.md)
    - [6.8.4. MQTT AMS and PA calibration](06.08.4-ams-pa.md)
  - [6.9. User presets](06.09-presets.md)
  - [6.10. HTTP / cloud service](06.10-http.md)
  - [6.11. Camera](06.11-camera.md)
  - [6.12. MakerWorld / Mall](06.12-makerworld.md)
  - [6.13. Tracking / telemetry](06.13-tracking.md)
  - [6.14. File Transfer ABI (`ft_*`)](06.14-file-transfer.md)
  - [6.15. Filament Manager](06.15-filament.md)
  - [6.16. Error codes](06.16-errors.md)
- [7. The `libBambuSource` library](07-bambusource.md)
- [8. Additional notes](08-notes.md)
- [9. Map of key source locations](09-source-map.md)
