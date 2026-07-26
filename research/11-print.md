## 11. Print jobs

How Bambu Studio starts a print or upload, which ABI entry points it chooses, and what the stock plugin does on the wire (cloud S3 / FTPS / `:6000`).

### Contents

- [11.1. Studio-side orchestration](11.01-studio-orchestration.md) — UI → `PrintJob` / `SendJob`, decision tree, callbacks
- [11.2. Cloud upload flow](11.02-cloud-upload.md) — MITM order, FTPS vs BRTC, `/my/task` trigger
- [11.3. Timelapse-storage preflight](11.03-timelapse-preflight.md) — Studio-built `ipcam_get_media_info`

ABI symbol table for `start_*` / `PrintParams`: [§8.8](08.08-print-abi.md). MQTT `project_file` wire: [§12.1](12.01-project-file.md). Field encryption / signing / PoP: [§10.3](10.03-mqtt-field-encryption.md) / [§10.4](10.04-mqtt-signing.md) / [§10.5](10.05-http-pop.md).
