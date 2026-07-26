## 12. MQTT wire format

On-wire JSON catalogues for print and calibration commands, and `push_status` capability bitmaps. How sessions are opened (LAN vs cloud, auth, dual subscribe) lives in [§6.2](06.02-mqtt.md).

### Contents

- [12.1. `project_file` command](12.01-project-file.md) — fields, URL schemes, PrintParams matrix
- [12.2. AMS and PA calibration commands](12.02-ams-pa.md)
- [12.3. `push_status` capability flags](12.03-push-status-capabilities.md)

Field encryption: [§10.3](10.03-mqtt-field-encryption.md). MQTT signing: [§10.4](10.04-mqtt-signing.md). Studio print orchestration: [§11](11-print.md).
