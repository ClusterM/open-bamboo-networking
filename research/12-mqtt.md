## 12. MQTT wire format (Studio-forwarded)

**Bonus chapter.** Catalogues of MQTT JSON that **Bambu Studio builds** and publishes through `bambu_network_send_message` / `bambu_network_send_message_to_printer`. The networking plugin **forwards these frames unchanged** — it does not implement AMS, PA, camera toggles, upgrade confirms, etc. Use this section when writing a custom client or debugging Studio ↔ printer MQTT.

Session open / topics / `sequence_id` / ack conventions: **[§6.2](06.02-mqtt.md)**. Plugin-built print start (`print.project_file`) and cloud `/my/task`: **[§8.8](08.08-print-abi.md)** — out of scope here. Field encryption / signing when Developer Mode is off: [§10.3](10.03-mqtt-field-encryption.md) / [§10.4](10.04-mqtt-signing.md).

**Exception — [§12.1](12.01-status.md):** documents both Studio’s `pushing.*` / `info.get_version` requests **and** inbound `print.push_status` telemetry (capability bits + leaf field catalogues §12.1.1–12.1.6). That telemetry is printer-built, not Studio-built; it is the other half of the status loop and is too important to omit.

### Contents

| Section | File |
| --- | --- |
| 12.1 Status / `push_status` (hub) | [12.01-status.md](12.01-status.md) |
| 12.1.1 Fields — job / progress | [12.01.01-fields-job.md](12.01.01-fields-job.md) |
| 12.1.2 Fields — thermal / fans / lights | [12.01.02-fields-thermal-fans.md](12.01.02-fields-thermal-fans.md) |
| 12.1.3 Fields — AMS / filament | [12.01.03-fields-ams.md](12.01.03-fields-ams.md) |
| 12.1.4 Fields — `device.*` | [12.01.04-fields-device.md](12.01.04-fields-device.md) |
| 12.1.5 Fields — camera / AI | [12.01.05-fields-camera-ai.md](12.01.05-fields-camera-ai.md) |
| 12.1.6 Fields — net / upgrade / errors | [12.01.06-fields-net-upgrade-errors.md](12.01.06-fields-net-upgrade-errors.md) |
| 12.2 System | [12.02-system.md](12.02-system.md) |
| 12.3 Print job & HMS | [12.03-print-job.md](12.03-print-job.md) |
| 12.4 Temperatures / extruder | [12.04-temps-extruder.md](12.04-temps-extruder.md) |
| 12.5 Fans / air duct | [12.05-fans.md](12.05-fans.md) |
| 12.6 Axis / homing | [12.06-axis.md](12.06-axis.md) |
| 12.7 AMS filament | [12.07-ams-filament.md](12.07-ams-filament.md) |
| 12.8 Pressure-advance (PA) | [12.08-pa-calibration.md](12.08-pa-calibration.md) |
| 12.9 Flow-ratio calibration | [12.09-flow-calibration.md](12.09-flow-calibration.md) |
| 12.10 Machine cali & `print_option` | [12.10-print-options-calib.md](12.10-print-options-calib.md) |
| 12.11 Camera / timelapse | [12.11-camera.md](12.11-camera.md) |
| 12.12 AI / xcam | [12.12-xcam.md](12.12-xcam.md) |
| 12.13 Firmware upgrade | [12.13-upgrade.md](12.13-upgrade.md) |
| 12.14 Nozzle rack / mapping | [12.14-nozzle-rack.md](12.14-nozzle-rack.md) |
| 12.15 Arbitrary G-code (`gcode_line`) | [12.15-gcode-line.md](12.15-gcode-line.md) |

### Common conventions

Each outbound command below follows the envelope from [§6.2](06.02-mqtt.md):

```json
{ "<section>": { "command": "<name>", "sequence_id": "<decimal-string>", "...": "..." } }
```

Studio assigns `sequence_id` in **20000–29999**. Replies arrive on `device/<dev_id>/report` under the same top-level section; Studio usually dispatches by `command` name (exact seq matching is sparse). See [§6.2 Request → response](06.02-mqtt.md#request--response-acks-and-errors).

**Out of scope:** `print.project_file` (plugin), TCP `:3000` `login.*`, cloud HTTPS ([§6.6](06.06-cloud-rest.md)).
