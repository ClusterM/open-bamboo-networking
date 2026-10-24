## 13. Printer ↔ cloud (device side)

The printer is a cloud client in its own right. It logs in to `api.bambulab.com` with its own credentials, keeps its own MQTT session on the regional broker, reports state, downloads cloud-print files and uploads snapshots, all without Studio. Studio only reaches the printer through the same broker ([§8.3](08.03-cloud-mqtt.md)) or over LAN ([§8.4](08.04-lan.md)).

This chapter documents that device side as seen on the wire. A networking plugin never speaks it, but it explains things the plugin does see: why cloud-authored MQTT frames verify on a printer with an empty app trust store, where the printer gets the cloud's signing certificate, how the printer half of a QR or PIN bind works, and which printer data the cloud already holds (for example the LAN access code, [§10.6](10.06-lan-tls-and-access-codes.md)).

### Contents

| Section | File |
| --- | --- |
| 13.1 Device login and HTTP headers | [13.01-device-auth.md](13.01-device-auth.md) |
| 13.2 Device REST endpoints | [13.02-device-endpoints.md](13.02-device-endpoints.md) |
| 13.3 Binding to an account (QR and PIN) | [13.03-bind-flows.md](13.03-bind-flows.md) |
| 13.4 Cloud MQTT session and command signing | [13.04-cloud-command-signing.md](13.04-cloud-command-signing.md) |

### What happens when

**On boot**, in this order, within a few seconds:

1. Device login: `GET …/device/login/ticket`, `POST …/device/login_v2` → device token ([§13.1](13.01-device-auth.md)).
2. `GET …/device/bind` (owner), `GET …/device/security/crls` and `GET …/device/security` (cloud service cert and CRLs, [§13.2](13.02-device-endpoints.md#security-material)).
3. MQTT `CONNECT` to the regional broker (`us.mqtt.bambulab.com:8883` here) and `SUBSCRIBE device/<serial>/request` ([§13.4](13.04-cloud-command-signing.md)).
4. `PUT …/device/info`, a burst of `POST …/device/ota`, HMS lookups, owner profile and avatar for the screen.

**On demand:**

- Camera opened in Studio → the cloud pushes a signed `liveview.prepare` ([§10.3](10.03-mqtt-field-encryption.md)).
- Studio provisions the printer's app trust store → `security.app_cert_install` relayed by the broker ([§10.2](10.02-secrets.md#provisioning-printer-trust-store)).
- Cloud print started in Studio → [Cloud print, end to end](#cloud-print-end-to-end) below.
- Bind from the printer screen → the ticket flow in [§13.3](13.03-bind-flows.md).

### Cloud print, end to end

Both halves of a cloud print (`start_print`, or `start_local_print_with_record`, which also ends in a cloud dispatch):

1. **Studio → cloud** ([§8.8.3](08.08-print-abi.md#883-bambu_network_start_local_print_with_record), [§8.8.4](08.08-print-abi.md#884-bambu_network_start_print)). Create a project, `PUT` the small config 3MF and the full sliced 3MF to `or-cloud-upload-prod` through presigned URLs, register the S3 URL on the project, then `POST /v1/user-service/my/task`.
2. **Cloud → printer** ([§13.4](13.04-cloud-command-signing.md)). The cloud publishes `print.project_file` on `device/<serial>/request`, signed with the service cert, `sequence_id "0"`, with the download URL inside `url_enc` ([§10.3](10.03-mqtt-field-encryption.md)).
3. **Printer → cloud and S3** ([§13.2](13.02-device-endpoints.md#cloud-print-task)). `PATCH …/device/task/{task_id}` `print_kickoff`, download the 3MF straight from S3, `print_start`. During preparation it uploads a camera frame from the bed foreign-object check to `or-cloud-device-prod`. Meanwhile it reports progress over MQTT `push_status` as usual ([§12](12-mqtt.md)).
4. **End of print** ([§13.2](13.02-device-endpoints.md#cloud-print-task)). `POST …/device/ttcode`, `PUT …/device/info`, a finish photo uploaded to `or-cloud-device-prod`, and `PATCH` `print_success` carrying that photo's URL.
5. **Print history.** Studio reads the task back from `GET /v1/user-service/my/tasks` ([§8.10](08.10-http.md)); the finish photo comes back as `snapShot`, re-signed for `GET`.

In a cloud print Studio and the printer never talk to each other directly; they share only the task id, the MQTT frame and the S3 objects.

### Evidence and scope

**Evidence:** printer-side MITM (TLS-terminating proxy for both HTTPS and MQTT) of one X2D (`N6`, firmware `01.02.00.00`, Developer Mode off, US region) with stock Studio `02.08.04.57` on Linux (network plugin `02.08.04.60`) on the other side, 2026-10-22: cold boots, liveview, the file browser and a successful cloud print, a QR-code bind and a PIN bind. Model code: [N6.json:3](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/resources/printers/N6.json#L3) and [L81-L82](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/resources/printers/N6.json#L81-L82).

Everything here comes from one printer model on one firmware. Other models may differ in header values, endpoint set and order.

Values that identify the printer or the account (serial, user id, tokens, `passwd`, ticket codes, access code, object URLs) are not recorded; only their shape is.

Out of scope: the AWS IoT WebSocket (`…-ats.iot.eu-west-1.amazonaws.com/mqtt`) that appears in the same proxy logs comes from another host on the LAN, not from the printer.
