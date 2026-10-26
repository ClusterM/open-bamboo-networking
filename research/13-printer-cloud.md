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
| 13.5 Cloud print | [13.05-cloud-print.md](13.05-cloud-print.md) |

### What happens when

**On boot**, in this order, within a few seconds:

1. Device login: `GET …/device/login/ticket`, `POST …/device/login_v2` → device token ([§13.1](13.01-device-auth.md)).
2. `GET …/device/bind` (owner), `GET …/device/security/crls` and `GET …/device/security` (cloud service cert and CRLs, [§13.2](13.02-device-endpoints.md#security-material)).
3. MQTT `CONNECT` to the regional broker (`us.mqtt.bambulab.com:8883` here) and `SUBSCRIBE device/<serial>/request` ([§13.4](13.04-cloud-command-signing.md)).
4. `PUT …/device/info`, a burst of `POST …/device/ota`, HMS lookups, owner profile and avatar for the screen.

**While idle** (and while printing):

- every hour after login, `GET …/device/security/crls` and `GET …/device/security` ([§13.2](13.02-device-endpoints.md#security-material));
- every 6 hours, with `improvement_policy` on, a small encrypted `event_track` upload ([§13.5](13.05-cloud-print.md#6-camera-data-uploads));
- sometimes `GET …/device/bind` again; what triggers it is not known yet ([§13.2](13.02-device-endpoints.md#device-state)).

**On demand:**

- Camera opened in Studio → the cloud pushes a signed `liveview.prepare` ([§10.3](10.03-mqtt-field-encryption.md)).
- Studio provisions the printer's app trust store → `security.app_cert_install` relayed by the broker ([§10.2](10.02-secrets.md#provisioning-printer-trust-store)).
- Cloud print started in Studio → the cloud pushes a signed `print.project_file`; the printer reports task events, fetches the model if it is on S3, and uploads camera data ([§13.5](13.05-cloud-print.md)).
- Print of a file on printer storage, started in Studio or on the printer screen → no cloud task and no task events, but the same camera uploads as a cloud print ([§13.5](13.05-cloud-print.md#prints-the-cloud-does-not-track)).
- Bind from the printer screen → the ticket flow in [§13.3](13.03-bind-flows.md).
- Refresh in the printer's filament picker → the owner's filament presets are fetched again ([§13.2](13.02-device-endpoints.md#user-filament-presets)). This is the only known way user filament presets reach the printer.

### Evidence and scope

**Evidence:** printer-side MITM (TLS-terminating proxy for both HTTPS and MQTT) of one X2D (`N6`, firmware `01.02.00.00`, Developer Mode off, US region) with stock Studio `02.08.04.57` on Linux (network plugin `02.08.04.60`) on the other side, 2026-10-22: cold boots, liveview, the file browser and a successful cloud print, a QR-code bind and a PIN bind. 2026-10-25: a QR bind after a factory reset, a refresh in the printer's filament picker, a second cloud print, this one with the model sent over LAN FTPS and different policy flags, three that paused on an error (objects on the bed, no build plate) and were then cancelled, a full cloud print without timelapse that paused on objects on the bed, was resumed and finished, two hybrid prints cancelled from Studio without any error (with and without timelapse), and three prints from the printer's USB drive, started in Studio or on the printer screen (one of them with objects on the bed). 2026-10-25/26: 14 hours idle overnight. Model code: [N6.json:3](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/resources/printers/N6.json#L3) and [L81-L82](https://github.com/bambulab/BambuStudio/blob/12f17b06f4f537f9c03162d08bb70cf733c42839/resources/printers/N6.json#L81-L82).

Everything here comes from one printer model on one firmware. Other models may differ in header values, endpoint set and order.

Values that identify the printer or the account (serial, user id, tokens, `passwd`, ticket codes, access code, object URLs) are not recorded; only their shape is.

Out of scope: the AWS IoT WebSocket (`…-ats.iot.eu-west-1.amazonaws.com/mqtt`) that appears in the same proxy logs comes from another host on the LAN, not from the printer.
