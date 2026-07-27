## 13. Cloud HTTP transport

Common HTTPS layer used by every cloud REST call the networking plugin makes — authentication, bind, print-job orchestration, preset sync, device firmware, MakerWorld, Filament Manager. Per-ABI symbol mappings live under [§8.10](08.10-http.md) and the other §8 HTTP surfaces; this page is only hosts, headers, and the shared response envelope.

### Regional hosts

Chosen by the user's `country_code` in `app_config` (the same switch `GUI_App::get_http_url` uses for the plugin manifest, see [§2.1](02-download.md)):

| Region | API host | Web host |
|--------|----------|----------|
| `US` / default | `https://api.bambulab.com` | `https://bambulab.com` |
| `CN` | `https://api.bambulab.cn` | `https://bambulab.cn` |

### Authentication header

All authenticated endpoints require exactly one mandatory header:

```
Authorization: Bearer <access_token>
```

### Fingerprint headers

MITM/SSLKEYLOGFILE captures of the stock plugin show the full fingerprint header set on every request:

```
User-Agent: bambu_network_agent/<agent-ver>
X-BBL-Client-Name: BambuStudio
X-BBL-Client-Type: slicer
X-BBL-Client-Version: <slicer-ver>
X-BBL-Device-ID: <slicer-machine-uuid>
X-BBL-Language: en-US
X-BBL-OS-Type: linux
X-BBL-OS-Version: <os-build, e.g. 10.0.26200>
X-BBL-Agent-Version: <agent-ver>
X-BBL-Executable-info: {}
X-BBL-Agent-OS-Type: linux
```

`X-BBL-Client-Version` is the slicer version; `X-BBL-Agent-Version` is the networking plugin version. `X-BBL-OS-Type` and `X-BBL-Agent-OS-Type` both report `linux` when running through pjarczak's WSL2 bridge; native Linux builds send `linux` directly. `X-BBL-OS-Version` carries the OS build string (Windows build number when relayed through pjarczak). `X-BBL-Executable-info` is always the literal string `{}`. `X-BBL-Device-ID` is a machine-local UUID, not the printer serial.

Plus anything Studio injects through `bambu_network_set_extra_http_header` ([§8.10](08.10-http.md)). Direct probes against the production server confirm that **none** of the `X-BBL-*` headers, nor even the custom `User-Agent`, are required for **most** endpoints (auth, profile, presets, bind, project/upload) — there they influence analytics only.

> **Exception — `POST /v1/user-service/my/task` (cloud print / "local print with record").** On live hardware two of these headers are **hard requirements**; without them the endpoint returns **HTTP 403** ("no access rights to the content") and the cloud print never starts:
> - **`X-BBL-Client-Name: BambuStudio`** — MakerWorld's user-service authorizes access to the just-uploaded print content only for the stock client identity. Other client-name values are rejected with 403.
> - **`X-BBL-OS-Type`** — must match the OS that performed the upload (`linux` / `windows` / `macos`); a mismatch also 403s.
>
> Subtractive bisection against the production server (2026-07) narrowed the requirement to exactly these two `X-BBL-*` headers; the remaining fingerprint headers stay analytics-only even on `/my/task`. The signed **command-security** headers (`x-bbl-app-certification-id`, `x-bbl-device-security-sign`) are additionally needed for a *secured* printer — see [§10.5](10.05-http-pop.md) and [§11.2.1](11.02-cloud-upload.md).

An additional header `X-BBL-Client-ID` appears on **device-scoped endpoints** (e.g. firmware version query, device metadata) but not on account-scoped endpoints (auth, profile, presets):

```
X-BBL-Client-ID: slicer:{user_id}:{4-char-suffix}
```

`user_id` is the numeric user ID (same as `uidStr` in the profile response). The 4-character suffix appears to be a random or session-derived nonce; its exact derivation is unconfirmed. This header is not required for the API to accept the call.

### Common JSON envelope

Most JSON responses share:

```json
{
  "message": "success" | "<human message>",
  "code":    null      | <integer error>,
  "error":   null      | "<string>",
  "...endpoint-specific fields..."
}
```

`code` is the "business" error code the GUI inspects (for example `14` for preset quota exceeded, `2` for missing resources). Transport-level failures surface as non-2xx HTTP codes — typically `400` for malformed bodies, `401` for a missing/expired bearer, `422` for invalid-input (e.g. `PATCH` against an unknown ID), `5xx` for server-side failures.

For endpoints that return a plain-text error (notably `POST /slicer/setting` with a missing mandatory field) the body is a bare string — the envelope is absent.

### Where the REST surfaces live

| Concern | Endpoint(s) | Section | Evidence |
|---------|-------------|---------|----------|
| Bearer-token login / refresh / profile / logout | `POST /v1/user-service/user/ticket/<T>`, `POST /v1/user-service/user/refreshtoken` (body `{"refreshToken":…}`), `GET /v1/user-service/my/profile`, `POST /v1/user-service/my/logout` (body `{"refreshtoken":…}`, on `user_logout(true)`) | [§8.5](08.05-auth.md) ([§8.5.1](08.05-auth.md), [§8.5.14](08.05-auth.md)) | MITM + probe |
| Device account bind / pin bind / unbind | Account bind cloud: `GET`+`POST /v1/user-service/my/ticket/<T>` (device ticket; LAN mint is TCP `:3000` login, [§8.6.3](08.06-bind.md)); pin: `POST /v1/user-service/my/pincode/<PIN>` body `{"pincode":…}`; unbind: `DELETE /v1/iot-service/api/user/bind` body `{"dev_id","force"}` | [§8.6](08.06-bind.md) ([§8.6.3](08.06-bind.md)–[§8.6.5](08.06-bind.md)) | MITM + LAN pcap (stock 2026-07) |
| Bind ownership query (`query_bind_status`) | `GET /v1/iot-service/api/user/bind_list?dev_ids=<id>[,…]` (not `/user/bind`) | [§8.6.7](08.06-bind.md) | MITM probe (`stock_query_bind.mitm`) |
| WebView SSO ticket | `GET /v1/user-service/user/ticket` then `POST /v1/user-service/my/ticket/<T>` | [§8.6.6](08.06-bind.md) | MITM |
| Device list / rename (not bind ABI) | `GET /v1/iot-service/api/user/bind`, `PATCH /v1/iot-service/api/user/device/info` (also `GET …/user/print`) | [§8.10](08.10-http.md) | MITM + probe |
| Printer firmware catalogue | stock: `GET /v1/iot-service/api/user/device/version?dev_id=<serial>` (add `X-BBL-Client-ID: slicer:<uid>:<4-char-suffix>`) | [§8.7](08.07-printer-selection.md) | SSLKEYLOGFILE (stock) |
| Cloud print-job pipeline | `POST /v1/iot-service/api/user/project`, `PUT <presigned>`, …, `POST /v1/user-service/my/task` | [§11.2](11.02-cloud-upload.md) | MITM |
| Generic HTTP ABI (`get_user_tasks`, …) | see per-symbol list | [§8.10](08.10-http.md) | MITM + probe |
| User presets sync | `<m> /v1/iot-service/api/slicer/setting[/<id>]?public=false&version=<bundle>` | [§8.9](08.09-presets.md) | MITM + probe |
| Filament Manager (spool catalogue) | `<m> /v1/design-user-service/my/filament/v2[/batch|/ams/sync]`, `GET /v1/design-user-service/filament/config` | [§8.15](08.15-filament.md) | MITM |
| MakerWorld / Mall, OSS upload | various `design-service` / `iot-service` / OSS paths | [§8.12](08.12-makerworld.md) | not captured |
| Camera / live view / HMS snapshot | not captured | [§8.11](08.11-camera.md) | — |
| Analytics / telemetry | not captured | [§8.13](08.13-tracking.md) | — |
