## 7. Lifecycle

Idle behaviour of the stock networking plugin **outside print** — what has to be running so Studio can show printers, telemetry, and be ready for a later job. This is not a single linear pipeline: after `start()`, discovery, cloud REST, cloud MQTT, LAN MQTT, and cert provisioning overlap in time and keep running for the whole session. Channel map: [§6](06-channels.md). Algorithms live in the linked chapters; here is only the operating picture.

Print / upload / `POST /my/task` are **out of scope** — see [§11 Print](11-print.md).

### Agent bring-up

Studio loads the plugin, checks version / signature ([§5](05-validation.md)), then creates an opaque agent and drives a fixed setup sequence before any networking work is allowed. That order is `create_agent` → `set_config_dir` → `init_log` → `set_cert_file` → HTTP extra headers → the full `set_on_*_fn` battery → `set_country_code` → `start` → `start_discovery`. Nothing that talks to printers or Bambu cloud should begin before `start()`; after that the agent’s worker threads and event loop own the rest of this chapter. Details and the Studio call site: [§8.1](08.01-initialization.md). Callback registration (the only safe path back onto the GUI thread) is [§8.2](08.02-callbacks.md).

### Shared app credentials (not user login)

Independently of whether anyone is logged in, the stock client needs the **shared Studio application** cert chain, CRL, and private-key material used for MQTT command signing and HTTP proof-of-possession when Developer Mode is off. Those come from a dedicated cloud cert endpoint unlocked by bootstrap secrets embedded in the stock binary — not from the user’s OAuth token. Fetching and caching this material is a background prerequisite for secured printers; it can (and does) run alongside login and discovery. Request/response shape: [§10.2](10.02-secrets.md). Signing / PoP: [§10.4](10.04-mqtt-signing.md), [§10.5](10.05-http-pop.md).

### User authentication

When the user signs in, Studio drives ticket / OAuth exchange through the auth ABI and ends up with an access token (and refresh path) for `api.bambulab.*`. That token is what authorizes printer-list and bind REST; it is **not** the same credential as the shared app cert above. Login can complete while SSDP is already listening and while the cert endpoint is still in flight. Token login, refresh, and profile shapes: [§8.5](08.05-auth.md). Shared HTTPS hosts / headers: [§13 Cloud HTTP transport](13-http-transport.md). Overview: [§6.6](06.06-cloud-rest.md).

### Printer inventory and bind metadata

Once a bearer token exists, the plugin (via Studio’s HTTP ABI calls) pulls the user’s device list and bind records — serials, names, model hints, and the plaintext `dev_access_code` used later as the LAN MQTT password. Bind / unbind / rename are the same REST surface; the idle path mainly needs a fresh print-info / bind snapshot so the Device tab and subscription manager know which `dev_id`s exist. This REST traffic runs in parallel with MQTT bring-up; a reconnect or refresh can re-hit the same endpoints at any time. ABI and endpoints: [§8.7](08.07-printer-selection.md), [§8.10](08.10-http.md), [§8.6](08.06-bind.md). Access code story: [§6](06-channels.md#access-code).

### Cloud MQTT while logged in

After login, `connect_server` opens the regional cloud MQTT broker and keeps the socket warm for the session. Studio then uses `add_subscribe` / `del_subscribe` (and related helpers) to manage which device report topics should be active on the cloud leg; the plugin buffers those lists and applies them on the next cloud `CONNACK`. Auth on that broker is the user token as MQTT password (`u_<user_id>`). The cloud session often stays connected even when LAN is carrying live telemetry — it is a standby as much as a primary feed. ABI surface: [§8.3](08.03-cloud-mqtt.md). Wire auth and dual-session policy: [§6.2](06.02-mqtt.md).

### SSDP discovery (LAN IP cache)

In parallel with everything above, `start_discovery` listens for printer **UDP NOTIFY on :2021** so printers can announce `dev_id` + LAN IP ([§6.1](06.01-ssdp.md)). That IP half of the LAN credential pair is what lets a **cloud-paired** printer still get a direct `mqtts://<ip>:8883` session; the access-code half comes from the REST inventory or the printer screen. Discovery is continuous idle work, not a one-shot boot step. ABI: [§8.4](08.04-lan.md). TLS leaf caveats: [§6](06-channels.md#optional-certificate-check-anti-mitm), [§10.6](10.06-lan-tls-and-access-codes.md).

### App-cert install on secured printers

When a printer is in the new-auth / secured world (Developer Mode off), privileged MQTT commands will fail until the printer’s RAM trust store holds the current shared app cert (+ CRL). Stock teaches that trust with `security.app_cert_install` (and can observe `app_cert_list`); the install is session-volatile and must be redone after printer reboot. This step needs both a working MQTT path to the printer and the app cert material from the cert endpoint. Flow and volatility: [§10.2](10.02-secrets.md#provisioning-printer-trust-store). Signing / field encryption: [§10.3](10.03-mqtt-field-encryption.md), [§10.4](10.04-mqtt-signing.md).

### Direct LAN MQTT and steady idle

Whenever the plugin (or Studio’s subscription manager) has both a LAN IP and an access code for a `dev_id`, it opens `connect_printer` to the printer broker (`bblp` / access code, typically TLS :8883) **even if the device is cloud-paired**. On a healthy LAN, Studio prefers that local session for `device/<id>/report` and leaves the cloud report topic unsubscribed while local telemetry flows — both sockets can be up at once ([§6.2](06.02-mqtt.md)). Steady idle is this ongoing overlap: SSDP refreshing IPs, REST occasionally refreshing codes and bind info, cloud MQTT kept warm, LAN MQTT carrying `push_status`, and re-installing app certs when a secured printer forgets them after reboot. Connection ABI: [§8.4](08.04-lan.md).
