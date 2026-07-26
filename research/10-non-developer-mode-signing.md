## 10. Non-developer mode signing

When **Developer Mode** is off, the printer and (for cloud-dispatched prints) Bambu’s cloud enforce extra signing and encryption on privileged commands. This chapter is the map of those requirements and the credentials behind them.

**Developer Mode** is the only documented firmware bypass for MQTT command verification / field encryption. **LAN-Only** does not disable signing.

### Contents

- [10.1. What changes when Developer Mode is off](10.01-overview.md) — checklist of extra requirements by surface; who verifies
- [10.2. Where Bambu secrets live](10.02-secrets.md) — embedded secrets; cert endpoint; provisioning (`app_cert_install`); printer device cert
- [10.3. MQTT field encryption](10.03-mqtt-field-encryption.md) — `url_enc` / `param_enc`; device-cert key
- [10.4. MQTT message signing](10.04-mqtt-signing.md) — which commands; `SignMessage`; app private key
- [10.5. HTTP proof-of-possession](10.05-http-pop.md) — which REST calls need the app key; PoP headers
- [10.6. LAN TLS and Studio certificate files](10.06-lan-tls-and-access-codes.md) — Studio PEMs; leaf shape → [§6](06-channels.md) for access code / CN-pin

Cross-references from the ABI chapters (§8) and the Print / MQTT wire chapters (§11 / §12) point here for detail.
