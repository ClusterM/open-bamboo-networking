## 10. Non-developer mode signing

When **Developer Mode** is off, the printer and (for cloud-dispatched prints) Bambu’s cloud enforce extra signing and encryption on privileged commands. This chapter is the map of those requirements and the credentials behind them.

**Developer Mode** is the only documented firmware bypass for MQTT command verification / field encryption. **LAN-Only** does not disable signing.

### Contents

| Section | File |
| --- | --- |
| 10.1 What changes when Developer Mode is off | [10.01-overview.md](10.01-overview.md) |
| 10.2 Where Bambu secrets live | [10.02-secrets.md](10.02-secrets.md) |
| 10.3 MQTT field encryption | [10.03-mqtt-field-encryption.md](10.03-mqtt-field-encryption.md) |
| 10.4 MQTT message signing | [10.04-mqtt-signing.md](10.04-mqtt-signing.md) |
| 10.5 HTTP proof-of-possession | [10.05-http-pop.md](10.05-http-pop.md) |
| 10.6 LAN TLS and Studio certificate files | [10.06-lan-tls-and-access-codes.md](10.06-lan-tls-and-access-codes.md) |

Cross-references from the ABI chapters (§8, including print [§8.8](08.08-print-abi.md)) and Studio-forwarded MQTT ([§12](12-mqtt.md)) point here for detail.
