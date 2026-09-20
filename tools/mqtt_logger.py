import os
import ssl
import sys
import paho.mqtt.client as mqtt

DEV = os.environ.get("BAMBU_DEV_ID", os.environ.get("BAMBU_SERIAL", ""))
HOST = os.environ.get("BAMBU_IP", os.environ.get("BAMBU_HOST", ""))
USER = os.environ.get("BAMBU_USER", "bblp")
PW = os.environ.get("BAMBU_ACCESS_CODE", os.environ.get("BAMBU_PW", ""))

if not HOST or not DEV or not PW:
    print(
        "Usage: BAMBU_IP=<ip> BAMBU_DEV_ID=<serial> BAMBU_ACCESS_CODE=<code> python tools/mqtt_logger.py",
        file=sys.stderr,
    )
    sys.exit(1)


def on_connect(c, u, f, rc, *a):
    print(f"# connected rc={rc}", flush=True)
    c.subscribe(f"device/{DEV}/report")
    c.subscribe(f"device/{DEV}/request")


def on_message(c, u, m):
    txt = m.payload.decode("utf-8", "replace")
    if "wifi_signal" in txt:
        return
    print(f"\n=== {m.topic} ===\n{txt}", flush=True)


def on_disconnect(c, u, rc, *a):
    print(f"# disconnected rc={rc}", flush=True)


try:  # paho 2.x
    c = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id="obn-logger",
        protocol=mqtt.MQTTv311,
    )
except Exception:  # paho 1.x
    c = mqtt.Client(client_id="obn-logger", protocol=mqtt.MQTTv311)

c.username_pw_set(USER, PW)
c.tls_set(cert_reqs=ssl.CERT_NONE)
c.tls_insecure_set(True)
c.on_connect = on_connect
c.on_message = on_message
c.on_disconnect = on_disconnect
c.connect(HOST, 8883, 60)
c.loop_forever()
