"""BambuLab protocol constants.

Shared constants for camera proxies, MQTT proxy, FTP proxy, and detection modules.
"""

# Protocol ports
RTSP_PORT = 322
CHAMBER_PORT = 6000
MQTT_PORT = 8883
FTP_PORT = 990


# Chamber image protocol constants
AUTH_MAGIC = 0x40
AUTH_COMMAND = 0x3000
MAX_PAYLOAD_SIZE = 10_000_000  # 10MB sanity limit

# Certificate constants
CERT_FILENAME = "pandaproxy.crt"
KEY_FILENAME = "pandaproxy.key"
