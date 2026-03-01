"""Constants for the ISEO Argo BLE Lock integration."""

DOMAIN = "iseo_argo_ble"
PLATFORMS = ["lock", "sensor"]

# Config entry keys
CONF_ADDRESS     = "address"
CONF_UUID        = "uuid"
CONF_PRIV_SCALAR = "priv_scalar"

# Event fired into the HA bus for every new access-log entry.
EVENT_TYPE = f"{DOMAIN}_event"
