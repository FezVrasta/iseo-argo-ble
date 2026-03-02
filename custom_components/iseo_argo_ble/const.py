"""Constants for the ISEO Argo BLE Lock integration."""

from .ble_client import UserSubType

DOMAIN = "iseo_argo_ble"
PLATFORMS = ["lock", "sensor"]

# Config entry keys
CONF_ADDRESS      = "address"
CONF_UUID         = "uuid"
CONF_PRIV_SCALAR  = "priv_scalar"
CONF_USER_SUBTYPE = "user_subtype"
CONF_USER_MAP     = "user_map"   # ConfigEntry.options key: {uuid_hex: ha_user_id}

# Default user subtype (smartphone)
DEFAULT_USER_SUBTYPE = UserSubType.BT_SMARTPHONE

# Event fired into the HA bus for every new access-log entry.
EVENT_TYPE = f"{DOMAIN}_event"
