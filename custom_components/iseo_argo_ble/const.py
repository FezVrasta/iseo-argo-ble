"""Constants for the ISEO Argo BLE Lock integration."""

from __future__ import annotations

from homeassistant.const import Platform

DOMAIN = "iseo_argo_ble"
PLATFORMS: list[Platform] = [Platform.LOCK, Platform.SWITCH]

# Config entry keys
CONF_ADDRESS = "address"
CONF_UUID = "uuid"
CONF_PRIV_SCALAR = "priv_scalar"
CONF_USER_MAPPING = "user_mapping"
CONF_ADMIN_UUID = "admin_uuid"
CONF_ADMIN_PRIV_SCALAR = "admin_priv_scalar"

# User subtypes
DEFAULT_USER_SUBTYPE: int = 17  # UserSubType.BT_GATEWAY
ADMIN_USER_SUBTYPE: int = 16  # UserSubType.BT_SMARTPHONE
