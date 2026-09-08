"""Constants for the ISEO Argo BLE Lock integration."""

from __future__ import annotations

from homeassistant.const import Platform

from .client import (
    USER_TYPE_ACCOUNT,
    USER_TYPE_BT,
    USER_TYPE_FINGERPRINT,
    USER_TYPE_INVITATION,
    USER_TYPE_PIN,
    USER_TYPE_RFID,
    UserEntry,
    UserSubType,
)

DOMAIN = "iseo_argo_ble"
PLATFORMS: list[Platform] = [
    Platform.LOCK,
    Platform.SWITCH,
    Platform.SENSOR,
    Platform.BINARY_SENSOR,
]


def signal_update(entry_id: str) -> str:
    """Dispatcher signal fired when new passive state / an event is available."""
    return f"{DOMAIN}_{entry_id}_update"


# Bus events fired by the lock entity
EVENT_LOCK_OPENED = f"{DOMAIN}_lock_opened"
EVENT_ALERT = f"{DOMAIN}_alert"

# Config entry keys
CONF_ADDRESS = "address"
CONF_UUID = "uuid"
CONF_PRIV_SCALAR = "priv_scalar"
CONF_USER_MAPPING = "user_mapping"
CONF_ADMIN_UUID = "admin_uuid"
CONF_ADMIN_PRIV_SCALAR = "admin_priv_scalar"
# Time profiles of users suspended from Home Assistant, {user_key: tag 16 hex}.
# Suspending overwrites the profile on the lock, so the only copy of a
# credential's original validity window lives here until it is re-enabled.
CONF_USER_VALIDITY = "user_validity"

# User subtypes
DEFAULT_USER_SUBTYPE: int = UserSubType.BT_GATEWAY
ADMIN_USER_SUBTYPE: int = UserSubType.BT_SMARTPHONE


def user_key(user_type: int, uuid_hex: str) -> str:
    """Identify one enrolled credential across options dicts and entity state."""
    return f"{user_type}_{uuid_hex}"


USER_TYPE_LABELS = {
    USER_TYPE_RFID: "RFID",
    USER_TYPE_BT: "Phone",
    USER_TYPE_PIN: "PIN",
    USER_TYPE_INVITATION: "Invitation",
    USER_TYPE_FINGERPRINT: "Fingerprint",
    USER_TYPE_ACCOUNT: "Account",
}


def is_ha_internal_user(user: UserEntry, admin_uuid_hex: str) -> bool:
    """Return True for the identities Home Assistant enrolled for itself.

    The gateway user does the opening and the admin user does the user
    management; neither is a credential the owner handed out, so neither should
    appear as something to name, map, or switch off.
    """
    if user.user_type == USER_TYPE_BT and user.inner_subtype == UserSubType.BT_GATEWAY:
        return True
    return bool(admin_uuid_hex and user.uuid_hex == admin_uuid_hex)
