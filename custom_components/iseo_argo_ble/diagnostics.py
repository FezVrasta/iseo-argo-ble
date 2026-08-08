"""Diagnostics platform for ISEO Argo BLE."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

from . import IseoConfigEntry
from .const import (
    CONF_ADDRESS,
    CONF_ADMIN_PRIV_SCALAR,
    CONF_ADMIN_UUID,
    CONF_PRIV_SCALAR,
    CONF_UUID,
)

TO_REDACT = {CONF_PRIV_SCALAR, CONF_UUID, CONF_ADMIN_PRIV_SCALAR, CONF_ADMIN_UUID}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: IseoConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    runtime = entry.runtime_data
    address = entry.data[CONF_ADDRESS]

    # BLE device info from last seen advertisement
    last_device = runtime.last_ble_device
    ble_device_info: dict[str, Any] | None = None
    if last_device is not None:
        ble_device_info = {
            "address": getattr(last_device, "address", None),
            "name": getattr(last_device, "name", None),
            "details": str(getattr(last_device, "details", None)),
        }

    # Lock entity state — find via entity registry
    lock_state: dict[str, Any] = {}
    ent_reg = er.async_get(hass)
    lock_entity_id = ent_reg.async_get_entity_id("lock", "iseo_argo_ble", f"{entry.unique_id}_lock")
    if lock_entity_id:
        if state := hass.states.get(lock_entity_id):
            lock_state = {
                "state": state.state,
                "attributes": state.attributes,
                "last_changed": state.last_changed.isoformat(),
                "last_updated": state.last_updated.isoformat(),
            }

    # User coordinator status
    coordinator_info: dict[str, Any] | None = None
    if (coord := runtime.user_coordinator) is not None:
        coordinator_info = {
            "last_update_success": coord.last_update_success,
            "last_exception": str(coord.last_exception) if coord.last_exception else None,
            "user_count": len(coord.data) if coord.data is not None else None,
        }

    now = datetime.now(tz=UTC)
    return {
        "config": async_redact_data(dict(entry.data), TO_REDACT),
        "options": dict(entry.options),
        "address": address,
        "admin_configured": runtime.admin_client is not None,
        "ble_lock_locked": runtime.ble_lock.locked(),
        "last_ble_device": ble_device_info,
        "lock_entity": lock_state,
        "user_coordinator": coordinator_info,
        "diagnostics_generated_at": now.isoformat(),
    }
