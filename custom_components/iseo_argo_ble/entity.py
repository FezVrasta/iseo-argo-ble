"""Shared base entity for ISEO Argo BLE entities fed by passive advertisements."""

from __future__ import annotations

from typing import cast

from homeassistant.core import callback
from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import Entity

from . import IseoConfigEntry
from .client import LockState
from .const import CONF_ADDRESS, DOMAIN, signal_update


def passage_mode_active(state: LockState) -> bool | None:
    """Return whether the lock is holding the latch open in passage mode."""
    if state.passage_mode_normal is None and state.passage_mode_light is None:
        return None
    return bool(state.passage_mode_normal) or bool(state.passage_mode_light)


class IseoPassiveEntity(Entity):
    """Base for entities driven entirely by the lock's passive BLE state.

    These entities never talk to the lock themselves — the lock entity parses
    each advertisement and publishes the shared state via a dispatcher signal,
    which these entities subscribe to. No extra BLE load.
    """

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, entry: IseoConfigEntry) -> None:
        """Initialize the passive entity."""
        self._entry = entry
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, cast(str, entry.unique_id))},
            connections={(CONNECTION_BLUETOOTH, entry.data[CONF_ADDRESS])},
        )

    async def async_added_to_hass(self) -> None:
        """Subscribe to shared passive-state updates."""
        self.async_on_remove(
            async_dispatcher_connect(self.hass, signal_update(self._entry.entry_id), self._handle_update)
        )

    @callback
    def _handle_update(self) -> None:
        self.async_write_ha_state()

    @property
    def available(self) -> bool:
        """Mirror the lock's availability (derived from advertisement recency)."""
        return self._entry.runtime_data.available

    @property
    def _state(self) -> LockState | None:
        """Latest parsed advertisement state, or None if not yet seen."""
        return self._entry.runtime_data.latest_state
