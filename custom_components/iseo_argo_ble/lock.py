"""ISEO BLE Lock entity."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import Any

from homeassistant.components.lock import LockEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_track_time_interval

from .ble_client import IseoAuthError, IseoClient, IseoConnectionError, LockState
from .const import CONF_ADDRESS, CONF_UUID, DOMAIN

_LOGGER = logging.getLogger(__name__)

# Seconds the entity stays in "unlocked" state before reverting to "locked".
# Used as a fallback when the lock does not expose a door-contact sensor.
_RELOCK_DELAY = 5

# How often to poll the lock for door state (when door status is supported).
_POLL_INTERVAL = timedelta(seconds=30)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    # Private key was already derived once in __init__.async_setup_entry.
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    uuid_bytes  = bytes.fromhex(entry.data[CONF_UUID])

    async_add_entities(
        [IseoLockEntity(entry, uuid_bytes, coordinator._identity_priv)],
        update_before_add=False,
    )


class IseoLockEntity(LockEntity):
    """Represents an ISEO X1R BLE door lock."""

    _attr_has_entity_name = True
    _attr_name            = None          # entity name = device name
    _attr_should_poll     = False

    def __init__(
        self,
        entry: ConfigEntry,
        uuid_bytes: bytes,
        identity_priv: Any,
    ) -> None:
        self._entry         = entry
        self._uuid_bytes    = uuid_bytes
        self._identity_priv = identity_priv
        self._relock_task:  asyncio.Task | None = None
        self._ble_lock      = asyncio.Lock()
        self._door_status_supported: bool | None = None  # None = not yet probed
        self._fw_version_set = False

        self._attr_unique_id = f"{entry.data[CONF_ADDRESS].replace(':', '').lower()}_lock"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="ISEO Lock",
            manufacturer="ISEO",
            model="X1R Smart Lock",
        )

        # Assume locked until we successfully open it.
        self._attr_is_locked   = True
        self._attr_is_unlocking = False

    # ── Lifecycle ──────────────────────────────────────────────────────────
    async def async_added_to_hass(self) -> None:
        """Probe door-status support; start polling if the lock supports it."""
        await self._poll_state()
        if self._door_status_supported:
            self.async_on_remove(
                async_track_time_interval(self.hass, self._poll_state, _POLL_INTERVAL)
            )

    async def _poll_state(self, _now: Any = None) -> None:
        """Read door state via TLV_INFO and update HA state."""
        if self._ble_lock.locked():
            # Another BLE operation is already in progress; skip this cycle.
            return

        client = IseoClient(
            address       = self._entry.data[CONF_ADDRESS],
            uuid_bytes    = self._uuid_bytes,
            identity_priv = self._identity_priv,
        )
        try:
            async with self._ble_lock:
                state: LockState = await client.read_state()
        except (IseoConnectionError, IseoAuthError) as exc:
            _LOGGER.debug("State poll failed: %s", exc)
            return
        except Exception as exc:
            _LOGGER.debug("Unexpected error during state poll: %s", exc)
            return

        # Update firmware version in device registry on first successful read.
        if not self._fw_version_set and state.firmware_info:
            fw_version = state.firmware_info[5:].strip() or state.firmware_info.strip()
            self._attr_device_info = DeviceInfo(
                identifiers={(DOMAIN, self._entry.entry_id)},
                name="ISEO Lock",
                manufacturer="ISEO",
                model="X1R Smart Lock",
                sw_version=fw_version,
            )
            self._fw_version_set = True
            _LOGGER.debug("Firmware version: %s", fw_version)

        if state.door_closed is None:
            # Lock does not expose a door sensor — no point polling further.
            if self._door_status_supported is not False:
                _LOGGER.debug("Door status not supported; polling disabled")
                self._door_status_supported = False
            return

        self._door_status_supported = True

        # Don't override state while an unlock command is in flight.
        if self._attr_is_unlocking:
            return

        new_locked = state.door_closed
        if new_locked != self._attr_is_locked:
            self._attr_is_locked = new_locked
            self.async_write_ha_state()

    # ── State helpers ──────────────────────────────────────────────────────
    def _set_unlocking(self) -> None:
        self._attr_is_locked    = False
        self._attr_is_unlocking = True
        self.async_write_ha_state()

    def _set_unlocked(self) -> None:
        self._attr_is_unlocking = False
        self._attr_is_locked    = False
        self.async_write_ha_state()

    def _set_locked(self) -> None:
        self._attr_is_unlocking = False
        self._attr_is_locked    = True
        self.async_write_ha_state()

    async def _auto_relock(self) -> None:
        """Revert to 'locked' after the motor has re-latched."""
        await asyncio.sleep(_RELOCK_DELAY)
        self._set_locked()

    # ── LockEntity interface ───────────────────────────────────────────────
    async def async_unlock(self, **kwargs: Any) -> None:
        """Open the lock (momentary actuator — always re-latches automatically)."""
        if self._relock_task and not self._relock_task.done():
            self._relock_task.cancel()

        self._set_unlocking()

        client = IseoClient(
            address       = self._entry.data[CONF_ADDRESS],
            uuid_bytes    = self._uuid_bytes,
            identity_priv = self._identity_priv,
        )
        try:
            async with self._ble_lock:
                await client.open_lock()
        except IseoAuthError as exc:
            self._set_locked()
            raise HomeAssistantError(
                f"Lock rejected identity: {exc}. "
                "Ensure the UUID is registered in the Argo app."
            ) from exc
        except (IseoConnectionError, Exception) as exc:
            self._set_locked()
            raise HomeAssistantError(f"Could not connect to lock: {exc}") from exc

        self._set_unlocked()
        self._relock_task = self.hass.async_create_task(self._auto_relock())

    async def async_lock(self, **kwargs: Any) -> None:
        """
        Not supported — the ISEO X1R re-latches physically after every open.
        This is a no-op so HA automations calling 'lock' don't throw errors.
        """
        _LOGGER.debug(
            "async_lock called on ISEO lock — no-op (lock re-latches automatically)"
        )
        self._set_locked()
