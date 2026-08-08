"""ISEO BLE Lock entity."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from habluetooth import get_manager
from homeassistant.components.bluetooth import (
    BluetoothChange,
    BluetoothServiceInfoBleak,
    async_register_callback,
)
from homeassistant.components.bluetooth.match import BluetoothCallbackMatcher
from homeassistant.components.lock import LockEntity
from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.event import async_track_time_interval

from . import IseoConfigEntry, get_ble_device
from .client import (
    BATTERY_LEVEL_LABELS,
    IseoAuthError,
    IseoClient,
    IseoConnectionError,
    LockState,
    parse_iseo_advertisement,
)
from .const import CONF_ADDRESS, CONF_PASSIVE_SCANNING, CONF_USER_MAPPING, DOMAIN

EVENT_LOCK_OPENED = f"{DOMAIN}_lock_opened"

_LOGGER = logging.getLogger(__name__)

PARALLEL_UPDATES = 1

# Seconds the entity stays in "unlocked" state before reverting to "locked".
_RELOCK_DELAY = 5

# How often to poll the lock for door state (when door status is supported).
_POLL_INTERVAL = timedelta(seconds=30)

# How long without a passive advertisement before the watchdog reconnects.
_PASSIVE_WATCHDOG_THRESHOLD = 2 * _POLL_INTERVAL


async def async_setup_entry(
    hass: HomeAssistant,
    entry: IseoConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up ISEO lock entity from a config entry."""
    async_add_entities(
        [
            IseoLockEntity(
                entry,
                entry.runtime_data.client,
            )
        ],
    )


class IseoLockEntity(LockEntity):
    """Represents an ISEO X1R BLE door lock."""

    _attr_has_entity_name = True
    _attr_name = None  # entity name = device name
    _attr_should_poll = False

    def __init__(
        self,
        entry: IseoConfigEntry,
        client: IseoClient,
    ) -> None:
        """Initialize the lock entity."""
        self._entry = entry
        self._relock_task: asyncio.Task[None] | None = None
        self._door_status_supported: bool | None = None
        self._poll_unsub: CALLBACK_TYPE | None = None
        self._passive_unsub: CALLBACK_TYPE | None = None
        self._fw_version_set = False
        self.client: IseoClient = client
        self._ble_lock = entry.runtime_data.ble_lock

        self._attr_unique_id = f"{entry.unique_id}_lock"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, cast(str, entry.unique_id))},
            connections={(CONNECTION_BLUETOOTH, entry.data[CONF_ADDRESS])},
            name=entry.title,
            manufacturer="ISEO",
            model="X1R Smart",
            model_id="X1R",
        )

        self._attr_is_locked = True
        self._attr_is_unlocking = False
        self._attr_available = True
        self._poll_suppress_until: datetime | None = None
        self._last_advertisement: datetime | None = None
        self._attr_extra_state_attributes: dict[str, Any] = {}

    async def async_added_to_hass(self) -> None:
        """Probe door-status support; start polling or passive scanning as configured."""
        passive_scanning = self._entry.data.get(CONF_PASSIVE_SCANNING, False)

        if not passive_scanning:
            await self._poll_state()

        if passive_scanning:
            self._register_passive_callback()
            self.async_on_remove(self._stop_passive_scanning)

        if self._door_status_supported is not False:
            # Always run a periodic poll — in passive mode this acts as a watchdog
            # so the lock is marked unavailable if advertisements stop arriving.
            self._poll_unsub = async_track_time_interval(self.hass, self._poll_state, _POLL_INTERVAL)
            self.async_on_remove(self._poll_unsub)

        self.async_on_remove(self._cancel_relock_task)

    def _register_passive_callback(self) -> None:
        """Register (or re-register) the passive BLE advertisement callback."""
        self._stop_passive_scanning()
        address = self._entry.data[CONF_ADDRESS]

        @callback
        def _on_advertisement(
            service_info: BluetoothServiceInfoBleak,
            _change: BluetoothChange,
        ) -> None:
            """Handle a passive BLE advertisement from the lock."""
            self._entry.runtime_data.last_ble_device = service_info.device
            self._last_advertisement = datetime.now(tz=UTC)
            self._handle_advertisement(service_info)
            self._clear_advertisement_history(address)

        self._passive_unsub = async_register_callback(
            self.hass,
            _on_advertisement,
            BluetoothCallbackMatcher(address=address),
            BluetoothChange.ADVERTISEMENT,
        )

    def _stop_passive_scanning(self) -> None:
        """Unregister the passive BLE callback."""
        if self._passive_unsub is not None:
            self._passive_unsub()
            self._passive_unsub = None

    @staticmethod
    def _clear_advertisement_history(address: str) -> None:
        """Clear the cached advertisement history for an address.

        The ISEO lock encodes door state as mutually-exclusive service UUIDs,
        so HA's change-detection guard would suppress repeated passive
        callbacks after the first advertisement.  Clearing the history makes the
        next advertisement be treated as new data, keeping the passive callback
        alive indefinitely.

        Uses the public ``async_clear_advertisement_history`` API added in
        habluetooth 5.11.0 (Home Assistant 2026.4), which resolves the private
        ``_previous_service_info`` workaround previously required here — see
        https://github.com/Bluetooth-Devices/habluetooth/issues/358.

        Note: the public API also clears the connectable/all-device history
        caches.  Connections stay covered because ``get_ble_device`` falls back
        to ``runtime_data.last_ble_device``, which is refreshed from the current
        advertisement immediately before this call.
        """
        get_manager().async_clear_advertisement_history(address)

    def _apply_state(self, state: LockState) -> None:
        """Update extra state attributes from a LockState (advertisement or poll)."""
        attrs: dict[str, Any] = {}
        if state.battery_level is not None:
            attrs["battery_level"] = BATTERY_LEVEL_LABELS.get(
                state.battery_level, f"Unknown ({state.battery_level})"
            )
        if state.aux_battery_low is not None:
            attrs["aux_battery_low"] = state.aux_battery_low
        if state.invitation_pending is not None:
            attrs["invitation_pending"] = state.invitation_pending
        if state.passage_mode_light is not None:
            attrs["passage_mode_light"] = state.passage_mode_light
        if state.passage_mode_normal is not None:
            attrs["passage_mode_normal"] = state.passage_mode_normal
        if state.privacy_mode is not None:
            attrs["privacy_mode"] = state.privacy_mode
        if state.vip_mode is not None:
            attrs["vip_mode"] = state.vip_mode
        if state.operational_mode is not None:
            attrs["operational_mode"] = state.operational_mode
        self._attr_extra_state_attributes = {
            **self._attr_extra_state_attributes,
            **attrs,
        }

    @callback
    def _handle_advertisement(self, service_info: BluetoothServiceInfoBleak) -> None:
        """Parse a passive advertisement and update door state."""
        state = parse_iseo_advertisement(list(service_info.service_uuids or []))
        if state is None or state.door_closed is None:
            return

        self._door_status_supported = True
        self._apply_state(state)

        if self._attr_is_unlocking:
            self.async_write_ha_state()
            return
        if self._poll_suppress_until and datetime.now(tz=UTC) < self._poll_suppress_until:
            self.async_write_ha_state()
            return

        new_locked = state.door_closed
        if new_locked != self._attr_is_locked:
            _LOGGER.debug(
                "Passive advertisement: door_closed=%s → is_locked=%s",
                state.door_closed,
                new_locked,
            )
            self._attr_is_locked = new_locked
        self.async_write_ha_state()

    def _cancel_relock_task(self) -> None:
        """Cancel any pending relock task."""
        if self._relock_task and not self._relock_task.done():
            self._relock_task.cancel()

    async def _poll_state(self, _now: datetime | None = None, force: bool = False) -> None:
        """Read door state via TLV_INFO and update HA state."""
        _LOGGER.debug("Polling lock state, current available: %s", self._attr_available)
        if self._door_status_supported is False and _now is not None and not force:
            return

        # In passive scanning mode, skip connecting if we received an advertisement
        # recently — passive ads already keep state up to date.  Only connect when
        # ads have been silent for longer than two poll intervals (watchdog behaviour).
        now = datetime.now(tz=UTC)
        if self._last_advertisement is not None:
            silence = now - self._last_advertisement
            if _now is not None and not force and silence < _PASSIVE_WATCHDOG_THRESHOLD:
                _LOGGER.debug("Skipping poll — passive advertisement received recently")
                return
            if silence >= _PASSIVE_WATCHDOG_THRESHOLD and self._passive_unsub is not None:
                _LOGGER.warning("No passive advertisement for %s — re-registering callback", silence)
                self._register_passive_callback()

        if self._ble_lock.locked():
            _LOGGER.debug("Skipping poll cycle — BLE operation already in progress")
            return

        ble_device = get_ble_device(self.hass, self._entry)
        if not ble_device:
            # In passive mode the lock may simply be idle and not advertising —
            # don't mark unavailable just because there's no device in the BLE cache.
            # Only a failed connection attempt is authoritative.
            passive = self._entry.data.get(CONF_PASSIVE_SCANNING, False)
            if not passive and self._attr_available:
                _LOGGER.info("Lock is unavailable: device not found")
                self._attr_available = False
                self.async_write_ha_state()
            return

        try:
            async with self._ble_lock:
                self.client.update_ble_device(ble_device)
                state: LockState = await self.client.read_state()
        except (TimeoutError, IseoConnectionError, IseoAuthError, OSError) as exc:
            if self._attr_available:
                _LOGGER.info("Lock is unavailable: %s", exc)
                self._attr_available = False
                self.async_write_ha_state()
            return

        if not self._attr_available:
            _LOGGER.info("Lock is back online")
            self._attr_available = True

        # Reset the watchdog timer so a successful poll counts as "heard from the lock".
        self._last_advertisement = now

        self._apply_state(state)

        if not self._fw_version_set and state.firmware_info:
            fw_version = state.firmware_info[5:].strip() or state.firmware_info.strip()
            dev_reg = dr.async_get(self.hass)
            if device := dev_reg.async_get_device(identifiers={(DOMAIN, cast(str, self._entry.unique_id))}):
                dev_reg.async_update_device(device.id, sw_version=fw_version)
                self._fw_version_set = True

        if state.door_closed is None:
            if self._door_status_supported is not False:
                _LOGGER.debug("Door status not supported; polling disabled")
                self._door_status_supported = False
                if self._poll_unsub:
                    self._poll_unsub()
                    self._poll_unsub = None
            self.async_write_ha_state()
            return

        self._door_status_supported = True

        if self._attr_is_unlocking:
            self.async_write_ha_state()
            return
        if not force and self._poll_suppress_until and now < self._poll_suppress_until:
            self.async_write_ha_state()
            return

        new_locked = state.door_closed
        if new_locked != self._attr_is_locked:
            self._attr_is_locked = new_locked
        self.async_write_ha_state()

    def _set_unlocking(self, available: bool = True) -> None:
        self._attr_is_locked = False
        self._attr_is_unlocking = True
        self._attr_available = available
        self.async_write_ha_state()

    def _set_unlocked(self, available: bool = True) -> None:
        self._attr_is_unlocking = False
        self._attr_is_locked = False
        self._attr_available = available
        self._poll_suppress_until = datetime.now(tz=UTC) + timedelta(seconds=_RELOCK_DELAY)
        self.async_write_ha_state()

    def _set_locked(self, available: bool = True) -> None:
        self._attr_is_unlocking = False
        self._attr_is_locked = True
        self._attr_available = available
        self._poll_suppress_until = None
        self.async_write_ha_state()

    async def _auto_relock(self) -> None:
        """Revert to 'locked' after the motor has re-latched."""
        try:
            if self._door_status_supported:
                await asyncio.sleep(2)
                await self._poll_state(force=True)
                if not self._attr_is_locked:
                    self._set_locked(available=self._attr_available)
                return

            await asyncio.sleep(_RELOCK_DELAY)
            self._set_locked(available=self._attr_available)
        except asyncio.CancelledError:
            pass

    async def async_lock(self, **kwargs: Any) -> None:
        """Lock the door (not supported)."""
        raise HomeAssistantError(
            translation_domain=DOMAIN,
            translation_key="lock_not_supported",
        )

    async def async_unlock(self, **kwargs: Any) -> None:
        """Open the lock (momentary actuator — always re-latches automatically)."""
        if self._relock_task and not self._relock_task.done():
            self._relock_task.cancel()

        self._set_unlocking()

        ble_device = get_ble_device(self.hass, self._entry)
        if not ble_device:
            self._set_locked(available=False)
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="cannot_connect",
            )

        # Resolve the calling HA user before connecting so we can log it
        ha_user_id: str | None = self._context.user_id if self._context else None
        ha_user_name: str | None = None
        if ha_user_id:
            user = await self.hass.auth.async_get_user(ha_user_id)
            ha_user_name = user.name if user else None

        try:
            async with self._ble_lock:
                self.client.update_ble_device(ble_device)
                await self.client.gw_open(remote_user_name=ha_user_name or "Home Assistant")
        except IseoAuthError as exc:
            self._set_locked()
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="lock_rejected_identity",
            ) from exc
        except (TimeoutError, IseoConnectionError, OSError) as exc:
            self._set_locked(available=False)
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="cannot_connect",
            ) from exc

        self._set_unlocked()
        self._relock_task = self.hass.async_create_task(self._auto_relock())

        self.hass.bus.async_fire(
            EVENT_LOCK_OPENED,
            {
                "entity_id": self.entity_id,
                "lock_name": self._entry.title,
                "ha_user_id": ha_user_id,
                "ha_user_name": ha_user_name,
            },
            context=self._context,
        )
