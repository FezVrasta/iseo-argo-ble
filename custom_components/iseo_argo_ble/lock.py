"""ISEO BLE Lock entity."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import logging
from typing import Any, cast

from iseo_argo_ble import (
    IseoAuthError,
    IseoClient,
    IseoConnectionError,
    LockState,
    parse_iseo_advertisement,
)

from homeassistant.components.bluetooth import (
    BluetoothChange,
    BluetoothServiceInfoBleak,
    async_ble_device_from_address,
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

from . import IseoConfigEntry
from .const import CONF_ADDRESS, CONF_PASSIVE_SCANNING, DOMAIN

_LOGGER = logging.getLogger(__name__)

PARALLEL_UPDATES = 1

# Seconds the entity stays in "unlocked" state before reverting to "locked".
_RELOCK_DELAY = 5

# How often to poll the lock for door state (when door status is supported).
_POLL_INTERVAL = timedelta(seconds=30)


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
                entry.runtime_data,
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
        self._ble_lock = asyncio.Lock()
        self._door_status_supported: bool | None = None
        self._poll_unsub: CALLBACK_TYPE | None = None
        self._passive_unsub: CALLBACK_TYPE | None = None
        self._fw_version_set = False
        self.client: IseoClient = client

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
        self._attr_extra_state_attributes: dict[str, Any] = {}

    async def async_added_to_hass(self) -> None:
        """Probe door-status support; start polling or passive scanning as configured."""
        passive_scanning = self._entry.data.get(CONF_PASSIVE_SCANNING, False)

        if not passive_scanning:
            await self._poll_state()

        if passive_scanning:
            # Register a passive BLE advertisement callback so we get door-state
            # updates without ever connecting.  We use the private-API workaround
            # from habluetooth issue #358 to keep callbacks alive: after every
            # advertisement the address history is cleared so HA treats the next
            # advertisement as "new" and fires our callback again.
            address = self._entry.data[CONF_ADDRESS]

            @callback
            def _on_advertisement(
                service_info: BluetoothServiceInfoBleak,
                change: BluetoothChange,
            ) -> None:
                """Handle a passive BLE advertisement from the lock."""
                self._handle_advertisement(service_info)
                self._clear_advertisement_history(address)

            self._passive_unsub = async_register_callback(
                self.hass,
                _on_advertisement,
                BluetoothCallbackMatcher(address=address),
                BluetoothChange.ADVERTISEMENT,
            )
            self.async_on_remove(self._stop_passive_scanning)
        elif self._door_status_supported is not False:
            # Fall back to active polling when passive scanning is disabled.
            self._poll_unsub = async_track_time_interval(
                self.hass, self._poll_state, _POLL_INTERVAL
            )
            self.async_on_remove(self._poll_unsub)

        self.async_on_remove(self._cancel_relock_task)

    def _stop_passive_scanning(self) -> None:
        """Unregister the passive BLE callback."""
        if self._passive_unsub is not None:
            self._passive_unsub()
            self._passive_unsub = None

    @staticmethod
    def _clear_advertisement_history(address: str) -> None:
        """Clear the habluetooth advertisement history for an address.

        This is the workaround described in habluetooth issue #358.
        Because the ISEO lock encodes door state as mutually-exclusive service
        UUIDs, HA's dedup logic would suppress repeated callbacks after the
        first advertisement.  Clearing the history tricks HA into treating every
        advertisement as new data, keeping callbacks alive indefinitely.

        This intentionally touches private internals (_all_history,
        _connectable_history, _previous_service_info) and must be updated if
        habluetooth ever exposes a public API for this pattern.
        """
        try:
            from habluetooth import get_manager  # type: ignore[import-untyped]
        except ImportError:
            return

        try:
            manager = get_manager()
        except Exception:  # noqa: BLE001
            return

        # Clear the two history dicts on the manager.
        getattr(manager, "_all_history", {}).pop(address, None)
        getattr(manager, "_connectable_history", {}).pop(address, None)

        # Clear per-scanner previous_service_info so the next advertisement
        # is treated as a new event by the change-detection logic.
        for scanner in getattr(manager, "_sources", {}).values():
            getattr(scanner, "_previous_service_info", {}).pop(address, None)

    def _apply_state(self, state: LockState) -> None:
        """Update extra state attributes from a LockState (advertisement or poll)."""
        attrs: dict[str, Any] = {}
        if state.battery_level is not None:
            attrs["battery_level"] = state.battery_level
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
        if (
            self._poll_suppress_until
            and datetime.now(tz=UTC) < self._poll_suppress_until
        ):
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

    async def _poll_state(
        self, _now: datetime | None = None, force: bool = False
    ) -> None:
        """Read door state via TLV_INFO and update HA state."""
        _LOGGER.debug("Polling lock state, current available: %s", self._attr_available)
        if self._door_status_supported is False and _now is not None and not force:
            return

        if self._ble_lock.locked():
            _LOGGER.debug("Skipping poll cycle — BLE operation already in progress")
            return

        if not (
            ble_device := async_ble_device_from_address(
                self.hass,
                self._entry.data[CONF_ADDRESS],
                connectable=True,
            )
        ):
            if self._attr_available:
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

        self._apply_state(state)

        if not self._fw_version_set and state.firmware_info:
            fw_version = state.firmware_info[5:].strip() or state.firmware_info.strip()
            dev_reg = dr.async_get(self.hass)
            if device := dev_reg.async_get_device(
                identifiers={(DOMAIN, cast(str, self._entry.unique_id))}
            ):
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
        if (
            not force
            and self._poll_suppress_until
            and datetime.now(tz=UTC) < self._poll_suppress_until
        ):
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
        self._poll_suppress_until = datetime.now(tz=UTC) + timedelta(
            seconds=_RELOCK_DELAY
        )
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

        if not (
            ble_device := async_ble_device_from_address(
                self.hass,
                self._entry.data[CONF_ADDRESS],
                connectable=True,
            )
        ):
            self._set_locked(available=False)
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="cannot_connect",
            )

        try:
            async with self._ble_lock:
                self.client.update_ble_device(ble_device)
                await self.client.gw_open(remote_user_name="Home Assistant")
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
