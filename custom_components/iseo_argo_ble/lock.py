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
from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.event import async_track_time_interval

from . import IseoConfigEntry, get_ble_device
from .client import (
    BATTERY_LEVEL_LABELS,
    IseoAuthError,
    IseoClient,
    IseoConnectionError,
    LockState,
    LogEntry,
    UserEntry,
    describe_event,
    parse_iseo_advertisement,
)
from .const import (
    CONF_ADDRESS,
    CONF_USER_MAPPING,
    DOMAIN,
    EVENT_ALERT,
    EVENT_LOCK_OPENED,
    signal_update,
)

# Access-log event codes that represent an actual door open (see
# LOG_EVENT_CODES.md). Authorized opens (app/RFID/PIN/fingerprint) are all
# code 8; the rest are mechanical key, internal handle, and remote/low-battery
# opens. Used to pick the relevant entry out of the drained unread log.
_OPEN_EVENT_CODES = frozenset({7, 8, 32, 33, 34, 45, 75, 102, 103})

# Security / fault event codes worth surfacing as alerts (see LOG_EVENT_CODES.md).
# NOTE: these are only seen when the unread log is drained on a door open, so
# they surface with a delay (at the next open) — the integration never polls.
_ALERT_EVENT_CODES = frozenset(
    {
        5,  # Wrong PIN
        21,  # Memory Full
        44,  # Open denied due to internal handle pressed
        52,  # Expired
        53,  # Out of Time Schedule
        61,  # Lithium backup battery KO
        68,  # Authentication mismatch
        77,  # Fingerprint mismatch
        86,  # Permission denied
        88,  # Opening denied
        89,  # Wrong password
        90,  # Hardware fault
        99,  # Master card error
    }
)

_LOGGER = logging.getLogger(__name__)

PARALLEL_UPDATES = 1

# Seconds the entity stays in "unlocked" state before reverting to "locked".
_RELOCK_DELAY = 5

# How often the availability watchdog runs.  It never connects to the lock — it
# only inspects how long ago the last passive advertisement arrived.
_AVAILABILITY_CHECK_INTERVAL = timedelta(seconds=30)

# Mark the lock unavailable if no passive advertisement has arrived for this
# long.  The lock advertises frequently, so prolonged silence means it is out
# of range or powered off.
_UNAVAILABLE_AFTER = timedelta(minutes=10)

# Re-register the passive callback if advertisements go silent for this long,
# in case the bluetooth stack dropped it.
_CALLBACK_REFRESH_AFTER = timedelta(minutes=2)


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
    """Represents an ISEO X1R BLE door lock.

    State is driven entirely by passive BLE advertisements — the lock encodes
    door status, battery, and mode flags into its advertised service UUIDs, so
    no periodic connection (polling) is needed.  The integration only connects
    to the lock on demand: to open it, and once per physical door-open to read
    the access log and report who opened the door.
    """

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
        self._open_investigation_task: asyncio.Task[None] | None = None
        self._passive_unsub: CALLBACK_TYPE | None = None
        self._availability_unsub: CALLBACK_TYPE | None = None
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
        # While set, passive advertisements do not update the locked state — used
        # to hold the "unlocked" state during the momentary-actuator relock.
        self._suppress_state_until: datetime | None = None
        self._last_advertisement: datetime | None = None
        self._attr_extra_state_attributes: dict[str, Any] = {}

    async def async_added_to_hass(self) -> None:
        """Start passive listening and the (connectionless) availability watchdog."""
        # Treat setup as "just heard from the lock" so the availability watchdog
        # grants a grace period before marking the lock unavailable.
        self._last_advertisement = datetime.now(tz=UTC)

        self._register_passive_callback()
        self.async_on_remove(self._stop_passive_scanning)

        self._availability_unsub = async_track_time_interval(
            self.hass, self._check_availability, _AVAILABILITY_CHECK_INTERVAL
        )
        self.async_on_remove(self._availability_unsub)

        self.async_on_remove(self._cancel_relock_task)
        self.async_on_remove(self._cancel_open_investigation)

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
            attrs["battery_level"] = BATTERY_LEVEL_LABELS.get(state.battery_level, f"Unknown ({state.battery_level})")
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

        # Any advertisement means the lock is reachable.
        self._attr_available = True
        self._apply_state(state)
        # Share the raw state (battery / modes / door) with the other entities.
        self._publish_update(state)

        if self._attr_is_unlocking:
            self.async_write_ha_state()
            return
        if self._suppress_state_until and datetime.now(tz=UTC) < self._suppress_state_until:
            self.async_write_ha_state()
            return

        new_locked = state.door_closed
        # door_closed True = closed/locked; a True -> False change is a door open.
        door_opened = self._attr_is_locked and not new_locked
        if new_locked != self._attr_is_locked:
            _LOGGER.debug(
                "Passive advertisement: door_closed=%s → is_locked=%s",
                state.door_closed,
                new_locked,
            )
            self._attr_is_locked = new_locked
        self.async_write_ha_state()

        if door_opened:
            # A physical open (HA-initiated opens already flip is_locked before
            # the advertisement arrives, so they never reach here).
            self._schedule_open_investigation()

    @callback
    def _publish_update(self, state: LockState | None = None) -> None:
        """Publish the latest passive state/availability to the other entities."""
        runtime = self._entry.runtime_data
        if state is not None:
            runtime.latest_state = state
        runtime.available = self._attr_available
        async_dispatcher_send(self.hass, signal_update(self._entry.entry_id))

    @callback
    def _check_availability(self, _now: datetime | None = None) -> None:
        """Mark the lock unavailable if passive advertisements stop arriving.

        Runs on a timer and never connects to the lock.
        """
        last = self._last_advertisement
        silence = None if last is None else datetime.now(tz=UTC) - last

        # The callback can be dropped by the bluetooth stack; re-arm it if the
        # lock has gone quiet for a while.
        if silence is not None and silence >= _CALLBACK_REFRESH_AFTER:
            _LOGGER.debug("No advertisement for %s — re-registering passive callback", silence)
            self._register_passive_callback()

        unavailable = silence is None or silence >= _UNAVAILABLE_AFTER
        if unavailable and self._attr_available:
            _LOGGER.info("Lock unavailable: no advertisement for %s", silence)
            self._attr_available = False
            self.async_write_ha_state()
            self._publish_update()

    def _schedule_open_investigation(self) -> None:
        """Read who opened the door without blocking the advertisement callback."""
        if self._open_investigation_task and not self._open_investigation_task.done():
            # An investigation is already running; don't stack connections.
            return
        self._open_investigation_task = self.hass.async_create_task(self._investigate_open())

    async def _investigate_open(self) -> None:
        """Connect once after a physical door-open to find out who opened it.

        This is the only lock connection that happens outside of an explicit
        unlock — it replaces the old periodic polling, which crashed the lock.
        """
        try:
            async with self._ble_lock:
                ble_device = get_ble_device(self.hass, self._entry)
                if ble_device is None:
                    _LOGGER.debug("No BLE device available to read open logs")
                    return
                self.client.update_ble_device(ble_device)
                logs = await self.client.gw_read_unread_logs()
        except (
            TimeoutError,
            IseoConnectionError,
            IseoAuthError,
            OSError,
            ValueError,
        ) as exc:
            _LOGGER.debug("Could not read access log after door open: %s", exc)
            return

        # gw_read_unread_logs drains *all* unread entries (opens, closes,
        # errors, ...). Surface the newest notable security/fault entry as an
        # alert, then attribute the newest actual open.
        alerts = [entry for entry in logs if entry.event_code in _ALERT_EVENT_CODES]
        if alerts:
            self._fire_alert_event(max(alerts, key=lambda entry: entry.timestamp))

        opens = [entry for entry in logs if entry.event_code in _OPEN_EVENT_CODES]
        if not opens:
            _LOGGER.debug("No open event among %d unread log entries", len(logs))
            return
        await self._fire_open_event(max(opens, key=lambda entry: entry.timestamp))

    @callback
    def _fire_alert_event(self, log: LogEntry) -> None:
        """Fire an alert event for a notable security/fault log entry."""
        event = describe_event(log.event_code)
        payload: dict[str, Any] = {
            "entity_id": self.entity_id,
            "lock_name": self._entry.title,
            "event": event,
            "event_code": log.event_code,
            "user_info": log.user_info or None,
            "extra_description": log.extra_description or None,
            "timestamp": log.timestamp.isoformat(),
        }
        _LOGGER.debug("Lock alert: %s (code %s)", event, log.event_code)
        self.hass.bus.async_fire(EVENT_ALERT, payload)
        self._entry.runtime_data.last_alert = payload
        self._publish_update()

    async def _fire_open_event(self, log: LogEntry) -> None:
        """Fire a lock-opened event, attributing the open to a user.

        Attribution has two levels: the lock's own user (from the user
        directory) and — if the user is linked in the options — the Home
        Assistant account, via the same `CONF_USER_MAPPING` the per-user
        switches use. Automations can key off `ha_user_name`/`ha_user_id`
        when available, or fall back to `opened_by`.
        """
        event = describe_event(log.event_code)
        payload: dict[str, Any] = {
            "entity_id": self.entity_id,
            "lock_name": self._entry.title,
            "source": "lock",
            "event": event,
            "event_code": log.event_code,
            "user_info": log.user_info or None,
            "extra_description": log.extra_description or None,
            "timestamp": log.timestamp.isoformat(),
        }

        user = self._match_log_user(log)
        if user is None:
            # No directory match (or no admin client to read the directory).
            # The lock embeds a human-readable name in extra_description (the
            # same "Custom Description" a gateway open sets), so prefer it;
            # user_info usually holds the UUID. This means we can still name
            # the opener without the admin `read_users` command.
            opened_by: str | None = (
                (log.extra_description or "").strip()
                or (log.user_info or "").strip()
                or None
            )
        else:
            opened_by = user.name.strip() or f"User {user.uuid_hex[:8]}"
            payload["uuid"] = user.uuid_hex
            payload["user_type"] = user.user_type
            payload["lock_user_name"] = opened_by
            # Map the lock user to a linked Home Assistant account if configured.
            mapping = self._entry.options.get(CONF_USER_MAPPING, {})
            if ha_user_id := mapping.get(f"{user.user_type}_{user.uuid_hex}"):
                ha_user = await self.hass.auth.async_get_user(ha_user_id)
                ha_user_name = ha_user.name if ha_user else None
                payload["ha_user_id"] = ha_user_id
                payload["ha_user_name"] = ha_user_name
                if ha_user_name:
                    opened_by = ha_user_name

        payload["opened_by"] = opened_by
        _LOGGER.debug("Door opened by %s (%s)", opened_by, event)
        self.hass.bus.async_fire(EVENT_LOCK_OPENED, payload)
        self._entry.runtime_data.last_event = payload
        if user is not None:
            # Record this open against the specific lock user so the per-user
            # switch entity can surface "last opened" for that credential.
            key = f"{user.user_type}_{user.uuid_hex}"
            self._entry.runtime_data.last_open_by_user[key] = payload
        self._publish_update()

    def _match_log_user(self, log: LogEntry) -> UserEntry | None:
        """Find the lock user referenced by a log entry.

        The opener is stored across two 32-char fields (`user_info` and
        `extra_description`); depending on the credential, one may hold the
        user's UUID and the other a name, so match either field against either
        the UUID or the stored name of the known users.
        """
        coordinator = self._entry.runtime_data.user_coordinator
        users = coordinator.data if coordinator else None
        if not users:
            return None
        candidates = {
            (log.user_info or "").strip(),
            (log.extra_description or "").strip(),
        }
        candidates.discard("")
        if not candidates:
            return None
        for user in users:
            names = {user.uuid_hex}
            if user.name and user.name.strip():
                names.add(user.name.strip())
            if candidates & names:
                return user
        return None

    def _cancel_relock_task(self) -> None:
        """Cancel any pending relock task."""
        if self._relock_task and not self._relock_task.done():
            self._relock_task.cancel()

    def _cancel_open_investigation(self) -> None:
        """Cancel any in-flight door-open log read."""
        if self._open_investigation_task and not self._open_investigation_task.done():
            self._open_investigation_task.cancel()

    def _set_unlocking(self, available: bool = True) -> None:
        self._attr_is_locked = False
        self._attr_is_unlocking = True
        self._attr_available = available
        self.async_write_ha_state()

    def _set_unlocked(self, available: bool = True) -> None:
        self._attr_is_unlocking = False
        self._attr_is_locked = False
        self._attr_available = available
        self._suppress_state_until = datetime.now(tz=UTC) + timedelta(seconds=_RELOCK_DELAY)
        self.async_write_ha_state()

    def _set_locked(self, available: bool = True) -> None:
        self._attr_is_unlocking = False
        self._attr_is_locked = True
        self._attr_available = available
        self._suppress_state_until = None
        self.async_write_ha_state()

    async def _auto_relock(self) -> None:
        """Revert to 'locked' after the momentary actuator re-latches.

        Passive advertisements report the re-latch too, but the relock delay
        suppresses passive updates, so restore the locked state afterwards.
        """
        try:
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

        payload = {
            "entity_id": self.entity_id,
            "lock_name": self._entry.title,
            "source": "ha",
            "event": "Opened via Home Assistant",
            "opened_by": ha_user_name,
            "ha_user_id": ha_user_id,
            "ha_user_name": ha_user_name,
            "timestamp": datetime.now(tz=UTC).isoformat(),
        }
        self.hass.bus.async_fire(EVENT_LOCK_OPENED, payload, context=self._context)
        self._entry.runtime_data.last_event = payload
        self._publish_update()
