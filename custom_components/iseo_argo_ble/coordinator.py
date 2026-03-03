"""IseoLogCoordinator — polls access logs from the ISEO lock."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from homeassistant.components.bluetooth import async_ble_device_from_address
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import Context
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .ble_client import (
    IseoAuthError,
    IseoClient,
    IseoConnectionError,
    LogEntry,
    UserEntry,
    UserSubType,
)
from .const import CONF_ADDRESS, CONF_USER_MAP, DOMAIN, EVENT_TYPE

_LOGGER = logging.getLogger(__name__)

_STORAGE_VERSION = 1
_LOG_POLL_INTERVAL = timedelta(minutes=5)
_MAX_ENTRIES_PER_POLL = 50
_USER_REFRESH_INTERVAL = timedelta(hours=1)
# Event codes that mean the user list changed — trigger an immediate user-dir refresh.
_USER_CHANGE_EVENT_CODES = {15, 16, 17}  # WL_USER_ADDED, WL_USER_DELETED, WL_USER_UPDATED

# Event code → human-readable name (from ArgoLogStdConstants.java in the APK).
_EVENT_NAMES: dict[int, str] = {
    0: "Software upgrade",
    3: "Denied: phone not paired",
    4: "Denied: not registered",
    5: "Denied: wrong PIN",
    6: "Denied: battery too low",
    7: "Opened (delayed)",
    8: "Opened",
    9: "Passage mode on",
    10: "Passage mode off",
    11: "VIP mode on",
    12: "VIP mode off",
    13: "Denied: VIP mode active",
    14: "Whitelist cleared",
    15: "User added",
    16: "User deleted",
    17: "User updated",
    19: "Closed",
    20: "Closed (delayed)",
    21: "Whitelist full",
    28: "Master mode entered",
    29: "Master mode exited",
    31: "Denied: privacy mode",
    32: "Opened by emergency key",
    33: "Opened by handle",
    34: "Opened by key",
    39: "Privacy mode on",
    40: "Privacy mode off",
    45: "Opened by remote button",
    51: "Denied: validity not started",
    52: "Denied: validity expired",
    53: "Denied: time profile",
    57: "Open denied",
    62: "OEM auth error",
    68: "Denied: auth mismatch",
    75: "Opened (low battery)",
    76: "Closed (low battery)",
    78: "Master mode activated",
    79: "Master mode deactivated",
    80: "Open timeout",
    81: "Opened by latch",
    86: "Denied: no permission",
    88: "Denied: inhibited",
    89: "Denied: wrong password",
    93: "Admin access",
    102: "Mechanical key used",
    103: "Opened mechanically",
    104: "Door locked",
    105: "Door locked (out of frame)",
}


def event_name(code: int) -> str:
    """Return a human-readable label for an event code."""
    return _EVENT_NAMES.get(code, f"Event {code}")


def _resolve_actor(raw: str, user_dir: dict[str, str]) -> str:
    """Return a display name for raw user_info: looks up 32-char hex UUIDs in user_dir."""
    key = raw.lower()
    if len(key) == 32:
        try:
            bytes.fromhex(key)
            return user_dir.get(key, raw)
        except ValueError:
            pass
    return raw


def entry_message(entry: LogEntry, user_dir: dict[str, str] | None = None) -> str:
    """Return a single-line description for a log entry."""
    raw = entry.user_info.strip() or entry.extra_description.strip()
    actor = _resolve_actor(raw, user_dir) if (raw and user_dir is not None) else raw
    name = event_name(entry.event_code)
    return f"{name} by {actor}" if actor else name


class IseoLogCoordinator(DataUpdateCoordinator["LogEntry | None"]):
    """
    Periodically fetches the most recent access-log entries from the lock.

    On each poll it:
    - Connects, authenticates (exchangeInfo + TLV_LOGIN), and reads up to
      _MAX_ENTRIES_PER_POLL entries (newest-first).
    - Fires an ``iseo_argo_ble_event`` into the HA event bus for every entry
      that is newer than the last-seen timestamp.
    - Returns the most-recent ``LogEntry`` as coordinator data for sensors.

    The last-seen timestamp is persisted in HA storage so events are not
    re-fired after a restart.
    """

    def __init__(
        self,
        hass: Any,
        entry: ConfigEntry,
        uuid_bytes: bytes,
        identity_priv: Any,
        user_subtype: int = UserSubType.BT_SMARTPHONE,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"ISEO Log {entry.data[CONF_ADDRESS]}",
            update_interval=_LOG_POLL_INTERVAL,
        )
        self._entry = entry
        self._uuid_bytes = uuid_bytes
        self._identity_priv = identity_priv
        self._user_subtype = user_subtype
        self._store = Store(hass, _STORAGE_VERSION, f"{DOMAIN}_{entry.entry_id}_log")
        self._last_ts: datetime | None = None
        self._baseline_set: bool = False
        # uuid_hex (lower-case, 32 chars) → display name; populated by _refresh_user_dir()
        self._user_dir: dict[str, str] = {}
        self._user_dir_ts: datetime | None = None
        # Full user list from last whitelist fetch
        self._users: list[UserEntry] = []

        # Maintain a single client instance to reuse connection slots
        self.client = IseoClient(
            address=entry.data[CONF_ADDRESS],
            uuid_bytes=uuid_bytes,
            identity_priv=identity_priv,
            subtype=user_subtype,
            ble_device=async_ble_device_from_address(hass, entry.data[CONF_ADDRESS], connectable=True),
        )

    @property
    def user_dir(self) -> dict[str, str]:
        """Return the current uuid_hex → name mapping."""
        return self._user_dir

    @property
    def users(self) -> list[UserEntry]:
        """Return the full whitelist user list from the last fetch."""
        return self._users

    async def _refresh_user_dir(self) -> None:
        """Fetch the whitelist from the lock and rebuild the name directory."""
        try:
            # Re-read BLE device just in case it moved/changed
            self.client._ble_device = async_ble_device_from_address(
                self.hass, self._entry.data[CONF_ADDRESS], connectable=True
            )
            users: list[UserEntry] = await self.client.read_users(skip_login=True)
        except (IseoConnectionError, IseoAuthError) as exc:
            _LOGGER.debug("User directory refresh failed: %s", exc)
            return
        except Exception as exc:
            _LOGGER.debug("Unexpected error during user refresh: %s", exc)
            return

        self._users = users
        # Only store users that have a non-empty name set.
        self._user_dir = {u.uuid_hex.lower(): u.name for u in users if u.name}
        self._user_dir_ts = datetime.now(tz=timezone.utc)
        _LOGGER.debug(
            "User directory refreshed: %d named users (of %d total)",
            len(self._user_dir),
            len(users),
        )

    async def async_setup(self) -> None:
        """Load persisted state (call once after creating the coordinator)."""
        stored = await self._store.async_load()
        if stored:
            ts_str = stored.get("last_ts")
            if ts_str:
                self._last_ts = datetime.fromisoformat(ts_str)
            self._baseline_set = bool(stored.get("baseline_set", False))

    async def _async_update_data(self) -> "LogEntry | None":
        try:
            # Re-read BLE device just in case it moved/changed
            self.client._ble_device = async_ble_device_from_address(
                self.hass, self._entry.data[CONF_ADDRESS], connectable=True
            )
            if self._user_subtype == UserSubType.BT_GATEWAY:
                entries = await self.client.gw_read_unread_logs(connect_timeout=20.0)
            else:
                entries = await self.client.read_logs(start=0, max_entries=_MAX_ENTRIES_PER_POLL)
        except (IseoConnectionError, IseoAuthError) as exc:
            raise UpdateFailed(f"Log fetch failed: {exc}") from exc

        if not entries:
            return self.data  # keep last known value

        # entries[0] is the most recent (lock returns newest-first)
        most_recent = entries[0]

        if not self._baseline_set:
            # First ever run: record the current state as baseline without
            # firing events, so we don't flood the logbook with old history.
            self._baseline_set = True
            self._last_ts = most_recent.timestamp
            await self._store.async_save(
                {
                    "last_ts": most_recent.timestamp.isoformat(),
                    "baseline_set": True,
                }
            )
            return most_recent

        # Find entries newer than the last-seen timestamp.
        new = [e for e in entries if self._last_ts is None or e.timestamp > self._last_ts]

        if new:
            # Refresh user directory if stale or if the whitelist changed.
            now = datetime.now(tz=timezone.utc)
            if (
                self._user_dir_ts is None
                or (now - self._user_dir_ts) >= _USER_REFRESH_INTERVAL
                or any(e.event_code in _USER_CHANGE_EVENT_CODES for e in new)
            ):
                await self._refresh_user_dir()

            entity_id = self._lock_entity_id()
            user_map: dict[str, str] = self._entry.options.get(CONF_USER_MAP, {})
            for e in reversed(new):  # fire in chronological order (oldest first)
                raw_actor = e.user_info.strip() or e.extra_description.strip()
                actor = _resolve_actor(raw_actor, self._user_dir) if raw_actor else ""
                # Map UUID → HA user ID for event context attribution.
                uuid_key = raw_actor.lower() if len(raw_actor) == 32 else None
                ha_user_id = user_map.get(uuid_key) if uuid_key else None
                event_ctx = Context(user_id=ha_user_id) if ha_user_id else None
                self.hass.bus.async_fire(
                    EVENT_TYPE,
                    {
                        "entity_id": entity_id,
                        "event_code": e.event_code,
                        "name": event_name(e.event_code),
                        "message": entry_message(e, self._user_dir),
                        "actor": actor,
                        "timestamp": e.timestamp.isoformat(),
                        "battery": e.battery,
                    },
                    context=event_ctx,
                )
            self._last_ts = most_recent.timestamp
            await self._store.async_save(
                {
                    "last_ts": most_recent.timestamp.isoformat(),
                    "baseline_set": True,
                }
            )

        return most_recent

    def _lock_entity_id(self) -> str | None:
        """Look up the lock entity_id from the entity registry."""
        unique_id = f"{self._entry.data[CONF_ADDRESS].replace(':', '').lower()}_lock"
        registry = er.async_get(self.hass)
        return registry.async_get_entity_id("lock", DOMAIN, unique_id)
