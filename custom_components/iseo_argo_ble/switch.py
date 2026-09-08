"""ISEO BLE user management switches."""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import IseoConfigEntry, async_set_passage_mode, get_ble_device
from .client import UserEntry
from .const import (
    CONF_ADMIN_UUID,
    CONF_USER_MAPPING,
    CONF_USER_VALIDITY,
    DOMAIN,
    USER_TYPE_LABELS,
    is_ha_internal_user,
    signal_update,
    user_key,
)
from .entity import IseoPassiveEntity, passage_mode_active

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: IseoConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up ISEO user switches from a config entry."""
    data = entry.runtime_data
    coordinator = data.user_coordinator

    admin_uuid_hex = entry.data.get(CONF_ADMIN_UUID, "")

    def _get_entities() -> list[IseoUserSwitch]:
        if coordinator is None:
            return []
        return [
            IseoUserSwitch(entry, user) for user in coordinator.data if not is_ha_internal_user(user, admin_uuid_hex)
        ]

    async_add_entities([IseoPassageModeSwitch(entry), *_get_entities()])


class IseoUserSwitch(CoordinatorEntity, SwitchEntity):
    """Represents a switch to enable/disable an ISEO user."""

    _attr_has_entity_name = True
    _attr_icon = "mdi:account-lock"

    def __init__(
        self,
        entry: IseoConfigEntry,
        user: UserEntry,
    ) -> None:
        """Initialize the user switch."""
        super().__init__(entry.runtime_data.user_coordinator)
        self._entry = entry
        self._uuid_hex = user.uuid_hex
        self._user_type = user.user_type

        # Use user name if available, otherwise fallback to shortened UUID
        name = user.name.strip() or f"User {user.uuid_hex[:8]}"
        self._attr_name = name

        self._linked_ha_user_name: str | None = None
        self._attr_unique_id = f"{entry.unique_id}_user_{user_key(user.user_type, user.uuid_hex)}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.unique_id)},
        )

    async def async_added_to_hass(self) -> None:
        """Resolve linked HA user name on startup and re-resolve on options update."""
        await super().async_added_to_hass()
        await self._resolve_linked_user()
        self.async_on_remove(self._entry.add_update_listener(self._on_options_updated))
        # Refresh when the lock attributes a new open (updates "last opened").
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                signal_update(self._entry.entry_id),
                self.async_write_ha_state,
            )
        )

    async def _on_options_updated(self, _hass: Any, _entry: Any) -> None:
        """Re-resolve linked user name when options change."""
        await self._resolve_linked_user()
        self.async_write_ha_state()

    async def _resolve_linked_user(self) -> None:
        """Look up the HA user name for the linked user ID."""
        mapping = self._entry.options.get(CONF_USER_MAPPING, {})
        if linked_user_id := mapping.get(self._user_key):
            user = await self.hass.auth.async_get_user(linked_user_id)
            self._linked_ha_user_name = user.name if user else None
        else:
            self._linked_ha_user_name = None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes."""
        user_type_label = USER_TYPE_LABELS.get(self._user_type, f"Unknown ({self._user_type})")

        attrs: dict[str, Any] = {
            "user_type": user_type_label,
            "uuid": self._uuid_hex,
        }

        mapping = self._entry.options.get(CONF_USER_MAPPING, {})
        if linked_user_id := mapping.get(self._user_key):
            attrs["linked_ha_user_id"] = linked_user_id
            if self._linked_ha_user_name is not None:
                attrs["linked_ha_user_name"] = self._linked_ha_user_name

        # Last door open attributed to this specific user (from the access log).
        if record := self._entry.runtime_data.last_open_by_user.get(self._user_key):
            attrs["last_opened"] = record.get("timestamp")
            attrs["last_open_event"] = record.get("event")

        return attrs

    @property
    def is_on(self) -> bool:
        """Return True if the user is enabled."""
        user = next(
            (u for u in self.coordinator.data if u.uuid_hex == self._uuid_hex and u.user_type == self._user_type), None
        )
        if user:
            return not user.disabled
        return False

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Enable the user."""
        await self._set_disabled(False)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Disable the user."""
        await self._set_disabled(True)

    @property
    def _user_key(self) -> str:
        """Key identifying this credential in the entry's options dicts."""
        return user_key(self._user_type, self._uuid_hex)

    def _validity_to_preserve(self) -> bytes | None:
        """The time profile suspension would destroy, or None if there is none.

        An already-suspended user has nothing worth keeping — its tag 16 is the
        expired sentinel — and saving that would turn a later enable into a
        no-op that leaves the credential locked out.
        """
        user = next(
            (u for u in self.coordinator.data if u.uuid_hex == self._uuid_hex and u.user_type == self._user_type),
            None,
        )
        if user is None or user.disabled:
            return None
        return user.validity

    def _stored_validity(self) -> dict[str, str]:
        """The saved time profiles, as a copy safe to mutate."""
        return dict(self._entry.options.get(CONF_USER_VALIDITY, {}))

    def _remember_validity(self, validity: bytes | None) -> None:
        """Save the time profile suspension is about to overwrite.

        Suspending replaces tag 16 with an expired range, so the lock stops
        being able to tell us what the credential was valid for. Without this
        copy, re-enabling could only clear every restriction — handing back an
        invitation good for one weekend as one good forever.
        """
        stored = self._stored_validity()
        if validity is None:
            stored.pop(self._user_key, None)
        else:
            stored[self._user_key] = validity.hex()
        self.hass.config_entries.async_update_entry(
            self._entry,
            options={**self._entry.options, CONF_USER_VALIDITY: stored},
        )

    async def _set_disabled(self, disabled: bool) -> None:
        """Set the disabled state on the lock."""
        admin_client = self._entry.runtime_data.admin_client
        ble_lock = self._entry.runtime_data.ble_lock

        if admin_client is None:
            # Optimistic state would otherwise flip and silently snap back on
            # the next write, with nothing shown for why.
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="no_admin_identity",
            )

        ble_device = get_ble_device(self.hass, self._entry)
        if not ble_device:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="cannot_connect",
            )

        # Save before the write, not after: once the lock is suspended its tag
        # 16 is the expired sentinel, and a refresh in between would leave the
        # cache holding that instead of the window worth restoring.
        validity: bytes | None = None
        if disabled:
            self._remember_validity(self._validity_to_preserve())
        elif saved := self._stored_validity().get(self._user_key):
            try:
                validity = bytes.fromhex(saved)
            except ValueError:
                _LOGGER.warning("Ignoring unreadable saved time profile for %s: %r", self._user_key, saved)

        try:
            async with ble_lock:
                admin_client.update_ble_device(ble_device)
                await admin_client.set_user_disabled(
                    uuid_hex=self._uuid_hex,
                    user_type=self._user_type,
                    disabled=disabled,
                    validity=validity,
                )
            self._patch_cached_user(disabled)
        except Exception as err:
            _LOGGER.error("Failed to set user disabled state: %s", err)
            raise

        if not disabled:
            # Restored — the lock holds the window again, so drop our copy.
            self._remember_validity(None)

    def _patch_cached_user(self, disabled: bool) -> None:
        """Apply the new state to the cached user list instead of re-reading it.

        Re-reading costs a whole second BLE session — connect, ECDH, master
        login, then a paginated read of every user — to learn a value we just
        set ourselves, and the lock is unresponsive for its duration. The write
        raises on failure, so reaching here means the lock accepted it.
        """
        users = self.coordinator.data
        if not users:
            return
        self.coordinator.async_set_updated_data(
            [
                replace(user, disabled=disabled)
                if user.user_type == self._user_type and user.uuid_hex == self._uuid_hex
                else user
                for user in users
            ]
        )


class IseoPassageModeSwitch(IseoPassiveEntity, SwitchEntity):
    """Passage mode — the lock holds the latch open until the mode is turned off.

    State comes from the passive advertisements like the other passive entities;
    only turning it on or off costs a BLE connection.
    """

    _attr_translation_key = "passage_mode"

    def __init__(self, entry: IseoConfigEntry) -> None:
        """Initialize the passage mode switch."""
        super().__init__(entry)
        self._attr_unique_id = f"{entry.unique_id}_passage_mode"

    @property
    def is_on(self) -> bool | None:
        """Return whether passage mode is active per the latest advertisement."""
        state = self._state
        if state is None:
            return None
        return passage_mode_active(state)

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Hold the latch open."""
        await async_set_passage_mode(self.hass, self._entry, enabled=True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Release the latch."""
        await async_set_passage_mode(self.hass, self._entry, enabled=False)
