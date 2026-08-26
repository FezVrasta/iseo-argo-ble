"""ISEO BLE user management switches."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import IseoConfigEntry, get_ble_device
from .client import USER_TYPE_BT, USER_TYPE_PIN, USER_TYPE_RFID, UserEntry
from .const import CONF_ADMIN_UUID, CONF_USER_MAPPING, DOMAIN, signal_update

_LOGGER = logging.getLogger(__name__)


def _is_ha_internal_user(user: UserEntry, admin_uuid_hex: str) -> bool:
    """Return True for users that are internal HA identities (gateway or admin)."""
    if user.user_type == USER_TYPE_BT and user.inner_subtype == 17:
        return True  # HA gateway user
    if admin_uuid_hex and user.uuid_hex == admin_uuid_hex:
        return True  # HA admin user
    return False


USER_TYPE_LABELS = {
    USER_TYPE_RFID: "RFID",
    USER_TYPE_BT: "Phone",
    USER_TYPE_PIN: "PIN",
    19: "Invitation",
    20: "Fingerprint",
    21: "Account",
}


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
        return [
            IseoUserSwitch(entry, user) for user in coordinator.data if not _is_ha_internal_user(user, admin_uuid_hex)
        ]

    async_add_entities(_get_entities())


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
        self._attr_unique_id = f"{entry.unique_id}_user_{user.user_type}_{user.uuid_hex}"
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
        user_key = f"{self._user_type}_{self._uuid_hex}"
        if linked_user_id := mapping.get(user_key):
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

        user_key = f"{self._user_type}_{self._uuid_hex}"

        mapping = self._entry.options.get(CONF_USER_MAPPING, {})
        if linked_user_id := mapping.get(user_key):
            attrs["linked_ha_user_id"] = linked_user_id
            if self._linked_ha_user_name is not None:
                attrs["linked_ha_user_name"] = self._linked_ha_user_name

        # Last door open attributed to this specific user (from the access log).
        if record := self._entry.runtime_data.last_open_by_user.get(user_key):
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

    async def _set_disabled(self, disabled: bool) -> None:
        """Set the disabled state on the lock."""
        admin_client = self._entry.runtime_data.admin_client
        ble_lock = self._entry.runtime_data.ble_lock

        if admin_client is None:
            _LOGGER.error("Cannot modify user: no admin identity configured")
            return

        ble_device = get_ble_device(self.hass, self._entry)
        if not ble_device:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="cannot_connect",
            )

        try:
            async with ble_lock:
                admin_client.update_ble_device(ble_device)
                await admin_client.set_user_disabled(
                    uuid_hex=self._uuid_hex,
                    user_type=self._user_type,
                    disabled=disabled,
                )
            await self.coordinator.async_request_refresh()
        except Exception as err:
            _LOGGER.error("Failed to set user disabled state: %s", err)
            raise
