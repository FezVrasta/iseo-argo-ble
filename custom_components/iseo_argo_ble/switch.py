"""ISEO BLE user management switches."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.bluetooth import async_ble_device_from_address
from homeassistant.components.switch import SwitchEntity
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import IseoConfigEntry
from .client import USER_TYPE_BT, USER_TYPE_PIN, USER_TYPE_RFID, UserEntry
from .const import CONF_ADDRESS, CONF_USER_MAPPING, DOMAIN

_LOGGER = logging.getLogger(__name__)

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

    def _get_entities() -> list[IseoUserSwitch]:
        return [
            IseoUserSwitch(entry, user)
            for user in coordinator.data
            if not (user.user_type == USER_TYPE_BT and user.inner_subtype == 17)
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

        self._attr_unique_id = f"{entry.unique_id}_user_{user.user_type}_{user.uuid_hex}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.unique_id)},
        )

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes."""
        user_type_label = USER_TYPE_LABELS.get(self._user_type, f"Unknown ({self._user_type})")

        attrs = {
            "user_type": user_type_label,
            "uuid": self._uuid_hex,
        }

        # Add linked user if any
        mapping = self._entry.options.get(CONF_USER_MAPPING, {})
        user_key = f"{self._user_type}_{self._uuid_hex}"
        if linked_user_id := mapping.get(user_key):
            attrs["linked_user_id"] = linked_user_id

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
        address = self._entry.data[CONF_ADDRESS]

        if admin_client is None:
            _LOGGER.error("Cannot modify user: no admin identity configured")
            return

        ble_device = (
            async_ble_device_from_address(self.hass, address, connectable=True)
            or self._entry.runtime_data.last_ble_device
        )
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
