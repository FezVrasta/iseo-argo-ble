"""Config flow for ISEO Argo BLE Lock."""

from __future__ import annotations

import logging
import uuid as uuid_module
from typing import Any

import voluptuous as vol
from cryptography.hazmat.primitives.asymmetric import ec
from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_ble_device_from_address,
    async_discovered_service_info,
)
from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import format_mac
from homeassistant.helpers.selector import (
    BooleanSelector,
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
)

from . import IseoData
from .client import (
    USER_TYPE_BT,
    IseoAuthError,
    IseoClient,
    IseoConnectionError,
    UserEntry,
    is_iseo_advertisement,
)
from .const import (
    CONF_ADDRESS,
    CONF_ADMIN_PRIV_SCALAR,
    CONF_ADMIN_UUID,
    CONF_PRIV_SCALAR,
    CONF_USER_MAPPING,
    CONF_UUID,
    DEFAULT_USER_SUBTYPE,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


def _generate_identity() -> ec.EllipticCurvePrivateKey:
    """Generate a fresh SECP224R1 private key for use as an Argo BT identity."""
    return ec.generate_private_key(ec.SECP224R1())


def _discover_locks(hass: HomeAssistant) -> list[BluetoothServiceInfoBleak]:
    """Query HA's bluetooth integration for nearby ISEO locks."""
    all_devices = sorted(
        async_discovered_service_info(hass, connectable=True),
        key=lambda i: i.rssi,
        reverse=True,
    )
    _LOGGER.debug("HA bluetooth cache — %d connectable device(s) visible", len(all_devices))

    found: list[BluetoothServiceInfoBleak] = []
    for info in all_devices:
        if not is_iseo_advertisement(list(info.service_uuids or [])):
            continue
        _LOGGER.debug(
            "  %s  name=%r  rssi=%d — ISEO lock",
            info.address,
            info.name,
            info.rssi,
        )
        found.append(info)

    return found


class IseoConfigFlow(ConfigFlow, domain=DOMAIN):  # type: ignore[call-arg]
    """Handle config flow for ISEO Argo BLE Lock."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize."""
        self._discovered: dict[str, BluetoothServiceInfoBleak] = {}
        self._address: str = ""
        self._device_name: str = ""
        self._uuid_hex: str = ""
        self._priv_scalar: str = ""
        self._gw_priv: ec.EllipticCurvePrivateKey | None = None
        self._admin_uuid_hex: str = ""
        self._admin_priv_scalar: str = ""
        self._admin_priv: ec.EllipticCurvePrivateKey | None = None

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Pick a lock from HA's BLE cache."""
        errors: dict[str, str] = {}

        if user_input is not None:
            address = user_input[CONF_ADDRESS]

            await self.async_set_unique_id(format_mac(address))
            self._abort_if_unique_id_configured()

            priv = _generate_identity()
            priv_int = priv.private_numbers().private_value  # type: ignore[attr-defined]
            new_uuid = uuid_module.uuid4().bytes

            self._address = address
            self._device_name = self._discovered[address].name if address in self._discovered else ""
            self._uuid_hex = new_uuid.hex()
            self._priv_scalar = hex(priv_int)
            self._gw_priv = priv

            return await self.async_step_gw_register()

        found = _discover_locks(self.hass)
        self._discovered = {info.address: info for info in found}

        if not self._discovered:
            return self.async_abort(reason="no_devices_found")

        configured = {entry.data.get(CONF_ADDRESS) for entry in self._async_current_entries()}

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_ADDRESS): SelectSelector(
                        SelectSelectorConfig(
                            options=[
                                SelectOptionDict(
                                    value=info.address,
                                    label=(
                                        f"{info.name or 'Unknown'}  —  {info.address}"
                                        f"  (RSSI {info.rssi} dBm)"
                                        + (" — already configured" if info.address in configured else "")
                                    ),
                                )
                                for info in found
                            ],
                            mode=SelectSelectorMode.LIST,
                        )
                    ),
                }
            ),
            errors=errors,
        )

    async def async_step_bluetooth(self, discovery_info: BluetoothServiceInfoBleak) -> ConfigFlowResult:
        """Called by HA when a matching BLE advertisement is seen."""
        await self.async_set_unique_id(format_mac(discovery_info.address))
        self._abort_if_unique_id_configured()

        if not is_iseo_advertisement(list(discovery_info.service_uuids or [])):
            return self.async_abort(reason="not_iseo_device")

        priv = _generate_identity()
        priv_int = priv.private_numbers().private_value  # type: ignore[attr-defined]
        new_uuid = uuid_module.uuid4().bytes

        self._address = discovery_info.address
        self._device_name = discovery_info.name or discovery_info.address
        self._uuid_hex = new_uuid.hex()
        self._priv_scalar = hex(priv_int)
        self._gw_priv = priv

        self.context["title_placeholders"] = {"name": self._device_name}
        return await self.async_step_bluetooth_confirm()

    async def async_step_bluetooth_confirm(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Confirm the discovered lock before proceeding to enrollment."""
        if user_input is not None:
            return await self.async_step_gw_register()

        return self.async_show_form(
            step_id="bluetooth_confirm",
            description_placeholders={"name": self._device_name},
        )

    async def async_step_gw_register(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Register the gateway and enable passive door-status scanning."""
        errors: dict[str, str] = {}
        if user_input is not None:
            enable_admin = user_input.get("enable_admin", False)

            # Generate admin credentials ahead of the BLE call so we can store them
            if enable_admin:
                admin_priv = _generate_identity()
                admin_priv_int = admin_priv.private_numbers().private_value  # type: ignore[attr-defined]
                admin_uuid = uuid_module.uuid4().bytes
                self._admin_uuid_hex = admin_uuid.hex()
                self._admin_priv_scalar = hex(admin_priv_int)
                self._admin_priv = admin_priv
            else:
                self._admin_uuid_hex = ""
                self._admin_priv_scalar = ""
                self._admin_priv = None

            if not (ble_device := async_ble_device_from_address(self.hass, self._address, connectable=True)):
                errors["base"] = "cannot_connect"
            else:
                client = IseoClient(
                    address=self._address,
                    uuid_bytes=bytes.fromhex(self._uuid_hex),
                    identity_priv=self._gw_priv,
                    subtype=DEFAULT_USER_SUBTYPE,
                    ble_device=ble_device,
                )
                try:
                    await client.setup_gateway(
                        name="Home Assistant",
                        enable_door_status=True,
                        admin_uuid_bytes=bytes.fromhex(self._admin_uuid_hex) if self._admin_uuid_hex else None,
                        admin_identity_priv=self._admin_priv,
                    )
                    return self._async_create_iseo_entry()
                except IseoConnectionError:
                    errors["base"] = "cannot_connect"
                except IseoAuthError as exc:
                    _LOGGER.debug("Gateway setup failed: %s", exc)
                    errors["base"] = "auth_failed"
                except Exception:
                    _LOGGER.exception("Unexpected error during gateway setup")
                    errors["base"] = "unknown"

        return self.async_show_form(
            step_id="gw_register",
            data_schema=vol.Schema(
                {
                    vol.Required("enable_admin", default=True): BooleanSelector(),
                }
            ),
            errors=errors,
        )

    def _async_create_iseo_entry(self) -> ConfigFlowResult:
        """Create the final config entry."""
        data: dict[str, Any] = {
            CONF_ADDRESS: self._address,
            CONF_UUID: self._uuid_hex,
            CONF_PRIV_SCALAR: self._priv_scalar,
        }
        if self._admin_uuid_hex and self._admin_priv_scalar:
            data[CONF_ADMIN_UUID] = self._admin_uuid_hex
            data[CONF_ADMIN_PRIV_SCALAR] = self._admin_priv_scalar
        return self.async_create_entry(
            title=self._device_name or f"ISEO Lock ({self._address})",
            data=data,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> IseoOptionsFlowHandler:
        """Get the options flow for this handler."""
        return IseoOptionsFlowHandler()


def _is_ha_internal_user(user: UserEntry, admin_uuid_hex: str) -> bool:
    """Return True for HA-internal lock identities (gateway or admin)."""
    if user.user_type == USER_TYPE_BT and user.inner_subtype == 17:
        return True
    if admin_uuid_hex and user.uuid_hex == admin_uuid_hex:
        return True
    return False


class IseoOptionsFlowHandler(OptionsFlow):
    """Handle options flow for ISEO Argo BLE Lock."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Manage the options."""
        if user_input is not None:
            choice = user_input.get("management_choice")
            if choice == "users":
                return await self.async_step_map_users()
            # For now, only 'users' is implemented.
            # In the future, we could add 'admin' logic here.

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required("management_choice"): SelectSelector(
                        SelectSelectorConfig(
                            options=[
                                SelectOptionDict(value="users", label="Manage User Linking"),
                                # SelectOptionDict(value="admin", label="Manage Admin Identity"),
                            ],
                            mode=SelectSelectorMode.LIST,
                        )
                    )
                }
            ),
        )

    async def async_step_map_users(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Link Argo users to Home Assistant users."""
        if user_input is not None:
            # Reconstruct the mapping using the key map saved in context
            user_key_map: dict[str, str] = self.context.get("user_key_map", {})
            mapping = {}
            for label, value in user_input.items():
                if value and value != "" and label in user_key_map:
                    user_key = user_key_map[label]
                    mapping[user_key] = value

            return self.async_create_entry(title="", data={CONF_USER_MAPPING: mapping})

        # Get the users from the coordinator
        data: IseoData = self.config_entry.runtime_data
        if data.user_coordinator is None or data.user_coordinator.data is None:
            return self.async_abort(reason="no_admin_configured")

        users = data.user_coordinator.data

        # Filter out HA-internal users (gateway and admin identities)
        admin_uuid_hex = self.config_entry.data.get(CONF_ADMIN_UUID, "")
        mappable_users = [u for u in users if not _is_ha_internal_user(u, admin_uuid_hex)]

        # Get existing mapping
        existing_mapping = self.config_entry.options.get(CONF_USER_MAPPING, {})

        # Build list of HA users for the select dropdown
        ha_users = await self.hass.auth.async_get_users()
        ha_user_options = [
            SelectOptionDict(value=u.id, label=u.name or u.id)
            for u in ha_users
            if not u.system_generated and u.is_active
        ]
        ha_user_options.insert(0, SelectOptionDict(value="", label="(none)"))

        schema = {}
        user_key_map = {}
        for user in mappable_users:
            user_name = user.name.strip() or f"User {user.uuid_hex[:8]}"
            label = f"{user_name} ({user.uuid_hex[:4]})"
            user_key = f"{user.user_type}_{user.uuid_hex}"
            user_key_map[label] = user_key

            schema[
                vol.Optional(
                    label,
                    description={"suggested_value": existing_mapping.get(user_key, "")},
                )
            ] = SelectSelector(SelectSelectorConfig(options=ha_user_options, mode=SelectSelectorMode.DROPDOWN))

        # Persist the label→key map so it's available when the form is submitted
        self.context["user_key_map"] = user_key_map

        return self.async_show_form(
            step_id="map_users",
            data_schema=vol.Schema(schema),
            description_placeholders={"count": str(len(mappable_users))},
        )
