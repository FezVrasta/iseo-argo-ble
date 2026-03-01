"""Config flow for ISEO Argo BLE Lock."""

from __future__ import annotations

import logging
import uuid as uuid_module
from typing import Any

import voluptuous as vol
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import SECP224R1, generate_private_key
from homeassistant import config_entries
from homeassistant.components.bluetooth import async_discovered_service_info
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.selector import (
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
)

from .ble_client import IseoAuthError, IseoClient, IseoConnectionError, is_iseo_advertisement
from .const import CONF_ADDRESS, CONF_PRIV_SCALAR, CONF_USER_MAP, CONF_UUID, DOMAIN

_LOGGER = logging.getLogger(__name__)


def _pub_to_bytes(priv: Any) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    raw = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return raw[1:]  # 56-byte X||Y


def _discover_locks(hass: HomeAssistant) -> dict[str, str]:
    """
    Query HA's bluetooth integration for nearby ISEO locks, sorted by signal
    strength (strongest first).

    ISEO locks advertise 16-bit service UUIDs in the range 0xF000–0xF03F that
    encode the device type.  We filter on that range rather than a fixed UUID.
    """
    all_devices = sorted(
        async_discovered_service_info(hass, connectable=True),
        key=lambda i: i.rssi,
        reverse=True,  # strongest signal first
    )
    _LOGGER.debug("HA bluetooth cache — %d connectable device(s) visible", len(all_devices))

    found: dict[str, str] = {}
    for info in all_devices:
        if not is_iseo_advertisement(list(info.service_uuids or [])):
            _LOGGER.debug("  %s  name=%r — skipped (no ISEO device-type UUID)", info.address, info.name)
            continue
        _LOGGER.debug("  %s  name=%r  rssi=%d — ISEO lock", info.address, info.name, info.rssi)
        name  = info.name or "Unknown"
        label = f"{name}  —  {info.address}  (RSSI {info.rssi} dBm)"
        found[info.address] = label

    return found


class IseoConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle config flow for ISEO Argo BLE Lock."""

    VERSION = 1

    @staticmethod
    @config_entries.callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> "IseoOptionsFlow":
        return IseoOptionsFlow(config_entry)

    def __init__(self) -> None:
        self._locks:       dict[str, str] = {}
        self._address:     str = ""
        self._uuid_hex:    str = ""
        self._priv_scalar: str = ""
        self._priv:        Any = None

    # ── Step 1: pick a lock from HA's BLE cache ───────────────────────────
    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None and CONF_ADDRESS in user_input:
            address = user_input[CONF_ADDRESS]

            await self.async_set_unique_id(address.replace(":", ""))
            self._abort_if_unique_id_configured()

            priv     = generate_private_key(SECP224R1(), default_backend())
            priv_int = priv.private_numbers().private_value
            new_uuid = uuid_module.uuid4().bytes

            self._address     = address
            self._uuid_hex    = new_uuid.hex()
            self._priv_scalar = hex(priv_int)
            self._priv        = priv

            return await self.async_step_register()

        # Query HA's BLE cache (re-queried every time the form is shown, so
        # the user can wake the lock and click Submit to refresh the list).
        self._locks = _discover_locks(self.hass)

        if not self._locks:
            errors["base"] = "no_devices_found"
            return self.async_show_form(
                step_id="user",
                data_schema=vol.Schema({}),
                errors=errors,
            )

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({
                vol.Required(CONF_ADDRESS): SelectSelector(
                    SelectSelectorConfig(
                        options=[
                            {"value": addr, "label": label}
                            for addr, label in self._locks.items()
                        ],
                        mode=SelectSelectorMode.LIST,
                    )
                ),
            }),
            errors=errors,
        )

    # ── Step 2: show UUID, send Open command to enroll ────────────────────
    async def async_step_register(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """
        Display the UUID for the admin to register in the Argo app.
        Submitting sends an Open command which proves key ownership and
        enrolls the public key on the lock. Success creates the config entry.
        """
        errors: dict[str, str] = {}

        if user_input is not None:
            client = IseoClient(
                address       = self._address,
                uuid_bytes    = bytes.fromhex(self._uuid_hex),
                identity_priv = self._priv,
            )
            try:
                await client.open_lock()
            except IseoAuthError:
                errors["base"] = "auth_failed"
            except IseoConnectionError:
                errors["base"] = "cannot_connect"
            except Exception:
                errors["base"] = "unknown"
            else:
                return self.async_create_entry(
                    title=f"ISEO Lock ({self._address})",
                    data={
                        CONF_ADDRESS:     self._address,
                        CONF_UUID:        self._uuid_hex,
                        CONF_PRIV_SCALAR: self._priv_scalar,
                    },
                )

        return self.async_show_form(
            step_id="register",
            data_schema=vol.Schema({}),
            description_placeholders={"uuid": self._uuid_hex.upper()},
            errors=errors,
        )


class IseoOptionsFlow(config_entries.OptionsFlow):
    """Options flow for mapping Argo users to HA accounts."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self._config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        # Get cached users from coordinator (no fresh BLE connection needed).
        coordinator = self.hass.data[DOMAIN][self._config_entry.entry_id]["coordinator"]
        bt_users = [u for u in coordinator.users if u.user_type == 17]  # BT users only

        # Build a name → uuid_hex lookup for the save step.
        # Keys in the form are Argo friendly names (readable labels); values stored are UUIDs.
        name_to_uuid: dict[str, str] = {
            (u.name or u.uuid_hex[:8]): u.uuid_hex.lower()
            for u in bt_users
        }

        if user_input is not None:
            # Convert form keys (Argo names) back to stable UUID keys before storing.
            mapping = {
                name_to_uuid[name]: ha_uid
                for name, ha_uid in user_input.items()
                if ha_uid and name in name_to_uuid
            }
            return self.async_create_entry(title="", data={CONF_USER_MAP: mapping})

        current_map: dict[str, str] = self._config_entry.options.get(CONF_USER_MAP, {})
        # Invert current_map (uuid → ha_uid) to (name → ha_uid) for pre-population.
        uuid_to_name = {v: k for k, v in name_to_uuid.items()}
        name_defaults: dict[str, str] = {
            uuid_to_name[uuid_key]: ha_uid
            for uuid_key, ha_uid in current_map.items()
            if uuid_key in uuid_to_name
        }

        # Fetch HA user accounts for the select options.
        ha_users = await self.hass.auth.async_get_users()
        ha_user_options = [
            {"value": u.id, "label": u.name or u.id}
            for u in ha_users
            if not u.system_generated and u.is_active
        ]

        # Build schema: one SelectSelector per BT user, keyed by Argo name (used as label).
        fields: dict = {}
        for u in bt_users:
            name    = u.name or u.uuid_hex[:8]
            default = name_defaults.get(name)
            desc    = {"suggested_value": default} if default else {}
            fields[vol.Optional(name, description=desc)] = SelectSelector(
                SelectSelectorConfig(
                    options=ha_user_options,
                    mode=SelectSelectorMode.DROPDOWN,
                )
            )

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(fields) if fields else vol.Schema({}),
            description_placeholders={"count": str(len(bt_users))},
        )
