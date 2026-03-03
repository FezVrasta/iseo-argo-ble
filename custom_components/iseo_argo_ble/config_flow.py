"""Config flow for ISEO Argo BLE Lock."""

from __future__ import annotations

import logging
import uuid as uuid_module
from typing import Any

import voluptuous as vol
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from homeassistant import config_entries
from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_ble_device_from_address,
    async_discovered_service_info,
)
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.selector import (
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
)

from .ble_client import IseoAuthError, IseoClient, IseoConnectionError, UserSubType, is_iseo_advertisement
from .const import (
    CONF_ADDRESS,
    CONF_ADMIN_PRIV_SCALAR,
    CONF_ADMIN_UUID,
    CONF_PRIV_SCALAR,
    CONF_USER_MAP,
    CONF_USER_SUBTYPE,
    CONF_UUID,
    DEFAULT_USER_SUBTYPE,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


def _pub_to_bytes(priv: Any) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    raw = priv.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return raw[1:]  # 56-byte X||Y


def _discover_locks(hass: HomeAssistant) -> list[BluetoothServiceInfoBleak]:
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

    found: list[BluetoothServiceInfoBleak] = []
    for info in all_devices:
        if not is_iseo_advertisement(list(info.service_uuids or [])):
            _LOGGER.debug("  %s  name=%r — skipped (no ISEO device-type UUID)", info.address, info.name)
            continue
        _LOGGER.debug("  %s  name=%r  rssi=%d — ISEO lock", info.address, info.name, info.rssi)
        found.append(info)

    return found


class IseoConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):  # type: ignore[call-arg]
    """Handle config flow for ISEO Argo BLE Lock."""

    VERSION = 1

    @staticmethod
    @config_entries.callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> "IseoOptionsFlow":
        return IseoOptionsFlow(config_entry)

    def __init__(self) -> None:
        self._discovered: dict[str, BluetoothServiceInfoBleak] = {}
        self._address: str = ""
        self._device_name: str = ""
        self._uuid_hex: str = ""
        self._priv_scalar: str = ""
        self._priv: Any = None
        self._user_subtype: int = DEFAULT_USER_SUBTYPE
        self._bt_users: list = []
        self._user_map: dict = {}
        self._admin_uuid_hex: str = ""
        self._admin_priv_scalar: str = ""

    # ── Step 1: pick a lock from HA's BLE cache ───────────────────────────
    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None and CONF_ADDRESS in user_input:
            address = user_input[CONF_ADDRESS]

            # Register the unique ID for this flow but do NOT abort if the
            # device is already configured — the user may intentionally be
            # re-enrolling (e.g. after a lock factory reset).
            await self.async_set_unique_id(address.replace(":", ""))

            priv = ec.generate_private_key(ec.SECP224R1(), default_backend())
            if not isinstance(priv, ec.EllipticCurvePrivateKey):
                raise TypeError("Expected EllipticCurvePrivateKey")
            priv_int = priv.private_numbers().private_value  # type: ignore[attr-defined]
            new_uuid = uuid_module.uuid4().bytes

            self._address = address
            self._device_name = self._discovered[address].name if address in self._discovered else ""
            self._uuid_hex = new_uuid.hex()
            self._priv_scalar = hex(priv_int)
            self._priv = priv
            self._user_subtype = UserSubType.BT_GATEWAY

            return await self.async_step_gw_register()

        # Query HA's BLE cache (re-queried every time the form is shown, so
        # the user can wake the lock and click Submit to refresh the list).
        found = _discover_locks(self.hass)
        self._discovered = {info.address: info for info in found}

        if not self._discovered:
            errors["base"] = "no_devices_found"
            return self.async_show_form(
                step_id="user",
                data_schema=vol.Schema({}),
                errors=errors,
            )

        # Mark devices that are already configured so the user can make an
        # informed choice, but don't prevent them from selecting one.
        configured = {entry.data.get(CONF_ADDRESS) for entry in self._async_current_entries()}

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_ADDRESS): SelectSelector(
                        SelectSelectorConfig(
                            options=[
                                {
                                    "value": info.address,
                                    "label": (
                                        f"{info.name or 'Unknown'}  —  {info.address}"
                                        f"  (RSSI {info.rssi} dBm)"
                                        + (" — already configured" if info.address in configured else "")
                                    ),
                                }
                                for info in found
                            ],
                            mode=SelectSelectorMode.LIST,
                        )
                    ),
                }
            ),
            errors=errors,
        )

    # ── Bluetooth auto-discovery ───────────────────────────────────────────
    async def async_step_bluetooth(self, discovery_info: BluetoothServiceInfoBleak) -> FlowResult:
        """Called by HA when a matching BLE advertisement is seen."""
        await self.async_set_unique_id(discovery_info.address.replace(":", ""))
        self._abort_if_unique_id_configured()

        # Safety check — only accept genuine ISEO advertisements.
        if not is_iseo_advertisement(list(discovery_info.service_uuids or [])):
            return self.async_abort(reason="not_iseo_device")

        priv = ec.generate_private_key(ec.SECP224R1(), default_backend())
        if not isinstance(priv, ec.EllipticCurvePrivateKey):
            raise TypeError("Expected EllipticCurvePrivateKey")
        priv_int = priv.private_numbers().private_value  # type: ignore[attr-defined]
        new_uuid = uuid_module.uuid4().bytes

        self._address = discovery_info.address
        self._device_name = discovery_info.name or discovery_info.address
        self._uuid_hex = new_uuid.hex()
        self._priv_scalar = hex(priv_int)
        self._priv = priv
        self._user_subtype = UserSubType.BT_GATEWAY

        self.context["title_placeholders"] = {"name": self._device_name}
        return await self.async_step_bluetooth_confirm()

    async def async_step_bluetooth_confirm(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Confirm the discovered lock before proceeding to enrollment."""
        if user_input is not None:
            return await self.async_step_gw_register()

        return self.async_show_form(
            step_id="bluetooth_confirm",
            description_placeholders={"name": self._device_name},
        )

    async def async_step_gw_register(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Step 1: Register the UUID as a Gateway (requires Master Card)."""
        errors: dict[str, str] = {}
        if user_input is not None:
            _LOGGER.debug("Starting Gateway registration for %s", self._address)
            client = IseoClient(
                address=self._address,
                uuid_bytes=bytes.fromhex(self._uuid_hex),
                identity_priv=self._priv,
                subtype=self._user_subtype,
                ble_device=async_ble_device_from_address(self.hass, self._address, connectable=True),
            )
            try:
                await client.register_user(name="Home Assistant")
                return await self.async_step_gw_register_logs()
            except (IseoConnectionError, IseoAuthError) as exc:
                _LOGGER.error("Gateway registration failed: %s", exc)
                errors["base"] = "auth_failed"

        return self.async_show_form(
            step_id="gw_register",
            description_placeholders={"uuid": self._uuid_hex.upper()},
            errors=errors,
        )

    async def async_step_gw_register_logs(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Step 2: Enable log notifications for the Gateway (requires Master Card)."""
        errors: dict[str, str] = {}
        if user_input is not None:
            _LOGGER.debug("Starting Gateway log registration for %s", self._address)
            client = IseoClient(
                address=self._address,
                uuid_bytes=bytes.fromhex(self._uuid_hex),
                identity_priv=self._priv,
                subtype=self._user_subtype,
                ble_device=async_ble_device_from_address(self.hass, self._address, connectable=True),
            )
            try:
                # Use the simplified client method which has a long internal timeout
                await client.gw_register_log_notif()
                return await self.async_step_gw_fetch_users()
            except (IseoConnectionError, IseoAuthError) as exc:
                _LOGGER.error("Gateway log registration failed: %s", exc)
                errors["base"] = "auth_failed"
            except Exception:
                _LOGGER.exception("Unexpected error during Gateway log registration")
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="gw_register_logs",
            data_schema=vol.Schema({}),
            errors=errors,
        )

    async def async_step_gw_fetch_users(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Step 3: Fetch the user list from the lock (requires Master Card)."""
        errors: dict[str, str] = {}
        if user_input is not None:
            client = IseoClient(
                address=self._address,
                uuid_bytes=bytes.fromhex(self._uuid_hex),
                identity_priv=self._priv,
                subtype=self._user_subtype,
                ble_device=async_ble_device_from_address(self.hass, self._address, connectable=True),
            )
            try:
                # This will wait for master card - use skip_login=True because
                # we assume the lock is already in Master Mode via physical card scan.
                self._bt_users = await client.read_users(skip_login=True)
                return await self.async_step_map_users()
            except (IseoConnectionError, IseoAuthError) as exc:
                _LOGGER.error("Failed to fetch users: %s", exc)
                errors["base"] = "auth_failed"

        return self.async_show_form(
            step_id="gw_fetch_users",
            data_schema=vol.Schema({}),
            errors=errors,
        )

    async def async_step_map_users(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Step 4: Map Argo users to HA accounts."""
        # Display all users regardless of type (RFID, BT, PIN, etc.)
        all_users = self._bt_users

        name_to_uuid: dict[str, str] = {(u.name or u.uuid_hex[:8]): u.uuid_hex.lower() for u in all_users}

        if user_input is not None:
            skip_mapping = user_input.pop("ignore_all", False)
            if not skip_mapping:
                self._user_map = {
                    name_to_uuid[name]: ha_uid for name, ha_uid in user_input.items() if ha_uid and name in name_to_uuid
                }

            return await self.async_step_admin_setup()

        # Fetch HA user accounts
        ha_users = await self.hass.auth.async_get_users()
        ha_user_options = [
            {"value": u.id, "label": u.name or u.id} for u in ha_users if not u.system_generated and u.is_active
        ]

        fields: dict = {vol.Optional("ignore_all", default=False): bool}
        for u in all_users:
            name = u.name or u.uuid_hex[:8]
            fields[vol.Optional(name)] = SelectSelector(
                SelectSelectorConfig(
                    options=ha_user_options,
                    mode=SelectSelectorMode.DROPDOWN,
                )
            )

        return self.async_show_form(
            step_id="map_users",
            data_schema=vol.Schema(fields),
        )

    async def async_step_admin_setup(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Optional: Configure an existing admin phone identity for management."""
        if user_input is not None:
            if not user_input.get("setup_admin"):
                return self._async_create_iseo_entry()

            # Generate new identity
            priv = ec.generate_private_key(ec.SECP224R1(), default_backend())
            if not isinstance(priv, ec.EllipticCurvePrivateKey):
                raise TypeError("Expected EllipticCurvePrivateKey")
            priv_int = priv.private_numbers().private_value  # type: ignore[attr-defined]
            new_uuid = uuid_module.uuid4().bytes

            self._admin_uuid_hex = new_uuid.hex()
            self._admin_priv_scalar = hex(priv_int)
            self._priv = priv  # Temporary store for the enrollment step

            return await self.async_step_admin_enroll()

        return self.async_show_form(
            step_id="admin_setup",
            data_schema=vol.Schema(
                {
                    vol.Required("setup_admin", default=False): bool,
                }
            ),
        )

    async def async_step_admin_enroll(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Step to show generated UUID and enroll via Open command."""
        errors: dict[str, str] = {}
        if user_input is not None:
            client = IseoClient(
                address=self._address,
                uuid_bytes=bytes.fromhex(self._admin_uuid_hex),
                identity_priv=self._priv,
                subtype=UserSubType.BT_SMARTPHONE,
                ble_device=async_ble_device_from_address(self.hass, self._address, connectable=True),
            )
            try:
                # The first open call is what stores the public key on the lock
                await client.open_lock()
                return self._async_create_iseo_entry()
            except (IseoConnectionError, IseoAuthError) as exc:
                _LOGGER.error("Admin enrollment failed: %s", exc)
                errors["base"] = "auth_failed"

        from homeassistant.helpers.selector import TextSelector, TextSelectorConfig

        return self.async_show_form(
            step_id="admin_enroll",
            data_schema=vol.Schema(
                {
                    vol.Optional("uuid_display", default=self._admin_uuid_hex.upper()): TextSelector(
                        TextSelectorConfig(multiline=False)
                    ),
                }
            ),
            description_placeholders={"uuid": self._admin_uuid_hex.upper()},
            errors=errors,
        )

    def _async_create_iseo_entry(self) -> FlowResult:
        """Helper to create the final config entry."""
        data = {
            CONF_ADDRESS: self._address,
            CONF_UUID: self._uuid_hex,
            CONF_PRIV_SCALAR: self._priv_scalar,
            CONF_USER_SUBTYPE: self._user_subtype,
        }
        if self._admin_uuid_hex and self._admin_priv_scalar:
            data[CONF_ADMIN_UUID] = self._admin_uuid_hex
            data[CONF_ADMIN_PRIV_SCALAR] = self._admin_priv_scalar

        return self.async_create_entry(
            title=self._device_name or f"ISEO Lock ({self._address})",
            data=data,
            options={
                CONF_USER_MAP: self._user_map,
            },
        )


class IseoOptionsFlow(config_entries.OptionsFlow):
    """Options flow for mapping Argo users to HA accounts and managing admin identity."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self._config_entry = config_entry
        self._bt_users: list = []
        self._admin_uuid_hex: str = ""
        self._admin_priv_scalar: str = ""
        self._priv: Any = None

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Menu to choose between User Management and Admin Identity."""
        if user_input is not None:
            choice = user_input["management_choice"]
            if choice == "users":
                if CONF_ADMIN_UUID in self._config_entry.data:
                    # Skip the refresh instruction step and go straight to the logic
                    return await self.async_step_user_management_refresh({})
                return await self.async_step_user_management_refresh()
            return await self.async_step_admin_identity()

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required("management_choice", default="users"): SelectSelector(
                        SelectSelectorConfig(
                            options=[
                                {"value": "users", "label": "Manage User Mappings"},
                                {"value": "admin", "label": "Manage Admin Identity"},
                            ],
                            mode=SelectSelectorMode.LIST,
                            translation_key="management_choice",
                        )
                    )
                }
            ),
        )

    async def async_step_user_management_refresh(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Step to refresh user list (automatically if admin exists, otherwise requires card)."""
        errors: dict[str, str] = {}
        has_admin = CONF_ADMIN_UUID in self._config_entry.data

        if user_input is not None:
            # Safely get the coordinator. It might not be in hass.data if the entry is being
            # configured but hasn't successfully loaded yet.
            domain_data = self.hass.data.get(DOMAIN, {})
            entry_data = domain_data.get(self._config_entry.entry_id, {})
            coordinator = entry_data.get("coordinator")

            client: IseoClient
            if coordinator:
                client = coordinator.client
            else:
                # Fallback: Create a temporary client if integration isn't loaded
                _LOGGER.debug("Coordinator not found; creating temporary client for user refresh")
                priv_int = int(self._config_entry.data[CONF_PRIV_SCALAR], 16)
                priv = await self.hass.async_add_executor_job(
                    ec.derive_private_key, priv_int, ec.SECP224R1(), default_backend()
                )
                client = IseoClient(
                    address=self._config_entry.data[CONF_ADDRESS],
                    uuid_bytes=bytes.fromhex(self._config_entry.data[CONF_UUID]),
                    identity_priv=priv,
                    subtype=self._config_entry.data.get(CONF_USER_SUBTYPE, UserSubType.BT_GATEWAY),
                )

            orig_uuid = client._uuid_bytes
            orig_priv = client._identity_priv
            orig_subtype = client._subtype

            try:
                client._ble_device = async_ble_device_from_address(
                    self.hass, self._config_entry.data[CONF_ADDRESS], connectable=True
                )
                if has_admin:
                    _LOGGER.debug("Refreshing users using configured admin identity")
                    # Reconstruct admin private key
                    priv_int = int(self._config_entry.data[CONF_ADMIN_PRIV_SCALAR], 16)
                    admin_priv = await self.hass.async_add_executor_job(
                        ec.derive_private_key, priv_int, ec.SECP224R1(), default_backend()
                    )
                    # Temporarily use admin credentials
                    client._uuid_bytes = bytes.fromhex(self._config_entry.data[CONF_ADMIN_UUID])
                    client._identity_priv = admin_priv
                    client._subtype = UserSubType.BT_SMARTPHONE

                    self._bt_users = await client.read_users(skip_login=False)
                else:
                    _LOGGER.debug("Refreshing users using Master Card scan")
                    self._bt_users = await client.read_users(skip_login=True)

                return await self.async_step_map_users()
            except (IseoConnectionError, IseoAuthError) as exc:
                _LOGGER.error("Failed to refresh users: %s", exc)
                errors["base"] = "auth_failed"
            finally:
                if has_admin:
                    # Restore original Gateway credentials
                    client._uuid_bytes = orig_uuid
                    client._identity_priv = orig_priv
                    client._subtype = orig_subtype

        return self.async_show_form(
            step_id="user_management_refresh",
            data_schema=vol.Schema({}),
            errors=errors,
        )

    async def async_step_admin_identity(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Manage (link/unlink) an admin phone identity."""
        if user_input is not None:
            choice = user_input["admin_action"]
            if choice == "remove":
                new_data = dict(self._config_entry.data)
                new_data.pop(CONF_ADMIN_UUID, None)
                new_data.pop(CONF_ADMIN_PRIV_SCALAR, None)
                self.hass.config_entries.async_update_entry(self._config_entry, data=new_data)
                return self.async_create_entry(title="", data={})

            if choice == "setup":
                # Generate new identity
                priv = ec.generate_private_key(ec.SECP224R1(), default_backend())
                if not isinstance(priv, ec.EllipticCurvePrivateKey):
                    raise TypeError("Expected EllipticCurvePrivateKey")
                priv_int = priv.private_numbers().private_value  # type: ignore[attr-defined]
                new_uuid = uuid_module.uuid4().bytes

                self._admin_uuid_hex = new_uuid.hex()
                self._admin_priv_scalar = hex(priv_int)
                self._priv = priv  # Temporary store for the enrollment step

                return await self.async_step_admin_enroll()

            # choice == "none"
            return self.async_create_entry(title="", data={})

        has_admin = CONF_ADMIN_UUID in self._config_entry.data
        options = [
            {"value": "setup", "label": "Configure/Rotate Admin Identity"},
            {"value": "none", "label": "Keep current configuration"},
        ]
        if has_admin:
            options.insert(1, {"value": "remove", "label": "Remove existing admin identity"})

        return self.async_show_form(
            step_id="admin_identity",
            data_schema=vol.Schema(
                {
                    vol.Required("admin_action", default="none"): SelectSelector(
                        SelectSelectorConfig(
                            options=options,
                            mode=SelectSelectorMode.LIST,
                            translation_key="admin_action",
                        )
                    ),
                }
            ),
        )

    async def async_step_admin_enroll(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Step to show generated UUID and enroll via Open command."""
        errors: dict[str, str] = {}
        if user_input is not None:
            domain_data = self.hass.data.get(DOMAIN, {})
            entry_data = domain_data.get(self._config_entry.entry_id, {})
            coordinator = entry_data.get("coordinator")

            client: IseoClient
            if coordinator:
                client = coordinator.client
            else:
                # Fallback: create temporary client if integration isn't loaded
                client = IseoClient(
                    address=self._config_entry.data[CONF_ADDRESS],
                    uuid_bytes=bytes.fromhex(self._admin_uuid_hex),
                    identity_priv=self._priv,
                    subtype=UserSubType.BT_SMARTPHONE,
                )

            client._ble_device = async_ble_device_from_address(
                self.hass, self._config_entry.data[CONF_ADDRESS], connectable=True
            )

            # We must temporarily use the admin credentials to perform the first open
            orig_uuid = client._uuid_bytes
            orig_priv = client._identity_priv
            orig_subtype = client._subtype

            client._uuid_bytes = bytes.fromhex(self._admin_uuid_hex)
            client._identity_priv = self._priv
            client._subtype = UserSubType.BT_SMARTPHONE

            try:
                await client.open_lock()

                # Success! Save the new admin identity to the entry data
                new_data = dict(self._config_entry.data)
                new_data[CONF_ADMIN_UUID] = self._admin_uuid_hex
                new_data[CONF_ADMIN_PRIV_SCALAR] = self._admin_priv_scalar
                self.hass.config_entries.async_update_entry(self._config_entry, data=new_data)

                return self.async_create_entry(title="", data={})
            except (IseoConnectionError, IseoAuthError) as exc:
                _LOGGER.error("Admin enrollment failed: %s", exc)
                errors["base"] = "auth_failed"
            finally:
                # Restore original client state
                client._uuid_bytes = orig_uuid
                client._identity_priv = orig_priv
                client._subtype = orig_subtype

        from homeassistant.helpers.selector import TextSelector, TextSelectorConfig

        return self.async_show_form(
            step_id="admin_enroll",
            data_schema=vol.Schema(
                {
                    vol.Optional("uuid_display", default=self._admin_uuid_hex.upper()): TextSelector(
                        TextSelectorConfig(multiline=False)
                    ),
                }
            ),
            description_placeholders={"uuid": self._admin_uuid_hex.upper()},
            errors=errors,
        )

    async def async_step_map_users(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Second step of options flow: map users."""
        # Display all users regardless of type (RFID, BT, PIN, etc.)
        all_users = self._bt_users

        name_to_uuid: dict[str, str] = {(u.name or u.uuid_hex[:8]): u.uuid_hex.lower() for u in all_users}

        if user_input is not None:
            mapping = {
                name_to_uuid[name]: ha_uid for name, ha_uid in user_input.items() if ha_uid and name in name_to_uuid
            }
            return self.async_create_entry(title="", data={CONF_USER_MAP: mapping})

        current_map: dict[str, str] = self._config_entry.options.get(CONF_USER_MAP, {})
        uuid_to_name = {v: k for k, v in name_to_uuid.items()}
        name_defaults: dict[str, str] = {
            uuid_to_name[uuid_key]: ha_uid for uuid_key, ha_uid in current_map.items() if uuid_key in uuid_to_name
        }

        ha_users = await self.hass.auth.async_get_users()
        ha_user_options = [
            {"value": u.id, "label": u.name or u.id} for u in ha_users if not u.system_generated and u.is_active
        ]

        fields: dict = {}
        for u in all_users:
            name = u.name or u.uuid_hex[:8]
            default = name_defaults.get(name)
            desc = {"suggested_value": default} if default else {}
            fields[vol.Optional(name, description=desc)] = SelectSelector(
                SelectSelectorConfig(
                    options=ha_user_options,
                    mode=SelectSelectorMode.DROPDOWN,
                )
            )

        return self.async_show_form(
            step_id="map_users",
            data_schema=vol.Schema(fields),
            description_placeholders={"count": str(len(all_users))},
        )
