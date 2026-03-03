"""ISEO Argo BLE Lock — Home Assistant integration."""

from __future__ import annotations

import asyncio
import logging

import voluptuous as vol
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import SECP224R1, derive_private_key
from homeassistant.components.bluetooth import async_ble_device_from_address
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import entity_platform
from homeassistant.helpers.typing import ConfigType

from .ble_client import IseoClient, UserSubType
from .const import (
    CONF_ADDRESS,
    CONF_PRIV_SCALAR,
    CONF_USER_SUBTYPE,
    CONF_UUID,
    DEFAULT_USER_SUBTYPE,
    DOMAIN,
    PLATFORMS,
)
from .coordinator import IseoLogCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the ISEO Argo BLE Lock component."""

    async def handle_read_users(call: ServiceCall):
        """Fetch the complete list of registered users from the lock."""
        if not (entries := hass.config_entries.async_entries(DOMAIN)):
            raise vol.Invalid("No ISEO locks configured.")

        entry = entries[0]
        if entry.entry_id not in hass.data.get(DOMAIN, {}):
            raise vol.Invalid("ISEO lock not loaded.")

        priv_int = int(entry.data[CONF_PRIV_SCALAR], 16)
        priv = await hass.async_add_executor_job(derive_private_key, priv_int, SECP224R1(), default_backend())

        client = IseoClient(
            address=entry.data[CONF_ADDRESS],
            uuid_bytes=bytes.fromhex(entry.data[CONF_UUID]),
            identity_priv=priv,
            subtype=entry.data.get(CONF_USER_SUBTYPE, DEFAULT_USER_SUBTYPE),
            ble_device=async_ble_device_from_address(hass, entry.data[CONF_ADDRESS], connectable=True),
        )

        users = await client.read_users()
        return {
            "users": [
                {
                    "uuid": u.uuid_hex.upper(),
                    "name": u.name,
                    "type": u.user_type,
                    "subtype": u.inner_subtype,
                }
                for u in users
            ]
        }

    async def handle_delete_user(call: ServiceCall):
        """Remove a user from the lock's whitelist."""
        target_uuid_hex = call.data["uuid"]

        if not (entries := hass.config_entries.async_entries(DOMAIN)):
            raise vol.Invalid("No ISEO locks configured.")

        entry = entries[0]
        if entry.entry_id not in hass.data.get(DOMAIN, {}):
            raise vol.Invalid("ISEO lock not loaded.")

        priv_int = int(entry.data[CONF_PRIV_SCALAR], 16)
        priv = await hass.async_add_executor_job(derive_private_key, priv_int, SECP224R1(), default_backend())

        client = IseoClient(
            address=entry.data[CONF_ADDRESS],
            uuid_bytes=bytes.fromhex(entry.data[CONF_UUID]),
            identity_priv=priv,
            subtype=entry.data.get(CONF_USER_SUBTYPE, DEFAULT_USER_SUBTYPE),
            ble_device=async_ble_device_from_address(hass, entry.data[CONF_ADDRESS], connectable=True),
        )

        # Step 1: Fetch users to find the correct subtype
        users = await client.read_users()
        target_user = next((u for u in users if u.uuid_hex.lower() == target_uuid_hex.lower()), None)

        if not target_user:
            raise vol.Invalid(f"User with UUID {target_uuid_hex} not found on lock.")

        subtype = target_user.inner_subtype or UserSubType.BT_SMARTPHONE

        # Step 2: Delete (user_type 17 = Bluetooth)
        await client.erase_user_by_uuid(
            uuid_bytes=bytes.fromhex(target_uuid_hex),
            user_type=17,
            subtype=subtype
        )

    hass.services.async_register(
        DOMAIN,
        "read_users",
        handle_read_users,
        supports_response=entity_platform.SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        "delete_user",
        handle_delete_user,
        schema=vol.Schema(
            {
                vol.Required("uuid"): cv.string,
            }
        ),
    )

    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up ISEO Argo BLE Lock from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    # Derive the private key once (CPU-bound; run in executor).
    priv_int = int(entry.data[CONF_PRIV_SCALAR], 16)
    priv = await hass.async_add_executor_job(derive_private_key, priv_int, SECP224R1(), default_backend())
    uuid_bytes = bytes.fromhex(entry.data[CONF_UUID])
    subtype = entry.data.get(CONF_USER_SUBTYPE, DEFAULT_USER_SUBTYPE)

    coordinator = IseoLogCoordinator(hass, entry, uuid_bytes, priv, subtype)
    await coordinator.async_setup()  # load persisted last-seen timestamp
    await coordinator.async_config_entry_first_refresh()  # initial poll

    hass.data[DOMAIN][entry.entry_id] = {"coordinator": coordinator}

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry. Best-effort unregister from lock if it's a Gateway."""
    # 1. Attempt best-effort cleanup on the physical lock
    try:
        priv_int = int(entry.data[CONF_PRIV_SCALAR], 16)
        priv = await hass.async_add_executor_job(derive_private_key, priv_int, SECP224R1(), default_backend())
        address = entry.data[CONF_ADDRESS]
        uuid_bytes = bytes.fromhex(entry.data[CONF_UUID])
        subtype = entry.data.get(CONF_USER_SUBTYPE, DEFAULT_USER_SUBTYPE)

        client = IseoClient(
            address=address,
            uuid_bytes=uuid_bytes,
            identity_priv=priv,
            subtype=subtype,
            ble_device=async_ble_device_from_address(hass, address, connectable=True),
        )

        if subtype == UserSubType.BT_GATEWAY:
            _LOGGER.debug("Best-effort unregistering gateway from lock %s", address)
            async with asyncio.timeout(35):
                await client.erase_user()
    except Exception as exc:
        _LOGGER.debug("Best-effort lock cleanup failed (ignoring): %s", exc)

    # 2. Unload platforms and data
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return ok
