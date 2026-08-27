"""ISEO Argo BLE Lock — Home Assistant integration."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ec import SECP224R1, derive_private_key
from homeassistant.components.bluetooth import async_ble_device_from_address
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady, HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .client import (
    OPEN_TYPE_PASSAGE_OFF,
    OPEN_TYPE_PASSAGE_ON,
    IseoAuthError,
    IseoClient,
    IseoConnectionError,
    LockState,
    UserEntry,
)
from .const import (
    ADMIN_USER_SUBTYPE,
    CONF_ADDRESS,
    CONF_ADMIN_PRIV_SCALAR,
    CONF_ADMIN_UUID,
    CONF_PRIV_SCALAR,
    CONF_UUID,
    DEFAULT_USER_SUBTYPE,
    DOMAIN,
    PLATFORMS,
)

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


@dataclass
class IseoData:
    """Runtime data for ISEO Argo BLE Lock."""

    client: IseoClient
    admin_client: IseoClient | None
    user_coordinator: DataUpdateCoordinator[list[UserEntry]] | None
    ble_lock: asyncio.Lock
    last_ble_device: Any  # BLEDevice | None — updated on each advertisement
    # Shared passive state, published by the lock entity and read by the
    # sensor/binary_sensor entities (all fed from the same BLE advertisements).
    latest_state: LockState | None = None
    available: bool = True
    last_event: dict[str, Any] | None = None
    last_alert: dict[str, Any] | None = None
    # Last open attributed to each lock user, keyed by "{user_type}_{uuid_hex}".
    last_open_by_user: dict[str, dict[str, Any]] = field(default_factory=dict)


type IseoConfigEntry = ConfigEntry[IseoData]


def get_ble_device(hass: HomeAssistant, entry: IseoConfigEntry) -> Any:
    """Return the best available BLEDevice for the lock address.

    Tries a fresh connectable lookup first; falls back to the most recently
    seen device cached from advertisement callbacks.
    """
    address = entry.data[CONF_ADDRESS]
    return async_ble_device_from_address(hass, address, connectable=True) or entry.runtime_data.last_ble_device


async def async_send_open(
    hass: HomeAssistant,
    entry: IseoConfigEntry,
    open_type: int,
    remote_user_name: str = "Home Assistant",
) -> None:
    """Send an open command to the lock, serialised against other BLE work.

    Passage and VIP mode changes ride on the same open command as a plain
    unlock — only the open type differs.
    """
    ble_device = get_ble_device(hass, entry)
    if not ble_device:
        raise IseoConnectionError(f"{entry.data[CONF_ADDRESS]}: no BLEDevice available")

    runtime = entry.runtime_data
    async with runtime.ble_lock:
        runtime.client.update_ble_device(ble_device)
        await runtime.client.gw_open(remote_user_name=remote_user_name, open_type=open_type)


async def async_set_passage_mode(hass: HomeAssistant, entry: IseoConfigEntry, *, enabled: bool) -> None:
    """Turn passage mode on or off, translating client errors for the UI."""
    open_type = OPEN_TYPE_PASSAGE_ON if enabled else OPEN_TYPE_PASSAGE_OFF
    try:
        await async_send_open(hass, entry, open_type)
    except IseoAuthError as exc:
        raise HomeAssistantError(
            translation_domain=DOMAIN,
            translation_key="lock_rejected_identity",
        ) from exc
    except (TimeoutError, IseoConnectionError, OSError) as exc:
        raise HomeAssistantError(
            translation_domain=DOMAIN,
            translation_key="cannot_connect",
        ) from exc


def _remove_legacy_passage_binary_sensor(hass: HomeAssistant, entry: IseoConfigEntry) -> None:
    """Drop the passage mode binary sensor superseded by the switch in 0.9.0.

    Without this the old entity lingers in the registry as unavailable, and the
    switch has to take a `_2` suffix on its entity id.
    """
    registry = er.async_get(hass)
    entity_id = registry.async_get_entity_id(Platform.BINARY_SENSOR, DOMAIN, f"{entry.unique_id}_passage_mode")
    if entity_id:
        _LOGGER.debug("Removing legacy passage mode binary sensor %s", entity_id)
        registry.async_remove(entity_id)


async def async_setup_entry(hass: HomeAssistant, entry: IseoConfigEntry) -> bool:
    """Set up ISEO Argo BLE Lock from a config entry."""
    address = entry.data[CONF_ADDRESS]
    ble_device = async_ble_device_from_address(hass, address, connectable=True) or async_ble_device_from_address(
        hass, address, connectable=False
    )
    if ble_device is None:
        raise ConfigEntryNotReady(f"Could not find ISEO lock {address} — is it powered on and in range?")

    priv_int = int(entry.data[CONF_PRIV_SCALAR], 16)
    priv = await hass.async_add_executor_job(derive_private_key, priv_int, SECP224R1())
    uuid_bytes = bytes.fromhex(entry.data[CONF_UUID])

    client = IseoClient(
        address=address,
        uuid_bytes=uuid_bytes,
        identity_priv=priv,
        subtype=DEFAULT_USER_SUBTYPE,
        ble_device=ble_device,
    )

    ble_lock = asyncio.Lock()

    # Build admin client if credentials were registered during setup
    admin_client: IseoClient | None = None
    if CONF_ADMIN_UUID in entry.data and CONF_ADMIN_PRIV_SCALAR in entry.data:
        admin_priv_int = int(entry.data[CONF_ADMIN_PRIV_SCALAR], 16)
        admin_priv = await hass.async_add_executor_job(derive_private_key, admin_priv_int, SECP224R1())
        admin_uuid_bytes = bytes.fromhex(entry.data[CONF_ADMIN_UUID])
        admin_client = IseoClient(
            address=address,
            uuid_bytes=admin_uuid_bytes,
            identity_priv=admin_priv,
            subtype=ADMIN_USER_SUBTYPE,
            ble_device=ble_device,
        )

    user_coordinator: DataUpdateCoordinator[list[UserEntry]] | None = None
    if admin_client is not None:

        async def _async_update_users() -> list[UserEntry]:
            """Fetch users from the lock."""
            _LOGGER.debug("Fetching users from lock %s", address)
            try:
                if dev := get_ble_device(hass, entry):
                    admin_client.update_ble_device(dev)
                async with ble_lock:
                    users = await admin_client.read_users()
                await asyncio.sleep(2)
                return users
            except Exception as err:
                raise UpdateFailed(f"Error communicating with lock: {err}") from err

        # No update_interval on purpose: periodic polling of the lock — even at
        # a 10-minute interval — crashes recent ISEO firmware (see README). The
        # user list is fetched once at setup and only refreshed on demand
        # (a user-enable/disable toggle, or the options "refresh users" step).
        user_coordinator = DataUpdateCoordinator(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{address}_users",
            update_method=_async_update_users,
        )
    entry.runtime_data = IseoData(
        client=client,
        admin_client=admin_client,
        user_coordinator=user_coordinator,
        ble_lock=ble_lock,
        last_ble_device=ble_device,
    )

    if user_coordinator is not None:
        await user_coordinator.async_config_entry_first_refresh()

    _remove_legacy_passage_binary_sensor(hass, entry)

    # Every platform loads regardless of user management: the switch platform
    # also carries the passage mode switch, which only needs the gateway client.
    # It also keeps setup symmetrical with async_unload_entry.
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: IseoConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
