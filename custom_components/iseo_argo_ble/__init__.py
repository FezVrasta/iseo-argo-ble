"""ISEO BLE Lock — Home Assistant integration."""

from __future__ import annotations

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import SECP224R1, derive_private_key
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import CONF_PRIV_SCALAR, CONF_UUID, DOMAIN, PLATFORMS
from .coordinator import IseoLogCoordinator


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    hass.data.setdefault(DOMAIN, {})

    # Derive the private key once (CPU-bound; run in executor).
    priv_int = int(entry.data[CONF_PRIV_SCALAR], 16)
    priv     = await hass.async_add_executor_job(
        derive_private_key, priv_int, SECP224R1(), default_backend()
    )
    uuid_bytes = bytes.fromhex(entry.data[CONF_UUID])

    coordinator = IseoLogCoordinator(hass, entry, uuid_bytes, priv)
    await coordinator.async_setup()          # load persisted last-seen timestamp
    await coordinator.async_config_entry_first_refresh()  # initial poll

    hass.data[DOMAIN][entry.entry_id] = {"coordinator": coordinator}

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return ok
