"""Device triggers for ISEO Argo BLE."""

from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant.components.device_automation import DEVICE_TRIGGER_BASE_SCHEMA
from homeassistant.components.homeassistant.triggers import event as event_trigger
from homeassistant.const import CONF_DEVICE_ID, CONF_DOMAIN, CONF_PLATFORM, CONF_TYPE
from homeassistant.core import CALLBACK_TYPE, HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.trigger import TriggerActionType, TriggerInfo
from homeassistant.helpers.typing import ConfigType

from .const import DOMAIN, EVENT_ALERT, EVENT_LOCK_OPENED

_EVENT_FOR_TYPE = {"opened": EVENT_LOCK_OPENED, "alert": EVENT_ALERT}

TRIGGER_SCHEMA = DEVICE_TRIGGER_BASE_SCHEMA.extend({vol.Required(CONF_TYPE): vol.In(set(_EVENT_FOR_TYPE))})


async def async_get_triggers(hass: HomeAssistant, device_id: str) -> list[dict[str, Any]]:
    """List the device triggers for an ISEO lock."""
    return [
        {
            CONF_PLATFORM: "device",
            CONF_DOMAIN: DOMAIN,
            CONF_DEVICE_ID: device_id,
            CONF_TYPE: trigger_type,
        }
        for trigger_type in _EVENT_FOR_TYPE
    ]


async def async_attach_trigger(
    hass: HomeAssistant,
    config: ConfigType,
    action: TriggerActionType,
    trigger_info: TriggerInfo,
) -> CALLBACK_TYPE:
    """Attach a device trigger, restricted to this device's lock entity."""
    event_data: dict[str, Any] = {}
    entities = er.async_entries_for_device(er.async_get(hass), config[CONF_DEVICE_ID])
    lock_entity_id = next(
        (e.entity_id for e in entities if e.domain == "lock" and e.platform == DOMAIN),
        None,
    )
    if lock_entity_id:
        event_data["entity_id"] = lock_entity_id

    event_config = event_trigger.TRIGGER_SCHEMA(
        {
            event_trigger.CONF_PLATFORM: "event",
            event_trigger.CONF_EVENT_TYPE: _EVENT_FOR_TYPE[config[CONF_TYPE]],
            event_trigger.CONF_EVENT_DATA: event_data,
        }
    )
    return await event_trigger.async_attach_trigger(hass, event_config, action, trigger_info, platform_type="device")
