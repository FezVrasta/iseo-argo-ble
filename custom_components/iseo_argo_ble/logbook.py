"""Logbook descriptions for ISEO Argo BLE events."""

from __future__ import annotations

from collections.abc import Callable

from homeassistant.components.logbook import (
    LOGBOOK_ENTRY_ENTITY_ID,
    LOGBOOK_ENTRY_MESSAGE,
    LOGBOOK_ENTRY_NAME,
)
from homeassistant.core import Event, HomeAssistant, callback

from .const import DOMAIN, EVENT_ALERT, EVENT_LOCK_OPENED


@callback
def async_describe_events(
    hass: HomeAssistant,
    async_describe_event: Callable[[str, str, Callable[[Event], dict[str, str]]], None],
) -> None:
    """Describe ISEO logbook events."""

    @callback
    def describe_opened(event: Event) -> dict[str, str]:
        data = event.data
        opened_by = data.get("opened_by") or "an unknown user"
        what = data.get("event") or "Opened"
        return {
            LOGBOOK_ENTRY_NAME: data.get("lock_name") or "ISEO lock",
            LOGBOOK_ENTRY_MESSAGE: f"{what} by {opened_by}",
            LOGBOOK_ENTRY_ENTITY_ID: data.get("entity_id"),
        }

    @callback
    def describe_alert(event: Event) -> dict[str, str]:
        data = event.data
        return {
            LOGBOOK_ENTRY_NAME: data.get("lock_name") or "ISEO lock",
            LOGBOOK_ENTRY_MESSAGE: f"alert — {data.get('event') or 'unknown'}",
            LOGBOOK_ENTRY_ENTITY_ID: data.get("entity_id"),
        }

    async_describe_event(DOMAIN, EVENT_LOCK_OPENED, describe_opened)
    async_describe_event(DOMAIN, EVENT_ALERT, describe_alert)
