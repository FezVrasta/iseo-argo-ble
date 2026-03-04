"""Logbook descriptions for ISEO Argo BLE Lock events."""

from __future__ import annotations

from homeassistant.core import callback

from .const import DOMAIN, EVENT_TYPE


def async_describe_events(hass, async_describe_event) -> None:
    """Register descriptions for custom events in the HA logbook."""

    @callback
    def _describe(event) -> dict:
        data = event.data
        message = data.get("message") or data.get("name") or "access event"
        return {
            "name": "ISEO Lock",
            "message": message,
        }

    async_describe_event(DOMAIN, EVENT_TYPE, _describe)
