"""ISEO Argo BLE sensors, fed by passive BLE advertisements."""

from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.const import PERCENTAGE, EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import IseoConfigEntry
from .client import battery_enum_to_pct
from .entity import IseoPassiveEntity

_OPERATIONAL_MODES = {0: "standard", 1: "office", 2: "timed"}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: IseoConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up ISEO sensors."""
    async_add_entities(
        [
            IseoBatterySensor(entry),
            IseoOperationalModeSensor(entry),
            IseoLastEventSensor(entry),
            IseoLastAlertSensor(entry),
        ]
    )


class IseoBatterySensor(IseoPassiveEntity, SensorEntity):
    """Battery level, decoded from the advertisement."""

    _attr_translation_key = "battery"
    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, entry: IseoConfigEntry) -> None:
        """Initialize."""
        super().__init__(entry)
        self._attr_unique_id = f"{entry.unique_id}_battery"

    @property
    def native_value(self) -> int | None:
        """Return the battery percentage."""
        state = self._state
        if state is None or state.battery_level is None:
            return None
        return battery_enum_to_pct(state.battery_level)


class IseoOperationalModeSensor(IseoPassiveEntity, SensorEntity):
    """Lock operational mode (Standard / Office / Timed)."""

    _attr_translation_key = "operational_mode"
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = list(_OPERATIONAL_MODES.values())
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, entry: IseoConfigEntry) -> None:
        """Initialize."""
        super().__init__(entry)
        self._attr_unique_id = f"{entry.unique_id}_operational_mode"

    @property
    def native_value(self) -> str | None:
        """Return the operational mode."""
        state = self._state
        if state is None or state.operational_mode is None:
            return None
        return _OPERATIONAL_MODES.get(state.operational_mode)


class IseoLastEventSensor(IseoPassiveEntity, SensorEntity):
    """The most recent door-open event and who caused it."""

    _attr_translation_key = "last_event"
    _attr_icon = "mdi:history"

    def __init__(self, entry: IseoConfigEntry) -> None:
        """Initialize."""
        super().__init__(entry)
        self._attr_unique_id = f"{entry.unique_id}_last_event"

    @property
    def native_value(self) -> str | None:
        """Return a short summary of the last open event."""
        event = self._entry.runtime_data.last_event
        if not event:
            return None
        summary = str(event.get("event") or "Open")
        if event.get("opened_by"):
            summary = f"{summary} — {event['opened_by']}"
        return summary[:255]

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Expose the full last-event payload."""
        event = self._entry.runtime_data.last_event
        if not event:
            return None
        return {key: value for key, value in event.items() if key != "entity_id"}


class IseoLastAlertSensor(IseoPassiveEntity, SensorEntity):
    """The most recent security/fault event seen in the access log.

    Surfaced when the unread log is read on a door open, so it can be delayed;
    the integration never polls the lock.
    """

    _attr_translation_key = "last_alert"
    _attr_icon = "mdi:alert"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, entry: IseoConfigEntry) -> None:
        """Initialize."""
        super().__init__(entry)
        self._attr_unique_id = f"{entry.unique_id}_last_alert"

    @property
    def native_value(self) -> str | None:
        """Return a short summary of the last alert."""
        alert = self._entry.runtime_data.last_alert
        if not alert:
            return None
        return str(alert.get("event") or "Alert")[:255]

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Expose the full last-alert payload."""
        alert = self._entry.runtime_data.last_alert
        if not alert:
            return None
        return {key: value for key, value in alert.items() if key != "entity_id"}
