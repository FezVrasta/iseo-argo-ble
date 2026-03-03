"""ISEO BLE Lock — sensors (last event, battery)."""

from __future__ import annotations

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .ble_client import LogEntry
from .const import DOMAIN
from .coordinator import IseoLogCoordinator, _resolve_actor, entry_message, event_name


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: IseoLogCoordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    async_add_entities(
        [
            IseoLastEventSensor(coordinator, entry),
            IseoBatterySensor(coordinator, entry),
        ]
    )


class IseoLastEventSensor(CoordinatorEntity[IseoLogCoordinator], SensorEntity):
    """Shows the most recent access-log entry from the lock."""

    _attr_has_entity_name = True
    _attr_translation_key = "last_event"

    def __init__(self, coordinator: IseoLogCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._attr_unique_id = f"{entry.data['address'].replace(':', '').lower()}_last_event"
        from homeassistant.helpers.device_registry import DeviceInfo

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
        )

    @property
    def native_value(self) -> str | None:
        entry: LogEntry | None = self.coordinator.data
        if entry is None:
            return None
        return entry_message(entry, self.coordinator.user_dir)

    @property
    def extra_state_attributes(self) -> dict:
        entry: LogEntry | None = self.coordinator.data
        if entry is None:
            return {}
        raw_actor = entry.user_info.strip() or entry.extra_description.strip()
        actor = _resolve_actor(raw_actor, self.coordinator.user_dir) if raw_actor else None
        return {
            "event_code": entry.event_code,
            "event_name": event_name(entry.event_code),
            "actor": actor or None,
            "timestamp": entry.timestamp.isoformat(),
            "battery": entry.battery,
        }


class IseoBatterySensor(CoordinatorEntity[IseoLogCoordinator], SensorEntity):
    """Shows battery level reported in the most recent access-log entry."""

    _attr_has_entity_name = True
    _attr_translation_key = "battery"
    _attr_device_class = SensorDeviceClass.BATTERY
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator: IseoLogCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.data['address'].replace(':', '').lower()}_battery"
        from homeassistant.helpers.device_registry import DeviceInfo

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
        )

    @property
    def native_value(self) -> int | None:
        entry: LogEntry | None = self.coordinator.data
        return entry.battery if entry is not None else None
