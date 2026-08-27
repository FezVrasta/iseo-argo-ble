"""ISEO Argo BLE binary sensors, fed by passive BLE advertisements."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from . import IseoConfigEntry
from .client import LockState
from .entity import IseoPassiveEntity, passage_mode_active


@dataclass(frozen=True, kw_only=True)
class IseoBinarySensorDescription(BinarySensorEntityDescription):
    """Describes an ISEO binary sensor derived from the advertisement state."""

    value_fn: Callable[[LockState], bool | None]


BINARY_SENSORS: tuple[IseoBinarySensorDescription, ...] = (
    IseoBinarySensorDescription(
        key="door",
        translation_key="door",
        device_class=BinarySensorDeviceClass.DOOR,
        value_fn=lambda s: (not s.door_closed) if s.door_closed is not None else None,
    ),
    IseoBinarySensorDescription(
        key="aux_battery_low",
        translation_key="aux_battery_low",
        device_class=BinarySensorDeviceClass.BATTERY,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: s.aux_battery_low,
    ),
    IseoBinarySensorDescription(
        key="privacy_mode",
        translation_key="privacy_mode",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: s.privacy_mode,
    ),
    IseoBinarySensorDescription(
        key="passage_mode",
        translation_key="passage_mode",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=passage_mode_active,
    ),
    IseoBinarySensorDescription(
        key="vip_mode",
        translation_key="vip_mode",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: s.vip_mode,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: IseoConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up ISEO binary sensors."""
    async_add_entities(IseoBinarySensor(entry, description) for description in BINARY_SENSORS)


class IseoBinarySensor(IseoPassiveEntity, BinarySensorEntity):
    """A binary sensor backed by the shared passive state."""

    entity_description: IseoBinarySensorDescription

    def __init__(self, entry: IseoConfigEntry, description: IseoBinarySensorDescription) -> None:
        """Initialize."""
        super().__init__(entry)
        self.entity_description = description
        self._attr_unique_id = f"{entry.unique_id}_{description.key}"

    @property
    def is_on(self) -> bool | None:
        """Return the sensor state from the latest advertisement."""
        state = self._state
        if state is None:
            return None
        return self.entity_description.value_fn(state)
