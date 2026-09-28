"""Room-map parsing and room-cleaning request helpers."""

from __future__ import annotations

import asyncio
import base64
import copy
import json
from collections.abc import Mapping
from dataclasses import dataclass
from json import JSONDecodeError
from typing import Any
from urllib.parse import urlsplit

import httpx

from .exceptions import ApiError
from .models import (
    ROOM_CLEAN_TIMES,
    Room,
    RoomCleaningSettings,
    RoomFanMode,
    RoomWaterLevel,
)
from .protocol import PushClient

COMPOSITE_INFO_TYPE = "30000"
MAP_INFO_TYPE = "20002"
ROOM_CLEANING_PATH = "/clean/record/setAreaAndCleaning"

LOAD_DATA = {
    "cmds": [
        {"infoType": "20001", "data": {}},
        {"infoType": "21014", "data": {}},
        {
            "infoType": "21011",
            "data": {"startPos": 0, "userId": 0, "mask": 0},
        },
    ],
    "mainCmds": [],
}

SWEEP_AREA_REFERENCE_FIELDS = (
    "active",
    "cacheType",
    "forbidType",
    "mode",
    "name",
    "roomType",
    "tag",
    "vertexs",
    "windMode",
)
SWEEP_AREA_PRIMITIVE_DEFAULTS = {
    "cleanTimes": 0,
    "id": 0,
    "material": 0,
    "radius": 0,
    "relativeRoom": -1,
    "waterPump": 0,
}


@dataclass(frozen=True, slots=True)
class RoomMap:
    """Current room map and its complete cleaning-area template."""

    map_id: int
    clean_id: str
    rooms: tuple[Room, ...]
    area_setting: dict[str, Any]


_ROOM_FAN_MODE_VALUES = frozenset(mode.value for mode in RoomFanMode)
_ROOM_WATER_LEVEL_VALUES = frozenset(level.value for level in RoomWaterLevel)


def validate_room_cleaning_settings(settings: object) -> RoomCleaningSettings:
    """Validate one public room-settings value without network access."""

    if not isinstance(settings, RoomCleaningSettings):
        raise ValueError("room settings must be RoomCleaningSettings instances")
    if settings.clean_times is not None and (
        isinstance(settings.clean_times, bool)
        or not isinstance(settings.clean_times, int)
        or settings.clean_times not in ROOM_CLEAN_TIMES
    ):
        raise ValueError("clean_times must be 1 or 2")
    if settings.fan_mode is not None and (
        not isinstance(settings.fan_mode, str)
        or settings.fan_mode not in _ROOM_FAN_MODE_VALUES
    ):
        raise ValueError("fan_mode must be quiet, auto, strong, or max")
    if settings.water_pump is not None and (
        isinstance(settings.water_pump, bool)
        or not isinstance(settings.water_pump, int)
        or settings.water_pump not in _ROOM_WATER_LEVEL_VALUES
    ):
        raise ValueError("water_pump must be 1, 2, or 3")
    return settings


def normalize_room_settings(
    room_ids: list[int],
    room_settings: Mapping[int, RoomCleaningSettings] | None,
) -> dict[int, RoomCleaningSettings]:
    """Validate and snapshot per-run overrides for selected rooms."""

    if room_settings is None:
        return {}
    if not isinstance(room_settings, Mapping):
        raise ValueError("room_settings must be a mapping")
    selected_ids = set(room_ids)
    normalized: dict[int, RoomCleaningSettings] = {}
    for room_id, settings in room_settings.items():
        if isinstance(room_id, bool) or not isinstance(room_id, int):
            raise ValueError("room_settings keys must be integer room IDs")
        if room_id not in selected_ids:
            raise ValueError(
                f"Room settings supplied for unselected room ID: {room_id}"
            )
        normalized[room_id] = validate_room_cleaning_settings(settings)
    return normalized


def _json_object(value: object, *, field: str) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except JSONDecodeError as exc:
            raise ApiError(f"{field} is invalid JSON", phase="protocol") from exc
    if not isinstance(value, dict):
        raise ApiError(f"{field} is invalid", phase="protocol")
    return value


def decode_room_name(value: object) -> str:
    """Decode the app's Base64-encoded room name."""

    if not isinstance(value, str) or not value:
        return ""
    normalized = value.replace(" ", "+")
    normalized += "=" * (-len(normalized) % 4)
    try:
        return base64.b64decode(normalized, validate=False).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ApiError("Room name is invalid", phase="protocol") from exc


def _optional_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _optional_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _room_vertices(value: object) -> tuple[tuple[int, int], ...] | None:
    """Return a valid room polygon without altering vendor coordinates."""

    if not isinstance(value, list) or len(value) < 3:
        return None
    vertices: list[tuple[int, int]] = []
    for point in value:
        if not isinstance(point, list) or len(point) != 2:
            return None
        x, y = point
        if (
            isinstance(x, bool)
            or not isinstance(x, int)
            or isinstance(y, bool)
            or not isinstance(y, int)
        ):
            return None
        vertices.append((x, y))
    return tuple(vertices)


def gson_sweep_area(value: object) -> dict[str, Any] | None:
    """Recreate the fields serialized by Gson for one SweepArea."""

    if not isinstance(value, dict):
        return None
    area: dict[str, Any] = {}
    for field in SWEEP_AREA_REFERENCE_FIELDS:
        field_value = value.get(field)
        if field_value is not None:
            area[field] = copy.deepcopy(field_value)
    for field, default in SWEEP_AREA_PRIMITIVE_DEFAULTS.items():
        field_value = value.get(field, default)
        area[field] = (
            field_value
            if isinstance(field_value, type(default))
            and not isinstance(field_value, bool)
            else default
        )
    return area


def gson_sweep_area_list(value: object) -> dict[str, Any] | None:
    """Recreate the app's Gson serialization of a SweepAreaList."""

    if not isinstance(value, dict):
        return None
    result: dict[str, Any] = {}
    for field in ("activeIds", "areaCleanActiveId"):
        if value.get(field) is not None:
            result[field] = copy.deepcopy(value[field])
    result["autoOrder"] = (
        value["autoOrder"] if isinstance(value.get("autoOrder"), bool) else False
    )
    result["cleanTimes"] = _optional_int(value.get("cleanTimes")) or 0
    result["isAttrOn"] = _optional_int(value.get("isAttrOn")) or 0
    result["mapId"] = _optional_int(value.get("mapId")) or 0
    areas = value.get("value")
    if areas is not None:
        result["value"] = (
            [
                area
                for item in areas
                if (area := gson_sweep_area(item)) is not None
            ]
            if isinstance(areas, list)
            else []
        )
    return result


def gson_json(value: object) -> str:
    """Encode JSON like the Android app's default Gson instance."""

    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    return (
        encoded.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("=", "\\u003d")
        .replace("'", "\\u0027")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def parse_room_map(map_info: object) -> RoomMap:
    """Parse a current MapInfo payload into public rooms and request state."""

    map_payload = _json_object(map_info, field="MapInfo")
    map_id = map_payload.get("mapId")
    clean_id = map_payload.get("cleanId")
    if isinstance(map_id, bool) or not isinstance(map_id, int):
        raise ApiError("MapInfo is missing a valid mapId", phase="protocol")
    if not isinstance(clean_id, str) or not clean_id:
        raise ApiError("MapInfo is missing a valid cleanId", phase="protocol")

    smart_area = _json_object(map_payload.get("smartArea"), field="smartArea")
    area_setting = gson_sweep_area_list(smart_area)
    if area_setting is None or not isinstance(area_setting.get("value"), list):
        raise ApiError("smartArea is missing room definitions", phase="protocol")

    rooms: list[Room] = []
    seen_ids: set[int] = set()
    for area in area_setting["value"]:
        room_id = area.get("id")
        if isinstance(room_id, bool) or not isinstance(room_id, int):
            raise ApiError("smartArea contains an invalid room id", phase="protocol")
        if room_id in seen_ids:
            raise ApiError("smartArea contains duplicate room ids", phase="protocol")
        seen_ids.add(room_id)
        rooms.append(
            Room(
                id=room_id,
                name=decode_room_name(area.get("name")),
                room_type=_optional_str(area.get("roomType")),
                clean_times=_optional_int(area.get("cleanTimes")),
                fan_mode=_optional_str(area.get("windMode")),
                water_pump=_optional_int(area.get("waterPump")),
                vertices=_room_vertices(area.get("vertexs")),
            )
        )
    return RoomMap(
        map_id=map_id,
        clean_id=clean_id,
        rooms=tuple(rooms),
        area_setting=area_setting,
    )


def _apply_room_settings(
    area_setting: dict[str, Any],
    room_settings: Mapping[int, RoomCleaningSettings],
) -> None:
    """Apply validated partial settings without changing unrelated fields."""

    for area in area_setting["value"]:
        settings = room_settings.get(area["id"])
        if settings is None:
            continue
        if settings.clean_times is not None:
            area["cleanTimes"] = settings.clean_times
        if settings.fan_mode is not None:
            area["windMode"] = settings.fan_mode
        if settings.water_pump is not None:
            area["waterPump"] = settings.water_pump


def prepare_area_setting(
    room_map: RoomMap,
    room_ids: list[int],
    room_settings: Mapping[int, RoomCleaningSettings] | None = None,
) -> str:
    """Select rooms while preserving the complete current area definitions."""

    if not room_ids:
        raise ValueError("room_ids must not be empty")
    if any(
        isinstance(room_id, bool) or not isinstance(room_id, int)
        for room_id in room_ids
    ):
        raise ValueError("room_ids must contain integers")
    selected_ids = list(dict.fromkeys(room_ids))
    known_ids = {room.id for room in room_map.rooms}
    unknown_ids = [room_id for room_id in selected_ids if room_id not in known_ids]
    if unknown_ids:
        raise ValueError(f"Unknown room IDs: {unknown_ids}")

    normalized_settings = normalize_room_settings(selected_ids, room_settings)
    area_setting = copy.deepcopy(room_map.area_setting)
    area_setting["activeIds"] = selected_ids
    _apply_room_settings(area_setting, normalized_settings)
    return gson_json(area_setting)


async def _download_map(http_client: httpx.AsyncClient, url: str) -> dict[str, Any]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ApiError("Map push URL is invalid", phase="protocol")
    try:
        response = await http_client.get(url)
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise ApiError(
            "Map push download returned an HTTP error",
            status_code=exc.response.status_code,
            phase="http",
        ) from exc
    except httpx.RequestError as exc:
        raise ApiError("Map push download failed", phase="transport") from exc
    try:
        return _json_object(response.json(), field="Map push download")
    except ValueError as exc:
        raise ApiError("Map push download returned invalid JSON", phase="json") from exc


async def _map_from_protocol(
    protocol: dict[str, Any],
    *,
    http_client: httpx.AsyncClient,
) -> dict[str, Any] | None:
    push_url = protocol.get("pushDataUrl")
    if isinstance(push_url, str) and push_url:
        downloaded = await _download_map(http_client, push_url)
        return await _map_from_protocol(downloaded, http_client=http_client)

    if str(protocol.get("infoType")) == MAP_INFO_TYPE:
        return _json_object(protocol.get("data"), field="MapInfo")
    if str(protocol.get("infoType")) != COMPOSITE_INFO_TYPE:
        return None
    composite = _json_object(protocol.get("data"), field="composite map data")
    commands = composite.get("cmds")
    if not isinstance(commands, list):
        return None
    for command in commands:
        if isinstance(command, dict):
            result = await _map_from_protocol(command, http_client=http_client)
            if result is not None:
                return result
    return None


async def wait_for_room_map(
    push: PushClient,
    *,
    device_id: str,
    http_client: httpx.AsyncClient,
    timeout: float,
) -> RoomMap:
    """Wait for the next current MapInfo push for one device."""

    async def wait() -> RoomMap:
        while True:
            event = await push.read_event()
            if event.get("sn") != device_id:
                continue
            try:
                protocol = _json_object(event.get("data"), field="protocol")
            except ApiError:
                continue
            map_info = await _map_from_protocol(protocol, http_client=http_client)
            if map_info is not None:
                return parse_room_map(map_info)

    try:
        return await asyncio.wait_for(wait(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise ApiError(
            "Timed out waiting for current room map",
            phase="timeout",
        ) from exc
