"""Local, read-only S9-P room/map protocol diagnostic.

This script intentionally uses private botslab360 helpers. It is a development
capture tool, not part of the package's public API.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import copy
import json
import logging
import os
import re
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import httpx

import botslab360.client as client_module
from botslab360 import ApiError, AuthenticationError, Botslab360Client
from botslab360.models import Device
from botslab360.protocol import PushClient, decode_push_envelope

COMPOSITE_INFO_TYPE = "30000"
MAP_INFO_TYPE = "20002"
ROOM_CLEANING_ENDPOINT = "clean/record/setAreaAndCleaning"
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
SWEEP_AREA_FIELDS = (
    "active",
    "cacheType",
    "cleanTimes",
    "forbidType",
    "id",
    "material",
    "mode",
    "name",
    "radius",
    "relativeRoom",
    "roomType",
    "tag",
    "vertexs",
    "waterPump",
    "windMode",
)
SWEEP_AREA_LIST_FIELDS = (
    "activeIds",
    "areaCleanActiveId",
    "autoOrder",
    "cleanTimes",
    "isAttrOn",
    "mapId",
    "value",
)
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
SUPPORT_CAPABILITIES = (
    "roomSweep",
    "smartArea",
    "setRoomAttrib",
    "sweepAreaInTimer",
)
_SUPPORT_CAPABILITY_NAMES = {
    re.sub(r"[^a-z0-9]", "", name.lower()): name for name in SUPPORT_CAPABILITIES
}


def _json_object(value: object) -> dict[str, Any] | None:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError):
            return None
    return value if isinstance(value, dict) else None


def _value_type(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    return type(value).__name__


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _safe_support_key(value: str) -> bool:
    normalized = _normalized_key(value)
    sensitive_parts = {
        "account",
        "auth",
        "cookie",
        "credential",
        "email",
        "key",
        "owner",
        "phone",
        "qid",
        "secret",
        "sid",
        "token",
        "user",
    }
    return not any(part in normalized for part in sensitive_parts)


def _is_block_clean_key(value: str) -> bool:
    return _normalized_key(value) in {"blockclean", "supportblockclean"}


def _decode_json_layers(value: object) -> tuple[object, int]:
    layers = 0
    while isinstance(value, str) and layers < 3:
        try:
            decoded = json.loads(value)
        except ValueError:
            break
        if decoded == value:
            break
        value = decoded
        layers += 1
    return value, layers


def _support_capability_values(value: object) -> dict[str, Any]:
    matches: dict[str, list[int | float | bool | str | None]] = {
        name: [] for name in SUPPORT_CAPABILITIES
    }

    def inspect(child: object) -> None:
        child, _ = _decode_json_layers(child)
        if isinstance(child, list):
            for item in child:
                inspect(item)
            return
        if not isinstance(child, dict):
            return
        for key, nested in child.items():
            if not isinstance(key, str):
                continue
            capability = _SUPPORT_CAPABILITY_NAMES.get(_normalized_key(key))
            if capability is not None:
                scalar = (
                    nested if isinstance(nested, (bool, int, float, str)) else None
                )
                matches[capability].append(scalar)
            inspect(nested)

    inspect(value)
    return {
        name: values[0] if values else None for name, values in matches.items()
    }


def _inspect_support_container(
    value: object,
    *,
    path: tuple[str, ...],
    keys: set[str],
    matches: list[tuple[str, int | float | bool | str | None]],
) -> None:
    value, _ = _decode_json_layers(value)
    if isinstance(value, list):
        for item in value:
            _inspect_support_container(
                item,
                path=path,
                keys=keys,
                matches=matches,
            )
        return
    if not isinstance(value, dict):
        return
    for key, child in value.items():
        if not isinstance(key, str):
            continue
        if _safe_support_key(key):
            keys.add(key)
        safe_key = key if _safe_support_key(key) else "<redacted-key>"
        child_path = (*path, safe_key)
        if _is_block_clean_key(key):
            scalar = child if isinstance(child, (bool, int, float, str)) else None
            matches.append((".".join(child_path), scalar))
        _inspect_support_container(
            child,
            path=child_path,
            keys=keys,
            matches=matches,
        )


def _support_diagnostic(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {
            "supportBlockClean": None,
            "supportField": "device payload is not an object",
            "supportJsonLayers": 0,
            "supportKeys": [],
            "supportCandidateKeys": [],
            "supportBlockCleanPaths": [],
            "supportCapabilities": {
                name: None for name in SUPPORT_CAPABILITIES
            },
        }

    missing = object()
    raw_support = payload.get("support", missing)
    candidate_keys = sorted(
        key
        for key in payload
        if isinstance(key, str)
        and _safe_support_key(key)
        and any(
            marker in _normalized_key(key)
            for marker in ("support", "capabilit", "feature", "blockclean")
        )
    )
    support_keys: set[str] = set()
    matches: list[tuple[str, int | float | bool | str | None]] = []
    json_layers = 0
    capability_values = {name: None for name in SUPPORT_CAPABILITIES}

    if raw_support is missing:
        field_description = "missing"
    else:
        decoded_support, json_layers = _decode_json_layers(raw_support)
        field_description = _value_type(raw_support)
        if json_layers:
            field_description += f" -> {_value_type(decoded_support)}"
        capability_values = _support_capability_values(decoded_support)
        _inspect_support_container(
            decoded_support,
            path=("support",),
            keys=support_keys,
            matches=matches,
        )

    for key in candidate_keys:
        if key == "support":
            continue
        if _is_block_clean_key(key):
            child = payload[key]
            scalar = child if isinstance(child, (bool, int, float, str)) else None
            matches.append((key, scalar))
            continue
        _inspect_support_container(
            payload[key],
            path=(key,),
            keys=support_keys,
            matches=matches,
        )

    value = matches[0][1] if matches else None
    return {
        "supportBlockClean": value,
        "supportField": field_description,
        "supportJsonLayers": json_layers,
        "supportKeys": sorted(support_keys, key=str.casefold),
        "supportCandidateKeys": candidate_keys,
        "supportBlockCleanPaths": [path for path, _ in matches],
        "supportCapabilities": capability_values,
    }


@contextmanager
def _capture_discovery_support():
    """Capture one safe capability while normal discovery parses devices."""

    captured: dict[str, dict[str, Any]] = {}
    original = client_module._device_from_payload

    def wrapped(payload: object, *, status_code: int) -> Device:
        device = original(payload, status_code=status_code)
        captured[device.id] = _support_diagnostic(payload)
        return device

    client_module._device_from_payload = wrapped
    try:
        yield captured
    finally:
        client_module._device_from_payload = original


def _event_number(event: dict[str, Any]) -> int | str | None:
    value = event.get("event")
    if isinstance(value, bool):
        return None
    return value if isinstance(value, (int, str)) else None


def _record_event(
    captures: list[dict[str, int | str | None]],
    *,
    event: int | str | None,
    info_type: object,
) -> None:
    safe_info_type = str(info_type) if info_type is not None else None
    captures.append({"event": event, "infoType": safe_info_type})
    print(f"Push: event={event} infoType={safe_info_type or 'unknown'}")


async def _download_protocol(
    http_client: httpx.AsyncClient,
    url: str,
) -> dict[str, Any]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ApiError("Map push URL is invalid", phase="protocol")
    try:
        response = await http_client.get(url)
        response.raise_for_status()
    except httpx.HTTPStatusError as error:
        raise ApiError(
            "Map push download returned an HTTP error",
            status_code=error.response.status_code,
            phase="http",
        ) from error
    except httpx.RequestError as error:
        raise ApiError("Map push download failed", phase="transport") from error
    try:
        payload = response.json()
    except ValueError as error:
        raise ApiError("Map push download returned invalid JSON", phase="json") from error
    if not isinstance(payload, dict):
        raise ApiError("Map push download returned invalid data", phase="protocol")
    return payload


async def _map_from_protocol(
    protocol: dict[str, Any],
    *,
    event: int | str | None,
    http_client: httpx.AsyncClient,
    captures: list[dict[str, int | str | None]],
    source: str = "direct",
) -> tuple[dict[str, Any], str] | None:
    push_url = protocol.get("pushDataUrl")
    if isinstance(push_url, str) and push_url:
        downloaded = await _download_protocol(http_client, push_url)
        return await _map_from_protocol(
            downloaded,
            event=event,
            http_client=http_client,
            captures=captures,
            source="pushDataUrl",
        )

    info_type = protocol.get("infoType")
    _record_event(captures, event=event, info_type=info_type)
    if str(info_type) == MAP_INFO_TYPE:
        map_data = _json_object(protocol.get("data"))
        if map_data is None:
            raise ApiError("Map push contains invalid MapInfo", phase="protocol")
        return map_data, source

    if str(info_type) != COMPOSITE_INFO_TYPE:
        return None
    composite = _json_object(protocol.get("data"))
    commands = composite.get("cmds") if composite is not None else None
    if not isinstance(commands, list):
        return None
    for command in commands:
        if not isinstance(command, dict):
            continue
        result = await _map_from_protocol(
            command,
            event=event,
            http_client=http_client,
            captures=captures,
            source=source,
        )
        if result is not None:
            return result
    return None


async def _wait_for_map(
    push: PushClient,
    *,
    device_id: str,
    http_client: httpx.AsyncClient,
    captures: list[dict[str, int | str | None]],
) -> tuple[dict[str, Any], str]:
    if push._reader is None:
        raise ApiError("Push client is not connected", phase="transport")

    while True:
        try:
            chunk = await push._reader.read(65536)
        except OSError as error:
            raise ApiError("Push connection failed", phase="transport") from error
        if not chunk:
            raise ApiError("Push connection closed", phase="transport")

        for prefix, envelope in push._frames.feed(chunk):
            await push._acknowledge(prefix)
            event_payload = decode_push_envelope(envelope, push._push_key)
            if event_payload.get("sn") != device_id:
                continue
            protocol = _json_object(event_payload.get("data"))
            if protocol is None:
                continue
            result = await _map_from_protocol(
                protocol,
                event=_event_number(event_payload),
                http_client=http_client,
                captures=captures,
            )
            if result is not None:
                return result


async def _capture_map_once(
    client: Botslab360Client,
    *,
    device_id: str,
    task_id: str,
    timeout: float,
    captures: list[dict[str, int | str | None]],
) -> tuple[dict[str, Any], str]:
    if client.session is None:
        raise AuthenticationError("Authentication is required", phase="authentication")

    push = PushClient(
        client.session.sid,
        client.session.push_key,
        host=client._push_host,
        port=client._push_port,
    )
    async with push:
        await client._post_robot_request(
            device_id=device_id,
            info_type=COMPOSITE_INFO_TYPE,
            data=json.dumps(LOAD_DATA, separators=(",", ":")),
            task_id=task_id,
            operation="diagnostic map request",
        )
        try:
            return await asyncio.wait_for(
                _wait_for_map(
                    push,
                    device_id=device_id,
                    http_client=client._http_client,
                    captures=captures,
                ),
                timeout=timeout,
            )
        except asyncio.TimeoutError as error:
            raise ApiError(
                "No 20002 map push received within the timeout",
                phase="timeout",
            ) from error


def _decode_room_name(value: object) -> str:
    if not isinstance(value, str) or not value:
        return ""
    normalized = value.replace(" ", "+")
    normalized += "=" * (-len(normalized) % 4)
    try:
        return base64.b64decode(normalized, validate=False).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return "<invalid Base64 name>"


def _safe_scalar(value: object) -> str | int | float | bool | None:
    return value if isinstance(value, (str, int, float, bool)) else None


def _captured_sweep_area(value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return {
        field: copy.deepcopy(value[field])
        for field in SWEEP_AREA_FIELDS
        if field in value
    }


def _captured_sweep_area_list(value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    result = {
        field: copy.deepcopy(value[field])
        for field in SWEEP_AREA_LIST_FIELDS
        if field in value and field != "value"
    }
    if "value" in value:
        areas = value["value"]
        result["value"] = (
            [
                area
                for item in areas
                if (area := _captured_sweep_area(item)) is not None
            ]
            if isinstance(areas, list)
            else copy.deepcopy(areas)
        )
    return result


def _gson_sweep_area(value: object) -> dict[str, Any] | None:
    """Recreate the fields serialized by Gson for one SweepArea instance."""

    if not isinstance(value, dict):
        return None
    area: dict[str, Any] = {}
    for field in SWEEP_AREA_REFERENCE_FIELDS:
        field_value = value.get(field)
        if field_value is not None:
            area[field] = copy.deepcopy(field_value)
    for field, default in SWEEP_AREA_PRIMITIVE_DEFAULTS.items():
        field_value = value.get(field, default)
        area[field] = field_value if isinstance(field_value, type(default)) else default
    return area


def _gson_sweep_area_list(value: object) -> dict[str, Any] | None:
    """Recreate Gson's default serialization of a SweepAreaList instance."""

    if not isinstance(value, dict):
        return None

    result: dict[str, Any] = {}
    active_ids = value.get("activeIds")
    if active_ids is not None:
        result["activeIds"] = copy.deepcopy(active_ids)
    area_clean_active_id = value.get("areaCleanActiveId")
    if area_clean_active_id is not None:
        result["areaCleanActiveId"] = copy.deepcopy(area_clean_active_id)
    result["autoOrder"] = (
        value["autoOrder"] if isinstance(value.get("autoOrder"), bool) else False
    )
    result["cleanTimes"] = (
        value["cleanTimes"]
        if isinstance(value.get("cleanTimes"), int)
        and not isinstance(value.get("cleanTimes"), bool)
        else 0
    )
    result["isAttrOn"] = (
        value["isAttrOn"]
        if isinstance(value.get("isAttrOn"), int)
        and not isinstance(value.get("isAttrOn"), bool)
        else 0
    )
    result["mapId"] = (
        value["mapId"]
        if isinstance(value.get("mapId"), int)
        and not isinstance(value.get("mapId"), bool)
        else 0
    )
    areas = value.get("value")
    if areas is not None:
        result["value"] = [
            area
            for item in areas
            if (area := _gson_sweep_area(item)) is not None
        ] if isinstance(areas, list) else []
    return result


def _gson_json(value: object) -> str:
    """Encode JSON like the app's default Gson instance."""

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


def _sanitize_map(map_info: dict[str, Any]) -> dict[str, Any]:
    captured_smart_area = _captured_sweep_area_list(map_info.get("smartArea"))
    area_setting_template = _gson_sweep_area_list(captured_smart_area)
    values = (
        area_setting_template.get("value")
        if isinstance(area_setting_template, dict)
        else []
    )
    if not isinstance(values, list):
        values = []

    rooms: list[dict[str, Any]] = []
    for room in values:
        if not isinstance(room, dict):
            continue
        vertexs = room.get("vertexs")
        rooms.append(
            {
                "id": _safe_scalar(room.get("id")),
                "name": _decode_room_name(room.get("name")),
                "roomType": _safe_scalar(room.get("roomType")),
                "vertexCount": len(vertexs) if isinstance(vertexs, list) else None,
                "cleanTimes": _safe_scalar(room.get("cleanTimes")),
                "windMode": _safe_scalar(room.get("windMode")),
                "waterPump": _safe_scalar(room.get("waterPump")),
            }
        )
    clean_id = _safe_scalar(map_info.get("cleanId"))
    return {
        "cleanId": clean_id,
        "cleanIdType": _value_type(clean_id),
        "mapId": _safe_scalar(map_info.get("mapId")),
        "smartArea": captured_smart_area,
        "areaSettingTemplate": area_setting_template,
        "smartAreaActiveIdsPresent": (
            isinstance(captured_smart_area, dict)
            and "activeIds" in captured_smart_area
        ),
        "smartAreaActiveIds": (
            copy.deepcopy(captured_smart_area.get("activeIds"))
            if isinstance(captured_smart_area, dict)
            else None
        ),
        "rooms": rooms,
    }


def _prepare_room_request(
    *,
    clean_id: object,
    map_id: object,
    smart_area: object,
    room_id: int,
) -> dict[str, Any]:
    if not isinstance(clean_id, str) or not clean_id:
        raise ValueError("MapInfo.cleanId is missing or is not a non-empty string")
    if isinstance(map_id, bool) or not isinstance(map_id, int):
        raise ValueError("MapInfo.mapId is missing or is not an integer")
    if not isinstance(smart_area, dict):
        raise ValueError("MapInfo.smartArea is missing or invalid")
    values = smart_area.get("value")
    if not isinstance(values, list):
        raise ValueError("MapInfo.smartArea.value is missing or invalid")
    available_ids = {
        area.get("id") for area in values if isinstance(area, dict)
    }
    if room_id not in available_ids:
        raise ValueError(
            f"Room ID {room_id} is not present; available IDs: "
            f"{sorted(value for value in available_ids if isinstance(value, int))}"
        )

    area_setting = copy.deepcopy(smart_area)
    area_setting["activeIds"] = [room_id]
    selected_area = next(
        area
        for area in values
        if isinstance(area, dict) and area.get("id") == room_id
    )
    return {
        "endpoint": ROOM_CLEANING_ENDPOINT,
        "method": "POST",
        "contentType": "application/x-www-form-urlencoded",
        "mapId": map_id,
        "roomId": room_id,
        "roomName": _decode_room_name(selected_area.get("name")),
        "form": {
            "sn": "present (redacted)",
            "cleanId": clean_id,
            "areaSetting": area_setting,
            "areaSettingJson": _gson_json(area_setting),
            "taskid": str(uuid4()),
        },
        "sent": False,
    }


def _room_request_summary(prepared: dict[str, Any]) -> dict[str, Any]:
    form = prepared["form"]
    area_setting = form["areaSetting"]
    values = area_setting.get("value", [])
    return {
        "endpoint": prepared["endpoint"],
        "mapId": prepared["mapId"],
        "selectedIds": [prepared["roomId"]],
        "roomName": prepared["roomName"],
        "roomsInAreaSetting": len(values) if isinstance(values, list) else 0,
        "cleanId": "present",
        "device": "present (redacted)",
    }


async def _post_room_cleaning(
    client: Botslab360Client,
    *,
    device_id: str,
    clean_id: str,
    area_setting_json: str,
    task_id: str,
) -> dict[str, int | bool | None]:
    """Send the explicitly confirmed diagnostic request exactly once."""

    if client.session is None:
        raise AuthenticationError(
            "Authentication is required before the room-cleaning test",
            phase="authentication",
        )
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "*/*",
        "Connection": "keep-alive",
        "Cookie": (
            f"q={client._credentials.q};t={client._credentials.t};"
            f"qid={client._credentials.qid};sid={client.session.sid}"
        ),
        "User-Agent": "QihooSuperApp_NoPods/11.1.0 (iPhone; iOS 14.8; Scale/3.00)",
        "Accept-Language": "de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8",
    }
    form = {
        "sn": device_id,
        "cleanId": clean_id,
        "areaSetting": area_setting_json,
        "taskid": task_id,
    }
    try:
        response = await client._http_client.post(
            f"{client._base_url}/{ROOM_CLEANING_ENDPOINT}",
            data=form,
            headers=headers,
        )
    except httpx.RequestError as error:
        raise ApiError(
            "Room-cleaning diagnostic request failed",
            phase="transport",
        ) from error

    try:
        payload = response.json()
    except ValueError:
        payload = None
    response_errno: int | None = None
    error_code: int | None = None
    if isinstance(payload, dict):
        try:
            response_errno = client_module._numeric_api_code(
                payload.get("errno"),
                status_code=response.status_code,
            )
            if "errorCode" in payload:
                error_code = client_module._numeric_api_code(
                    payload["errorCode"],
                    status_code=response.status_code,
                )
        except ApiError:
            response_errno = None
            error_code = None
    effective_errno = (
        error_code if error_code not in (None, 0) else response_errno
    )
    accepted = response.is_success and effective_errno == 0
    return {
        "httpStatus": response.status_code,
        "errno": effective_errno,
        "responseErrno": response_errno,
        "errorCode": error_code,
        "accepted": accepted,
    }


def _record_protocol_info_types(
    captures: list[dict[str, int | str | None]],
    *,
    event: int | str | None,
    protocol: dict[str, Any],
) -> None:
    _record_event(captures, event=event, info_type=protocol.get("infoType"))
    if str(protocol.get("infoType")) != COMPOSITE_INFO_TYPE:
        return
    composite = _json_object(protocol.get("data"))
    commands = composite.get("cmds") if composite is not None else None
    if not isinstance(commands, list):
        return
    for command in commands:
        if isinstance(command, dict):
            _record_protocol_info_types(
                captures,
                event=event,
                protocol=command,
            )


async def _capture_safe_push_events(
    push: PushClient,
    *,
    device_id: str,
    duration: float,
) -> list[dict[str, int | str | None]]:
    captures: list[dict[str, int | str | None]] = []
    if push._reader is None:
        raise ApiError("Push client is not connected", phase="transport")
    loop = asyncio.get_running_loop()
    deadline = loop.time() + duration
    while (remaining := deadline - loop.time()) > 0:
        try:
            chunk = await asyncio.wait_for(push._reader.read(65536), remaining)
        except asyncio.TimeoutError:
            break
        except OSError as error:
            raise ApiError("Push observation failed", phase="transport") from error
        if not chunk:
            break
        for prefix, envelope in push._frames.feed(chunk):
            await push._acknowledge(prefix)
            try:
                event_payload = decode_push_envelope(envelope, push._push_key)
            except ApiError:
                continue
            if event_payload.get("sn") != device_id:
                continue
            protocol = _json_object(event_payload.get("data"))
            if protocol is not None:
                _record_protocol_info_types(
                    captures,
                    event=_event_number(event_payload),
                    protocol=protocol,
                )
    return captures


def _safe_status(status: object) -> dict[str, Any] | None:
    if status is None:
        return None
    return {
        "online": status.online,
        "state": status.state,
        "battery": status.battery,
        "charging": status.charging,
        "fanMode": status.fan_mode,
        "cleanedAreaM2": status.cleaned_area_m2,
        "cleaningTimeSeconds": status.cleaning_time_seconds,
        "errorCode": status.error_code,
    }


async def _run_confirmed_room_test(
    client: Botslab360Client,
    *,
    device_id: str,
    prepared: dict[str, Any],
    observation_seconds: float,
    status_timeout: float,
) -> dict[str, Any]:
    summary = _room_request_summary(prepared)
    print()
    print("Selected room:")
    print(f"  ID: {prepared['roomId']}")
    print(f"  Name: {prepared['roomName']}")
    print()
    print("Request:")
    for key, value in summary.items():
        if key != "roomName":
            print(f"  {key}: {value}")
    print()
    confirmation = await asyncio.to_thread(
        input,
        f"Type CLEAN ROOM {prepared['roomId']} to continue: ",
    )
    if confirmation != f"CLEAN ROOM {prepared['roomId']}":
        print("Confirmation did not match; no request was sent.")
        return {
            "selectedRoomId": prepared["roomId"],
            "roomName": prepared["roomName"],
            "mapId": prepared["mapId"],
            "sent": False,
        }

    if client.session is None:
        raise AuthenticationError(
            "Authentication is required before the room-cleaning test",
            phase="authentication",
        )
    push = PushClient(
        client.session.sid,
        client.session.push_key,
        host=client._push_host,
        port=client._push_port,
    )
    form = prepared["form"]
    async with push:
        http_result = await _post_room_cleaning(
            client,
            device_id=device_id,
            clean_id=form["cleanId"],
            area_setting_json=form["areaSettingJson"],
            task_id=form["taskid"],
        )
        print()
        print("HTTP result:")
        print(f"  status: {http_result['httpStatus']}")
        print(f"  errno: {http_result['errno']}")
        print(f"  accepted: {http_result['accepted']}")
        push_error = None
        try:
            push_events = await _capture_safe_push_events(
                push,
                device_id=device_id,
                duration=observation_seconds,
            )
        except ApiError as error:
            push_events = []
            push_error = {"phase": error.phase}

    status = None
    status_error = None
    try:
        status = await client.get_status(device_id, timeout=status_timeout)
    except ApiError as error:
        status_error = {
            "phase": error.phase,
            "httpStatus": error.status_code,
            "errno": error.errno,
        }
    safe_status = _safe_status(status)
    print()
    print("Robot status:")
    print(json.dumps(safe_status or {"error": status_error}, indent=2))
    return {
        "selectedRoomId": prepared["roomId"],
        "roomName": prepared["roomName"],
        "mapId": prepared["mapId"],
        "sent": True,
        "httpStatus": http_result["httpStatus"],
        "errno": http_result["errno"],
        "accepted": http_result["accepted"],
        "pushEvents": push_events,
        "pushError": push_error,
        "robotStatus": safe_status,
        "statusError": status_error,
    }


def _select_device(devices: list[Device], index: int | None) -> Device | None:
    if not devices:
        print("No devices found.")
        return None
    if index is None and len(devices) == 1:
        return devices[0]
    if index is None:
        print("Multiple devices found; rerun with --device-index:")
        for number, device in enumerate(devices, start=1):
            print(f"  {number}: {device.name} ({device.model})")
        return None
    if index < 1 or index > len(devices):
        print(f"Invalid --device-index; expected 1..{len(devices)}.")
        return None
    return devices[index - 1]


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def _write_diagnostic(path: Path, diagnostic: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(diagnostic, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print()
    print(f"Sanitized diagnostic written to: {path}")


async def _run(args: argparse.Namespace, q: str, t: str) -> int:
    captures: list[dict[str, int | str | None]] = []
    real_test_capture: dict[str, Any] | None = None
    try:
        async with Botslab360Client(q, t) as client:
            await client.authenticate()
            with _capture_discovery_support() as support_values:
                devices = await client.get_devices()
            device = _select_device(devices, args.device_index)
            if device is None:
                return 1
            support = support_values.get(device.id, _support_diagnostic(None))

            print(f"Device: {device.name}")
            print(f"Model: {device.model}")
            print(f"Online: {device.online}")
            support_value = support["supportBlockClean"]
            print(
                "supportBlockClean: "
                f"{support_value if support_value is not None else 'not found'}"
            )
            print(f"support field: {support['supportField']}")
            print(f"support JSON layers: {support['supportJsonLayers']}")
            print(f"support keys: {support['supportKeys']}")
            print(f"support candidate keys: {support['supportCandidateKeys']}")
            print(f"supportBlockClean paths: {support['supportBlockCleanPaths']}")
            print("selected support capabilities:")
            for name in SUPPORT_CAPABILITIES:
                print(f"  {name}: {support['supportCapabilities'][name]}")

            diagnostic = {
                "model": device.model,
                "supportBlockClean": support["supportBlockClean"],
                "supportField": support["supportField"],
                "supportJsonLayers": support["supportJsonLayers"],
                "supportKeys": support["supportKeys"],
                "supportCandidateKeys": support["supportCandidateKeys"],
                "supportBlockCleanPaths": support["supportBlockCleanPaths"],
                "supportCapabilities": support["supportCapabilities"],
            }
            if args.support_only:
                if args.output is not None:
                    _write_diagnostic(args.output, diagnostic)
                return 0
            print()

            task_id = str(uuid4())
            map_info, source = await client._with_session_refresh(
                lambda: _capture_map_once(
                    client,
                    device_id=device.id,
                    task_id=task_id,
                    timeout=args.timeout,
                    captures=captures,
                )
            )
            safe_map = _sanitize_map(map_info)
            if args.clean_room is not None:
                try:
                    prepared = _prepare_room_request(
                        clean_id=safe_map["cleanId"],
                        map_id=safe_map["mapId"],
                        smart_area=safe_map["areaSettingTemplate"],
                        room_id=args.clean_room,
                    )
                except ValueError as error:
                    print(f"Cannot prepare room request: {error}", file=sys.stderr)
                    return 5
                real_test_capture = await _run_confirmed_room_test(
                    client,
                    device_id=device.id,
                    prepared=prepared,
                    observation_seconds=args.observe_seconds,
                    status_timeout=args.timeout,
                )
    except AuthenticationError as error:
        print(f"Authentication failed (phase={error.phase}).", file=sys.stderr)
        return 2
    except ApiError as error:
        print(f"Capture failed: {error} (phase={error.phase}).", file=sys.stderr)
        return 4

    print()
    print("Map:")
    print(f"  mapId: {safe_map['mapId']}")
    if args.clean_room is not None:
        clean_id_display = "present" if safe_map["cleanId"] else "missing"
        print(f"  cleanId: {clean_id_display}")
    else:
        print(f"  cleanId: {safe_map['cleanId']}")
    print(f"  cleanId type: {safe_map['cleanIdType']}")
    print(
        "  smartArea.activeIds present: "
        f"{safe_map['smartAreaActiveIdsPresent']}"
    )
    print(f"  smartArea.activeIds: {safe_map['smartAreaActiveIds']}")
    print(f"  source: {source}")
    print()
    print("Rooms:")
    rooms = safe_map["rooms"]
    if not rooms:
        print("  No rooms in MapInfo.smartArea.value[].")
    for room in rooms:
        print(f"  - id: {room['id']}")
        print(f"    name: {room['name']}")
        print(f"    roomType: {room['roomType']}")
        print(f"    vertex count: {room['vertexCount']}")
        print(f"    cleanTimes: {room['cleanTimes']}")
        print(f"    windMode: {room['windMode']}")
        print(f"    waterPump: {room['waterPump']}")

    prepared_request: dict[str, Any] | None = None
    if args.prepare_room is not None:
        try:
            prepared_request = _prepare_room_request(
                clean_id=safe_map["cleanId"],
                map_id=safe_map["mapId"],
                smart_area=safe_map["areaSettingTemplate"],
                room_id=args.prepare_room,
            )
        except ValueError as error:
            print(f"Cannot prepare room request: {error}", file=sys.stderr)
            return 5
        print()
        print("Prepared room-cleaning request (NOT SENT):")
        print(json.dumps(prepared_request, ensure_ascii=False, indent=2))

    if args.output is not None:
        if args.clean_room is not None:
            if real_test_capture is not None:
                _write_diagnostic(args.output, real_test_capture)
            return 0
        diagnostic.update(
            {
                "mapId": safe_map["mapId"],
                "cleanId": safe_map["cleanId"],
                "cleanIdType": safe_map["cleanIdType"],
                "source": source,
                "smartArea": safe_map["smartArea"],
                "areaSettingTemplate": safe_map["areaSettingTemplate"],
                "smartAreaActiveIdsPresent": safe_map[
                    "smartAreaActiveIdsPresent"
                ],
                "smartAreaActiveIds": safe_map["smartAreaActiveIds"],
                "rooms": rooms,
                "pushEvents": captures,
            }
        )
        if prepared_request is not None:
            diagnostic["preparedRoomRequest"] = prepared_request
        _write_diagnostic(args.output, diagnostic)
    return 0


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Capture the active S9-P map and optionally run one explicitly "
            "confirmed room-cleaning diagnostic."
        ),
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--support-only",
        action="store_true",
        help="inspect discovery support metadata without requesting a map",
    )
    parser.add_argument(
        "--device-index",
        type=int,
        help="1-based discovery result to inspect (required for multiple devices)",
    )
    mode.add_argument(
        "--prepare-room",
        type=int,
        metavar="ROOM_ID",
        help="prepare but never send a room-cleaning form request",
    )
    mode.add_argument(
        "--clean-room",
        type=int,
        metavar="ROOM_ID",
        help="send one room-cleaning request after exact interactive confirmation",
    )
    parser.add_argument(
        "--observe-seconds",
        type=_positive_float,
        default=8.0,
        help="seconds to capture safe push metadata after --clean-room (default: 8)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="seconds to wait for infoType 20002 (default: 30)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="optional path for sanitized diagnostic JSON",
    )
    return parser.parse_args()


def main() -> int:
    logging.getLogger("httpx").disabled = True
    logging.getLogger("httpcore").disabled = True
    args = _arguments()
    q = os.environ.get("BOTSLAB360_Q")
    t = os.environ.get("BOTSLAB360_T")
    if not q or not t:
        print(
            "Set BOTSLAB360_Q and BOTSLAB360_T before running this script.",
            file=sys.stderr,
        )
        return 1
    return asyncio.run(_run(args, q, t))


if __name__ == "__main__":
    raise SystemExit(main())
