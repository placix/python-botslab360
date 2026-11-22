"""Shared MapInfo push transport, independent of rooms and grid parsing."""

from __future__ import annotations

import asyncio
import json
from json import JSONDecodeError
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx

from .exceptions import ApiError

if TYPE_CHECKING:
    from .protocol import PushClient

COMPOSITE_INFO_TYPE = "30000"
MAP_INFO_TYPE = "20002"

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


def _json_object(value: object, *, field: str) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except JSONDecodeError as exc:
            raise ApiError(f"{field} is invalid JSON", phase="protocol") from exc
    if not isinstance(value, dict):
        raise ApiError(f"{field} is invalid", phase="protocol")
    return value


async def _download_map(
    http_client: httpx.AsyncClient,
    url: str,
    *,
    request_timeout: float,
) -> dict[str, Any]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ApiError("Map push URL is invalid", phase="protocol")
    try:
        response = await http_client.get(url, timeout=request_timeout)
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
    request_timeout: float,
) -> dict[str, Any] | None:
    push_url = protocol.get("pushDataUrl")
    if isinstance(push_url, str) and push_url:
        downloaded = await _download_map(
            http_client,
            push_url,
            request_timeout=request_timeout,
        )
        return await _map_from_protocol(
            downloaded,
            http_client=http_client,
            request_timeout=request_timeout,
        )

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
            result = await _map_from_protocol(
                command,
                http_client=http_client,
                request_timeout=request_timeout,
            )
            if result is not None:
                return result
    return None


async def wait_for_map_info(
    push: PushClient,
    *,
    device_id: str,
    http_client: httpx.AsyncClient,
    request_timeout: float,
    timeout: float,
) -> dict[str, Any]:
    """Wait for the next current MapInfo push for one device."""

    async def wait() -> dict[str, Any]:
        while True:
            event = await push.read_event()
            if event.get("sn") != device_id:
                continue
            try:
                protocol = _json_object(event.get("data"), field="protocol")
            except ApiError:
                continue
            map_info = await _map_from_protocol(
                protocol,
                http_client=http_client,
                request_timeout=request_timeout,
            )
            if map_info is not None:
                return map_info

    try:
        return await asyncio.wait_for(wait(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise ApiError(
            "Timed out waiting for current map",
            phase="timeout",
        ) from exc
