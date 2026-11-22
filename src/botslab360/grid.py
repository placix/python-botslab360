"""Occupancy-grid parsing for the robot's current MapInfo."""

from __future__ import annotations

import base64
import binascii
import math
from typing import Any

from .exceptions import ApiError
from .models import OccupancyGrid
from .rooms import has_room_segmentation

# Upper bound for width * height. At 5 cm per cell this is a 100 m x 100 m map;
# it keeps a corrupt or hostile payload from allocating unbounded memory.
MAX_GRID_CELLS = 4_000_000

# Grid fields whose complete absence means the MapInfo carries no grid at all.
_GRID_FIELDS = ("width", "height", "map")


def _protocol_error(message: str) -> ApiError:
    return ApiError(message, phase="protocol")


def _strict_int(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _protocol_error(f"MapInfo has an invalid {field}")
    return value


def _finite_number(value: object, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _protocol_error(f"MapInfo has an invalid {field}")
    number = float(value)
    if not math.isfinite(number):
        raise _protocol_error(f"MapInfo has an invalid {field}")
    return number


def _decode_base64(value: object) -> bytes:
    """Decode the grid's Base64 text, where '+' may arrive as a space."""

    if not isinstance(value, str) or not value:
        raise _protocol_error("MapInfo has an invalid map")
    normalized = value.replace(" ", "+")
    normalized += "=" * (-len(normalized) % 4)
    try:
        return base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise _protocol_error("MapInfo map is not valid Base64") from exc


def _read_length(src: bytes, index: int, length: int) -> tuple[int, int]:
    """Read an LZ4 length extension that follows a nibble value of 15."""

    if length != 15:
        return length, index
    while True:
        byte = src[index]
        index += 1
        length += byte
        if byte != 255:
            return length, index


def decompress_lz4_block(src: bytes, expected_size: int) -> bytes:
    """Decompress one raw LZ4 block that must expand to exactly expected_size.

    The block has no frame header. Output never grows past expected_size, so a
    corrupt block cannot allocate more memory than the declared grid.
    """

    dst = bytearray()
    index = 0
    end = len(src)
    try:
        while index < end:
            token = src[index]
            index += 1
            literals, index = _read_length(src, index, token >> 4)
            if index + literals > end or len(dst) + literals > expected_size:
                raise _protocol_error("MapInfo map has corrupt LZ4 literals")
            dst += src[index : index + literals]
            index += literals
            if index >= end:
                break
            offset = src[index] | (src[index + 1] << 8)
            index += 2
            if offset == 0 or offset > len(dst):
                raise _protocol_error("MapInfo map has a corrupt LZ4 offset")
            match_length, index = _read_length(src, index, token & 0x0F)
            match_length += 4
            if len(dst) + match_length > expected_size:
                raise _protocol_error("MapInfo map has a corrupt LZ4 match")
            start = len(dst) - offset
            if match_length <= offset:
                dst += dst[start : start + match_length]
            else:
                # Overlapping match: the last `offset` bytes repeat.
                pattern = dst[start:]
                repeats = match_length // offset + 1
                dst += (pattern * repeats)[:match_length]
    except IndexError as exc:
        raise _protocol_error("MapInfo map has a truncated LZ4 block") from exc
    if len(dst) != expected_size:
        raise _protocol_error("MapInfo map does not match its width and height")
    return bytes(dst)


def _dock_position(value: object) -> tuple[int, int] | None:
    """Parse chargeHandlePos with the same rules as the status pos field."""

    if value in (None, []):
        return None
    if not isinstance(value, list) or len(value) < 2:
        raise _protocol_error("MapInfo has an invalid chargeHandlePos")
    return (
        _strict_int(value[0], field="chargeHandlePos"),
        _strict_int(value[1], field="chargeHandlePos"),
    )


def parse_occupancy_grid(map_payload: dict[str, Any]) -> OccupancyGrid:
    """Parse the occupancy grid carried by a current MapInfo payload."""

    map_id = map_payload.get("mapId")
    if isinstance(map_id, bool) or not isinstance(map_id, int):
        raise _protocol_error("MapInfo is missing a valid mapId")
    if all(field not in map_payload for field in _GRID_FIELDS):
        raise ApiError(
            "The current map does not include an occupancy grid",
            phase="unsupported",
        )

    width = _strict_int(map_payload.get("width"), field="width")
    height = _strict_int(map_payload.get("height"), field="height")
    if width <= 0 or height <= 0:
        raise _protocol_error("MapInfo has invalid grid dimensions")
    if width * height > MAX_GRID_CELLS:
        raise _protocol_error("MapInfo grid is larger than supported")
    resolution = _finite_number(map_payload.get("resolution"), field="resolution")
    if resolution <= 0:
        raise _protocol_error("MapInfo has an invalid resolution")
    x_min = _finite_number(map_payload.get("x_min"), field="x_min")
    y_min = _finite_number(map_payload.get("y_min"), field="y_min")

    compressed = _decode_base64(map_payload.get("map"))
    if "lz4_len" in map_payload:
        lz4_len = _strict_int(map_payload["lz4_len"], field="lz4_len")
        if lz4_len != len(compressed):
            raise _protocol_error("MapInfo lz4_len does not match the map")
    cells = decompress_lz4_block(compressed, width * height)

    return OccupancyGrid(
        map_id=map_id,
        width=width,
        height=height,
        resolution=resolution,
        x_min=x_min,
        y_min=y_min,
        cells=cells,
        dock=_dock_position(map_payload.get("chargeHandlePos")),
        room_segmentation=has_room_segmentation(map_payload),
    )
