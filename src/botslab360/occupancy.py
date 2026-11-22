"""Bounds-checked vendor occupancy-grid parsing, verified for the 360 S6.

The raw-block algorithm follows the reference in HA PR #6 by DrLabel; protocol
validation and the typed result are library concerns, with no image rendering.
"""

from __future__ import annotations

import base64
import binascii
import math

from .exceptions import ApiError, UnsupportedOccupancyGridError
from .map_info import _json_object
from .models import OccupancyGrid

# About 65 times the observed 166x92 S6 grid, or 50x50 m at 5 cm/cell.
# Keep output/temporary allocations conservative until a larger map is evidenced.
_MAX_CELLS = 1_000_000
# A generous compressed-input bound also limits Base64 allocation and scanning.
_MAX_ENCODED_LENGTH = 4 * ((2 * _MAX_CELLS + 2) // 3)
_GRID_FIELDS = {
    "width",
    "height",
    "resolution",
    "x_min",
    "y_min",
    "map",
    "lz4_len",
    "base64_len",
}


def _error(message: str) -> ApiError:
    return ApiError(message, phase="protocol")


def _integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _error(f"Occupancy grid has an invalid {field}")
    return value


def _finite_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _error(f"Occupancy grid has an invalid {field}")
    try:
        number = float(value)
    except OverflowError:
        raise _error(f"Occupancy grid has an invalid {field}") from None
    if not math.isfinite(number):
        raise _error(f"Occupancy grid has an invalid {field}")
    return number


def _read_length(source: bytes, index: int, length: int) -> tuple[int, int]:
    if length == 15:
        while True:
            if index >= len(source):
                raise _error("Truncated LZ4 map length")
            extra = source[index]
            index += 1
            length += extra
            if extra != 255:
                break
    return length, index


def _decode_lz4_block(source: bytes, expected_size: int) -> bytes:
    """Decode a raw block, including overlapping matches, within a fixed bound."""

    if not 0 < expected_size <= _MAX_CELLS:
        raise _error("Occupancy grid exceeds the supported cell limit")
    output = bytearray()
    index = 0
    while index < len(source):
        token = source[index]
        index += 1
        literal_length, index = _read_length(source, index, token >> 4)
        if index + literal_length > len(source):
            raise _error("Truncated LZ4 map literals")
        if len(output) + literal_length > expected_size:
            raise _error("LZ4 map literals exceed the expected grid size")
        output.extend(source[index : index + literal_length])
        index += literal_length
        if index == len(source):
            break
        if index + 2 > len(source):
            raise _error("Truncated LZ4 map offset")
        offset = source[index] | (source[index + 1] << 8)
        index += 2
        if offset == 0 or offset > len(output):
            raise _error("Invalid LZ4 map offset")
        match_length, index = _read_length(source, index, token & 15)
        match_length += 4
        if len(output) + match_length > expected_size:
            raise _error("LZ4 map match exceeds the expected grid size")
        start = len(output) - offset
        if match_length <= offset:
            output.extend(output[start : start + match_length])
        else:
            # Overlap repeats the last offset-byte pattern, including a tail.
            # Unlike the reference's extra repeat, divmod allocates exactly
            # the match length, with the output bound checked above.
            pattern = output[start:]
            repeats, remainder = divmod(match_length, offset)
            output.extend(pattern * repeats)
            output.extend(pattern[:remainder])
    if len(output) != expected_size:
        raise _error("Decompressed map size does not match grid dimensions")
    return bytes(output)


def parse_occupancy_grid(map_info: object) -> OccupancyGrid:
    """Validate geometry and decode cells without guessing room capabilities."""

    info = _json_object(map_info, field="MapInfo")
    map_id = _integer(info.get("mapId"), "mapId")
    # Validate any reported position before declaring an absent grid, so
    # malformed coordinates cannot be mislabeled as unsupported capability.
    dock_position = None
    dock = info.get("chargeHandlePos")
    # Same rules as status pos: absent/empty or first two strict integers;
    # trailing metadata is neither interpreted nor exposed.
    if dock not in (None, []):
        if not isinstance(dock, list) or len(dock) < 2:
            raise _error("Occupancy grid has an invalid dock position")
        dock_position = (
            _integer(dock[0], "dock x coordinate"),
            _integer(dock[1], "dock y coordinate"),
        )
    if _GRID_FIELDS.isdisjoint(info):
        raise UnsupportedOccupancyGridError(
            "The current map does not include an occupancy grid", phase="unsupported"
        )
    width = _integer(info.get("width"), "width")
    height = _integer(info.get("height"), "height")
    cell_count = width * height
    if width <= 0 or height <= 0 or cell_count > _MAX_CELLS:
        raise _error("Occupancy grid has invalid or excessive dimensions")
    resolution = _finite_number(info.get("resolution"), "resolution")
    if resolution <= 0:
        raise _error("Occupancy grid resolution must be positive")
    x_min = _finite_number(info.get("x_min"), "x_min")
    y_min = _finite_number(info.get("y_min"), "y_min")

    encoded = info.get("map")
    if not isinstance(encoded, str) or not encoded:
        raise _error("MapInfo is missing a usable occupancy-grid payload")
    # Even a tiny declared grid must not cause a global-limit-sized decode.
    # Raw LZ4 blocks fit within 2*N+1 bytes for N output bytes; allow that
    # conservative envelope plus Base64 padding, capped by the global guard.
    encoded_limit = min(_MAX_ENCODED_LENGTH, 4 * ((2 * cell_count + 3) // 3))
    if len(encoded) > encoded_limit:
        raise _error("Encoded occupancy grid exceeds the supported input limit")
    encoded = encoded.replace(" ", "+")
    try:
        compressed = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4), validate=True
        )
    except (ValueError, binascii.Error):
        raise _error("MapInfo contains invalid Base64 grid data") from None
    if "lz4_len" in info:
        compressed_length = _integer(info["lz4_len"], "lz4_len")
        if compressed_length != len(compressed):
            raise _error("MapInfo lz4_len does not match the compressed payload")

    return OccupancyGrid(
        map_id=map_id,
        width=width,
        height=height,
        resolution=resolution,
        x_min=x_min,
        y_min=y_min,
        cells=_decode_lz4_block(compressed, cell_count),
        dock_position=dock_position,
    )
