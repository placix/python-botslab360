"""Synthetic S6 grid vectors, adapted from the reference tests in HA PR #6."""

import base64
from dataclasses import FrozenInstanceError

import pytest

from botslab360 import (
    GRID_CELL_FREE,
    GRID_CELL_OCCUPIED,
    GRID_CELL_UNKNOWN,
    ApiError,
    OccupancyGrid,
    UnsupportedOccupancyGridError,
    UnsupportedRoomMapError,
)
from botslab360.occupancy import _decode_lz4_block, parse_occupancy_grid
from botslab360.protocol import _optional_position


def literal_block(cells: bytes) -> bytes:
    length = len(cells)
    if length < 15:
        return bytes([length << 4]) + cells
    rest = length - 15
    return b"\xf0" + b"\xff" * (rest // 255) + bytes([rest % 255]) + cells


def grid_info() -> dict:
    cells = bytes([0, 127, 255, 42] * 3)
    block = literal_block(cells)
    return {
        "mapId": 17,
        "area": [],
        "width": 4,
        "height": 3,
        "resolution": 0.05,
        "x_min": -0.5,
        "y_min": -0.25,
        "map": base64.b64encode(block).decode(),
        "lz4_len": len(block),
        "chargeHandlePos": [100, -200],
    }


@pytest.mark.parametrize(
    ("block", "size", "expected"),
    [
        (b"\x30\x00\x7f\xff", 3, b"\x00\x7f\xff"),
        (b"\x17\x7f\x01\x00", 12, b"\x7f" * 12),
        (b"\x40abcd\x04\x00", 8, b"abcdabcd"),
        (literal_block(b"x" * 300), 300, b"x" * 300),
        (b"\x1fx\x01\x00\xff\x00", 275, b"x" * 275),
    ],
)
def test_lz4_literal_match_and_extended_lengths(block, size, expected):
    assert _decode_lz4_block(block, size) == expected


@pytest.mark.parametrize(
    ("block", "size"),
    [
        (b"\x17\x7f\x00\x00", 12),  # zero offset
        (b"\x17\x7f\x05\x00", 12),  # offset beyond output
        (b"\x17\x7f\x01\x00", 8),  # match exceeds expected size
        (b"\x20ab", 1),  # literals exceed expected size
        (b"\x50ab", 5),  # truncated literal run
        (b"\x10a\x01", 5),  # truncated offset
        (b"\xf0", 15),  # truncated literal length
        (b"\xf0\xff", 300),  # unterminated extended length
        (b"\x1fa\x01\x00", 20),  # truncated match length
        (b"\x20ab", 5),  # final size mismatch
        (b"", 1),
        (b"\x10a", 1_000_001),
    ],
)
def test_lz4_rejects_corruption_and_excessive_output(block, size):
    with pytest.raises(ApiError) as raised:
        _decode_lz4_block(block, size)
    assert raised.value.phase == "protocol"


def test_s6_grid_geometry_and_immutable_public_model():
    grid = parse_occupancy_grid(grid_info())
    assert isinstance(grid, OccupancyGrid)
    assert (grid.map_id, grid.width, grid.height) == (17, 4, 3)
    assert (grid.resolution, grid.x_min, grid.y_min) == (0.05, -0.5, -0.25)
    assert grid.dock_position == (100, -200)
    assert grid.cells == bytes([0, 127, 255, 42] * 3)
    assert "cells=" not in repr(grid)
    with pytest.raises(FrozenInstanceError):
        grid.width = 2


def test_all_cell_values_are_preserved_without_palette_mapping():
    info = grid_info()
    cells = bytes(range(256))
    block = literal_block(cells)
    info.update(
        width=16, height=16, map=base64.b64encode(block).decode(), lz4_len=len(block)
    )
    assert parse_occupancy_grid(info).cells == cells


def test_base64_spaces_are_plus_and_missing_padding_is_restored():
    info = grid_info()
    block = literal_block(b"\x00\x3e")
    encoded = base64.b64encode(block).decode()
    assert "+" in encoded
    info.update(width=2, height=1, map=encoded.replace("+", " "), lz4_len=len(block))
    assert parse_occupancy_grid(info).cells == b"\x00\x3e"
    block = literal_block(b"\xff")
    encoded = base64.b64encode(block).decode()
    assert encoded.endswith("=")
    info.update(width=1, map=encoded.rstrip("="), lz4_len=len(block))
    assert parse_occupancy_grid(info).cells == b"\xff"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        *(("mapId", value) for value in (None, True, False, "17", 17.0)),
        *(
            (field, value)
            for field in ("width", "height")
            for value in (None, True, False, "4", 4.0, 0, -1)
        ),
        *(
            ("resolution", value)
            for value in (
                None,
                True,
                "0.05",
                0,
                -1,
                float("nan"),
                float("inf"),
                -float("inf"),
                10**1000,
            )
        ),
        *(
            (field, value)
            for field in ("x_min", "y_min")
            for value in (
                None,
                True,
                "0",
                float("nan"),
                float("inf"),
                -float("inf"),
                10**1000,
            )
        ),
        *(
            ("map", value)
            for value in (None, 123, True, "", "Q", "private-map-Ω", "AA\n", "###")
        ),
        *(("lz4_len", value) for value in (None, True, "13", 13.0, -1, 0, 999)),
        *(
            ("chargeHandlePos", value)
            for value in (
                {},
                [1],
                [True, 2],
                [1, "2"],
                [1.0, 2],
                [float("nan"), 2],
            )
        ),
    ],
)
def test_grid_fields_are_strict_and_messages_do_not_expose_payloads(field, value):
    info = grid_info()
    info[field] = value
    with pytest.raises(ApiError) as raised:
        parse_occupancy_grid(info)
    assert raised.value.phase == "protocol"
    assert "private-map" not in str(raised.value)
    assert (
        info["map"] not in str(raised.value)
        if isinstance(info["map"], str) and info["map"]
        else True
    )


@pytest.mark.parametrize(
    "field", ["mapId", "width", "height", "resolution", "x_min", "y_min", "map"]
)
def test_required_grid_fields_cannot_be_missing(field):
    info = grid_info()
    del info[field]
    with pytest.raises(ApiError):
        parse_occupancy_grid(info)


def test_grid_size_guard_precedes_decoding():
    info = grid_info()
    info.update(width=1001, height=1000, map="not-Base64")
    with pytest.raises(ApiError, match="dimensions"):
        parse_occupancy_grid(info)


def test_encoded_grid_size_is_bounded_before_base64_allocation():
    info = grid_info()
    info["map"] = "A" * 2_700_000
    with pytest.raises(ApiError, match="input limit"):
        parse_occupancy_grid(info)


def test_optional_metadata_and_numeric_geometry_do_not_guess_other_capabilities():
    info = grid_info()
    del info["chargeHandlePos"]
    del info["lz4_len"]
    info.update(
        resolution=1,
        x_min=0,
        y_min=-1,
        chargeHandlePhi=91,
        chargeHandleState=9,
        base64_len=len(info["map"]),
    )
    grid = parse_occupancy_grid(info)
    assert (grid.resolution, grid.x_min, grid.y_min) == (1.0, 0.0, -1.0)
    assert grid.dock_position is None
    info["chargeHandlePos"] = [0, 0]
    assert parse_occupancy_grid(info).dock_position == (0, 0)


def test_long_overlap_with_remainder_and_trailing_literals():
    """PR #3 vector covers a match extension followed by a new sequence."""
    block = b"\x2fab\x02\x00\x03\x10c"
    assert _decode_lz4_block(block, 25) == b"ab" * 12 + b"c"


def test_optimized_matches_agree_with_bytewise_overlap_reference():
    """Exercise offsets, exact repeats, partial repeats and both copy paths."""
    literals = bytes(range(32))
    for offset in (1, 2, 3, 7, 16, 32):
        for length in (4, 7, 16, 19, 20, 63, 257, 1000):
            nibble = min(length - 4, 15)
            extension = b""
            if nibble == 15:
                extra = length - 4 - 15
                extension = b"\xff" * (extra // 255) + bytes([extra % 255])
            block = (
                bytes([0xF0 | nibble, len(literals) - 15])
                + literals
                + offset.to_bytes(2, "little")
                + extension
                + b"\x10z"
            )
            expected = bytearray(literals)
            for _ in range(length):
                expected.append(expected[-offset])
            expected.extend(b"z")
            assert _decode_lz4_block(block, len(expected)) == bytes(expected)


def test_exact_conservative_cell_limit_accepts_long_compressed_match():
    """Adapted from PR #3: test the accepted boundary, not only rejection."""
    limit = 1_000_000
    extra = limit - 1 - 4 - 15
    extension = b"\xff" * (extra // 255) + bytes([extra % 255])
    block = b"\x1f\x7f\x01\x00" + extension
    info = grid_info()
    info.update(
        width=1000,
        height=1000,
        map=base64.b64encode(block).decode(),
        lz4_len=len(block),
    )
    assert parse_occupancy_grid(info).cells == bytes([GRID_CELL_UNKNOWN]) * limit


@pytest.mark.parametrize("value", [None, [], [5, -6], [5, -6, 0]])
def test_dock_position_matches_existing_status_position_semantics(value):
    info = grid_info()
    info["chargeHandlePos"] = value
    status_position = _optional_position(value)
    expected = None if status_position == (None, None) else status_position
    assert parse_occupancy_grid(info).dock_position == expected


@pytest.mark.parametrize(
    "info",
    [
        {"mapId": 1, "area": []},
        {"mapId": 1, "cleanId": "synthetic", "smartArea": {"value": []}},
        {"mapId": 1},
    ],
)
def test_complete_absence_of_grid_is_typed_unsupported(info):
    with pytest.raises(UnsupportedOccupancyGridError) as raised:
        parse_occupancy_grid(info)
    assert isinstance(raised.value, ApiError)
    assert not isinstance(raised.value, UnsupportedRoomMapError)
    assert raised.value.phase == "unsupported"


@pytest.mark.parametrize(
    "field",
    ["width", "height", "resolution", "x_min", "y_min", "map", "lz4_len", "base64_len"],
)
def test_partial_grid_metadata_is_corruption_not_unsupported(field):
    with pytest.raises(ApiError) as raised:
        parse_occupancy_grid({"mapId": 1, field: None})
    assert not isinstance(raised.value, UnsupportedOccupancyGridError)
    assert raised.value.phase == "protocol"


@pytest.mark.parametrize("map_id", [None, True, "1", 1.5])
def test_invalid_map_id_precedes_unsupported_classification(map_id):
    with pytest.raises(ApiError) as raised:
        parse_occupancy_grid({"mapId": map_id})
    assert not isinstance(raised.value, UnsupportedOccupancyGridError)
    assert raised.value.phase == "protocol"


@pytest.mark.parametrize("position", [[1], [True, 2], ["1", 2], {}])
def test_invalid_dock_is_never_classified_as_absent_grid(position):
    with pytest.raises(ApiError) as raised:
        parse_occupancy_grid({"mapId": 1, "chargeHandlePos": position})
    assert raised.value.phase == "protocol"
    assert not isinstance(raised.value, UnsupportedOccupancyGridError)


@pytest.mark.parametrize(
    "room_fields",
    [{}, {"area": []}, {"cleanId": "synthetic", "smartArea": {"value": []}}],
)
def test_occupancy_model_does_not_claim_room_segmentation(room_fields):
    info = grid_info()
    del info["area"]
    model = parse_occupancy_grid(info | room_fields)
    assert not hasattr(model, "room_segmentation")
    assert model.dock_position == (100, -200)


def test_public_cell_constants_preserve_s6_meanings_without_restricting_bytes():
    assert (GRID_CELL_OCCUPIED, GRID_CELL_UNKNOWN, GRID_CELL_FREE) == (0, 127, 255)


def test_tiny_grid_input_limit_is_checked_before_base64_decode(monkeypatch):
    from botslab360 import occupancy

    monkeypatch.setattr(
        occupancy.base64,
        "b64decode",
        lambda *args, **kwargs: pytest.fail("Oversized input reached decoder"),
    )
    info = grid_info()
    info.update(width=1, height=1, map="A" * 8)
    with pytest.raises(ApiError, match="input limit") as raised:
        parse_occupancy_grid(info)
    assert raised.value.phase == "protocol"
    assert not isinstance(raised.value, UnsupportedOccupancyGridError)
