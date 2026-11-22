from __future__ import annotations

import asyncio
import base64
import json
from typing import ClassVar
from urllib.parse import parse_qs

import httpx
import pytest

import botslab360.client as client_module
from botslab360 import (
    GRID_CELL_FREE,
    GRID_CELL_OCCUPIED,
    GRID_CELL_UNKNOWN,
    ApiError,
    Botslab360Client,
    Device,
    OccupancyGrid,
    SmartSession,
    UnsupportedRoomMapError,
)
from botslab360.grid import (
    MAX_GRID_CELLS,
    decompress_lz4_block,
    parse_occupancy_grid,
)

QID = "1234567890"
Q = f"u=360H{QID}&n=synthetic&m=not-a-real-token"
T = "s=synthetic-session&t=1700000000&v=2.0"
DEVICE = Device(
    id="synthetic-device",
    name="Synthetic Robot",
    model="S6-test",
    online=True,
)
WIDTH, HEIGHT = 8, 6


def run(coro):
    return asyncio.run(coro)


def literal_block(data: bytes) -> bytes:
    """Encode bytes as a valid literal-only LZ4 block."""

    if len(data) < 15:
        return bytes([len(data) << 4]) + data
    rest = len(data) - 15
    return bytes([0xF0]) + b"\xff" * (rest // 255) + bytes([rest % 255]) + data


def grid_cells() -> bytes:
    """Unknown border, free floor inside and one occupied cell."""

    cells = bytearray([GRID_CELL_UNKNOWN] * (WIDTH * HEIGHT))
    for row in range(1, HEIGHT - 1):
        for col in range(1, WIDTH - 1):
            cells[row * WIDTH + col] = GRID_CELL_FREE
    cells[2 * WIDTH + 3] = GRID_CELL_OCCUPIED
    return bytes(cells)


def grid_map_info(cells: bytes | None = None) -> dict:
    """A synthetic MapInfo shaped like the one sent by a 360 S6."""

    block = literal_block(grid_cells() if cells is None else cells)
    return {
        "mapId": 1700000000,
        "area": [],
        "width": WIDTH,
        "height": HEIGHT,
        "resolution": 0.05,
        "x_min": -0.2,
        "y_min": -0.1,
        "lz4_len": len(block),
        # The robot sends Base64 with spaces in place of "+".
        "map": base64.b64encode(block).decode().replace("+", " "),
        "chargeHandlePos": [-150, 40],
    }


def map_event(payload: dict | str) -> dict:
    data = payload if isinstance(payload, str) else json.dumps(payload)
    return {
        "sn": DEVICE.id,
        "data": json.dumps({"infoType": "20002", "data": data}),
    }


class FakePushClient:
    events: ClassVar[list[dict]] = []
    instances: ClassVar[list[FakePushClient]] = []

    def __init__(self, sid, push_key, **kwargs):
        self.closed = False
        self._events = iter(self.events)
        self.instances.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        self.closed = True

    async def read_event(self):
        return next(self._events)


def authenticated_client(http_client: httpx.AsyncClient) -> Botslab360Client:
    client = Botslab360Client(Q, T, http_client=http_client)
    client._session = SmartSession(
        qid=QID,
        sid="synthetic/sid+=",
        push_key="synthetic-push-key",
    )
    return client


def test_lz4_literals_and_overlapping_match() -> None:
    # One literal 0x7f, then offset 1 with length 7 + 4 -> twelve 0x7f bytes.
    block = bytes([(1 << 4) | 7, 0x7F, 0x01, 0x00])
    assert decompress_lz4_block(block, 12) == b"\x7f" * 12


def test_lz4_long_literals_and_long_match() -> None:
    assert decompress_lz4_block(literal_block(b"x" * 300), 300) == b"x" * 300
    # Two literals, then an overlapping match with an extended length
    # (15 + 3 + 4 = 22 bytes), then one trailing literal.
    block = bytes([(2 << 4) | 15]) + b"ab" + bytes([2, 0, 3, 1 << 4]) + b"c"
    assert decompress_lz4_block(block, 25) == b"ab" * 12 + b"c"


def test_lz4_non_overlapping_match() -> None:
    block = bytes([4 << 4]) + b"abcd" + bytes([4, 0])
    assert decompress_lz4_block(block, 8) == b"abcdabcd"


@pytest.mark.parametrize(
    ("block", "size"),
    [
        (bytes([(1 << 4) | 7, 0x7F, 0x00, 0x00]), 12),  # offset 0
        (bytes([(1 << 4) | 7, 0x7F, 0x05, 0x00]), 12),  # offset beyond output
        (bytes([(1 << 4) | 7, 0x7F, 0x01, 0x00]), 8),  # grows past the size
        (bytes([(1 << 4) | 7, 0x7F, 0x01]), 12),  # truncated offset
        (bytes([0xF0]), 20),  # truncated literal length
        (bytes([0x50, 1, 2]), 5),  # truncated literals
        (bytes([0x20, 1, 2]), 5),  # shorter than the size
    ],
)
def test_lz4_rejects_corrupt_blocks(block: bytes, size: int) -> None:
    with pytest.raises(ApiError) as raised:
        decompress_lz4_block(block, size)
    assert raised.value.phase == "protocol"


def test_occupancy_grid_parses_s6_shaped_map() -> None:
    grid = parse_occupancy_grid(grid_map_info())

    assert grid == OccupancyGrid(
        map_id=1700000000,
        width=WIDTH,
        height=HEIGHT,
        resolution=0.05,
        x_min=-0.2,
        y_min=-0.1,
        cells=grid_cells(),
        dock=(-150, 40),
        room_segmentation=False,
    )
    assert "cells" not in repr(grid)


def test_occupancy_grid_restores_plus_sent_as_space() -> None:
    cells = bytes([0x3E, 0xFB, 0xEF]) * (WIDTH * HEIGHT // 3)
    info = grid_map_info(cells)
    assert " " in info["map"]

    assert parse_occupancy_grid(info).cells == cells


def test_occupancy_grid_accepts_integer_geometry_and_missing_optionals() -> None:
    info = grid_map_info() | {"resolution": 1, "x_min": 0, "y_min": -3}
    del info["lz4_len"]
    del info["chargeHandlePos"]

    grid = parse_occupancy_grid(info)

    assert (grid.resolution, grid.x_min, grid.y_min) == (1.0, 0.0, -3.0)
    assert grid.dock is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, None), ([], None), ([5, -6], (5, -6)), ([5, -6, 0], (5, -6))],
)
def test_dock_position_follows_status_position_rules(value, expected) -> None:
    info = grid_map_info() | {"chargeHandlePos": value}

    assert parse_occupancy_grid(info).dock == expected


def test_grid_at_cell_limit_is_accepted() -> None:
    cells = bytes([GRID_CELL_UNKNOWN]) * MAX_GRID_CELLS
    # One literal, then one overlapping match that fills the whole grid.
    rest = MAX_GRID_CELLS - 1 - 4 - 15
    match = b"\xff" * (rest // 255) + bytes([rest % 255])
    block = bytes([(1 << 4) | 15, GRID_CELL_UNKNOWN, 1, 0]) + match
    info = grid_map_info() | {
        "width": MAX_GRID_CELLS // 2,
        "height": 2,
        "map": base64.b64encode(block).decode(),
        "lz4_len": len(block),
    }

    assert parse_occupancy_grid(info).cells == cells


def test_map_without_room_fields_is_not_reported_unsegmented() -> None:
    info = grid_map_info()
    del info["area"]

    assert parse_occupancy_grid(info).room_segmentation is True


def test_room_capable_map_without_rooms_is_segmented() -> None:
    info = grid_map_info() | {
        "cleanId": "synthetic-clean-id",
        "smartArea": {"mapId": 1700000000, "value": []},
    }

    assert parse_occupancy_grid(info).room_segmentation is True


@pytest.mark.parametrize(
    "change",
    [
        *({"mapId": value} for value in (None, True, "1", 1.5)),
        *({"width": value} for value in (None, 0, -1, True, "8", 8.0)),
        *({"height": value} for value in (None, 0, -1, True, "6", 6.0)),
        {"width": MAX_GRID_CELLS, "height": 2},
        *(
            {"resolution": value}
            for value in (None, 0, -0.05, True, "0.05", float("nan"), float("inf"))
        ),
        *({"x_min": value} for value in (None, True, "0", float("nan"))),
        *({"y_min": value} for value in (None, False, [], float("-inf"))),
        *({"map": value} for value in (None, 123, "")),
        *({"lz4_len": value} for value in (None, 1, True, "5", 5.0)),
        *(
            {"chargeHandlePos": value}
            for value in ([0], ["0", 0], [True, 0], [0.5, 0], "0,0", {})
        ),
        {"width": WIDTH + 1},
    ],
)
def test_occupancy_grid_rejects_invalid_fields(change: dict) -> None:
    with pytest.raises(ApiError) as raised:
        parse_occupancy_grid(grid_map_info() | change)
    assert raised.value.phase == "protocol"


@pytest.mark.parametrize("value", ["Q", "@@@@", "QUJD\n", "QU-D"])
def test_occupancy_grid_rejects_invalid_base64(value: str) -> None:
    info = grid_map_info() | {"map": value}
    del info["lz4_len"]
    with pytest.raises(ApiError, match="Base64") as raised:
        parse_occupancy_grid(info)
    assert raised.value.phase == "protocol"


def test_occupancy_grid_rejects_missing_mandatory_field() -> None:
    for field in ("width", "height", "map", "resolution", "x_min", "y_min"):
        info = grid_map_info()
        del info[field]
        with pytest.raises(ApiError) as raised:
            parse_occupancy_grid(info)
        assert raised.value.phase == "protocol"


def test_map_without_grid_is_unsupported() -> None:
    with pytest.raises(ApiError) as raised:
        parse_occupancy_grid({"mapId": 1, "area": []})
    assert raised.value.phase == "unsupported"
    assert not isinstance(raised.value, UnsupportedRoomMapError)


@pytest.mark.parametrize("as_json", [False, True])
def test_get_occupancy_grid_uses_shared_map_request(monkeypatch, as_json) -> None:
    async def scenario() -> None:
        info = grid_map_info()
        FakePushClient.events = [map_event(json.dumps(info) if as_json else info)]
        FakePushClient.instances = []
        monkeypatch.setattr(client_module, "PushClient", FakePushClient)
        requests: list[dict[str, list[str]]] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            requests.append(parse_qs((await request.aread()).decode()))
            return httpx.Response(200, json={"errno": 0})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            grid = await authenticated_client(http).get_occupancy_grid(
                DEVICE,
                timeout=1,
            )

        assert grid.cells == grid_cells()
        assert grid.room_segmentation is False
        assert len(requests) == 1
        assert requests[0]["infoType"] == ["30000"]
        assert json.loads(requests[0]["data"][0]) == client_module.LOAD_DATA
        assert FakePushClient.instances[0].closed is True

    run(scenario())


def test_rooms_and_grid_come_from_the_same_map(monkeypatch) -> None:
    async def scenario() -> None:
        info = grid_map_info()
        FakePushClient.instances = []
        monkeypatch.setattr(client_module, "PushClient", FakePushClient)
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"errno": 0})
            )
        ) as http:
            client = authenticated_client(http)
            FakePushClient.events = [map_event(info)]
            assert await client.get_rooms(DEVICE, timeout=1) == []
            FakePushClient.events = [map_event(info)]
            grid = await client.get_occupancy_grid(DEVICE, timeout=1)
        assert grid.room_segmentation is False
        assert all(push.closed for push in FakePushClient.instances)

    run(scenario())


def test_get_occupancy_grid_timeout_closes_push(monkeypatch) -> None:
    async def scenario() -> None:
        class WaitingPushClient(FakePushClient):
            async def read_event(self):
                await asyncio.Event().wait()

        WaitingPushClient.instances = []
        monkeypatch.setattr(client_module, "PushClient", WaitingPushClient)
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"errno": 0})
            )
        ) as http:
            with pytest.raises(ApiError) as raised:
                await authenticated_client(http).get_occupancy_grid(
                    DEVICE,
                    timeout=0.01,
                )

        assert raised.value.phase == "timeout"
        assert WaitingPushClient.instances[0].closed is True

    run(scenario())


def test_get_occupancy_grid_requires_authentication() -> None:
    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"errno": 0})
            )
        ) as http:
            client = Botslab360Client(Q, T, http_client=http)
            with pytest.raises(ApiError) as raised:
                await client.get_occupancy_grid(DEVICE, timeout=1)
        assert raised.value.phase == "authentication"

    run(scenario())


@pytest.mark.parametrize(
    ("timeout", "message"),
    [
        (None, "Authentication is required before requesting rooms"),
        (0.01, "Timed out waiting for current room map"),
    ],
)
def test_room_error_messages_are_unchanged(monkeypatch, timeout, message) -> None:
    async def scenario() -> None:
        class WaitingPushClient(FakePushClient):
            async def read_event(self):
                await asyncio.Event().wait()

        WaitingPushClient.instances = []
        monkeypatch.setattr(client_module, "PushClient", WaitingPushClient)
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"errno": 0})
            )
        ) as http:
            if timeout is None:
                client = Botslab360Client(Q, T, http_client=http)
            else:
                client = authenticated_client(http)
            with pytest.raises(ApiError) as raised:
                await client.get_rooms(DEVICE, timeout=timeout or 1)
        assert str(raised.value) == message

    run(scenario())
