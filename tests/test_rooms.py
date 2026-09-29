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
    ROOM_CLEAN_TIMES,
    ApiError,
    Botslab360Client,
    Device,
    InvalidSessionError,
    Room,
    RoomCleaningMode,
    RoomCleaningSettings,
    RoomFanMode,
    RoomWaterLevel,
    SmartSession,
)
from botslab360.rooms import (
    parse_room_map,
    prepare_area_setting,
)

QID = "1234567890"
Q = f"u=360H{QID}&n=synthetic&m=not-a-real-token"
T = "s=synthetic-session&t=1700000000&v=2.0"
DEVICE = Device(
    id="synthetic-device",
    name="Synthetic Robot",
    model="S9-P-test",
    online=True,
)


def run(coro):
    return asyncio.run(coro)


def encoded_name(name: str) -> str:
    return base64.b64encode(name.encode()).decode().rstrip("=")


def smart_area() -> dict:
    rooms = []
    for room_id in range(10):
        room = {
            "active": True,
            "cacheType": "room",
            "cleanTimes": room_id + 1,
            "forbidType": "none",
            "id": room_id,
            "material": 0,
            "mode": 2,
            "name": encoded_name(f"Room {room_id}"),
            "radius": 0,
            "relativeRoom": -1,
            "tag": f"tag-{room_id}",
            "vertexs": [[room_id, 0], [room_id, 1]],
            "waterPump": 2,
            "windMode": "max",
        }
        if room_id != 9:
            room["roomType"] = "living"
        rooms.append(room)
    return {
        "activeIds": [6, 1],
        "areaCleanActiveId": 6,
        "autoOrder": True,
        "cleanTimes": 2,
        "isAttrOn": 1,
        "mapId": 1,
        "value": rooms,
    }


def map_info() -> dict:
    return {
        "mapId": 1,
        "cleanId": "synthetic-clean-id",
        "smartArea": smart_area(),
    }


def map_event(payload: dict | None = None) -> dict:
    map_payload = payload if payload is not None else map_info()
    return {
        "sn": DEVICE.id,
        "data": json.dumps(
            {
                "infoType": "20002",
                "data": json.dumps(map_payload, separators=(",", ":")),
            }
        ),
    }


class FakePushClient:
    events: ClassVar[list[dict]] = []
    instances: ClassVar[list[FakePushClient]] = []

    def __init__(self, sid, push_key, **kwargs):
        self.sid = sid
        self.push_key = push_key
        self.kwargs = kwargs
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


def test_map_info_parses_ten_public_rooms() -> None:
    parsed = parse_room_map(map_info())

    assert len(parsed.rooms) == 10
    assert parsed.rooms[1] == Room(
        id=1,
        name="Room 1",
        room_type="living",
        clean_times=2,
        fan_mode="max",
        water_pump=2,
        mode=2,
    )
    assert parsed.rooms[9].room_type is None
    assert parsed.map_id == 1
    assert parsed.clean_id == "synthetic-clean-id"


def test_room_vertices_parse_polygon_and_preserve_order() -> None:
    payload = map_info()
    payload["smartArea"]["value"][1]["vertexs"] = [
        [100, 200],
        [500, 200],
        [450, 600],
        [120, 550],
    ]

    room = parse_room_map(payload).rooms[1]

    assert room.vertices == (
        (100, 200),
        (500, 200),
        (450, 600),
        (120, 550),
    )


def test_room_vertices_accept_triangle_without_appending_closing_point() -> None:
    payload = map_info()
    payload["smartArea"]["value"][0]["vertexs"] = [[0, 0], [8, 0], [4, 6]]

    assert parse_room_map(payload).rooms[0].vertices == ((0, 0), (8, 0), (4, 6))


@pytest.mark.parametrize(
    "vertices",
    [
        None,
        [],
        [[0, 0], [1, 1]],
        [[0, 0], [1, 1], [2]],
        [[0, 0], [1, 1], [2, 2, 3]],
        [[0, 0], [1, 1], [2, "3"]],
        [[0, 0], [1, 1], [True, 3]],
        [[0, 0], [1, 1], [2, False]],
    ],
)
def test_room_vertices_ignore_missing_or_malformed_polygons(vertices: object) -> None:
    payload = map_info()
    area = payload["smartArea"]["value"][0]
    if vertices is None:
        area.pop("vertexs", None)
    else:
        area["vertexs"] = vertices

    assert parse_room_map(payload).rooms[0].vertices is None


def test_room_vertices_do_not_affect_base64_name_decoding() -> None:
    payload = map_info()
    payload["smartArea"]["value"][0]["vertexs"] = [[0, 0], [2, 0], [1, 1]]

    room = parse_room_map(payload).rooms[0]

    assert room.name == "Room 0"
    assert room.vertices == ((0, 0), (2, 0), (1, 1))


def test_room_model_remains_compatible_without_vertices() -> None:
    room = Room(1, "Bad", None, 2, "max", 0)

    assert room.vertices is None
    assert room.mode is None


@pytest.mark.parametrize("mode", [1, 2, 3, 99])
def test_room_mode_parsing_preserves_supported_and_unknown_values(mode: int) -> None:
    payload = map_info()
    payload["smartArea"]["value"][1]["mode"] = mode

    assert parse_room_map(payload).rooms[1].mode == mode


def test_room_mode_parsing_ignores_malformed_values() -> None:
    payload = map_info()
    payload["smartArea"]["value"][1]["mode"] = "future-mode"

    assert parse_room_map(payload).rooms[1].mode is None


def test_public_room_setting_choices_match_android_values() -> None:
    assert ROOM_CLEAN_TIMES == (1, 2)
    assert [mode.value for mode in RoomFanMode] == [
        "quiet",
        "auto",
        "strong",
        "max",
    ]
    assert [level.value for level in RoomWaterLevel] == [1, 2, 3]
    assert [mode.value for mode in RoomCleaningMode] == [1, 2, 3]


@pytest.mark.parametrize("mode", [1, 2, 3])
def test_prepare_area_setting_accepts_supported_cleaning_modes(mode: int) -> None:
    room_map = parse_room_map(map_info())

    result = json.loads(
        prepare_area_setting(room_map, [1], {1: RoomCleaningSettings(mode=mode)})
    )

    assert result["value"][1]["mode"] == mode
    assert result["value"][0] == room_map.area_setting["value"][0]


@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        (RoomCleaningSettings(clean_times=1), {"cleanTimes": 1}),
        (RoomCleaningSettings(fan_mode="quiet"), {"windMode": "quiet"}),
        (RoomCleaningSettings(water_pump=3), {"waterPump": 3}),
        (RoomCleaningSettings(mode=2), {"mode": 2}),
        (
            RoomCleaningSettings(
                clean_times=1,
                fan_mode=RoomFanMode.AUTO,
                water_pump=RoomWaterLevel.LOW,
                mode=RoomCleaningMode.SWEEP_AND_MOP,
            ),
            {
                "cleanTimes": 1,
                "windMode": "auto",
                "waterPump": 1,
                "mode": 1,
            },
        ),
    ],
)
def test_prepare_area_setting_applies_only_explicit_overrides(
    settings: RoomCleaningSettings,
    expected: dict[str, object],
) -> None:
    room_map = parse_room_map(map_info())
    original = room_map.area_setting["value"][1]

    result = json.loads(prepare_area_setting(room_map, [1], {1: settings}))
    updated = result["value"][1]

    assert result["activeIds"] == [1]
    assert [area["id"] for area in result["value"]] == list(range(10))
    for key, value in expected.items():
        assert updated[key] == value
    for key, value in original.items():
        if key not in expected:
            assert updated[key] == value
    assert result["value"][0] == room_map.area_setting["value"][0]


def test_prepare_area_setting_supports_different_selected_room_settings() -> None:
    room_map = parse_room_map(map_info())

    result = json.loads(
        prepare_area_setting(
            room_map,
            [6, 1],
            {
                1: RoomCleaningSettings(clean_times=1, fan_mode="strong"),
                6: RoomCleaningSettings(water_pump=3),
            },
        )
    )

    assert result["activeIds"] == [6, 1]
    assert [area["id"] for area in result["value"]] == list(range(10))
    assert result["value"][1]["cleanTimes"] == 1
    assert result["value"][1]["windMode"] == "strong"
    assert result["value"][1]["waterPump"] == 2
    assert result["value"][6]["cleanTimes"] == 7
    assert result["value"][6]["windMode"] == "max"
    assert result["value"][6]["waterPump"] == 3
    assert result["value"][5] == room_map.area_setting["value"][5]


@pytest.mark.parametrize(
    ("settings", "expected_exception"),
    [
        (RoomCleaningSettings(clean_times=0), ValueError),
        (RoomCleaningSettings(clean_times=3), ValueError),
        (RoomCleaningSettings(clean_times=True), TypeError),
        (RoomCleaningSettings(clean_times="1"), TypeError),  # type: ignore[arg-type]
        (RoomCleaningSettings(fan_mode="turbo"), ValueError),
        (RoomCleaningSettings(fan_mode=1), TypeError),  # type: ignore[arg-type]
        (RoomCleaningSettings(water_pump=0), ValueError),
        (RoomCleaningSettings(water_pump=4), ValueError),
        (RoomCleaningSettings(water_pump=True), TypeError),
        (RoomCleaningSettings(water_pump="1"), TypeError),  # type: ignore[arg-type]
        (RoomCleaningSettings(mode=0), ValueError),
        (RoomCleaningSettings(mode=4), ValueError),
        (RoomCleaningSettings(mode=True), TypeError),
        (RoomCleaningSettings(mode="2"), TypeError),  # type: ignore[arg-type]
        (object(), TypeError),
    ],
)
def test_prepare_area_setting_rejects_invalid_settings(
    settings: object,
    expected_exception: type[Exception],
) -> None:
    with pytest.raises(expected_exception):
        prepare_area_setting(
            parse_room_map(map_info()),
            [1],
            {1: settings},  # type: ignore[dict-item]
        )


@pytest.mark.parametrize(
    ("room_settings", "expected_exception"),
    [
        ({6: RoomCleaningSettings(clean_times=1)}, ValueError),
        ({True: RoomCleaningSettings(clean_times=1)}, TypeError),
        ([(1, RoomCleaningSettings(clean_times=1))], TypeError),
    ],
)
def test_prepare_area_setting_rejects_invalid_settings_mapping(
    room_settings: object,
    expected_exception: type[Exception],
) -> None:
    with pytest.raises(expected_exception):
        prepare_area_setting(
            parse_room_map(map_info()),
            [1],
            room_settings,  # type: ignore[arg-type]
        )


def test_get_rooms_requests_current_composite_and_closes_push(monkeypatch) -> None:
    async def scenario() -> None:
        FakePushClient.events = [map_event()]
        FakePushClient.instances = []
        monkeypatch.setattr(client_module, "PushClient", FakePushClient)
        requests: list[dict[str, list[str]]] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            form = parse_qs((await request.aread()).decode())
            requests.append(form)
            return httpx.Response(200, json={"errno": 0})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            rooms = await authenticated_client(http_client).get_rooms(
                DEVICE,
                timeout=1,
            )

        assert len(rooms) == 10
        assert requests[0]["infoType"] == ["30000"]
        assert json.loads(requests[0]["data"][0]) == client_module.LOAD_DATA
        assert FakePushClient.instances[0].closed is True

    run(scenario())


@pytest.mark.parametrize("selected_ids", [[1], [1, 6], [1, 1, 6]])
def test_clean_rooms_sends_complete_current_area_setting(
    monkeypatch,
    selected_ids: list[int],
) -> None:
    async def scenario() -> None:
        FakePushClient.events = [map_event()]
        FakePushClient.instances = []
        monkeypatch.setattr(client_module, "PushClient", FakePushClient)
        cleaning_form: dict[str, list[str]] = {}

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal cleaning_form
            form = parse_qs((await request.aread()).decode())
            if request.url.path == "/clean/record/setAreaAndCleaning":
                assert request.headers["content-type"] == (
                    "application/x-www-form-urlencoded"
                )
                assert request.headers["user-agent"] == "okhttp/4.10.0"
                assert request.headers["cookie"] == (
                    f"q={Q};t={T};qid={QID};sid=synthetic%2Fsid%2B%3D"
                )
                cleaning_form = form
            return httpx.Response(200, json={"errno": 0})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            result = await authenticated_client(http_client).clean_rooms(
                DEVICE,
                selected_ids,
                timeout=1,
            )

        assert result is None
        assert set(cleaning_form) == {
            "sn",
            "cleanId",
            "areaSetting",
            "taskid",
            "from",
            "devType",
            "channel_id",
            "appVer",
            "lang",
            "model",
            "manufacturer",
        }
        assert cleaning_form["sn"] == [DEVICE.id]
        assert cleaning_form["cleanId"] == ["synthetic-clean-id"]
        assert cleaning_form["from"] == ["mpc_and"]
        area_setting = json.loads(cleaning_form["areaSetting"][0])
        assert area_setting["activeIds"] == list(dict.fromkeys(selected_ids))
        assert len(area_setting["value"]) == 10
        assert area_setting["value"] == parse_room_map(map_info()).area_setting["value"]
        assert smart_area()["activeIds"] == [6, 1]
        assert FakePushClient.instances[0].closed is True

    run(scenario())


def test_clean_rooms_sends_per_room_overrides_through_public_api(
    monkeypatch,
) -> None:
    async def scenario() -> None:
        FakePushClient.events = [map_event()]
        FakePushClient.instances = []
        monkeypatch.setattr(client_module, "PushClient", FakePushClient)
        cleaning_form: dict[str, list[str]] = {}

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal cleaning_form
            if request.url.path == "/clean/record/setAreaAndCleaning":
                cleaning_form = parse_qs((await request.aread()).decode())
            return httpx.Response(200, json={"errno": 0})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            await authenticated_client(http_client).clean_rooms(
                DEVICE,
                [1, 6],
                room_settings={
                    1: RoomCleaningSettings(
                        clean_times=1,
                        fan_mode="quiet",
                    ),
                    6: RoomCleaningSettings(water_pump=3),
                },
                timeout=1,
            )

        area_setting = json.loads(cleaning_form["areaSetting"][0])
        assert area_setting["activeIds"] == [1, 6]
        assert area_setting["value"][1]["cleanTimes"] == 1
        assert area_setting["value"][1]["windMode"] == "quiet"
        assert area_setting["value"][1]["waterPump"] == 2
        assert area_setting["value"][6]["cleanTimes"] == 7
        assert area_setting["value"][6]["windMode"] == "max"
        assert area_setting["value"][6]["waterPump"] == 3
        assert (
            area_setting["value"][5]
            == (parse_room_map(map_info()).area_setting["value"][5])
        )

    run(scenario())


@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        (RoomCleaningSettings(clean_times=1), {"cleanTimes": 1}),
        (RoomCleaningSettings(fan_mode="quiet"), {"windMode": "quiet"}),
        (RoomCleaningSettings(water_pump=3), {"waterPump": 3}),
        (RoomCleaningSettings(mode=2), {"mode": 2}),
        (
            RoomCleaningSettings(
                clean_times=1,
                fan_mode="strong",
                water_pump=3,
                mode=3,
            ),
            {"cleanTimes": 1, "windMode": "strong", "waterPump": 3, "mode": 3},
        ),
    ],
)
def test_clean_rooms_applies_each_settings_shape_through_public_api(
    monkeypatch,
    settings: RoomCleaningSettings,
    expected: dict[str, object],
) -> None:
    async def scenario() -> None:
        FakePushClient.events = [map_event()]
        FakePushClient.instances = []
        monkeypatch.setattr(client_module, "PushClient", FakePushClient)
        cleaning_form: dict[str, list[str]] = {}

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal cleaning_form
            if request.url.path == "/clean/record/setAreaAndCleaning":
                cleaning_form = parse_qs((await request.aread()).decode())
            return httpx.Response(200, json={"errno": 0})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            await authenticated_client(http_client).clean_rooms(
                DEVICE,
                [1],
                room_settings={1: settings},
                timeout=1,
            )

        original = parse_room_map(map_info()).area_setting
        area_setting = json.loads(cleaning_form["areaSetting"][0])
        updated = area_setting["value"][1]
        assert area_setting["activeIds"] == [1]
        for key, value in expected.items():
            assert updated[key] == value
        for key, value in original["value"][1].items():
            if key not in expected:
                assert updated[key] == value
        assert area_setting["value"][0] == original["value"][0]

    run(scenario())


def test_clean_rooms_applies_same_settings_to_multiple_rooms(monkeypatch) -> None:
    async def scenario() -> None:
        FakePushClient.events = [map_event()]
        FakePushClient.instances = []
        monkeypatch.setattr(client_module, "PushClient", FakePushClient)
        cleaning_form: dict[str, list[str]] = {}

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal cleaning_form
            if request.url.path == "/clean/record/setAreaAndCleaning":
                cleaning_form = parse_qs((await request.aread()).decode())
            return httpx.Response(200, json={"errno": 0})

        settings = RoomCleaningSettings(clean_times=2, fan_mode="auto")
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            await authenticated_client(http_client).clean_rooms(
                DEVICE,
                [1, 6],
                room_settings={1: settings, 6: settings},
                timeout=1,
            )

        area_setting = json.loads(cleaning_form["areaSetting"][0])
        assert area_setting["activeIds"] == [1, 6]
        for room_id in (1, 6):
            assert area_setting["value"][room_id]["cleanTimes"] == 2
            assert area_setting["value"][room_id]["windMode"] == "auto"

    run(scenario())


def test_clean_rooms_preserves_vendor_water_pump_zero(monkeypatch) -> None:
    async def scenario() -> None:
        payload = map_info()
        payload["smartArea"]["value"][1]["waterPump"] = 0
        FakePushClient.events = [map_event(payload)]
        FakePushClient.instances = []
        monkeypatch.setattr(client_module, "PushClient", FakePushClient)
        cleaning_form: dict[str, list[str]] = {}

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal cleaning_form
            if request.url.path == "/clean/record/setAreaAndCleaning":
                cleaning_form = parse_qs((await request.aread()).decode())
            return httpx.Response(200, json={"errno": 0})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            await authenticated_client(http_client).clean_rooms(
                DEVICE,
                [1],
                room_settings={1: RoomCleaningSettings(clean_times=1)},
                timeout=1,
            )

        area_setting = json.loads(cleaning_form["areaSetting"][0])
        assert area_setting["value"][1]["cleanTimes"] == 1
        assert area_setting["value"][1]["waterPump"] == 0

    run(scenario())


@pytest.mark.parametrize(
    ("room_ids", "room_settings", "expected_exception"),
    [
        ([1], {1: RoomCleaningSettings(clean_times=0)}, ValueError),
        ([1], {1: RoomCleaningSettings(clean_times=3)}, ValueError),
        ([1], {1: RoomCleaningSettings(clean_times=True)}, TypeError),
        ([1], {1: RoomCleaningSettings(fan_mode="turbo")}, ValueError),
        ([1], {1: RoomCleaningSettings(water_pump=0)}, ValueError),
        ([1], {1: RoomCleaningSettings(water_pump=4)}, ValueError),
        ([1], {1: RoomCleaningSettings(water_pump=True)}, TypeError),
        ([1], {1: RoomCleaningSettings(mode=0)}, ValueError),
        ([1], {1: RoomCleaningSettings(mode=4)}, ValueError),
        ([1], {1: RoomCleaningSettings(mode=True)}, TypeError),
        ([1], {1: object()}, TypeError),
        ([1], {6: RoomCleaningSettings(clean_times=1)}, ValueError),
        ([1], {True: RoomCleaningSettings(clean_times=1)}, TypeError),
        ([99], {99: RoomCleaningSettings(clean_times=1)}, ValueError),
    ],
)
def test_clean_rooms_validation_prevents_cleaning_post(
    monkeypatch,
    room_ids: list[int],
    room_settings: object,
    expected_exception: type[Exception],
) -> None:
    async def scenario() -> None:
        FakePushClient.events = [map_event()]
        FakePushClient.instances = []
        monkeypatch.setattr(client_module, "PushClient", FakePushClient)
        cleaning_posts = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal cleaning_posts
            if request.url.path == "/clean/record/setAreaAndCleaning":
                cleaning_posts += 1
            return httpx.Response(200, json={"errno": 0})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            with pytest.raises(expected_exception):
                await authenticated_client(http_client).clean_rooms(
                    DEVICE,
                    room_ids,
                    room_settings=room_settings,  # type: ignore[arg-type]
                    timeout=1,
                )

        assert cleaning_posts == 0

    run(scenario())


@pytest.mark.parametrize(
    ("room_ids", "expected_exception"),
    [
        ([], ValueError),
        ([99], ValueError),
        ([True], TypeError),
        (["1"], TypeError),
    ],
)
def test_clean_rooms_rejects_invalid_selection_before_cleaning_post(
    monkeypatch,
    room_ids: list[object],
    expected_exception: type[Exception],
) -> None:
    async def scenario() -> None:
        FakePushClient.events = [map_event()]
        FakePushClient.instances = []
        monkeypatch.setattr(client_module, "PushClient", FakePushClient)
        cleaning_posts = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal cleaning_posts
            if request.url.path == "/clean/record/setAreaAndCleaning":
                cleaning_posts += 1
            return httpx.Response(200, json={"errno": 0})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            with pytest.raises(expected_exception):
                await authenticated_client(http_client).clean_rooms(
                    DEVICE,
                    room_ids,  # type: ignore[arg-type]
                    timeout=1,
                )

        assert cleaning_posts == 0

    run(scenario())


@pytest.mark.parametrize("errno", [102, 212])
def test_clean_rooms_maps_api_errors(monkeypatch, errno: int) -> None:
    async def scenario() -> None:
        FakePushClient.events = [map_event()]
        FakePushClient.instances = []
        monkeypatch.setattr(client_module, "PushClient", FakePushClient)

        async def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/common/user/login":
                return httpx.Response(
                    200,
                    json={
                        "errno": 0,
                        "data": {
                            "sid": "refreshed-sid",
                            "pushKey": "refreshed-push-key",
                        },
                    },
                )
            if request.url.path == "/clean/record/setAreaAndCleaning":
                return httpx.Response(200, json={"errno": errno})
            return httpx.Response(200, json={"errno": 0})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            expected = InvalidSessionError if errno == 102 else ApiError
            with pytest.raises(expected) as raised:
                await authenticated_client(http_client).clean_rooms(
                    DEVICE,
                    [1],
                    timeout=1,
                )
        assert raised.value.errno == errno

    run(scenario())


def test_get_rooms_timeout_closes_push(monkeypatch) -> None:
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
        ) as http_client:
            with pytest.raises(ApiError) as raised:
                await authenticated_client(http_client).get_rooms(
                    DEVICE,
                    timeout=0.01,
                )

        assert raised.value.phase == "timeout"
        assert WaitingPushClient.instances[0].closed is True

    run(scenario())


def test_map_session_refresh_creates_new_push_client(monkeypatch) -> None:
    async def scenario() -> None:
        FakePushClient.events = [map_event()]
        FakePushClient.instances = []
        monkeypatch.setattr(client_module, "PushClient", FakePushClient)
        map_requests = 0
        logins = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal map_requests, logins
            if request.url.path == "/common/user/login":
                logins += 1
                return httpx.Response(
                    200,
                    json={
                        "errno": 0,
                        "data": {
                            "sid": "refreshed-sid",
                            "pushKey": "refreshed-push-key",
                        },
                    },
                )
            map_requests += 1
            return httpx.Response(
                200,
                json={"errno": 102 if map_requests == 1 else 0},
            )

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            rooms = await authenticated_client(http_client).get_rooms(
                DEVICE,
                timeout=1,
            )

        assert len(rooms) == 10
        assert logins == 1
        assert map_requests == 2
        assert [(push.sid, push.push_key) for push in FakePushClient.instances] == [
            ("synthetic/sid+=", "synthetic-push-key"),
            ("refreshed-sid", "refreshed-push-key"),
        ]
        assert all(push.closed for push in FakePushClient.instances)

    run(scenario())
