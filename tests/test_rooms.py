from __future__ import annotations

import asyncio
import base64
import json
from urllib.parse import parse_qs

import httpx
import pytest

import botslab360.client as client_module
from botslab360 import (
    ApiError,
    Botslab360Client,
    Device,
    InvalidSessionError,
    Room,
    SmartSession,
)
from botslab360.rooms import parse_room_map

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
            "mode": "normal",
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


def map_event() -> dict:
    return {
        "sn": DEVICE.id,
        "data": json.dumps(
            {
                "infoType": "20002",
                "data": json.dumps(map_info(), separators=(",", ":")),
            }
        ),
    }


class FakePushClient:
    events: list[dict] = []
    instances: list["FakePushClient"] = []

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
    )
    assert parsed.rooms[9].room_type is None
    assert parsed.map_id == 1
    assert parsed.clean_id == "synthetic-clean-id"


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


@pytest.mark.parametrize("room_ids", [[], [99]])
def test_clean_rooms_rejects_invalid_selection_before_cleaning_post(
    monkeypatch,
    room_ids: list[int],
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
            with pytest.raises(ValueError):
                await authenticated_client(http_client).clean_rooms(
                    DEVICE,
                    room_ids,
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
