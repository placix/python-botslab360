from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path
from urllib.parse import parse_qs

import httpx

from botslab360 import Botslab360Client
from botslab360.models import SmartSession

QID = "1234567890"
Q = f"u=360H{QID}&n=synthetic&m=not-a-real-token"
T = "s=synthetic-session&t=1700000000&v=2.0"


def _diagnostic_module():
    path = Path(__file__).parents[1] / "diagnostics" / "capture_s9p_rooms.py"
    spec = importlib.util.spec_from_file_location("capture_s9p_rooms", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _smart_area() -> dict:
    return {
        "activeIds": [],
        "autoOrder": False,
        "cleanTimes": 2,
        "isAttrOn": 1,
        "mapId": 1,
        "value": [
            {"id": 5, "name": "RW50cnk=", "vertexs": [[1, 2]]},
            {"id": 6, "name": "Q2xvc2V0", "vertexs": [[3, 4]]},
        ],
    }


def test_prepare_room_request_keeps_every_room() -> None:
    module = _diagnostic_module()
    smart_area = module._gson_sweep_area_list(_smart_area())

    prepared = module._prepare_room_request(
        clean_id="synthetic-clean-id",
        map_id=1,
        smart_area=smart_area,
        room_id=6,
    )

    area_setting = prepared["form"]["areaSetting"]
    assert prepared["roomName"] == "Closet"
    assert area_setting["activeIds"] == [6]
    assert [room["id"] for room in area_setting["value"]] == [5, 6]
    assert json.loads(prepared["form"]["areaSettingJson"]) == area_setting
    assert smart_area["activeIds"] == []


def test_room_post_uses_exact_form_fields() -> None:
    module = _diagnostic_module()

    async def scenario() -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/clean/record/setAreaAndCleaning"
            assert request.method == "POST"
            assert request.headers["content-type"] == (
                "application/x-www-form-urlencoded"
            )
            form = parse_qs((await request.aread()).decode())
            assert set(form) == {"sn", "cleanId", "areaSetting", "taskid"}
            assert form["sn"] == ["synthetic-device"]
            assert form["cleanId"] == ["synthetic-clean-id"]
            assert form["areaSetting"] == ['{"activeIds":[6]}']
            assert form["taskid"] == ["synthetic-task-id"]
            return httpx.Response(200, json={"errno": 0})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            client._session = SmartSession(
                qid=QID,
                sid="synthetic-sid",
                push_key="synthetic-push-key",
            )
            result = await module._post_room_cleaning(
                client,
                device_id="synthetic-device",
                clean_id="synthetic-clean-id",
                area_setting_json='{"activeIds":[6]}',
                task_id="synthetic-task-id",
            )

        assert result == {
            "httpStatus": 200,
            "errno": 0,
            "responseErrno": 0,
            "errorCode": None,
            "accepted": True,
        }

    asyncio.run(scenario())


def test_wrong_confirmation_never_sends(monkeypatch) -> None:
    module = _diagnostic_module()
    prepared = module._prepare_room_request(
        clean_id="synthetic-clean-id",
        map_id=1,
        smart_area=module._gson_sweep_area_list(_smart_area()),
        room_id=6,
    )
    monkeypatch.setattr("builtins.input", lambda prompt: "CLEAN ROOM 5")

    result = asyncio.run(
        module._run_confirmed_room_test(
            object(),
            device_id="synthetic-device",
            prepared=prepared,
            observation_seconds=0.01,
            status_timeout=0.01,
        )
    )

    assert result == {
        "selectedRoomId": 6,
        "roomName": "Closet",
        "mapId": 1,
        "sent": False,
    }
