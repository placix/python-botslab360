from __future__ import annotations

import asyncio
import json
from urllib.parse import parse_qs
from uuid import UUID

import httpx
import pytest

import botslab360.client as client_module
from botslab360 import ApiError, Botslab360Client, NetworkInfo
from botslab360.protocol import parse_network_info_event

QID = "1234567890"
Q = f"u=360H{QID}&n=synthetic&m=not-a-real-token"
T = "s=synthetic-session&t=1700000000&v=2.0"
SID = "synthetic-smart-sid"
PUSH_KEY = "synthetic-push-key"


def _event(
    payload: object,
    *,
    device_id: str = "synthetic-device",
    task_id: str = "synthetic-task",
    info_type: str = "21019",
    event: int = 10,
) -> dict[str, object]:
    return {
        "event": event,
        "sn": device_id,
        "taskid": task_id,
        "data": json.dumps({"infoType": info_type, "data": payload}),
    }


def test_parse_network_info_response_and_normalize_mac() -> None:
    result = parse_network_info_event(
        _event(
            json.dumps(
                {
                    "staIp": "192.168.1.176",
                    "staMac": "B0-59-47-C1-2E-C1",
                    "staId": "Private SSID",
                    "staSignal": -51,
                    "apId": "robot-ap",
                    "apIp": "192.168.10.1",
                    "compileVer": 123,
                    "mcuVer": "456",
                    "rssi": -52,
                }
            )
        ),
        device_id="synthetic-device",
        task_id="synthetic-task",
    )

    assert result == NetworkInfo(
        station_ip="192.168.1.176",
        station_mac="b0:59:47:c1:2e:c1",
        station_ssid="Private SSID",
        station_signal=-51,
        ap_id="robot-ap",
        ap_ip="192.168.10.1",
        compile_version=123,
        mcu_version="456",
        rssi=-52,
    )


def test_parse_network_info_allows_missing_optional_fields() -> None:
    assert parse_network_info_event(
        _event({}),
        device_id="synthetic-device",
        task_id="synthetic-task",
    ) == NetworkInfo(None, None, None, None)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("staIp", "not-an-ip"),
        ("staMac", "not-a-mac"),
        ("staId", 123),
        ("staSignal", "strong"),
        ("compileVer", True),
    ],
)
def test_parse_network_info_rejects_malformed_optional_values(field, value) -> None:
    with pytest.raises(ApiError) as raised:
        parse_network_info_event(
            _event({field: value}),
            device_id="synthetic-device",
            task_id="synthetic-task",
        )

    assert raised.value.phase == "protocol"


def test_parse_network_info_requires_matching_correlation() -> None:
    payload = {"staIp": "192.168.1.176"}
    assert (
        parse_network_info_event(
            _event(payload, task_id="other"),
            device_id="synthetic-device",
            task_id="synthetic-task",
        )
        is None
    )
    assert (
        parse_network_info_event(
            _event(payload, info_type="20001"),
            device_id="synthetic-device",
            task_id="synthetic-task",
        )
        is None
    )
    assert (
        parse_network_info_event(
            _event(payload, event=4),
            device_id="synthetic-device",
            task_id="synthetic-task",
        )
        is None
    )


def test_get_network_info_posts_21019_and_waits_for_push(monkeypatch) -> None:
    async def scenario() -> None:
        events: list[str] = []
        expected = NetworkInfo(
            "192.168.1.176",
            "b0:59:47:c1:2e:c1",
            None,
            -50,
        )

        class FakePushClient:
            def __init__(self, sid, push_key, **kwargs):
                assert sid == SID
                assert push_key == PUSH_KEY

            async def __aenter__(self):
                events.append("push-connected")
                return self

            async def __aexit__(self, *args):
                events.append("push-closed")

            async def wait_for_network_info(self, *, device_id, task_id, timeout):
                assert events == ["push-connected", "http-requested"]
                assert device_id == "synthetic-device"
                UUID(task_id)
                assert timeout == 7.5
                return expected

        monkeypatch.setattr(client_module, "PushClient", FakePushClient)

        async def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/common/user/login":
                return httpx.Response(
                    200,
                    json={"errno": 0, "data": {"sid": SID, "pushKey": PUSH_KEY}},
                )
            events.append("http-requested")
            form = parse_qs((await request.aread()).decode(), keep_blank_values=True)
            assert request.url.path == "/clean/cmd/send"
            assert form["infoType"] == ["21019"]
            assert form["data"] == [""]
            assert form["sn"] == ["synthetic-device"]
            UUID(form["taskid"][0])
            return httpx.Response(200, json={"errno": 0})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            await client.authenticate()
            result = await client.get_network_info(
                "synthetic-device",
                timeout=7.5,
            )

        assert result == expected
        assert events == ["push-connected", "http-requested", "push-closed"]

    asyncio.run(scenario())


def test_wait_for_network_info_timeout_is_api_error() -> None:
    async def scenario() -> None:
        from botslab360.protocol import PushClient

        class FakePush(PushClient):
            def __init__(self) -> None:
                self._reader = object()
                self._writer = object()

            async def read_event(self):
                await asyncio.Future()

        with pytest.raises(ApiError) as raised:
            await FakePush().wait_for_network_info(
                device_id="synthetic-device",
                task_id="synthetic-task",
                timeout=0.001,
            )

        assert raised.value.phase == "timeout"

    asyncio.run(scenario())
