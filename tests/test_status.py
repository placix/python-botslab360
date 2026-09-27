from __future__ import annotations

import asyncio
from urllib.parse import parse_qs
from uuid import UUID

import httpx
import pytest

import botslab360.client as client_module
from botslab360 import ApiError, AuthenticationError, Botslab360Client, RobotStatus

QID = "1234567890"
Q = f"u=360H{QID}&n=synthetic&m=not-a-real-token"
T = "s=synthetic-session&t=1700000000&v=2.0"
SID = "synthetic-smart-sid"
PUSH_KEY = "synthetic-push-key"


def run(coro):
    return asyncio.run(coro)


def login_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={"errno": 0, "data": {"sid": SID, "pushKey": PUSH_KEY}},
    )


def test_get_status_connects_push_before_sending_http_request(monkeypatch) -> None:
    async def scenario() -> None:
        events: list[str] = []
        requested_task_id: str | None = None
        expected_status = RobotStatus(
            device_id="synthetic-device-1",
            online=True,
            battery=85,
            state="charge",
            charging=True,
            fan_mode="quiet",
            cleaned_area=4200,
            cleaning_time=1800,
            error_code=0,
        )

        class FakePushClient:
            def __init__(self, sid, push_key, *, host, port):
                assert sid == SID
                assert push_key == PUSH_KEY
                assert host == "push.synthetic.invalid"
                assert port == 1234

            async def __aenter__(self):
                events.append("push-connected")
                return self

            async def __aexit__(self, *args):
                events.append("push-closed")

            async def wait_for_status(self, *, device_id, task_id, timeout):
                assert events == ["push-connected", "http-requested"]
                assert device_id == "synthetic-device-1"
                assert task_id == requested_task_id
                assert timeout == 7.5
                return expected_status

        monkeypatch.setattr(client_module, "PushClient", FakePushClient)

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal requested_task_id
            if request.url.path == "/common/user/login":
                return login_response()

            assert events == ["push-connected"]
            events.append("http-requested")
            assert request.url == "https://q.smart.360.cn/clean/cmd/send"
            assert request.method == "POST"
            assert request.headers["content-type"] == (
                "application/x-www-form-urlencoded"
            )
            assert request.headers["accept"] == "*/*"
            assert request.headers["cookie"] == (
                f"q={Q};t={T};qid={QID};sid={SID}"
            )

            form = parse_qs((await request.aread()).decode(), keep_blank_values=True)
            assert set(form) == {
                "countryId",
                "data",
                "devType",
                "from",
                "infoType",
                "lang",
                "sn",
                "taskid",
            }
            assert form["countryId"] == ["DE"]
            assert form["data"] == [""]
            assert form["devType"] == ["3"]
            assert form["from"] == ["mpc_ios"]
            assert form["infoType"] == ["20001"]
            assert form["lang"] == ["de_DE"]
            assert form["sn"] == ["synthetic-device-1"]
            requested_task_id = form["taskid"][0]
            UUID(requested_task_id)
            return httpx.Response(200, json={"errno": 0})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as http_client:
            client = Botslab360Client(
                Q,
                T,
                http_client=http_client,
                push_host="push.synthetic.invalid",
                push_port=1234,
            )
            await client.authenticate()
            status = await client.get_status("synthetic-device-1", timeout=7.5)

        assert status == expected_status
        assert events == ["push-connected", "http-requested", "push-closed"]

    run(scenario())


def test_get_status_requires_authentication() -> None:
    async def scenario() -> None:
        transport = httpx.MockTransport(lambda request: None)
        async with httpx.AsyncClient(transport=transport) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            with pytest.raises(AuthenticationError) as raised:
                await client.get_status("synthetic-device-1")
            assert raised.value.phase == "authentication"

    run(scenario())


def test_status_http_api_error_closes_push(monkeypatch) -> None:
    async def scenario() -> None:
        closed = False

        class FakePushClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                nonlocal closed
                closed = True

            async def wait_for_status(self, **kwargs):
                raise AssertionError("No push should be awaited after an API error")

        monkeypatch.setattr(client_module, "PushClient", FakePushClient)

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/common/user/login":
                return login_response()
            return httpx.Response(200, json={"errno": 102})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            await client.authenticate()
            with pytest.raises(ApiError) as raised:
                await client.get_status("synthetic-device-1")
            assert raised.value.errno == 102
            assert raised.value.phase == "api"

        assert closed is True

    run(scenario())
