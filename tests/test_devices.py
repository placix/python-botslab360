from __future__ import annotations

import asyncio
from urllib.parse import parse_qs
from uuid import UUID

import httpx
import pytest

from botslab360 import (
    ApiError,
    AuthenticationError,
    Botslab360Client,
    InvalidSessionError,
)

QID = "1234567890"
Q = f"u=360H{QID}&n=synthetic&m=not-a-real-token"
T = "s=synthetic-session&t=1700000000&v=2.0"
SID = "synthetic-smart-sid"


def run(coro):
    return asyncio.run(coro)


def login_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "errno": 0,
            "data": {
                "sid": SID,
                "pushKey": "synthetic-push-key",
            },
        },
    )


def test_get_devices_sends_expected_request_and_returns_models() -> None:
    async def scenario() -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/common/user/login":
                return login_response()

            assert request.url == "https://q.smart.360.cn/common/dev/GetList"
            assert request.method == "POST"
            assert request.headers["content-type"] == "application/x-www-form-urlencoded"
            assert request.headers["accept"] == "*/*"
            assert request.headers["connection"] == "keep-alive"
            assert request.headers["user-agent"] == (
                "QihooSuperApp_NoPods/11.1.0 (iPhone; iOS 14.8; Scale/3.00)"
            )
            assert request.headers["accept-language"] == (
                "de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8"
            )

            cookie = request.headers["cookie"]
            assert cookie == f"q={Q};t={T};qid={QID};sid={SID}"
            assert [part.partition("=")[0] for part in cookie.split(";")] == [
                "q",
                "t",
                "qid",
                "sid",
            ]

            form = parse_qs((await request.aread()).decode(), keep_blank_values=True)
            assert set(form) == {"countryId", "devType", "from", "lang", "taskid"}
            assert form["countryId"] == ["DE"]
            assert form["devType"] == ["3"]
            assert form["from"] == ["mpc_ios"]
            assert form["lang"] == ["de_DE"]
            UUID(form["taskid"][0])

            return httpx.Response(
                200,
                json={
                    "errno": "0",
                    "data": {
                        "list": [
                            {
                                "sn": "synthetic-device-1",
                                "title": "Living Room",
                                "hardware": "S9",
                                "online": 1,
                            },
                            {
                                "sn": "synthetic-device-2",
                                "title": "Upstairs",
                                "hardware": "X90",
                                "online": 0,
                            },
                        ]
                    },
                },
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            await client.authenticate()
            devices = await client.get_devices()

        assert [(device.name, device.model, device.online) for device in devices] == [
            ("Living Room", "S9", True),
            ("Upstairs", "X90", False),
        ]
        assert devices[0].id == "synthetic-device-1"

    run(scenario())


def test_get_devices_requires_authentication() -> None:
    async def scenario() -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError("No request expected")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            with pytest.raises(AuthenticationError) as raised:
                await client.get_devices()
            assert raised.value.phase == "authentication"

    run(scenario())


@pytest.mark.parametrize(
    ("errno", "exception_type"),
    [(102, InvalidSessionError), (103, AuthenticationError), (999, ApiError)],
)
def test_get_devices_maps_api_errors(
    errno: int,
    exception_type: type[ApiError],
) -> None:
    async def scenario() -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/common/user/login":
                return login_response()
            return httpx.Response(200, json={"errno": errno})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            await client.authenticate()
            with pytest.raises(exception_type) as raised:
                await client.get_devices()
            assert raised.value.errno == errno
            assert raised.value.phase == "api"

    run(scenario())


@pytest.mark.parametrize(
    "data",
    [None, {"list": "not-a-list"}, {"list": [{"title": "No id"}]}],
)
def test_get_devices_validates_response(data: object) -> None:
    async def scenario() -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/common/user/login":
                return login_response()
            return httpx.Response(200, json={"errno": 0, "data": data})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            await client.authenticate()
            with pytest.raises(ApiError) as raised:
                await client.get_devices()
            assert raised.value.phase == "response-validation"

    run(scenario())


def test_get_devices_treats_missing_list_as_empty() -> None:
    async def scenario() -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/common/user/login":
                return login_response()
            return httpx.Response(200, json={"errno": 0, "data": {}})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            await client.authenticate()
            assert await client.get_devices() == []

    run(scenario())


def test_get_devices_maps_http_error_without_response_body() -> None:
    async def scenario() -> None:
        secret_body = "synthetic-response-body"

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/common/user/login":
                return login_response()
            return httpx.Response(503, text=secret_body)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            await client.authenticate()
            with pytest.raises(ApiError) as raised:
                await client.get_devices()
            assert raised.value.phase == "http"
            assert raised.value.status_code == 503
            assert secret_body not in str(raised.value)

    run(scenario())
