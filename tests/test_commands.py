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
    Device,
    InvalidSessionError,
)

QID = "1234567890"
Q = f"u=360H{QID}&n=synthetic&m=not-a-real-token"
T = "s=synthetic-session&t=1700000000&v=2.0"
SID = "synthetic-smart-sid"
DEVICE = Device(
    id="synthetic-device-1",
    name="Synthetic Robot",
    model="S9-P-test",
    online=True,
)


def run(coro):
    return asyncio.run(coro)


def login_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "errno": 0,
            "data": {"sid": SID, "pushKey": "synthetic-push-key"},
        },
    )


@pytest.mark.parametrize(
    ("method_name", "info_type", "data", "requires_task_id"),
    [
        (
            "start_cleaning",
            "21005",
            '{"mode":"smartClean","globalCleanTimes":1}',
            True,
        ),
        ("pause", "21017", '{"cmd":"pause"}', True),
        ("resume", "21017", '{"cmd":"continue"}', True),
        ("return_to_dock", "21012", '{"cmd":"start"}', True),
        ("locate", "21020", '{"ctrlCode":3010}', False),
    ],
)
def test_command_sends_verified_request(
    method_name: str,
    info_type: str,
    data: str,
    requires_task_id: bool,
) -> None:
    async def scenario() -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/common/user/login":
                return login_response()

            assert request.url == "https://q.smart.360.cn/clean/cmd/send"
            assert request.method == "POST"
            assert request.headers["content-type"] == (
                "application/x-www-form-urlencoded"
            )
            assert request.headers["accept"] == "*/*"
            assert request.headers["connection"] == "keep-alive"
            assert request.headers["user-agent"] == (
                "QihooSuperApp_NoPods/11.1.0 (iPhone; iOS 14.8; Scale/3.00)"
            )
            assert request.headers["accept-language"] == (
                "de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8"
            )
            assert request.headers["cookie"] == (f"q={Q};t={T};qid={QID};sid={SID}")

            form = parse_qs((await request.aread()).decode(), keep_blank_values=True)
            expected_fields = {
                "countryId",
                "data",
                "devType",
                "from",
                "infoType",
                "lang",
                "sn",
            }
            if requires_task_id:
                expected_fields.add("taskid")
            assert set(form) == expected_fields
            assert form["countryId"] == ["DE"]
            assert form["data"] == [data]
            assert form["devType"] == ["3"]
            assert form["from"] == ["mpc_ios"]
            assert form["infoType"] == [info_type]
            assert form["lang"] == ["de_DE"]
            assert form["sn"] == [DEVICE.id]
            if requires_task_id:
                UUID(form["taskid"][0])
            return httpx.Response(200, json={"errno": "0"})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            await client.authenticate()
            result = await getattr(client, method_name)(DEVICE)

        assert result is None

    run(scenario())


def test_command_requires_authentication() -> None:
    async def scenario() -> None:
        transport = httpx.MockTransport(
            lambda request: pytest.fail("No HTTP request expected")
        )
        async with httpx.AsyncClient(transport=transport) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            with pytest.raises(AuthenticationError) as raised:
                await client.pause(DEVICE)
            assert raised.value.phase == "authentication"

    run(scenario())


@pytest.mark.parametrize(
    ("errno", "exception_type"),
    [(102, InvalidSessionError), (103, AuthenticationError), (212, ApiError)],
)
def test_command_maps_api_errors(
    errno: int,
    exception_type: type[ApiError],
) -> None:
    async def scenario() -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/common/user/login":
                return login_response()
            return httpx.Response(200, json={"errno": errno})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            await client.authenticate()
            with pytest.raises(exception_type) as raised:
                await client.return_to_dock(DEVICE)
            assert raised.value.errno == errno
            assert raised.value.phase == "api"

    run(scenario())


def test_command_does_not_include_response_body_in_http_error() -> None:
    async def scenario() -> None:
        secret_body = "synthetic-sensitive-response"

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/common/user/login":
                return login_response()
            return httpx.Response(503, text=secret_body)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            await client.authenticate()
            with pytest.raises(ApiError) as raised:
                await client.start_cleaning(DEVICE)
            assert raised.value.phase == "http"
            assert raised.value.status_code == 503
            assert secret_body not in str(raised.value)

    run(scenario())


def test_command_refreshes_expired_session_once_and_retries() -> None:
    async def scenario() -> None:
        login_count = 0
        command_cookies: list[str] = []
        command_task_ids: list[str] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal login_count
            if request.url.path == "/common/user/login":
                login_count += 1
                return httpx.Response(
                    200,
                    json={
                        "errno": 0,
                        "data": {
                            "sid": f"synthetic-sid-{login_count}",
                            "pushKey": f"synthetic-push-key-{login_count}",
                        },
                    },
                )

            command_cookies.append(request.headers["cookie"])
            form = parse_qs((await request.aread()).decode())
            command_task_ids.append(form["taskid"][0])
            return httpx.Response(
                200,
                json={"errno": 102 if len(command_cookies) == 1 else 0},
            )

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            await client.authenticate()
            await client.pause(DEVICE)

        assert login_count == 2
        assert len(command_cookies) == 2
        assert "sid=synthetic-sid-1" in command_cookies[0]
        assert "sid=synthetic-sid-2" in command_cookies[1]
        assert command_task_ids[0] == command_task_ids[1]

    run(scenario())


def test_session_refresh_propagates_authentication_error_without_retry() -> None:
    async def scenario() -> None:
        login_count = 0
        command_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal login_count, command_count
            if request.url.path == "/common/user/login":
                login_count += 1
                if login_count == 1:
                    return login_response()
                return httpx.Response(200, json={"errno": 103})

            command_count += 1
            return httpx.Response(200, json={"errno": 102})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            await client.authenticate()
            with pytest.raises(AuthenticationError) as raised:
                await client.pause(DEVICE)

        assert raised.value.errno == 103
        assert login_count == 2
        assert command_count == 1

    run(scenario())


def test_command_does_not_refresh_for_other_api_errors() -> None:
    async def scenario() -> None:
        login_count = 0
        command_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal login_count, command_count
            if request.url.path == "/common/user/login":
                login_count += 1
                return login_response()
            command_count += 1
            return httpx.Response(200, json={"errno": 212})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            await client.authenticate()
            with pytest.raises(ApiError) as raised:
                await client.pause(DEVICE)

        assert raised.value.errno == 212
        assert login_count == 1
        assert command_count == 1

    run(scenario())
