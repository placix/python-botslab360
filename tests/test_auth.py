from __future__ import annotations

import asyncio
import hashlib
import json
from urllib.parse import parse_qs
from uuid import UUID

import httpx
import pytest

from botslab360 import (
    ApiError,
    AuthenticationError,
    Botslab360Client,
    InvalidSessionError,
    SmartSession,
    credentials_from_tokens,
    derive_qid,
)

QID = "1234567890"
Q_RAW = f"u=360H{QID}&n=synthetic&m=not-a-real-token"
T_RAW = "s=synthetic-session&t=1700000000&v=2.0"
Q_ENCODED = f"u%3D360H{QID}%26n%3Dsynthetic%26m%3Dnot-a-real-token"
T_ENCODED = "s%3Dsynthetic-session%26t%3D1700000000%26v%3D2.0"


def run(coro):
    return asyncio.run(coro)


def test_client_exposes_stable_account_fingerprint_without_qid() -> None:
    async def scenario() -> None:
        transport = httpx.MockTransport(
            lambda request: pytest.fail("No HTTP request expected")
        )
        async with httpx.AsyncClient(transport=transport) as http_client:
            first = Botslab360Client(Q_RAW, T_RAW, http_client=http_client)
            second = Botslab360Client(Q_ENCODED, T_ENCODED, http_client=http_client)

        expected = hashlib.sha256(f"botslab360:{QID}".encode()).hexdigest()
        assert first.account_fingerprint == expected
        assert second.account_fingerprint == expected
        assert QID not in first.account_fingerprint

    run(scenario())


def test_derive_qid_from_raw_and_url_encoded_q() -> None:
    assert derive_qid(Q_RAW) == QID
    assert derive_qid(Q_ENCODED) == QID
    assert derive_qid(f"Q={Q_ENCODED}") == QID


def test_derive_qid_accepts_numeric_u_variant() -> None:
    assert derive_qid("u=987654321") == "987654321"


@pytest.mark.parametrize("q", ["", "n=no-user-field", "u=360Hnot-numeric"])
def test_derive_qid_rejects_unknown_q_format(q: str) -> None:
    with pytest.raises(AuthenticationError):
        derive_qid(q)


def test_credentials_and_session_repr_redact_all_sensitive_values() -> None:
    credentials = credentials_from_tokens(Q_RAW, T_RAW)
    session = SmartSession(qid=QID, sid="synthetic-sid", push_key="synthetic-key")

    credentials_repr = repr(credentials)
    session_repr = repr(session)
    for secret in (Q_RAW, T_RAW, QID, "synthetic-sid", "synthetic-key"):
        assert secret not in credentials_repr
        assert secret not in session_repr


def test_authenticate_sends_poc_request_and_parses_string_errno() -> None:
    async def scenario() -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            assert request.url == "https://q.smart.360.cn/common/user/login"
            assert request.headers["user-agent"] == "qhsa-iphone-11.1.0"
            assert request.headers["accept"] == "*/*"
            assert request.headers["content-type"] == "application/x-www-form-urlencoded"
            assert request.headers["connection"] == "keep-alive"
            assert request.headers["accept-language"] == (
                "de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8"
            )

            cookie = request.headers["cookie"]
            assert cookie == f"q={Q_RAW};t={T_RAW};qid={QID}"
            assert [part.partition("=")[0] for part in cookie.split(";")] == [
                "q",
                "t",
                "qid",
            ]

            form = parse_qs((await request.aread()).decode(), keep_blank_values=True)
            assert set(form) == {"clientInfo", "lang", "phoneNum", "taskid"}
            assert form["lang"] == ["de_DE"]
            assert form["phoneNum"] == [""]
            UUID(form["taskid"][0])
            assert json.loads(form["clientInfo"][0]) == {
                "release": "appstore",
                "brand": "iPhone",
                "model": "iPhone10,5",
                "notifyId": (
                    "aa0ad645269de676a5ee6a728ba13b777"
                    "ed3d4aa4d0e08a578097fbe78768b02"
                ),
                "lang": "de_DE",
                "imei": "f3bc82b802bd91a51d0dcc6499efeba3",
            }
            return httpx.Response(
                200,
                json={
                    "errno": "0",
                    "errmsg": "ok",
                    "data": {
                        "sid": "synthetic-smart-sid",
                        "pushKey": "synthetic-push-key",
                    },
                },
            )

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as http_client:
            client = Botslab360Client(
                Q_ENCODED,
                T_ENCODED,
                http_client=http_client,
            )
            session = await client.authenticate()

        assert session.qid == QID
        assert session.sid == "synthetic-smart-sid"
        assert session.push_key == "synthetic-push-key"

    run(scenario())


@pytest.mark.parametrize(
    ("errno", "exception_type"),
    [(102, InvalidSessionError), ("103", AuthenticationError), (999, ApiError)],
)
def test_errno_mapping(errno: object, exception_type: type[ApiError]) -> None:
    async def scenario() -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"errno": errno, "errmsg": "synthetic error"})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = Botslab360Client(Q_RAW, T_RAW, http_client=http_client)
            with pytest.raises(exception_type) as raised:
                await client.authenticate()
            assert raised.value.errno == int(errno)

    run(scenario())


@pytest.mark.parametrize("errno", [None, True, 1.5, "not-a-number"])
def test_invalid_errno_is_rejected(errno: object) -> None:
    async def scenario() -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"errno": errno})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = Botslab360Client(Q_RAW, T_RAW, http_client=http_client)
            with pytest.raises(ApiError, match="invalid errno"):
                await client.authenticate()

    run(scenario())


def test_nonzero_error_code_takes_precedence_over_errno() -> None:
    async def scenario() -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"errno": 0, "errorCode": "103"})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = Botslab360Client(Q_RAW, T_RAW, http_client=http_client)
            with pytest.raises(AuthenticationError) as raised:
                await client.authenticate()
            assert raised.value.errno == 103

    run(scenario())


@pytest.mark.parametrize(
    "data",
    [None, {}, {"sid": "synthetic-smart-sid"}, {"pushKey": "synthetic-push-key"}],
)
def test_success_response_requires_sid_and_push_key(data: object) -> None:
    async def scenario() -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"errno": 0, "data": data})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = Botslab360Client(Q_RAW, T_RAW, http_client=http_client)
            with pytest.raises(ApiError):
                await client.authenticate()

    run(scenario())


def test_http_error_does_not_include_response_body() -> None:
    async def scenario() -> None:
        secret_body = "synthetic-secret-that-must-not-leak"

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(503, text=secret_body)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
            client = Botslab360Client(Q_RAW, T_RAW, http_client=http_client)
            with pytest.raises(ApiError) as raised:
                await client.authenticate()
            assert raised.value.status_code == 503
            assert secret_body not in str(raised.value)

    run(scenario())
