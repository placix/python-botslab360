"""Offline transport and HTTP recovery tests through the public status API."""

import asyncio
import base64
import errno
import json
import logging
import socket
from email.utils import formatdate
from unittest.mock import AsyncMock
from urllib.parse import parse_qs

import httpx
import pytest
from test_protocol import application_packet, bind_ack, synthetic_event
from test_status import SID, Q, T, login_response, run

import botslab360.client as client_module
from botslab360 import ApiError, Botslab360Client

PRIVATE_CONTEXT = "synthetic private transport context"


class StatusTransport:
    """Exercise the real push registration and HTTP status paths with fake peers."""

    def __init__(self, plan):
        self.plan = iter(plan)
        self.next_response = None
        self.connections = 0
        self.streams = []
        self.closed = []
        self.posts = []

    async def open(self, *args):
        assert len(self.closed) == len(self.streams)
        self.connections += 1
        self.next_response = next(self.plan)
        if isinstance(self.next_response, (OSError, asyncio.TimeoutError)):
            raise self.next_response
        reader = asyncio.StreamReader()
        self.streams.append(reader)
        transport = self

        class Writer:
            def write(self, data):
                if data[2:4] == b"\x00\x02":
                    reader.feed_data(bind_ack())

            async def drain(self):
                pass

            def close(self):
                transport.closed.append(reader)

            async def wait_closed(self):
                pass

        return reader, Writer()

    def http(self, request):
        if request.url.path == "/common/user/login":
            return login_response()
        form = parse_qs(request.content.decode())
        self.posts.append(form["infoType"][0])
        response = self.next_response
        if isinstance(response, int):
            return httpx.Response(response)
        if isinstance(response, tuple):
            code, retry_after = response
            return httpx.Response(code, headers={"Retry-After": retry_after})
        if isinstance(response, httpx.RequestError):
            try:
                raise OSError(errno.ENETUNREACH, PRIVATE_CONTEXT)
            except OSError as cause:
                raise response from cause

        if response == "reader_reset":
            self.streams[-1].set_exception(
                ConnectionResetError(errno.ECONNRESET, PRIVATE_CONTEXT)
            )
            return httpx.Response(200, json={"errno": 0})

        event = dict(synthetic_event(), sn="robot", taskid=form["taskid"][0])
        payload = base64.b64encode(json.dumps(event).encode()).decode()
        packet, _ = application_packet({"encrypt": 0, "data": payload})
        self.streams[-1].feed_data(packet)
        return httpx.Response(200, json={"errno": 0})


@pytest.mark.parametrize(
    ("failure", "reason", "metadata"),
    [
        *[
            (OSError(code, PRIVATE_CONTEXT), "network_error", f"os_errno={code}")
            for code in (
                errno.EHOSTUNREACH,
                errno.ENETUNREACH,
                errno.ECONNREFUSED,
                errno.ECONNRESET,
            )
        ],
        (asyncio.TimeoutError(PRIVATE_CONTEXT), "connect_timeout", "phase=transport"),
        (
            socket.gaierror(socket.EAI_AGAIN, PRIVATE_CONTEXT),
            "dns_temporary",
            "gaierror",
        ),
        (
            httpx.ConnectError(PRIVATE_CONTEXT),
            "network_error",
            "ConnectError -> OSError",
        ),
        (httpx.ConnectTimeout(PRIVATE_CONTEXT), "connect_timeout", "ConnectTimeout"),
        ("reader_reset", "network_error", f"os_errno={errno.ECONNRESET}"),
        (502, "http_server_error", "http_status=502"),
        (503, "http_server_error", "http_status=503"),
        (504, "http_server_error", "http_status=504"),
    ],
)
def test_status_retries_transient_network_or_http_failure(
    monkeypatch, caplog, failure, reason, metadata
):
    async def scenario():
        transport = StatusTransport([failure, None])
        monkeypatch.setattr(client_module.asyncio, "open_connection", transport.open)
        backoff = AsyncMock()

        async def sleep(delay):
            if delay in (1.0, 2.0):
                await backoff(delay)
            else:
                await asyncio.Future()

        monkeypatch.setattr(client_module.asyncio, "sleep", sleep)
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(transport.http)
        ) as http:
            client = Botslab360Client(Q, T, http_client=http, push_port=1234)
            await client.authenticate()
            assert (await client.get_status("robot", total_timeout=125)).battery == 85

        assert transport.connections == 2
        assert transport.closed == transport.streams
        assert len(transport.posts) == (
            1 if isinstance(failure, (OSError, asyncio.TimeoutError)) else 2
        )
        assert backoff.await_args_list[0].args == (
            (1.0,) if isinstance(failure, int) else (2.0,)
        )

    with caplog.at_level(logging.DEBUG, logger="botslab360.client"):
        run(scenario())
    assert f"reason={reason}" in caplog.text
    assert metadata in caplog.text
    assert "attempt=2 result=succeeded" in caplog.text
    assert all(
        record.levelno == logging.DEBUG
        for record in caplog.records
        if record.name == "botslab360.client"
    )
    for secret in (PRIVATE_CONTEXT, Q, T, SID):
        assert secret not in caplog.text


@pytest.mark.parametrize(
    ("plan", "backoffs", "expected_status"),
    [
        ([OSError(errno.EHOSTUNREACH, PRIVATE_CONTEXT)] * 3, [2.0, 5.0], None),
        ([502, 504, 503], [1.0, 3.0], 503),
        ([OSError(errno.EHOSTUNREACH, PRIVATE_CONTEXT), 502, 504], [2.0, 3.0], 504),
        (
            [503, socket.gaierror(socket.EAI_AGAIN, PRIVATE_CONTEXT), 502],
            [1.0, 5.0],
            502,
        ),
        ([(429, "2"), (429, "2")], [2.0], 429),
    ],
)
def test_status_retry_attempts_are_shared_across_failure_types(
    monkeypatch, caplog, plan, backoffs, expected_status
):
    async def scenario():
        transport = StatusTransport(plan)
        monkeypatch.setattr(client_module.asyncio, "open_connection", transport.open)
        delays = []
        loop = asyncio.get_running_loop()
        monotonic = loop.time
        monkeypatch.setattr(loop, "time", lambda: monotonic() + sum(delays))

        async def sleep(delay):
            if delay in (1.0, 2.0, 3.0, 5.0):
                delays.append(delay)
            else:
                await asyncio.Future()

        monkeypatch.setattr(client_module.asyncio, "sleep", sleep)
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(transport.http)
        ) as http:
            client = Botslab360Client(Q, T, http_client=http, push_port=1234)
            await client.authenticate()
            with pytest.raises(ApiError) as raised:
                await client.get_status("robot", total_timeout=125)

        assert raised.value.status_code == expected_status
        assert transport.connections == len(plan)
        assert transport.closed == transport.streams
        assert delays == backoffs

    with caplog.at_level(logging.DEBUG, logger="botslab360.client"):
        run(scenario())
    assert "skip_reason=attempt_limit" in caplog.text


@pytest.mark.parametrize(
    ("response", "budget", "delay", "skip_reason"),
    [
        ((429, "4"), 125.0, 4.0, None),
        ((429, formatdate(1_800_000_006, usegmt=True)), 125.0, 6.0, None),
        ((429, "Fri Jan 15 08:00:06 2027"), 125.0, 6.0, None),
        (
            (429, "Fri, 15 Jan 2027 08:00:06"),
            125.0,
            None,
            "missing_or_invalid_retry_after",
        ),
        ((429, "0"), 125.0, 1.0, None),
        ((503, "7"), 125.0, 7.0, None),
        ((429, "780"), 125.0, None, "budget"),
        ((503, "123456789012345"), 125.0, None, "budget"),
        ((429, PRIVATE_CONTEXT), 125.0, None, "missing_or_invalid_retry_after"),
        (429, 125.0, None, "missing_or_invalid_retry_after"),
        (502, 75.5, None, "budget"),
        (500, 125.0, None, "permanent"),
        (401, 125.0, None, "permanent"),
        (403, 125.0, None, "permanent"),
        (404, 125.0, None, "permanent"),
        (socket.gaierror(socket.EAI_NONAME, PRIVATE_CONTEXT), 125.0, None, "permanent"),
        (OSError(errno.EACCES, PRIVATE_CONTEXT), 125.0, None, "permanent"),
        (httpx.RemoteProtocolError(PRIVATE_CONTEXT), 125.0, None, "permanent"),
    ],
)
def test_status_retry_after_budget_and_permanent_failures(
    monkeypatch, caplog, response, budget, delay, skip_reason
):
    async def scenario():
        transport = StatusTransport([response, None])
        monkeypatch.setattr(client_module.asyncio, "open_connection", transport.open)
        monkeypatch.setattr(client_module.time, "time", lambda: 1_800_000_000)
        delays = []
        loop = asyncio.get_running_loop()
        monotonic = loop.time
        monkeypatch.setattr(loop, "time", lambda: monotonic() + sum(delays))

        async def sleep(seconds):
            if seconds < 15:
                delays.append(seconds)
            else:
                await asyncio.Future()

        monkeypatch.setattr(client_module.asyncio, "sleep", sleep)
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(transport.http)
        ) as http:
            client = Botslab360Client(Q, T, http_client=http, push_port=1234)
            await client.authenticate()
            if delay is None:
                with pytest.raises(ApiError):
                    await client.get_status("robot", total_timeout=budget)
            else:
                assert (
                    await client.get_status("robot", total_timeout=budget)
                ).battery == 85

        assert delays == ([] if delay is None else [delay])
        assert transport.connections == (1 if delay is None else 2)
        assert transport.closed == transport.streams

    with caplog.at_level(logging.DEBUG, logger="botslab360.client"):
        run(scenario())
    if skip_reason is not None:
        assert f"skip_reason={skip_reason}" in caplog.text
    assert PRIVATE_CONTEXT not in caplog.text


@pytest.mark.parametrize("failure", [OSError(errno.EHOSTUNREACH, PRIVATE_CONTEXT), 502])
def test_status_cancelled_during_network_or_http_backoff(monkeypatch, failure):
    async def scenario():
        transport = StatusTransport([failure])
        monkeypatch.setattr(client_module.asyncio, "open_connection", transport.open)
        waiting = asyncio.Event()
        cancelled = asyncio.Event()

        async def sleep(seconds):
            if seconds in (1.0, 2.0):
                assert transport.closed == transport.streams
                waiting.set()
                try:
                    await asyncio.Future()
                finally:
                    cancelled.set()
            else:
                await asyncio.Future()

        monkeypatch.setattr(client_module.asyncio, "sleep", sleep)
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(transport.http)
        ) as http:
            client = Botslab360Client(Q, T, http_client=http, push_port=1234)
            await client.authenticate()
            status = asyncio.create_task(client.get_status("robot", total_timeout=125))
            await asyncio.wait_for(waiting.wait(), timeout=2)
            status.cancel()
            with pytest.raises(asyncio.CancelledError):
                await status
            assert cancelled.is_set()
        assert transport.connections == 1

    run(scenario())


@pytest.mark.parametrize("code", [429, 502, 503, 504])
def test_robot_command_is_never_replayed_on_recoverable_status_http_errors(code):
    async def scenario():
        sent = []

        def handle(request):
            if request.url.path == "/common/user/login":
                return login_response()
            sent.append(request)
            return httpx.Response(code, headers={"Retry-After": "1"})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
            client = Botslab360Client(Q, T, http_client=http)
            await client.authenticate()
            with pytest.raises(ApiError) as raised:
                await client.start_cleaning("robot")
            assert raised.value.status_code == code
        assert len(sent) == 1

    run(scenario())


def test_status_does_not_retry_if_budget_expires_during_backoff(monkeypatch):
    async def scenario():
        transport = StatusTransport([502])
        monkeypatch.setattr(client_module.asyncio, "open_connection", transport.open)
        loop = asyncio.get_running_loop()
        monotonic = loop.time
        offset = 0.0
        monkeypatch.setattr(loop, "time", lambda: monotonic() + offset)

        async def sleep(seconds):
            if seconds != 1.0:
                await asyncio.Future()
            nonlocal offset
            offset = 130.0

        monkeypatch.setattr(client_module.asyncio, "sleep", sleep)
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(transport.http)
        ) as http:
            client = Botslab360Client(Q, T, http_client=http, push_port=1234)
            await client.authenticate()
            with pytest.raises(ApiError, match="total time budget"):
                await client.get_status("robot", total_timeout=125)

        assert transport.connections == 1
        assert transport.closed == transport.streams

    run(scenario())


def test_status_without_total_timeout_does_not_retry_http_failure(monkeypatch):
    async def scenario():
        transport = StatusTransport([502])
        monkeypatch.setattr(client_module.asyncio, "open_connection", transport.open)
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(transport.http)
        ) as http:
            client = Botslab360Client(Q, T, http_client=http, push_port=1234)
            await client.authenticate()
            with pytest.raises(ApiError) as raised:
                await client.get_status("robot")
            assert raised.value.status_code == 502

        assert transport.connections == 1
        assert transport.closed == transport.streams

    run(scenario())


@pytest.mark.parametrize("code", [429, 503])
def test_retry_after_cooldown_blocks_later_status_polls_until_expiry(
    monkeypatch, caplog, code
):
    async def scenario():
        transport = StatusTransport([(code, "180"), None, None])
        monkeypatch.setattr(client_module.asyncio, "open_connection", transport.open)
        loop = asyncio.get_running_loop()
        monotonic = loop.time
        offset = 0.0
        monkeypatch.setattr(loop, "time", lambda: monotonic() + offset)
        commands = []

        def handle(request):
            if request.url.path != "/common/user/login":
                info_type = parse_qs(request.content.decode())["infoType"][0]
                if info_type != "20001":
                    commands.append(info_type)
                    return httpx.Response(200, json={"errno": 0})
            return transport.http(request)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
            client = Botslab360Client(Q, T, http_client=http, push_port=1234)
            await client.authenticate()
            with pytest.raises(ApiError) as original:
                await client.get_status("robot", total_timeout=125)
            assert original.value.phase == "http"
            assert original.value.status_code == code
            assert transport.connections == len(transport.posts) == 1
            assert transport.closed == transport.streams

            for offset in (60.0, 120.0, 179.0):
                results = await asyncio.gather(
                    client.get_status("robot", total_timeout=125),
                    client.get_status("another-robot"),
                    return_exceptions=True,
                )
                assert all(isinstance(result, ApiError) for result in results)
                assert {result.phase for result in results} == {"http-cooldown"}
                assert {result.status_code for result in results} == {code}
                assert transport.connections == len(transport.posts) == 1
                assert not client._status_recovery_tasks

            await client.start_cleaning("robot")
            assert len(commands) == 1

            other_client = Botslab360Client(Q, T, http_client=http, push_port=1234)
            await other_client.authenticate()
            assert (await other_client.get_status("robot")).battery == 85
            assert transport.connections == len(transport.posts) == 2

            offset = 180.1
            assert (await client.get_status("robot", total_timeout=125)).battery == 85
            assert transport.connections == len(transport.posts) == 3
            assert transport.closed == transport.streams

    with caplog.at_level(logging.DEBUG, logger="botslab360.client"):
        run(scenario())
    assert caplog.text.count(f"Status cooldown: http_status={code}") == 6
    assert "skip_reason=budget" in caplog.text


def test_retry_after_learned_without_budget_applies_to_budgeted_status(monkeypatch):
    async def scenario():
        transport = StatusTransport([(429, "180")])
        monkeypatch.setattr(client_module.asyncio, "open_connection", transport.open)
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(transport.http)
        ) as http:
            client = Botslab360Client(Q, T, http_client=http, push_port=1234)
            await client.authenticate()
            with pytest.raises(ApiError) as original:
                await client.get_status("robot")
            assert original.value.phase == "http"
            with pytest.raises(ApiError) as cooldown:
                await client.get_status("robot", total_timeout=125)
            assert cooldown.value.phase == "http-cooldown"
            assert transport.connections == len(transport.posts) == 1

    run(scenario())
