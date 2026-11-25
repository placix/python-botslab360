"""Offline tests for opt-in status recovery."""

import asyncio
import logging
from unittest.mock import AsyncMock
from urllib.parse import parse_qs

import httpx
import pytest
from test_protocol import synthetic_event
from test_push_profiles import make_client
from test_status import SID, Q, T, login_response, run

import botslab360.client as client_module
from botslab360 import (
    ApiError,
    AuthenticationError,
    Botslab360Client,
    InvalidSessionError,
)


def transient_error(kind):
    if kind == "http":
        error = ApiError("Robot status request failed", phase="transport")
        error.__cause__ = httpx.ReadTimeout("private HTTP context")
    else:
        error = ApiError(f"Timed out waiting for {kind}", phase="timeout")
        error.__cause__ = TimeoutError("private push context")
    return error


@pytest.mark.parametrize("kind", ["push registration", "http", "robot status"])
def test_transient_status_failure_recovers_with_fresh_task_id(
    monkeypatch, caplog, kind
):
    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: login_response())
        ) as http:
            client = Botslab360Client(Q, T, http_client=http, push_port=1234)
            await client.authenticate()
            expected = object()
            attempt = AsyncMock(side_effect=[transient_error(kind), expected])
            monkeypatch.setattr(client, "_get_status_once", attempt)

            assert (
                await client.get_status("robot", timeout=7, total_timeout=90)
                is expected
            )
            first, second = (call.kwargs for call in attempt.await_args_list)
            assert first["task_id"] != second["task_id"]
            assert first["timeout"] == second["timeout"] == 7

    with caplog.at_level(logging.DEBUG, logger="botslab360.client"):
        run(scenario())
    assert "retry=started" in caplog.text
    assert "result=succeeded" in caplog.text
    for secret in (Q, T, SID, "private HTTP context", "private push context"):
        assert secret not in caplog.text


@pytest.mark.parametrize(
    ("budget", "error_type", "attempts"),
    [
        (None, "transient", 1),
        (40, "transient", 1),
        (120, "transient", 2),
        (120, "authentication", 1),
        (120, "permanent", 1),
        (120, "session", 2),
    ],
)
def test_status_recovery_limit(monkeypatch, budget, error_type, attempts):
    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: login_response())
        ) as http:
            client = Botslab360Client(Q, T, http_client=http, push_port=1234)
            await client.authenticate()
            first = {
                "transient": transient_error("robot status"),
                "authentication": AuthenticationError("rejected"),
                "permanent": ApiError("invalid response", phase="response-validation"),
                "session": InvalidSessionError("expired"),
            }[error_type]
            last = InvalidSessionError("expired again")
            attempt = AsyncMock(side_effect=[first, last])
            refresh = AsyncMock()
            monkeypatch.setattr(client, "_get_status_once", attempt)
            monkeypatch.setattr(client, "authenticate", refresh)
            with pytest.raises(ApiError) as raised:
                await client.get_status("robot", total_timeout=budget)
            assert raised.value is (first if attempts == 1 else last)
            assert attempt.await_count == attempts
            assert refresh.await_count == (error_type == "session")

    run(scenario())


@pytest.mark.parametrize("external_cancel", [False, True])
def test_status_budget_cancels_and_awaits_cleanup(monkeypatch, external_cancel):
    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: login_response())
        ) as http:
            client = Botslab360Client(Q, T, http_client=http)
            await client.authenticate()
            entered = asyncio.Event()
            cleaned = asyncio.Event()

            async def blocked(**kwargs):
                try:
                    entered.set()
                    await asyncio.Future()
                finally:
                    await asyncio.sleep(0)
                    cleaned.set()

            monkeypatch.setattr(client, "_get_status_once", blocked)
            task = asyncio.create_task(
                client.get_status(
                    "robot", total_timeout=60 if external_cancel else 0.05
                )
            )
            if external_cancel:
                await entered.wait()
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            else:
                with pytest.raises(ApiError, match="total time budget"):
                    await task
            assert cleaned.is_set()

    run(scenario())


@pytest.mark.parametrize("fallback", [False, True])
def test_http_read_timeout_reopens_push_after_cleanup(monkeypatch, fallback):
    async def scenario():
        events = []
        task_ids = []
        ports = []

        class Push:
            _reader = _writer = object()
            wait_for_status = client_module.PushClient.wait_for_status
            _wait_for_status = client_module.PushClient._wait_for_status

            def __init__(self, *args, port, **kwargs):
                self.port = port
                self.messages = None
                ports.append(port)

            async def __aenter__(self):
                if fallback and self.port == 80:
                    raise transient_error("push registration")
                events.append("open")
                return self

            async def close(self):
                events.append("failed setup closed")

            async def __aexit__(self, *args):
                events.append("close")

            async def read_event(self):
                if self.messages is None:
                    assert len(set(task_ids)) == 2
                    self.messages = iter(
                        [
                            dict(
                                synthetic_event(),
                                sn="robot",
                                taskid=task_ids[0],
                                data={},
                            ),
                            dict(synthetic_event(), sn="robot", taskid=task_ids[1]),
                        ]
                    )
                events.append("event")
                return next(self.messages)

        def handler(request):
            if request.url.path == "/common/user/login":
                return login_response()
            events.append("post")
            task_ids.append(parse_qs(request.content.decode())["taskid"][0])
            if len(task_ids) == 1:
                raise httpx.ReadTimeout("private HTTP context", request=request)
            return httpx.Response(200, json={"errno": 0})

        monkeypatch.setattr(client_module, "PushClient", Push)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            if fallback:
                client = make_client(http)
            else:
                client = Botslab360Client(Q, T, http_client=http, push_port=1234)
                await client.authenticate()
            status = await client.get_status("robot", total_timeout=120)
            assert status.battery == 85
            expected = [
                "open",
                "post",
                "close",
                "open",
                "post",
                "event",
                "event",
                "close",
            ]
            assert events == (["failed setup closed"] if fallback else []) + expected
            assert ports == ([80, 443, 443] if fallback else [1234, 1234])

    run(scenario())


def test_status_recovery_does_not_cancel_parallel_map(monkeypatch):
    async def scenario():
        map_waiting = asyncio.Event()
        status_recovered = asyncio.Event()
        closed = []
        requests = []
        status_result, map_result = object(), object()

        class Push:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                closed.append(self)

            async def wait_for_status(self, **kwargs):
                status_recovered.set()
                return status_result

        async def map_waiter(push, **kwargs):
            map_waiting.set()
            await status_recovered.wait()
            assert push not in closed
            return {}

        async def handler(request):
            if request.url.path == "/common/user/login":
                return login_response()
            form = parse_qs(request.content.decode())
            requests.append(form["infoType"][0])
            if requests[-1] == "20001" and requests.count("20001") == 1:
                await map_waiting.wait()
                raise httpx.ReadTimeout("private HTTP context", request=request)
            return httpx.Response(200, json={"errno": 0})

        monkeypatch.setattr(client_module, "PushClient", lambda *args, **kwargs: Push())
        monkeypatch.setattr(client_module, "wait_for_map_info", map_waiter)
        monkeypatch.setattr(client_module, "parse_occupancy_grid", lambda _: map_result)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = Botslab360Client(Q, T, http_client=http, push_port=1234)
            await client.authenticate()
            results = await asyncio.wait_for(
                asyncio.gather(
                    client.get_status("robot", total_timeout=90),
                    client.get_occupancy_grid("robot"),
                ),
                timeout=2,
            )
        assert results == [status_result, map_result]
        assert requests.count("20001") == 2
        assert len(requests) == len(closed) == 3

    run(scenario())


@pytest.mark.parametrize(
    ("kind", "elapsed"),
    [("push registration", 15.032), ("http", 30.581), ("robot status", 30.825)],
)
@pytest.mark.parametrize("profiles", [1, 2])
@pytest.mark.parametrize("budget", [60.0, 120.0, 125.0])
def test_observed_status_failure_budget(monkeypatch, kind, elapsed, profiles, budget):
    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: login_response())
        ) as http:
            kwargs = {"push_port": 1234} if profiles == 1 else {}
            client = make_client(http, **kwargs)
            assert len(client._push_profiles) == profiles
            loop = asyncio.get_running_loop()
            start = loop.time()
            offset = 0.0
            attempts = 0
            error = transient_error(kind)
            expected = object()

            async def attempt(**kwargs):
                nonlocal attempts, offset
                attempts += 1
                if attempts == 1:
                    offset = elapsed
                    raise error
                return expected

            def clock():
                return start + offset

            # Advance elapsed time only when the first attempt fails, without
            # blocking the test or changing the configured phase timeouts.
            with monkeypatch.context() as mock:
                mock.setattr(client, "_get_status_once", attempt)
                mock.setattr(loop, "time", clock)
                retry = budget == 125.0 or (
                    budget == 120.0 and (profiles == 1 or kind == "push registration")
                )
                if retry:
                    assert (
                        await client.get_status("robot", total_timeout=budget)
                        is expected
                    )
                    assert attempts == 2
                else:
                    with pytest.raises(ApiError) as raised:
                        await client.get_status("robot", total_timeout=budget)
                    assert raised.value is error
                    assert attempts == 1

    run(scenario())
