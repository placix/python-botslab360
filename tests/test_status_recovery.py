"""Offline tests for opt-in status recovery."""

import asyncio
import base64
import json
import logging
from unittest.mock import AsyncMock, Mock
from urllib.parse import parse_qs

import httpx
import pytest
from test_protocol import application_packet, bind_ack, synthetic_event
from test_push_profiles import make_client
from test_status import SID, Q, T, login_response, run

import botslab360.client as client_module
import botslab360.protocol as protocol_module
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
            monotonic = loop.time
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
                return monotonic() + offset

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


@pytest.mark.parametrize("final_result", ["success", "eof", "no_budget"])
def test_registration_timeout_then_retry_eof_uses_fresh_stream(
    monkeypatch, caplog, final_result
):
    async def scenario():
        readers = []
        closed = []
        delays = []
        requests = []
        paths = []
        clock = asyncio.get_running_loop()
        wall_time = clock.time
        elapsed = 0.0

        class Writer:
            def __init__(self, index):
                self.index = index

            def write(self, data):
                if data[2:4] == b"\x00\x02":
                    if self.index == 1 or final_result == "eof" and self.index == 2:
                        readers[self.index].feed_eof()
                    if self.index == 2 and final_result == "success":
                        readers[self.index].feed_data(bind_ack())

            async def drain(self):
                pass

            def close(self):
                closed.append(self.index)

            async def wait_closed(self):
                pass

        async def open_connection(*args):
            assert len(closed) == len(readers)
            index = len(readers)
            readers.append(asyncio.StreamReader())
            return readers[-1], Writer(index)

        wait_until_ready = protocol_module.PushClient.wait_until_ready

        async def wait(push, *, timeout):
            nonlocal elapsed
            if len(readers) == 1:
                if final_result == "no_budget":
                    elapsed = 14.6
                timeout = 0
            return await wait_until_ready(push, timeout=timeout)

        sleep = asyncio.sleep

        async def backoff(delay):
            if delay not in (0.25, 0.5):
                await sleep(delay)
                return
            nonlocal elapsed
            assert len(closed) == len(readers)
            delays.append(delay)
            elapsed += delay

        def handler(request):
            paths.append(request.url.path)
            if request.url.path == "/common/user/login":
                return login_response()
            requests.append(request)
            task = parse_qs(request.content.decode())["taskid"][0]
            packet, _ = application_packet(
                {
                    "encrypt": 0,
                    "data": base64.b64encode(
                        json.dumps(
                            dict(synthetic_event(), sn="robot", taskid=task)
                        ).encode()
                    ).decode(),
                }
            )
            # The timeout socket receives a late event. Only the event on
            # the newly registered stream may complete the status request.
            readers[0].feed_data(packet)
            readers[-1].feed_data(packet)
            return httpx.Response(200, json={"errno": 0})

        monkeypatch.setattr(protocol_module.asyncio, "open_connection", open_connection)
        monkeypatch.setattr(protocol_module.PushClient, "wait_until_ready", wait)
        monkeypatch.setattr(client_module.asyncio, "sleep", backoff)
        monkeypatch.setattr(clock, "time", lambda: wall_time() + elapsed)
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = Botslab360Client(Q, T, http_client=http, push_port=1234)
            await client.authenticate()
            if final_result == "success":
                status = await client.get_status("robot", total_timeout=125)
                assert status.battery == 85
            else:
                with pytest.raises(ApiError, match="Push connection closed"):
                    await client.get_status(
                        "robot",
                        total_timeout=90 if final_result == "no_budget" else 125,
                    )

        expected_attempts = 2 if final_result == "no_budget" else 3
        assert closed == list(range(expected_attempts))
        assert len(requests) == (final_result == "success")
        assert delays == ([0.25] if final_result == "no_budget" else [0.25, 0.5])
        assert paths.count("/common/user/login") == 1

    with caplog.at_level(logging.DEBUG, logger="botslab360"):
        run(scenario())
    assert all(
        record.levelno == logging.DEBUG
        for record in caplog.records
        if record.name.startswith("botslab360")
    )
    assert "reason=push_registration_eof phase=transport" in caplog.text
    assert "Push cleanup: elapsed_ms=" in caplog.text
    assert ("result=succeeded" in caplog.text) == (final_result == "success")
    assert ("retry=skipped budget" in caplog.text) == (final_result == "no_budget")


def test_status_recovery_is_serial_and_shutdown_cancels_pending_work(monkeypatch):
    async def scenario():
        started = asyncio.Event()
        cleaned = asyncio.Event()
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: login_response())
        ) as http:
            client = Botslab360Client(Q, T, http_client=http)
            await client.authenticate()

            async def attempt(**kwargs):
                try:
                    started.set()
                    await asyncio.Future()
                finally:
                    await asyncio.sleep(0)
                    cleaned.set()

            mock = AsyncMock(side_effect=attempt)
            monkeypatch.setattr(client, "_get_status_once", mock)
            first = asyncio.create_task(client.get_status("robot", total_timeout=125))
            await started.wait()
            second = asyncio.create_task(client.get_status("other", total_timeout=125))
            await asyncio.sleep(0)
            await asyncio.sleep(0)
            mock.assert_awaited_once()
            await client.close()
            assert cleaned.is_set()
            for operation in (first, second):
                with pytest.raises(asyncio.CancelledError):
                    await operation
            assert not http.is_closed
            mock.assert_awaited_once()

    run(scenario())


def test_close_during_open_disposes_late_stream_and_prevents_duplicate_connect(
    monkeypatch,
):
    async def scenario():
        entered = asyncio.Event()
        release = asyncio.Event()
        writer = AsyncMock()
        writer.close = Mock()
        writer.write = Mock()

        async def opening(*args):
            entered.set()
            await release.wait()
            return asyncio.StreamReader(), writer

        open_connection = AsyncMock(side_effect=opening)
        monkeypatch.setattr(protocol_module.asyncio, "open_connection", open_connection)
        push = protocol_module.PushClient(SID, "synthetic-key")
        connection = asyncio.create_task(push.connect())
        await entered.wait()
        with pytest.raises(ApiError, match="already connected"):
            await push.connect()
        await push.close()
        release.set()
        with pytest.raises(ApiError, match="Push connection closed") as raised:
            await connection
        assert type(raised.value) is ApiError
        open_connection.assert_awaited_once()
        writer.close.assert_called_once()
        writer.write.assert_not_called()
        writer.wait_closed.assert_awaited_once()

    run(scenario())


def test_reopening_same_push_client_ignores_late_ack_from_previous_stream(monkeypatch):
    async def scenario():
        first = asyncio.StreamReader()
        second = asyncio.StreamReader()

        writers = [AsyncMock(), AsyncMock()]
        for writer in writers:
            writer.close = Mock()
            writer.write = Mock()
        monkeypatch.setattr(
            protocol_module.asyncio,
            "open_connection",
            AsyncMock(side_effect=[(first, writers[0]), (second, writers[1])]),
        )
        push = protocol_module.PushClient(SID, "synthetic-key")
        first_bind_sent = asyncio.Event()
        writers[0].write.side_effect = lambda _: first_bind_sent.set()
        first_connect = asyncio.create_task(push.connect())
        await first_bind_sent.wait()
        await push.close()
        with pytest.raises(ApiError, match="Push connection closed"):
            await first_connect
        assert push._reader_task is None
        assert push._heartbeat_task is None

        registered = asyncio.Event()
        writers[1].write.side_effect = lambda _: registered.set()
        connect = asyncio.create_task(push.connect())
        await registered.wait()
        first.feed_data(bind_ack())
        await asyncio.sleep(0)
        assert not connect.done()
        second.feed_data(bind_ack())
        await connect
        await push.close()
        for writer in writers:
            writer.wait_closed.assert_awaited_once()

    run(scenario())


def test_cancel_during_registration_backoff_does_not_open_another_push(monkeypatch):
    async def scenario():
        backoff_entered = asyncio.Event()
        backoff_exited = asyncio.Event()
        sleep = asyncio.sleep

        async def backoff(delay):
            if delay != 0.25:
                return await sleep(delay)
            try:
                backoff_entered.set()
                await asyncio.Future()
            finally:
                backoff_exited.set()

        monkeypatch.setattr(client_module.asyncio, "sleep", backoff)
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: login_response())
        ) as http:
            client = Botslab360Client(Q, T, http_client=http)
            await client.authenticate()
            attempt = AsyncMock(side_effect=transient_error("push registration"))
            monkeypatch.setattr(client, "_get_status_once", attempt)
            status = asyncio.create_task(client.get_status("robot", total_timeout=125))
            await backoff_entered.wait()
            status.cancel()
            with pytest.raises(asyncio.CancelledError):
                await status
            assert backoff_exited.is_set()
            attempt.assert_awaited_once()

    run(scenario())


def test_queued_status_calls_expire_without_starting_transport(monkeypatch):
    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: login_response())
        ) as http:
            client = Botslab360Client(Q, T, http_client=http)
            await client.authenticate()
            attempt = AsyncMock()
            monkeypatch.setattr(client, "_get_status_once", attempt)

            async with client._status_recovery_lock:
                calls = [
                    client.get_status(f"robot-{index}", total_timeout=0.02)
                    for index in range(5)
                ]
                results = await asyncio.gather(*calls, return_exceptions=True)
                for result in results:
                    assert isinstance(result, ApiError)
                    assert result.phase == "timeout"

            await asyncio.sleep(0)
            attempt.assert_not_awaited()
            assert not client._status_recovery_tasks
            assert (
                await client.get_status("robot", total_timeout=125)
                is attempt.return_value
            )

    run(scenario())


def test_status_checks_expired_budget_when_serialization_lock_is_released(monkeypatch):
    async def scenario():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: login_response())
        ) as http:
            client = Botslab360Client(Q, T, http_client=http)
            await client.authenticate()
            attempt = AsyncMock()
            monkeypatch.setattr(client, "_get_status_once", attempt)

            loop = asyncio.get_running_loop()
            monotonic = loop.time
            offset = 0
            monkeypatch.setattr(loop, "time", lambda: monotonic() + offset)

            waiting = asyncio.Event()

            async def wait_for_worker(tasks, *, timeout):
                # Give the worker the first turn when the lock and deadline are
                # both ready, before the caller handles its timeout.
                waiting.set()
                worker = next(iter(tasks))
                try:
                    await worker
                except ApiError:
                    pass
                return tasks, set()

            monkeypatch.setattr(client_module.asyncio, "wait", wait_for_worker)
            async with client._status_recovery_lock:
                status = asyncio.create_task(
                    client.get_status("robot", total_timeout=1)
                )
                await waiting.wait()
                offset = 2

            with pytest.raises(ApiError, match="total time budget"):
                await status
            attempt.assert_not_awaited()
            assert not client._status_recovery_tasks

    run(scenario())
