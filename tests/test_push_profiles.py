"""Offline coverage of push establishment fallback without command replay."""

from __future__ import annotations

import asyncio
import json
import logging
from urllib.parse import parse_qs

import httpx
import pytest

import botslab360.client as client_module
from botslab360 import (
    ApiError,
    AuthBackend,
    AuthenticationError,
    Botslab360Client,
    DeviceIdentity,
    InvalidSessionError,
    NetworkInfo,
    QihooCredentials,
    RobotStatus,
    SmartSession,
)

QID = "1234567890"
Q = f"u=360H{QID}&n=synthetic&m=not-a-real-token"
T = "s=synthetic-session&t=1700000000&v=2.0"
SID = "synthetic-private-sid"
PUSH_KEY = "synthetic-private-push-key"
DEVICE_ID = "synthetic-private-device"
IDENTITY = DeviceIdentity(
    mid="0123456789abcdef0123456789abcdef",
    android_id="0123456789abcdef",
    m2="00000000-0000-4000-8000-000000000001",
)
ANDROID = (80, "1.21", 20, 15.0)
LEGACY = (443, "1.7", 30, 25.0)


def make_client(http, backend=AuthBackend.ROBOT360, **kwargs):
    if backend is None:
        client = Botslab360Client(Q, T, http_client=http, **kwargs)
    else:
        client = Botslab360Client.from_credentials(
            "synthetic@example.invalid",
            "synthetic-private-password",
            backend=backend,
            device_identity=IDENTITY,
            http_client=http,
            **kwargs,
        )
        client._set_credentials(QihooCredentials(q=Q, t=T, qid=QID))
    client._session = SmartSession(qid=QID, sid=SID, push_key=PUSH_KEY)
    return client


@pytest.mark.parametrize(
    ("operation", "scenario"),
    [
        (operation, scenario)
        for operation in ("rooms", "status", "network", "clean_rooms")
        for scenario in ("android", "fallback", "both", "post_push", "post_http")
    ]
    + [("clean_rooms", "cleaning_http"), ("rooms", "map_parse")],
)
def test_profile_fallback_never_replays_operations(
    monkeypatch, caplog, operation, scenario
):
    async def run():
        attempts = []
        posts = []
        issued = asyncio.Event()
        connected = False
        final_error = ApiError("Push connection closed", phase="transport")

        class FakePush:
            def __init__(self, sid, push_key, **kwargs):
                assert (sid, push_key) == (SID, PUSH_KEY)
                self.profile = tuple(
                    kwargs[key]
                    for key in (
                        "port",
                        "client_version",
                        "heartbeat_timeout",
                        "heartbeat_interval",
                    )
                )
                self.closed = False
                attempts.append(self)

            async def __aenter__(self):
                nonlocal connected
                if scenario == "both" or (
                    scenario == "fallback" and len(attempts) == 1
                ):
                    raise final_error
                connected = True
                return self

            async def close(self):
                nonlocal connected
                self.closed = True
                connected = False

            async def __aexit__(self, *args):
                await self.close()

            async def receive(self):
                await issued.wait()
                if scenario == "post_push":
                    raise final_error

            async def read_event(self):
                await self.receive()
                if scenario == "map_parse":
                    return {"sn": DEVICE_ID, "data": {"infoType": "20002", "data": []}}
                return {
                    "sn": DEVICE_ID,
                    "data": json.dumps(
                        {
                            "infoType": "20002",
                            "data": {
                                "mapId": 1,
                                "cleanId": "synthetic-private-clean-id",
                                "smartArea": {
                                    "activeIds": [],
                                    "value": [{"id": 1, "name": "Um9vbQ=="}],
                                },
                            },
                        }
                    ),
                }

            async def wait_for_network_info(self, **kwargs):
                await self.receive()
                return NetworkInfo("192.0.2.1", None, None, None)

            async def wait_for_status(self, **kwargs):
                await self.receive()
                return RobotStatus(DEVICE_ID, True, 80, "idle", False, "auto", 0, 0, 0)

        monkeypatch.setattr(client_module, "PushClient", FakePush)

        async def handler(request):
            if request.url.path == "/clean/cmd/send":
                assert connected
            posts.append((request.url.path, parse_qs(request.content.decode())))
            issued.set()
            if scenario == "post_http" or (
                scenario == "cleaning_http"
                and request.url.path == "/clean/record/setAreaAndCleaning"
            ):
                return httpx.Response(200, json={"errno": 999})
            return httpx.Response(200, json={"errno": 0})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = make_client(http)
            method = {
                "rooms": client.get_rooms,
                "status": client.get_status,
                "network": client.get_network_info,
                "clean_rooms": lambda device: client.clean_rooms(device, [1]),
            }[operation]
            if scenario in {
                "both",
                "post_push",
                "post_http",
                "cleaning_http",
                "map_parse",
            }:
                with pytest.raises(ApiError) as raised:
                    await method(DEVICE_ID)
                if scenario in {"both", "post_push"}:
                    assert raised.value is final_error
            else:
                result = await method(DEVICE_ID)
                if operation == "rooms":
                    assert [(room.id, room.name) for room in result] == [(1, "Room")]
                elif operation == "status":
                    assert result.state == "idle"
                elif operation == "network":
                    assert result.station_ip == "192.0.2.1"
            await client.close()
            assert not http.is_closed

        assert [push.profile for push in attempts] == (
            [ANDROID, LEGACY] if scenario in {"fallback", "both"} else [ANDROID]
        )
        assert all(push.closed for push in attempts)
        assert not connected
        expected_posts = 0 if scenario == "both" else 1
        if operation == "clean_rooms" and scenario in {
            "android",
            "fallback",
            "cleaning_http",
        }:
            expected_posts = 2
            assert posts[1][0] == "/clean/record/setAreaAndCleaning"
            assert json.loads(posts[1][1]["areaSetting"][0])["activeIds"] == [1]
        assert len(posts) == expected_posts
        if posts:
            assert posts[0][0] == "/clean/cmd/send"
            assert posts[0][1]["infoType"] == [
                {"status": "20001", "network": "21019"}.get(operation, "30000")
            ]

    caplog.set_level(logging.DEBUG, logger="botslab360.client")
    asyncio.run(run())
    diagnostics = "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name == "botslab360.client"
    )
    assert "profile=android" in diagnostics
    if scenario == "fallback":
        assert "profile=legacy result=succeeded" in diagnostics
    for secret in (
        Q,
        T,
        QID,
        SID,
        PUSH_KEY,
        DEVICE_ID,
        "synthetic-private-password",
        "synthetic-private-clean-id",
        "Push connection closed",
    ):
        assert secret not in diagnostics
    assert all(record.exc_info is None for record in caplog.records)


@pytest.mark.parametrize("phase", ["transport", "timeout", "protocol"])
def test_initial_registration_phases_allow_one_fallback(monkeypatch, phase):
    _check_setup_error(
        monkeypatch, ApiError("synthetic-error", phase=phase), expected_ports=[80, 443]
    )


@pytest.mark.parametrize(
    "error",
    [
        ApiError("synthetic-error", phase="json"),
        ApiError("synthetic-error", phase="api"),
        ApiError("synthetic-error", phase="response-validation"),
        AuthenticationError("synthetic-error", phase="transport"),
        InvalidSessionError("synthetic-error", phase="transport"),
    ],
)
def test_non_transport_or_session_errors_do_not_switch_profiles(monkeypatch, error):
    _check_setup_error(monkeypatch, error, expected_ports=[80])


@pytest.mark.parametrize(
    "backend,override,expected_ports",
    [
        (None, None, [443]),
        (AuthBackend.BOTSLAB, None, [443]),
        (AuthBackend.ROBOT360, 1234, [1234]),
    ],
)
def test_default_backends_and_explicit_port_remain_authoritative(
    monkeypatch, backend, override, expected_ports
):
    _check_setup_error(
        monkeypatch,
        ApiError("synthetic-error", phase="transport"),
        expected_ports=expected_ports,
        backend=backend,
        override=override,
    )


def _check_setup_error(
    monkeypatch, error, *, expected_ports, backend=AuthBackend.ROBOT360, override=None
):
    async def run():
        attempts = []
        closed = []

        class FailingPush:
            def __init__(self, sid, push_key, **kwargs):
                self.port = kwargs["port"]
                attempts.append(self.port)

            async def __aenter__(self):
                raise error

            async def close(self):
                closed.append(self.port)

            async def __aexit__(self, *args):
                pytest.fail("A failed entry must not register an exit callback")

        monkeypatch.setattr(client_module, "PushClient", FailingPush)
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: pytest.fail("No HTTP expected")
            )
        ) as http:
            client = make_client(
                http,
                backend,
                **({"push_port": override} if override is not None else {}),
            )
            with pytest.raises(ApiError) as raised:
                async with client._push_connection():
                    pytest.fail("No established channel expected")
            assert raised.value is error
            await client.close()
        assert attempts == expected_ports
        assert closed == expected_ports

    asyncio.run(run())


@pytest.mark.parametrize(
    ("plans", "late_failures", "preferred_ports"),
    [
        pytest.param(
            [[(80, True)], [(80, True)]],
            [False, False],
            [80, 80],
            id="android-stays-preferred",
        ),
        pytest.param(
            [[(80, False), (443, True)], [(443, True)]],
            [False, False],
            [443, 443],
            id="legacy-promoted",
        ),
        pytest.param(
            [[(80, False), (443, True)], [(443, False), (80, True)], [(80, True)]],
            [False, False, False],
            [443, 80, 80],
            id="android-promoted-again",
        ),
        pytest.param(
            [[(80, False), (443, False)], [(80, True)]],
            [False, False],
            [80, 80],
            id="both-fail-no-promotion",
        ),
        pytest.param(
            [[(80, False), (443, True)], [(443, False), (80, False)], [(443, True)]],
            [False, False, False],
            [443, 443, 443],
            id="both-fail-preserve-legacy",
        ),
        pytest.param(
            [[(80, False), (443, True)], [(443, True)]],
            [True, False],
            [443, 443],
            id="late-operation-error-no-replay",
        ),
    ],
)
def test_successful_profile_is_preferred_for_later_operations(
    monkeypatch, caplog, plans, late_failures, preferred_ports
):
    async def run():
        script = iter(attempt for plan in plans for attempt in plan)
        pushes = []
        errors = []
        requests = []
        late_failure = False

        class ScriptedPush:
            def __init__(self, sid, push_key, **kwargs):
                self.port = kwargs["port"]
                self.closed = False
                pushes.append(self)

            async def __aenter__(self):
                expected_port, success = next(script)
                assert self.port == expected_port
                if not success:
                    error = ApiError("synthetic-private-setup-error", phase="transport")
                    errors.append(error)
                    raise error
                return self

            async def close(self):
                self.closed = True

            async def __aexit__(self, *args):
                await self.close()

            async def wait_for_status(self, **kwargs):
                if late_failure:
                    raise ApiError(
                        "synthetic-private-operation-error", phase="transport"
                    )
                return RobotStatus(DEVICE_ID, True, 80, "idle", False, "auto", 0, 0, 0)

        monkeypatch.setattr(client_module, "PushClient", ScriptedPush)

        async def handler(request):
            assert request.url.path == "/clean/cmd/send"
            requests.append(request)
            return httpx.Response(200, json={"errno": 0})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = make_client(http)
            original_profiles = client._push_profiles
            expected_requests = 0
            for plan, late_failure, preferred_port in zip(
                plans, late_failures, preferred_ports
            ):
                established = any(success for _, success in plan)
                expected_requests += int(established)
                if not established or late_failure:
                    with pytest.raises(ApiError) as raised:
                        await client.get_status(DEVICE_ID)
                    if not established:
                        assert raised.value is errors[-1]
                else:
                    assert (await client.get_status(DEVICE_ID)).state == "idle"
                assert len(requests) == expected_requests
                assert client._preferred_push_profile.port == preferred_port
                assert client._push_profiles is original_profiles
                assert any(
                    client._preferred_push_profile is profile
                    for profile in original_profiles
                )
                assert all(push.closed for push in pushes)
            assert len(pushes) == sum(len(plan) for plan in plans)
            # Preference is client-local and is not carried into a fresh client.
            fresh_client = make_client(http)
            assert fresh_client._preferred_push_profile.port == 80
            await fresh_client.close()
            await client.close()
            assert not http.is_closed

    caplog.set_level(logging.DEBUG, logger="botslab360.client")
    asyncio.run(run())
    diagnostics = "\n".join(
        record.getMessage()
        for record in caplog.records
        if record.name == "botslab360.client"
    )
    assert "synthetic-private" not in diagnostics
    if plans == [[(80, False), (443, True)], [(443, True)]]:
        assert diagnostics.splitlines() == [
            "Push setup: profile=android result=failed fallback=True",
            "Push setup: profile=legacy result=succeeded",
            "Push setup: profile=legacy result=succeeded",
        ]


@pytest.mark.parametrize("second_android_fails", [False, True])
def test_concurrent_operations_keep_independent_attempt_order(
    monkeypatch, second_android_fails
):
    async def run():
        a_started = asyncio.Event()
        b_started = asyncio.Event()
        a_legacy_started = asyncio.Event()
        release_a = asyncio.Event()
        release_b = asyncio.Event()
        history = {"a": [], "b": [], "next": []}
        pushes = []
        requests = []

        class ConcurrentPush:
            def __init__(self, sid, push_key, **kwargs):
                name = asyncio.current_task().get_name()
                self.name = name if name in {"a", "b"} else "next"
                self.port = kwargs["port"]
                self.closed = False
                history[self.name].append(self.port)
                pushes.append(self)

            async def __aenter__(self):
                if self.name == "a" and self.port == 80:
                    a_started.set()
                    await release_a.wait()
                    raise ApiError("synthetic-a-setup-error", phase="transport")
                if self.name == "a":
                    a_legacy_started.set()
                if self.name == "b" and self.port == 80:
                    b_started.set()
                    await release_b.wait()
                    if second_android_fails:
                        raise ApiError("synthetic-b-setup-error", phase="transport")
                return self

            async def close(self):
                self.closed = True

            async def __aexit__(self, *args):
                await self.close()

            async def wait_for_status(self, **kwargs):
                return RobotStatus(DEVICE_ID, True, 80, "idle", False, "auto", 0, 0, 0)

        monkeypatch.setattr(client_module, "PushClient", ConcurrentPush)

        async def handler(request):
            requests.append(request)
            return httpx.Response(200, json={"errno": 0})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = make_client(http)
            profiles = client._push_profiles
            a = asyncio.create_task(client.get_status(DEVICE_ID), name="a")
            await a_started.wait()
            b = asyncio.create_task(client.get_status(DEVICE_ID), name="b")
            await b_started.wait()
            release_a.set()
            await a_legacy_started.wait()
            await a
            assert client._preferred_push_profile is profiles[1]
            # b captured Android first before a promoted Legacy. Its remaining
            # attempts must not be changed or skipped by that promotion.
            release_b.set()
            await b
            preferred = profiles[1] if second_android_fails else profiles[0]
            assert client._preferred_push_profile is preferred
            await client.get_status(DEVICE_ID)
            assert history == {
                "a": [80, 443],
                "b": [80, 443] if second_android_fails else [80],
                "next": [preferred.port],
            }
            assert client._push_profiles is profiles
            assert all(push.closed for push in pushes)
            assert len(requests) == 3
            await client.close()

    asyncio.run(asyncio.wait_for(run(), timeout=5))
