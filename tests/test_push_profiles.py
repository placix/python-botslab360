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
