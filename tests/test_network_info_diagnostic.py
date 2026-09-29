from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from uuid import UUID

import pytest

from botslab360 import ApiError, AuthBackend, Device, DeviceIdentity, SmartSession

IDENTITY = DeviceIdentity(
    mid="0123456789abcdef0123456789abcdef",
    android_id="0123456789abcdef",
    m2="12345678-1234-5678-9234-567812345678",
)
DEVICE = Device("synthetic-device", "Upstairs", "360 S9-P", True)
TASK_ID = "5ba41bb3-14ff-45e1-a6b2-1de6ab4dfa6a"


def _script_path() -> Path:
    return Path(__file__).parents[1] / "diagnostics" / "test_network_info.py"


def _load_diagnostic() -> ModuleType:
    name = "network_info_diagnostic"
    spec = importlib.util.spec_from_file_location(name, _script_path())
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


def _event(
    *,
    data: object,
    event: int = 10,
    task_id: str = "synthetic-task",
) -> dict[str, object]:
    return {
        "event": event,
        "sn": DEVICE.id,
        "taskid": task_id,
        "data": json.dumps(
            {
                "infoType": "21019",
                "data": data,
                "sid": "must-not-be-retained",
            }
        ),
        "pushKey": "must-not-be-retained",
    }


def test_parses_only_network_identity_fields() -> None:
    module = _load_diagnostic()
    identity = module.parse_network_info_event(
        _event(
            data=json.dumps(
                {
                    "staIp": "192.168.4.20",
                    "staMac": "AA-BB-CC-DD-EE-FF",
                    "staId": "Private Home",
                    "hostname": "robot-vacuum",
                    "token": "must-not-be-retained",
                }
            )
        ),
        device_id=DEVICE.id,
        task_id="synthetic-task",
    )

    assert identity.station_ip == "192.168.4.20"
    assert identity.station_mac == "aa:bb:cc:dd:ee:ff"
    assert identity.oui == "aa:bb:cc"
    assert identity.ssid == "Private Home"
    assert identity.hostname == "robot-vacuum"
    assert not hasattr(identity, "token")


def test_ignores_unrelated_push_events() -> None:
    module = _load_diagnostic()

    assert (
        module.parse_network_info_event(
            _event(data={}, event=4),
            device_id=DEVICE.id,
            task_id="synthetic-task",
        )
        is None
    )
    assert (
        module.parse_network_info_event(
            _event(data={}),
            device_id=DEVICE.id,
            task_id="different-task",
        )
        is None
    )


def test_invalid_identity_field_does_not_leak_payload() -> None:
    module = _load_diagnostic()
    raw_secret = "private-value-that-must-not-leak"

    with pytest.raises(ApiError) as raised:
        module.parse_network_info_event(
            _event(
                data={
                    "staIp": raw_secret,
                    "staMac": "aa:bb:cc:dd:ee:ff",
                }
            ),
            device_id=DEVICE.id,
            task_id="synthetic-task",
        )

    assert raw_secret not in str(raised.value)
    assert raised.value.phase == "protocol"


def test_network_info_request_uses_command_21019_and_arms_waiter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_diagnostic()
    events: list[object] = []

    class FakePushClient:
        def __init__(self, sid, push_key, **kwargs):
            assert sid == "synthetic-sid"
            assert push_key == "synthetic-push-key"
            assert kwargs == {
                "host": "push.synthetic.invalid",
                "port": 80,
                "client_version": "1.21",
                "heartbeat_timeout": 20,
                "heartbeat_interval": 15.0,
            }

        async def __aenter__(self):
            events.append("push-connected")
            return self

        async def __aexit__(self, *args):
            events.append("push-closed")

        async def read_event(self):
            events.append("waiter-armed")
            while "http-requested" not in events:
                await asyncio.sleep(0)
            return _event(
                data={
                    "staIp": "192.168.4.20",
                    "staMac": "aabbccddeeff",
                },
                task_id=TASK_ID,
            )

    class FakeClient:
        session = SmartSession(
            "synthetic-qid",
            "synthetic-sid",
            "synthetic-push-key",
        )
        _push_host = "push.synthetic.invalid"
        _push_port = 80
        _push_client_version = "1.21"
        _push_heartbeat_timeout = 20
        _push_heartbeat_interval = 15.0

        async def _post_robot_request(self, **kwargs):
            assert events == ["push-connected", "waiter-armed"]
            events.append("http-requested")
            assert kwargs["device_id"] == DEVICE.id
            assert kwargs["info_type"] == "21019"
            assert kwargs["data"] == ""
            assert kwargs["operation"] == "network info request"
            UUID(kwargs["task_id"])

    monkeypatch.setattr(module, "PushClient", FakePushClient)
    result = asyncio.run(
        module._request_network_info_once(
            FakeClient(),
            device_id=DEVICE.id,
            task_id=TASK_ID,
            timeout=1.0,
        )
    )

    assert result.station_ip == "192.168.4.20"
    assert result.station_mac == "aa:bb:cc:dd:ee:ff"
    assert events == [
        "push-connected",
        "waiter-armed",
        "http-requested",
        "push-closed",
    ]


def test_live_flow_selects_s9p_and_redacts_sensitive_values(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_diagnostic()
    calls: list[object] = []

    class FakeClient:
        @classmethod
        def from_credentials(cls, **kwargs):
            calls.append(("factory", kwargs))
            return cls()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def authenticate(self):
            calls.append("authenticate")

        async def get_devices(self):
            calls.append("get_devices")
            return [Device("other", "Other", "X90", True), DEVICE]

    async def request_network_info(client, *, device_id, timeout):
        calls.append(("network_info", device_id, timeout))
        return module.NetworkIdentity(
            "192.168.4.20",
            "aa:bb:cc:dd:ee:ff",
            "Private Home",
            None,
        )

    monkeypatch.setattr(module, "Botslab360Client", FakeClient)
    monkeypatch.setattr(module, "_request_network_info", request_network_info)

    result = asyncio.run(
        module.run_network_info_test(
            "private-account",
            "private-password",
            IDENTITY,
        )
    )

    assert result == 0
    assert calls == [
        (
            "factory",
            {
                "email": "private-account",
                "password": "private-password",
                "backend": AuthBackend.ROBOT360,
                "device_identity": IDENTITY,
            },
        ),
        "authenticate",
        "get_devices",
        ("network_info", DEVICE.id, 30.0),
    ]
    output = capsys.readouterr().out
    assert "Device: 360 S9-P" in output
    assert "Station IP: 192.168.4.20" in output
    assert "Station MAC: aa:bb:cc:dd:ee:ff" in output
    assert "OUI: aa:bb:cc" in output
    assert "SSID: present (redacted)" in output
    assert "NETWORK INFO DIAGNOSTIC STATUS: PASS" in output
    for secret in (
        "private-account",
        "private-password",
        "Private Home",
        "synthetic-qid",
        "synthetic-sid",
        "synthetic-push-key",
    ):
        assert secret not in output
