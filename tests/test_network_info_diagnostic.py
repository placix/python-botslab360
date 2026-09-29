from __future__ import annotations

import ast
import asyncio
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from botslab360 import AuthBackend, Device, DeviceIdentity, NetworkInfo

IDENTITY = DeviceIdentity(
    mid="0123456789abcdef0123456789abcdef",
    android_id="0123456789abcdef",
    m2="12345678-1234-5678-9234-567812345678",
)
DEVICE = Device("synthetic-device", "Upstairs", "360 S9-P", True)


def _script_path() -> Path:
    return Path(__file__).parents[1] / "diagnostics" / "test_network_info.py"


def _load_diagnostic() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "network_info_diagnostic",
        _script_path(),
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_script_uses_only_public_botslab360_api() -> None:
    tree = ast.parse(_script_path().read_text(encoding="utf-8"))
    botslab_imports = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module is not None
        and node.module.startswith("botslab360")
    ]

    assert len(botslab_imports) == 1
    assert botslab_imports[0].module == "botslab360"
    assert {alias.name for alias in botslab_imports[0].names} == {
        "ApiError",
        "AuthBackend",
        "Botslab360Client",
        "CaptchaRequired",
        "Device",
        "DeviceIdentity",
        "NetworkInfo",
    }


def test_live_flow_uses_public_api_and_redacts_sensitive_values(
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

        async def get_network_info(self, device, *, timeout):
            calls.append(("get_network_info", device, timeout))
            return NetworkInfo(
                station_ip="192.168.4.20",
                station_mac="aa:bb:cc:dd:ee:ff",
                station_ssid="Private Home",
                station_signal=-48,
            )

    monkeypatch.setattr(module, "Botslab360Client", FakeClient)

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
        ("get_network_info", DEVICE, 30.0),
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
    ):
        assert secret not in output
