from __future__ import annotations

import ast
import asyncio
import importlib.util
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from botslab360 import (
    AuthBackend,
    CaptchaChallenge,
    CaptchaRequired,
    Device,
    DeviceIdentity,
    Room,
    SmartSession,
)

IDENTITY = DeviceIdentity(
    mid="0123456789abcdef0123456789abcdef",
    android_id="0123456789abcdef",
    m2="12345678-1234-5678-9234-567812345678",
)
DEVICE = Device("synthetic-device", "Synthetic Robot", "test", True)
ROOMS = [Room(1, "Bad", "bathroom", 1, "max", 2)]


def _script_path() -> Path:
    return Path(__file__).parents[1] / "diagnostics" / "test_public_room_api.py"


def _load_diagnostic() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "public_room_api_diagnostic",
        _script_path(),
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_script_imports_only_public_botslab360_api() -> None:
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
        "DeviceIdentity",
    }


def test_public_room_flow_uses_only_public_operations(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_diagnostic()
    calls: list[object] = []
    session = SmartSession("synthetic-qid", "synthetic-sid", "synthetic-key")

    class FakeClient:
        def __init__(self) -> None:
            self.session = session

        @classmethod
        def from_credentials(cls, **kwargs: object) -> "FakeClient":
            calls.append(("factory", kwargs))
            return cls()

        async def __aenter__(self):
            calls.append("enter")
            return self

        async def __aexit__(self, *args: object):
            calls.append("exit")

        async def authenticate(self):
            calls.append("authenticate")

        async def get_devices(self):
            calls.append("get_devices")
            return [DEVICE]

        async def get_rooms(self, device: Device):
            calls.append(("get_rooms", device))
            return ROOMS

        async def clean_rooms(self, device: Device, room_ids: list[int]):
            calls.append(("clean_rooms", device, room_ids))

    monkeypatch.setattr(module, "Botslab360Client", FakeClient)
    monkeypatch.setattr(
        module,
        "input",
        lambda prompt: module.CLEAN_CONFIRMATION,
        raising=False,
    )

    result = asyncio.run(
        module.run_room_api_test("private-account", "private-password", IDENTITY)
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
        "enter",
        "authenticate",
        "get_devices",
        ("get_rooms", DEVICE),
        ("clean_rooms", DEVICE, [1]),
        "exit",
    ]
    output = capsys.readouterr().out
    assert "Public get_rooms(): success" in output
    assert "Public clean_rooms([1]): success" in output
    assert "PUBLIC ROOM API LIVE STATUS: PASS" in output
    for secret in (
        "private-account",
        "private-password",
        "synthetic-qid",
        "synthetic-sid",
        "synthetic-key",
    ):
        assert secret not in output


def test_cleaning_requires_exact_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_diagnostic()
    cleaned = False

    class FakeClient:
        session = SimpleNamespace()

        @classmethod
        def from_credentials(cls, **kwargs: object) -> "FakeClient":
            return cls()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args: object):
            pass

        async def authenticate(self):
            pass

        async def get_devices(self):
            return [DEVICE]

        async def get_rooms(self, device: Device):
            return ROOMS

        async def clean_rooms(self, device: Device, room_ids: list[int]):
            nonlocal cleaned
            cleaned = True

    monkeypatch.setattr(module, "Botslab360Client", FakeClient)
    monkeypatch.setattr(module, "input", lambda prompt: "clean room 1", raising=False)

    result = asyncio.run(module.run_room_api_test("account", "password", IDENTITY))

    assert result == 2
    assert cleaned is False


def test_public_captcha_continuation_does_not_expose_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_diagnostic()
    challenge = CaptchaChallenge(b"synthetic-image", "opaque-sc")
    session = SmartSession("synthetic-qid", "synthetic-sid", "synthetic-key")
    continued = False

    class FakeClient:
        def __init__(self) -> None:
            self.session = session

        @classmethod
        def from_credentials(cls, **kwargs: object) -> "FakeClient":
            return cls()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args: object):
            pass

        async def authenticate(self):
            raise CaptchaRequired(challenge)

        async def continue_authentication(self, supplied, code):
            nonlocal continued
            assert supplied is challenge
            assert code == "private-captcha-code"
            continued = True

        async def get_devices(self):
            return [DEVICE]

        async def get_rooms(self, device: Device):
            return ROOMS

        async def clean_rooms(self, device: Device, room_ids: list[int]):
            pass

    answers = iter([module.CAPTCHA_CONFIRMATION, module.CLEAN_CONFIRMATION])
    monkeypatch.setattr(module, "Botslab360Client", FakeClient)
    monkeypatch.setattr(module, "input", lambda prompt: next(answers), raising=False)
    monkeypatch.setattr(module, "getpass", lambda prompt: "private-captcha-code")

    result = asyncio.run(
        module.run_room_api_test(
            "private-account",
            "private-password",
            IDENTITY,
            captcha_path=tmp_path / "captcha.img",
        )
    )

    assert result == 0
    assert continued is True
    output = capsys.readouterr().out
    for secret in (
        "private-account",
        "private-password",
        "private-captcha-code",
        "opaque-sc",
        "synthetic-qid",
        "synthetic-sid",
        "synthetic-key",
    ):
        assert secret not in output
