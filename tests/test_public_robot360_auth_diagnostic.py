from __future__ import annotations

import ast
import asyncio
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from botslab360 import (
    AuthBackend,
    CaptchaChallenge,
    CaptchaRequired,
    DeviceIdentity,
    SmartSession,
)

IDENTITY = DeviceIdentity(
    mid="0123456789abcdef0123456789abcdef",
    android_id="0123456789abcdef",
    m2="12345678-1234-5678-9234-567812345678",
)


def _script_path() -> Path:
    return (
        Path(__file__).parents[1]
        / "diagnostics"
        / "test_public_robot360_auth.py"
    )


def _load_diagnostic() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "public_robot360_auth_diagnostic",
        _script_path(),
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_script_imports_only_public_botslab360_api() -> None:
    tree = ast.parse(_script_path().read_text(encoding="utf-8"))
    botslab_imports = [
        node for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
        and node.module is not None
        and node.module.startswith("botslab360")
    ]

    assert len(botslab_imports) == 1
    assert botslab_imports[0].module == "botslab360"
    assert {alias.name for alias in botslab_imports[0].names} == {
        "AuthBackend",
        "Botslab360Client",
        "CaptchaRequired",
        "DeviceIdentity",
        "SmartSession",
    }


def test_public_captcha_flow_uses_exactly_two_auth_calls_and_closes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_diagnostic()
    challenge = CaptchaChallenge(b"synthetic-image", "opaque-sc")
    session = SmartSession(
        qid="synthetic-qid",
        sid="synthetic-sid",
        push_key="synthetic-push-key",
    )
    calls: list[object] = []

    class FakeClient:
        @classmethod
        def from_credentials(cls, **kwargs: object) -> "FakeClient":
            calls.append(("factory", kwargs))
            return cls()

        async def authenticate(self) -> SmartSession:
            calls.append("authenticate")
            raise CaptchaRequired(challenge)

        async def continue_authentication(
            self,
            supplied_challenge: CaptchaChallenge,
            captcha_code: str,
        ) -> SmartSession:
            calls.append(("continue", supplied_challenge, captcha_code))
            return session

        async def close(self) -> None:
            calls.append("close")

        async def get_devices(self) -> None:
            pytest.fail("get_devices must not be called")

        async def start_cleaning(self, *args: object) -> None:
            pytest.fail("commands must not be called")

    monkeypatch.setattr(module, "Botslab360Client", FakeClient)
    monkeypatch.setattr(
        module, "input", lambda prompt: module.CONFIRMATION, raising=False
    )
    monkeypatch.setattr(module, "getpass", lambda prompt: "captcha-code")
    image_path = tmp_path / "captcha.img"

    result = asyncio.run(
        module.run_auth_test(
            "private-account",
            "private-password",
            IDENTITY,
            captcha_path=image_path,
        )
    )

    assert result == 0
    assert image_path.read_bytes() == challenge.image
    assert calls[0] == (
        "factory",
        {
            "email": "private-account",
            "password": "private-password",
            "backend": AuthBackend.ROBOT360,
            "device_identity": IDENTITY,
        },
    )
    assert calls[1:] == [
        "authenticate",
        ("continue", challenge, "captcha-code"),
        "close",
    ]
    output = capsys.readouterr().out
    assert "authenticated: true" in output
    assert "backend: robot360" in output
    assert "session established: true" in output
    assert "sid present: true" in output
    assert "pushKey present: true" in output
    for secret in (
        "private-account",
        "private-password",
        "captcha-code",
        "opaque-sc",
        "synthetic-qid",
        "synthetic-sid",
        "synthetic-push-key",
    ):
        assert secret not in output


def test_direct_public_authentication_stops_after_session_and_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_diagnostic()
    calls: list[str] = []

    class FakeClient:
        @classmethod
        def from_credentials(cls, **kwargs: object) -> "FakeClient":
            assert kwargs["backend"] is AuthBackend.ROBOT360
            assert "region" not in kwargs
            return cls()

        async def authenticate(self) -> SmartSession:
            calls.append("authenticate")
            return SmartSession(
                qid="synthetic-qid",
                sid="synthetic-sid",
                push_key="synthetic-push-key",
            )

        async def continue_authentication(self, *args: object) -> SmartSession:
            pytest.fail("captcha continuation must not be called")

        async def close(self) -> None:
            calls.append("close")

    monkeypatch.setattr(module, "Botslab360Client", FakeClient)

    assert asyncio.run(
        module.run_auth_test("account", "password", IDENTITY)
    ) == 0
    assert calls == ["authenticate", "close"]


def test_identity_file_is_created_once_and_reused(tmp_path: Path) -> None:
    module = _load_diagnostic()
    path = tmp_path / "identity.json"

    created_identity, created = module._load_or_create_identity(path)
    loaded_identity, created_again = module._load_or_create_identity(path)

    assert created is True
    assert created_again is False
    assert loaded_identity == created_identity
