from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from botslab360 import (
    ApiError,
    CaptchaChallenge,
    CaptchaRequired,
    DeviceIdentity,
    QucAuthenticationError,
)

IDENTITY = DeviceIdentity(
    mid="0123456789abcdef0123456789abcdef",
    android_id="0123456789abcdef",
    m2="12345678-1234-5678-9234-567812345678",
)


def _load_example() -> ModuleType:
    path = Path(__file__).parents[1] / "examples" / "test_credentials_auth.py"
    spec = importlib.util.spec_from_file_location("credential_smoke_example", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _CaptchaFile:
    name = "synthetic-captcha.png"

    def __init__(self, writes: list[bytes]) -> None:
        self._writes = writes

    def __enter__(self) -> _CaptchaFile:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def write(self, value: bytes) -> None:
        self._writes.append(value)


def _quc_error(
    region: str, errno: int, errmsg: str = "rejected"
) -> QucAuthenticationError:
    return QucAuthenticationError(
        "QUC rejected the supplied credentials",
        region=region,
        errno=errno,
        errmsg=errmsg,
        status_code=200,
        user_present=False,
        captcha_required=False,
        captcha_type=None,
    )


def _install_probe_factory(
    module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    outcomes: dict[str, BaseException | None],
    events: list[object],
) -> None:
    class Client:
        def __init__(self, region: str, identity: DeviceIdentity) -> None:
            self.region = region
            self.device_identity = identity

        async def __aenter__(self) -> Client:
            events.append(("enter", self.region))
            return self

        async def __aexit__(self, *args: object) -> None:
            events.append(("exit", self.region))

        async def authenticate(self) -> None:
            events.append(("authenticate", self.region))
            outcome = outcomes[self.region]
            if outcome is not None:
                raise outcome

        async def get_devices(self) -> list[SimpleNamespace]:
            events.append(("get_devices", self.region))
            return [SimpleNamespace(name="Robot", model="S9-P", online=True)]

    class ClientFactory:
        @classmethod
        def from_credentials(
            cls,
            *args: object,
            **kwargs: object,
        ) -> Client:
            region = str(kwargs["region"])
            identity = kwargs["device_identity"]
            assert isinstance(identity, DeviceIdentity)
            events.append(("factory", region, identity))
            return Client(region, identity)

    monkeypatch.setattr(module, "Botslab360Client", ClientFactory)


def test_captcha_continues_once_on_same_client(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_example()
    challenge = CaptchaChallenge(b"synthetic-image", "secret-sc")
    events: list[object] = []
    writes: list[bytes] = []

    class Client:
        device_identity = IDENTITY

        async def __aenter__(self) -> Client:
            events.append("enter")
            return self

        async def __aexit__(self, *args: object) -> None:
            events.append("exit")

        async def authenticate(self) -> None:
            events.append("authenticate")
            raise CaptchaRequired(challenge, region="eu1", errmsg="captcha")

        async def continue_authentication(
            self,
            received_challenge: CaptchaChallenge,
            captcha_code: str,
        ) -> None:
            events.append(("continue", received_challenge, captcha_code))

        async def get_devices(self) -> list[SimpleNamespace]:
            events.append("get_devices")
            return [SimpleNamespace(name="Robot", model="S9-P", online=True)]

    client = Client()

    class ClientFactory:
        @classmethod
        def from_credentials(cls, *args: object, **kwargs: object) -> Client:
            events.append(("factory", kwargs["device_identity"]))
            return client

    monkeypatch.setattr(module, "Botslab360Client", ClientFactory)
    monkeypatch.setattr(module, "getpass", lambda prompt: "secret-code")
    monkeypatch.setattr(
        module.tempfile,
        "NamedTemporaryFile",
        lambda **kwargs: _CaptchaFile(writes),
    )

    result = asyncio.run(
        module.run_login(
            "user@example.invalid",
            "secret-password",
            "eu1",
            IDENTITY,
        )
    )
    output = capsys.readouterr().out

    assert result == 0
    assert events == [
        ("factory", IDENTITY),
        "enter",
        "authenticate",
        ("continue", challenge, "secret-code"),
        "get_devices",
        "exit",
    ]
    assert writes == [b"synthetic-image"]
    assert "Captcha image: synthetic-captcha.png" in output
    assert "Devices found: 1" in output
    assert "QUC authentication failed" not in output
    assert "secret-code" not in output
    assert "secret-sc" not in output


def test_incorrect_captcha_prints_safe_diagnostic_without_retry(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_example()
    challenge = CaptchaChallenge(b"synthetic-image", "secret-sc")
    events: list[object] = []

    class Client:
        device_identity = IDENTITY

        async def __aenter__(self) -> Client:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def authenticate(self) -> None:
            events.append("authenticate")
            raise CaptchaRequired(challenge, region="eu1", errmsg="captcha")

        async def continue_authentication(
            self,
            received_challenge: CaptchaChallenge,
            captcha_code: str,
        ) -> None:
            events.append(("continue", received_challenge, captcha_code))
            raise QucAuthenticationError(
                "QUC rejected the supplied credentials",
                region="eu1",
                errno=5011,
                errmsg="Verification code incorrect",
                status_code=200,
                user_present=False,
                captcha_required=False,
                captcha_type="graph",
            )

        async def get_devices(self) -> list[object]:
            pytest.fail("Device discovery must not run after captcha failure")

    client = Client()

    class ClientFactory:
        @classmethod
        def from_credentials(cls, *args: object, **kwargs: object) -> Client:
            return client

    monkeypatch.setattr(module, "Botslab360Client", ClientFactory)
    monkeypatch.setattr(module, "getpass", lambda prompt: "secret-code")
    monkeypatch.setattr(
        module.tempfile,
        "NamedTemporaryFile",
        lambda **kwargs: _CaptchaFile([]),
    )

    result = asyncio.run(
        module.run_login(
            "user@example.invalid",
            "secret-password",
            "eu1",
            IDENTITY,
        )
    )
    output = capsys.readouterr().out

    assert result == 1
    assert events == [
        "authenticate",
        ("continue", challenge, "secret-code"),
    ]
    assert "QUC authentication failed:" in output
    assert "errno: 5011" in output
    assert "message: Verification code incorrect" in output
    assert "diagnosis: incorrect captcha" in output
    assert "secret-code" not in output
    assert "secret-sc" not in output
    assert "secret-password" not in output


def test_probe_continues_from_eu1_to_na1_only_on_1036(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_example()
    events: list[object] = []
    _install_probe_factory(
        module,
        monkeypatch,
        {"eu1": _quc_error("eu1", 1036), "na1": None},
        events,
    )

    result = asyncio.run(
        module.run_login(
            "user@example.invalid",
            "secret-password",
            "eu1",
            IDENTITY,
            probe_regions=True,
        )
    )
    output = capsys.readouterr().out

    assert result == 0
    assert [event[1] for event in events if event[0] == "authenticate"] == [
        "eu1",
        "na1",
    ]
    assert "eu1 -> errno 1036 (account not found in this region)" in output
    assert "na1 -> errno 0 (authenticated)" in output
    assert "Selected region: na1" in output


def test_probe_checks_ap1_after_two_1036_responses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_example()
    events: list[object] = []
    _install_probe_factory(
        module,
        monkeypatch,
        {
            "eu1": _quc_error("eu1", 1036),
            "na1": _quc_error("na1", 1036),
            "ap1": None,
        },
        events,
    )

    result = asyncio.run(
        module.run_login(
            "user@example.invalid",
            "secret-password",
            "eu1",
            IDENTITY,
            probe_regions=True,
        )
    )

    assert result == 0
    assert [event[1] for event in events if event[0] == "authenticate"] == [
        "eu1",
        "na1",
        "ap1",
    ]


def test_probe_stops_immediately_on_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_example()
    events: list[object] = []
    _install_probe_factory(module, monkeypatch, {"eu1": None}, events)

    result = asyncio.run(
        module.run_login(
            "user@example.invalid",
            "secret-password",
            "eu1",
            IDENTITY,
            probe_regions=True,
        )
    )

    assert result == 0
    assert [event[1] for event in events if event[0] == "authenticate"] == ["eu1"]


def test_probe_stops_immediately_on_other_errno(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_example()
    events: list[object] = []
    _install_probe_factory(
        module,
        monkeypatch,
        {"eu1": _quc_error("eu1", 5011, "incorrect captcha")},
        events,
    )

    result = asyncio.run(
        module.run_login(
            "user@example.invalid",
            "secret-password",
            "eu1",
            IDENTITY,
            probe_regions=True,
        )
    )

    assert result == 1
    assert [event[1] for event in events if event[0] == "authenticate"] == ["eu1"]
    assert "eu1 -> errno 5011 (stopped)" in capsys.readouterr().out


def test_probe_stops_immediately_on_network_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_example()
    events: list[object] = []
    _install_probe_factory(
        module,
        monkeypatch,
        {
            "eu1": ApiError(
                "synthetic transport error",
                status_code=None,
                phase="transport",
            )
        },
        events,
    )

    result = asyncio.run(
        module.run_login(
            "user@example.invalid",
            "secret-password",
            "eu1",
            IDENTITY,
            probe_regions=True,
        )
    )

    assert result == 1
    assert [event[1] for event in events if event[0] == "authenticate"] == ["eu1"]
    assert "network/API error (stopped)" in capsys.readouterr().out


def test_probe_reuses_exact_identity_for_every_region(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_example()
    events: list[object] = []
    _install_probe_factory(
        module,
        monkeypatch,
        {
            "eu1": _quc_error("eu1", 1036),
            "na1": _quc_error("na1", 1036),
            "ap1": None,
        },
        events,
    )

    result = asyncio.run(
        module.run_login(
            "user@example.invalid",
            "secret-password",
            "eu1",
            IDENTITY,
            probe_regions=True,
        )
    )

    assert result == 0
    identities = [event[2] for event in events if event[0] == "factory"]
    assert len(identities) == 3
    assert all(identity is IDENTITY for identity in identities)


def test_probe_captcha_stays_on_selected_region_and_redacts_secrets(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_example()
    email = "secret-email@example.invalid"
    password = "secret-password"
    captcha_code = "secret-code"
    challenge = CaptchaChallenge(b"synthetic-image", "secret-sc")
    events: list[object] = []
    writes: list[bytes] = []

    class Client:
        device_identity = IDENTITY

        def __init__(self, region: str) -> None:
            self.region = region

        async def __aenter__(self) -> Client:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def authenticate(self) -> None:
            events.append(("authenticate", self.region))
            if self.region == "eu1":
                raise _quc_error("eu1", 1036)
            raise CaptchaRequired(
                challenge,
                region="na1",
                status_code=200,
                errmsg="captcha",
            )

        async def continue_authentication(
            self,
            received_challenge: CaptchaChallenge,
            received_code: str,
        ) -> None:
            events.append(("continue", self.region, received_challenge, received_code))
            raise _quc_error(
                "na1",
                1036,
                f"rejected {email} {password} {challenge.sc} {captcha_code}",
            )

        async def get_devices(self) -> list[object]:
            pytest.fail("Device discovery must not run after captcha failure")

    class ClientFactory:
        @classmethod
        def from_credentials(
            cls,
            *args: object,
            **kwargs: object,
        ) -> Client:
            assert kwargs["device_identity"] is IDENTITY
            return Client(str(kwargs["region"]))

    monkeypatch.setattr(module, "Botslab360Client", ClientFactory)
    monkeypatch.setattr(module, "getpass", lambda prompt: captcha_code)
    monkeypatch.setattr(
        module.tempfile,
        "NamedTemporaryFile",
        lambda **kwargs: _CaptchaFile(writes),
    )

    result = asyncio.run(
        module.run_login(
            email,
            password,
            "eu1",
            IDENTITY,
            probe_regions=True,
        )
    )
    output = capsys.readouterr().out

    assert result == 1
    assert events == [
        ("authenticate", "eu1"),
        ("authenticate", "na1"),
        ("continue", "na1", challenge, captcha_code),
    ]
    assert writes == [b"synthetic-image"]
    assert "na1 -> errno 5010 (captcha required)" in output
    assert "Selected region: na1" in output
    assert "ap1" not in output
    for secret in (email, password, challenge.sc, captcha_code):
        assert secret not in output


def test_identity_file_is_created_and_reused(tmp_path: Path) -> None:
    module = _load_example()
    path = tmp_path / "identity.json"

    created_identity, created = module._load_or_create_identity(path)
    loaded_identity, created_again = module._load_or_create_identity(path)

    assert created is True
    assert created_again is False
    assert loaded_identity == created_identity
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "mid": created_identity.mid,
        "android_id": created_identity.android_id,
        "m2": created_identity.m2,
    }
