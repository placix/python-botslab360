from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
from urllib.parse import parse_qs, quote

import httpx
import pytest

from botslab360 import DeviceIdentity
from botslab360.quc import (
    ANDROID_360_PROFILE,
    compute_signature,
    des_decrypt_base64,
    des_encrypt_base64,
    md5_hex,
)

IDENTITY = DeviceIdentity(
    mid="0123456789abcdef0123456789abcdef",
    android_id="0123456789abcdef",
    m2="12345678-1234-5678-9234-567812345678",
)


def _load_diagnostic() -> ModuleType:
    path = Path(__file__).parents[1] / "diagnostics" / "test_android_360_auth.py"
    spec = importlib.util.spec_from_file_location("android_360_diagnostic", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _response(payload: object) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "ret": des_encrypt_base64(
                json.dumps(payload, separators=(",", ":")),
                "AAAAAAAA",
            )
        },
    )


def _request_params(request: httpx.Request) -> dict[str, list[str]]:
    outer = parse_qs(request.content.decode(), keep_blank_values=True)
    ciphertext = outer["parad"][0]
    ciphertext += "=" * (-len(ciphertext) % 4)
    plaintext = des_decrypt_base64(ciphertext, "AAAAAAAA")
    return parse_qs(plaintext, keep_blank_values=True)


def test_default_dry_run_performs_no_network(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_diagnostic()

    class UnexpectedClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pytest.fail("dry-run must not allocate an HTTP client")

    monkeypatch.setattr(module.httpx, "AsyncClient", UnexpectedClient)
    monkeypatch.setattr(module, "_parse_args", lambda: type("Args", (), {
        "send_once": False,
        "continue_captcha": False,
        "mint_session_once": False,
        "identity": module.DEFAULT_IDENTITY_PATH,
    })())

    assert module.main() == 0
    output = capsys.readouterr().out
    assert "profile: android_360" in output
    assert "endpoint: https://passport.360.cn/request.php" in output
    assert "full-key length: 117" in output
    assert "signature_profile: android360" in output
    assert "random_charset_size: 70" in output
    assert "signing_suffix_present: true" in output
    assert "java_urlencoder: true" in output
    assert "des_mode: CBC" in output
    assert "des_iv_source: des_key" in output
    assert "offline_vectors_verified: true" in output
    assert "key_base64_padding: false" in output
    assert "parad_base64_padding: false" in output
    assert "generated_key_encoded_length: 171" in output
    assert "key_ends_with_padding: false" in output
    assert "parad_ends_with_padding: false" in output
    assert "sent: false" in output


def test_send_once_non_captcha_error_does_not_retry(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_diagnostic()
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _response({"errno": 1036, "errmsg": "safe diagnostic"})

    monkeypatch.setattr(
        "botslab360.quc._random_ascii",
        lambda length, charset: "A" * length,
    )
    async def scenario() -> int:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            return await module.send_once(
                "account-name",
                "synthetic-password",
                IDENTITY,
                http_client=http_client,
            )

    assert asyncio.run(scenario()) == 1
    assert len(requests) == 1
    request = requests[0]
    assert str(request.url) == "https://passport.360.cn/request.php"
    assert request.headers["user-agent"] == (
        "360accounts andv3.2.4 mpl_smarthome_and"
    )
    outer = parse_qs(request.content.decode())
    assert set(outer) == {
        "device_lang", "from", "key", "method", "parad", "quc_lang", "trace_id"
    }
    assert outer["from"] == ["mpl_smarthome_and"]
    assert len(outer["key"][0]) == 171
    assert not outer["key"][0].endswith("=")
    assert not outer["parad"][0].endswith("=")
    output = capsys.readouterr().out
    assert "errno: 1036" in output
    assert "captchaRequired: False" in output


def test_send_once_fetches_one_android_captcha_and_stops(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_diagnostic()
    requests: list[httpx.Request] = []
    sc = "opaque-captcha-token"
    image = b"synthetic-captcha-image"

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return _response(
                {
                    "errno": 5010,
                    "errmsg": "Show verification code",
                    "errdetail": {"captchaType": "graph"},
                }
            )
        assert len(requests) == 2
        assert str(request.url) == "https://passport.360.cn/request.php"
        assert request.headers["user-agent"] == (
            "360accounts andv3.2.4 mpl_smarthome_and"
        )
        outer = parse_qs(request.content.decode())
        assert outer["from"] == ["mpl_smarthome_and"]
        params = _request_params(request)
        assert params["method"] == ["UserIntf.getCaptcha"]
        signature = params.pop("sig")[0]
        flattened = {key: values[0] for key, values in params.items()}
        assert signature == compute_signature(
            flattened,
            profile=ANDROID_360_PROFILE,
        )
        return httpx.Response(
            200,
            content=image,
            headers={"Sc": sc, "Content-Type": "image/jpeg"},
        )

    monkeypatch.setattr(
        "botslab360.quc._random_ascii",
        lambda length, charset: "A" * length,
    )
    image_path = tmp_path / "captcha.jpg"

    async def scenario() -> int:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            return await module.send_once(
                "account-name",
                "synthetic-password",
                IDENTITY,
                http_client=http_client,
                captcha_path=image_path,
            )

    assert asyncio.run(scenario()) == 1
    assert len(requests) == 2
    assert image_path.read_bytes() == image
    output = capsys.readouterr().out
    assert "HTTP status: 200" in output
    assert f"image byte length: {len(image)}" in output
    assert "sc present: True" in output
    assert f"sc length: {len(sc)}" in output
    assert "content type: image/jpeg" in output
    assert str(image_path) in output
    assert sc not in output


@pytest.mark.parametrize(
    ("retry_payload", "expected_result"),
    [
        (
            {
                "errno": 0,
                "user": {
                    "q": "synthetic-q",
                    "t": "synthetic-t",
                    "qid": "synthetic-qid",
                },
            },
            0,
        ),
        ({"errno": 5011, "errmsg": "incorrect captcha"}, 1),
    ],
)
def test_continue_captcha_sends_exactly_one_retry(
    retry_payload: dict[str, object],
    expected_result: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_diagnostic()
    requests: list[httpx.Request] = []
    sc = "opaque-captcha-token"
    captcha_code = "2468"

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            return _response(
                {
                    "errno": 5010,
                    "errmsg": "Show verification code",
                    "errdetail": {"captchaType": "graph"},
                }
            )
        if len(requests) == 2:
            assert _request_params(request)["method"] == [
                "UserIntf.getCaptcha"
            ]
            return httpx.Response(
                200,
                content=b"image",
                headers={"sc": sc, "Content-Type": "image/png"},
            )
        assert len(requests) == 3
        params = _request_params(request)
        assert params["method"] == ["UserIntf.login"]
        assert params["sc"] == [sc]
        assert params["uc"] == [captcha_code]
        assert params["captchaType"] == ["graph"]
        return _response(retry_payload)

    monkeypatch.setattr(
        "botslab360.quc._random_ascii",
        lambda length, charset: "A" * length,
    )
    monkeypatch.setattr(module, "getpass", lambda prompt: captcha_code)

    async def scenario() -> int:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            return await module.send_once(
                "account-name",
                "synthetic-password",
                IDENTITY,
                http_client=http_client,
                continue_captcha=True,
                captcha_path=tmp_path / "captcha.png",
            )

    assert asyncio.run(scenario()) == expected_result
    assert len(requests) == 3
    assert all(request.url.host == "passport.360.cn" for request in requests)
    output = capsys.readouterr().out
    assert sc not in output
    assert captcha_code not in output
    assert "synthetic-q" not in output
    assert "synthetic-t" not in output
    assert "synthetic-qid" not in output
    if expected_result == 0:
        assert "q present: True" in output
        assert "t present: True" in output
        assert "qid present: True" in output
    else:
        assert "errno: 5011" in output


def test_mint_session_once_reuses_quc_credentials_without_follow_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_diagnostic()
    requests: list[httpx.Request] = []
    qid = "1234567890"
    q_raw = f"u=360H{qid}&n=synthetic&m=not-a-real-token"
    t_raw = "s=synthetic-session&t=1700000000&v=2.0"
    sc = "opaque-captcha-token"
    captcha_code = "2468"
    sid = "synthetic-smart-sid"
    push_key = "synthetic-push-key"

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        step = len(requests)
        if step == 1:
            return _response(
                {
                    "errno": 5010,
                    "errmsg": "Show verification code",
                    "errdetail": {"captchaType": "graph"},
                }
            )
        if step == 2:
            return httpx.Response(
                200,
                content=b"image",
                headers={"sc": sc, "Content-Type": "image/png"},
            )
        if step == 3:
            params = _request_params(request)
            assert params["sc"] == [sc]
            assert params["uc"] == [captcha_code]
            assert params["captchaType"] == ["graph"]
            return _response(
                {
                    "errno": 0,
                    "errmsg": "OK",
                    "user": {
                        "q": quote(q_raw, safe=""),
                        "t": quote(t_raw, safe=""),
                        "qid": qid,
                    },
                }
            )
        assert step == 4
        assert request.url == "https://q.smart.360.cn/common/user/login"
        assert request.headers["user-agent"] == "qhsa-iphone-11.1.0"
        assert request.headers["cookie"] == f"q={q_raw};t={t_raw};qid={qid}"
        form = parse_qs(request.content.decode(), keep_blank_values=True)
        assert set(form) == {"clientInfo", "lang", "phoneNum", "taskid"}
        return httpx.Response(
            200,
            json={
                "errno": 0,
                "errmsg": "OK",
                "data": {"sid": sid, "pushKey": push_key},
            },
        )

    monkeypatch.setattr(
        "botslab360.quc._random_ascii",
        lambda length, charset: "A" * length,
    )
    monkeypatch.setattr(module, "getpass", lambda prompt: captcha_code)
    monkeypatch.setattr(
        module,
        "input",
        lambda prompt: module.MINT_CONFIRMATION,
        raising=False,
    )

    async def unexpected_follow_up(*args: object, **kwargs: object) -> None:
        pytest.fail("No device discovery or TCP connection expected")

    monkeypatch.setattr(
        "botslab360.client.Botslab360Client.get_devices",
        unexpected_follow_up,
    )
    monkeypatch.setattr(asyncio, "open_connection", unexpected_follow_up)

    async def scenario() -> int:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            return await module.send_once(
                "account-name",
                "synthetic-password",
                IDENTITY,
                http_client=http_client,
                continue_captcha=True,
                mint_session_once=True,
                captcha_path=tmp_path / "captcha.png",
            )

    assert asyncio.run(scenario()) == 0
    assert len(requests) == 4
    assert [request.url.host for request in requests] == [
        "passport.360.cn",
        "passport.360.cn",
        "passport.360.cn",
        "q.smart.360.cn",
    ]
    output = capsys.readouterr().out
    assert "QUC credentials obtained: True" in output
    assert "sid present: True" in output
    assert "pushKey present: True" in output
    for secret in (
        q_raw,
        quote(q_raw, safe=""),
        t_raw,
        quote(t_raw, safe=""),
        qid,
        sid,
        push_key,
        sc,
        captcha_code,
    ):
        assert secret not in output


def test_mint_session_is_skipped_when_quc_credentials_are_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_diagnostic()
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return _response(
            {
                "errno": 0,
                "errmsg": "OK",
                "user": {"q": "synthetic-q", "qid": "1234567890"},
            }
        )

    monkeypatch.setattr(
        "botslab360.quc._random_ascii",
        lambda length, charset: "A" * length,
    )
    monkeypatch.setattr(
        module,
        "input",
        lambda prompt: pytest.fail("Mint confirmation must not be requested"),
        raising=False,
    )

    async def scenario() -> int:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            return await module.send_once(
                "account-name",
                "synthetic-password",
                IDENTITY,
                http_client=http_client,
                continue_captcha=True,
                mint_session_once=True,
            )

    assert asyncio.run(scenario()) == 1
    assert requests == 1


def test_mint_session_requires_second_exact_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_diagnostic()
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        assert requests == 1
        return _response(
            {
                "errno": 0,
                "errmsg": "OK",
                "user": {
                    "q": "u=360H1234567890&n=synthetic",
                    "t": "s=synthetic-session",
                    "qid": "1234567890",
                },
            }
        )

    monkeypatch.setattr(
        "botslab360.quc._random_ascii",
        lambda length, charset: "A" * length,
    )
    monkeypatch.setattr(
        module,
        "input",
        lambda prompt: "MINT ONE ANDROID 360 SESSION ",
        raising=False,
    )

    async def scenario() -> int:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            return await module.send_once(
                "account-name",
                "synthetic-password",
                IDENTITY,
                http_client=http_client,
                continue_captcha=True,
                mint_session_once=True,
            )

    assert asyncio.run(scenario()) == 1
    assert requests == 1


def test_send_once_redacts_credentials_and_crypto_secrets(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_diagnostic()
    account = "private-account"
    password = "private-password"
    captured: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        outer = parse_qs(request.content.decode())
        captured.extend([outer["key"][0], outer["parad"][0], "AAAAAAAA"])
        message = " | ".join(
            [account, password, md5_hex(password), *captured]
        )
        return _response({"errno": 1036, "errmsg": message})

    monkeypatch.setattr(
        "botslab360.quc._random_ascii",
        lambda length, charset: "A" * length,
    )
    async def scenario() -> int:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            return await module.send_once(
                account,
                password,
                IDENTITY,
                http_client=http_client,
            )

    assert asyncio.run(scenario()) == 1
    output = capsys.readouterr().out
    for secret in (account, password, md5_hex(password), *captured):
        assert secret not in output


def test_success_does_not_continue_to_smart_login(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _load_diagnostic()
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return _response(
            {
                "errno": 0,
                "user": {
                    "q": "synthetic-q",
                    "t": "synthetic-t",
                    "qid": "synthetic-qid",
                },
            }
        )

    monkeypatch.setattr(
        "botslab360.quc._random_ascii",
        lambda length, charset: "A" * length,
    )

    async def scenario() -> int:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            return await module.send_once(
                "account-name",
                "synthetic-password",
                IDENTITY,
                http_client=http_client,
            )

    assert asyncio.run(scenario()) == 0
    assert requests == 1
    output = capsys.readouterr().out
    assert "QUC credentials obtained: True" in output
    assert "synthetic-q" not in output
    assert "synthetic-t" not in output
    assert "synthetic-qid" not in output


def test_identity_file_is_reused(tmp_path: Path) -> None:
    module = _load_diagnostic()
    path = tmp_path / "identity.json"

    created_identity, created = module._load_or_create_identity(path)
    loaded_identity, created_again = module._load_or_create_identity(path)

    assert created is True
    assert created_again is False
    assert loaded_identity == created_identity


@pytest.mark.parametrize(
    ("confirmation", "expected_calls"),
    [
        ("SEND ONE ANDROID 360 LOGIN", 1),
        ("SEND ONE ANDROID 360 LOGIN ", 0),
        ("send one android 360 login", 0),
    ],
)
def test_send_requires_exact_confirmation(
    confirmation: str,
    expected_calls: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_diagnostic()
    answers = iter(("account-name", confirmation))
    calls = 0

    async def fake_send_once(*args: object, **kwargs: object) -> int:
        nonlocal calls
        calls += 1
        return 0

    monkeypatch.setattr(
        module,
        "_parse_args",
        lambda: SimpleNamespace(
            send_once=True,
            continue_captcha=False,
            mint_session_once=False,
            identity=tmp_path / "identity.json",
        ),
    )
    monkeypatch.setattr(
        module, "input", lambda prompt: next(answers), raising=False
    )
    monkeypatch.setattr(module, "getpass", lambda prompt: "synthetic-password")
    monkeypatch.setattr(module, "send_once", fake_send_once)

    result = module.main()

    assert calls == expected_calls
    assert result == (0 if expected_calls else 1)


def test_continue_captcha_requires_exact_confirmation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_diagnostic()
    answers = iter(("account-name", module.CAPTCHA_CONFIRMATION))
    calls: list[bool] = []

    async def fake_send_once(
        *args: object, continue_captcha: bool = False, **kwargs: object
    ) -> int:
        calls.append(continue_captcha)
        return 0

    monkeypatch.setattr(
        module,
        "_parse_args",
        lambda: SimpleNamespace(
            send_once=False,
            continue_captcha=True,
            mint_session_once=False,
            identity=tmp_path / "identity.json",
        ),
    )
    monkeypatch.setattr(
        module, "input", lambda prompt: next(answers), raising=False
    )
    monkeypatch.setattr(module, "getpass", lambda prompt: "synthetic-password")
    monkeypatch.setattr(module, "send_once", fake_send_once)

    assert module.main() == 0
    assert calls == [True]
