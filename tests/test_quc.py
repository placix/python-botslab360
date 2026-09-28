from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
from urllib.parse import parse_qs, quote
from uuid import UUID

import httpx
import pytest

from botslab360 import (
    AuthBackend,
    AuthenticationError,
    Botslab360Client,
    CaptchaChallenge,
    CaptchaRequired,
    DeviceIdentity,
    QucAuthenticationError,
)
from botslab360.quc import (
    ANDROID_360_PROFILE,
    BOTSLAB_CLOUD_PROFILE,
    OUTER_FORM_FIELDS,
    QUC_FROM,
    QUC_USER_AGENT,
    QucAuth,
    _ANDROID_INNER_PARAMETER_ORDER,
    _ANDROID_RANDOM_CHARSET,
    _encode_base64,
    _java_urlencode_component,
    _rsa_public_key,
    _serialize_inner_params,
    build_envelope,
    compute_signature,
    des_decrypt_base64,
    des_encrypt_base64,
    md5_hex,
    rsa_encrypt_key,
)

QID = "1234567890"
Q_VALUE = f"u=360H{QID}&n=synthetic&m=not-a-real-token"
T_VALUE = "s=synthetic-session&t=1700000000&v=2.0"
IDENTITY = DeviceIdentity(
    mid="0123456789abcdef0123456789abcdef",
    android_id="0123456789abcdef",
    m2="12345678-1234-5678-9234-567812345678",
)


def _android_vector_params() -> dict[str, str]:
    return {
        "device_lang": "zh-CN",
        "app": "360Robot",
        "device_os": "android",
        "format": "json",
        "from": "mpl_smarthome_and",
        "mSystemVersion": "android 15",
        "method": "UserIntf.login",
        "mname": "",
        "oaid": "dummy-oaid",
        "os_board": "goldfish_x86_64",
        "os_manufacturer": "Google",
        "os_model": "sdk_gphone64_x86_64",
        "os_sdk_version": "android_35",
        "quc_lang": "en",
        "quc_sdk_version": "v3.2.4",
        "res_mode": "1",
        "sdpi": "2.75",
        "sh": "2138.0",
        "sw": "1080.0",
        "ua": (
            "Dalvik/2.1.0 (Linux; U; Android 15; "
            "sdk_gphone64_x86_64 Build/AE3A.240806.043)"
        ),
        "ui_ver": "4.2.8.1-alert-ui",
        "v": "11.1.7",
        "androidid": "0123456789abcdef",
        "mid": "0123456789abcdef0123456789abcdef",
        "qh_id": "dummy-qh-id",
        "vt_guid": "1700000000000",
        "fields": "qid,username,nickname,loginemail,head_pic,mobile",
        "head_type": "q",
        "is_keep_alive": "1",
        "loginType": "801",
        "needDeviceCheck": "1",
        "password": md5_hex("dummy-password"),
        "sec_type": "bool",
        "trace_id": "src_and_1916_1700000000000",
        "username": "dummy@example.invalid",
    }


def run(coro):
    return asyncio.run(coro)


def _encrypted_response(payload: object, key: str = "AAAAAAAA") -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "ret": des_encrypt_base64(
                json.dumps(payload, separators=(",", ":")),
                key,
            )
        },
    )


def _decrypt_request(
    request: httpx.Request, key: str = "AAAAAAAA"
) -> dict[str, list[str]]:
    outer = parse_qs(request.content.decode(), keep_blank_values=True)
    ciphertext = outer["parad"][0]
    ciphertext += "=" * (-len(ciphertext) % 4)
    plaintext = des_decrypt_base64(ciphertext, key)
    return parse_qs(plaintext, keep_blank_values=True)


def test_compute_signature_sorts_raw_values_and_excludes_sig() -> None:
    params = {"z": "last", "sig": "ignored", "a": "first", "A": "upper"}

    assert compute_signature(params) == "5aab09e6dd9cf40a7027a630c8bb13dc"
    assert compute_signature({**params, "sig": "different"}) == compute_signature(
        params
    )


def test_password_md5_is_utf8_and_not_plaintext(
    caplog: pytest.LogCaptureFixture,
) -> None:
    password = "synthetic-password-never-log"

    with caplog.at_level(logging.DEBUG):
        digest = md5_hex(password)

    assert digest == "50e4ab3c179df4824c4603a59e2e710c"
    assert password not in caplog.text


def test_generated_device_identity_formats() -> None:
    identity = DeviceIdentity.generate()

    assert re.fullmatch(r"[0-9a-f]{32}", identity.mid)
    assert re.fullmatch(r"[0-9a-f]{16}", identity.android_id)
    assert str(UUID(identity.m2)) == identity.m2


def test_supplied_device_identity_is_preserved() -> None:
    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: pytest.fail("No HTTP request expected")
            )
        ) as http_client:
            client = Botslab360Client.from_credentials(
                "user@example.invalid",
                "synthetic-password",
                device_identity=IDENTITY,
                http_client=http_client,
            )
            assert client.device_identity is IDENTITY
            assert client.auth_backend is AuthBackend.BOTSLAB
            assert client._quc_auth is not None
            assert client._quc_auth.url == (
                "https://eu1-sapp-login.botslab.com/request.php"
            )

    run(scenario())


def test_auth_backend_is_public_typed_selection() -> None:
    assert AuthBackend.BOTSLAB.value == "botslab"
    assert AuthBackend.ROBOT360.value == "robot360"


@pytest.mark.parametrize(
    ("backend", "region", "expected_url"),
    [
        (
            AuthBackend.BOTSLAB,
            "na1",
            "https://na1-sapp-login.botslab.com/request.php",
        ),
        (
            AuthBackend.ROBOT360,
            None,
            "https://passport.360.cn/request.php",
        ),
    ],
)
def test_explicit_credential_backend_selects_only_its_profile(
    backend: AuthBackend,
    region: str | None,
    expected_url: str,
) -> None:
    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: pytest.fail("No HTTP request expected")
            )
        ) as http_client:
            client = Botslab360Client.from_credentials(
                "user@example.invalid",
                "synthetic-password",
                backend=backend,
                region=region,
                device_identity=IDENTITY,
                http_client=http_client,
            )
            assert client.auth_backend is backend
            assert client._quc_auth is not None
            assert client._quc_auth.url == expected_url

    run(scenario())


def test_robot360_backend_rejects_region_without_network() -> None:
    with pytest.raises(ValueError, match="region is not supported"):
        Botslab360Client.from_credentials(
            "user@example.invalid",
            "synthetic-password",
            backend=AuthBackend.ROBOT360,
            region="eu1",
            device_identity=IDENTITY,
        )


def test_credential_client_rejects_unknown_region_without_network() -> None:
    async def scenario() -> None:
        async with httpx.AsyncClient() as http_client:
            with pytest.raises(ValueError, match="region"):
                Botslab360Client.from_credentials(
                    "user@example.invalid",
                    "synthetic-password",
                    region="invalid",
                    http_client=http_client,
                )

    run(scenario())


def test_des_envelope_roundtrip_and_known_ciphertext() -> None:
    ciphertext = des_encrypt_base64("a=1&message=hello", "12345678")

    assert ciphertext == "sxvBJP0328GQcekQUqeUjOBsoZBREoQl"
    assert des_decrypt_base64(ciphertext, "12345678") == "a=1&message=hello"
    assert len(base64.b64decode(ciphertext)) % 8 == 0


def test_rsa_envelope_key_uses_1024_bit_public_key() -> None:
    encrypted = base64.b64decode(rsa_encrypt_key("A" * 114))

    assert _rsa_public_key().key_size == 1024
    assert len(encrypted) == 128


def test_build_envelope_uses_last_eight_bytes_as_des_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "botslab360.quc._random_ascii",
        lambda length, charset: "A" * length,
    )

    envelope, key = build_envelope({"message": "space and / punctuation!"})

    assert key == "AAAAAAAA"
    assert des_decrypt_base64(envelope["parad"], key) == (
        "message=space%20and%20%2F%20punctuation!"
    )


def test_cloud_profile_preserves_existing_transport_values() -> None:
    profile = BOTSLAB_CLOUD_PROFILE

    assert profile.endpoint("eu1") == (
        "https://eu1-sapp-login.botslab.com/request.php"
    )
    assert profile.from_value == QUC_FROM == "mpl_cloudsmartoem_and"
    assert profile.user_agent == QUC_USER_AGENT
    assert profile.login_type == "801"
    assert profile.need_device_check == 0
    assert profile.full_random_key_length == 114
    assert profile.des_key_length == 8
    assert profile.random_charset == (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    )
    assert profile.rsa_base64_padding is True
    assert profile.des_base64_padding is True
    assert profile.signing_strategy == "cloud"
    assert profile.signing_suffix == ""
    assert profile.inner_encoding_strategy == "javascript_component"
    assert profile.inner_parameter_order is None
    assert profile.app == "Botslab"
    assert profile.quc_sdk_version == "v3.2.4.6"
    assert profile.ui_version == "4.3.4.1-alert-ui"
    assert profile.app_version == "2.24.0"


def test_android_profile_uses_runtime_confirmed_values() -> None:
    profile = ANDROID_360_PROFILE

    assert profile.endpoint("eu1") == "https://passport.360.cn/request.php"
    assert profile.from_value == "mpl_smarthome_and"
    assert profile.user_agent == "360accounts andv3.2.4 mpl_smarthome_and"
    assert profile.login_type == "801"
    assert profile.need_device_check == 1
    assert profile.full_random_key_length == 117
    assert profile.des_key_length == 8
    assert profile.random_charset == _ANDROID_RANDOM_CHARSET
    assert len(profile.random_charset) == 70
    assert hashlib.sha256(profile.random_charset.encode("ascii")).hexdigest() == (
        "9ca4f3450cc3052e7bc1bdb2559264a9cd2ba8b8e2669e2048f9140a1efde689"
    )
    assert profile.rsa_base64_padding is False
    assert profile.des_base64_padding is False
    assert profile.signing_strategy == "android360"
    assert profile.signing_suffix == "i7v2m5x6q"
    assert profile.inner_encoding_strategy == "java_urlencoder"
    assert profile.inner_parameter_order == _ANDROID_INNER_PARAMETER_ORDER
    assert profile.app == "360Robot"
    assert profile.quc_sdk_version == "v3.2.4"
    assert profile.ui_version == "4.2.8.1-alert-ui"
    assert profile.app_version == "11.1.7"
    assert profile.native_crypto_verified is True


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("a b", "a+b"),
        ("a+b", "a%2Bb"),
        ("a/b", "a%2Fb"),
        ("a=b", "a%3Db"),
        ("a%b", "a%25b"),
        ("Grüße", "Gr%C3%BC%C3%9Fe"),
        ("(value)", "%28value%29"),
        ("*.-_", "*.-_"),
    ],
)
def test_java_urlencoder_matches_android(value: str, expected: str) -> None:
    assert _java_urlencode_component(value) == expected


def test_android_offline_signature_plaintext_des_and_parad_vectors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    params = _android_vector_params()
    signature = compute_signature(params, profile=ANDROID_360_PROFILE)
    assert signature == "f7e02d0861f0a76cb4e1ceea6d22bc53"
    params["sig"] = signature

    plaintext = _serialize_inner_params(params, profile=ANDROID_360_PROFILE)
    plaintext_bytes = plaintext.encode("utf-8")
    assert len(plaintext_bytes) == 854
    assert hashlib.sha256(plaintext_bytes).hexdigest() == (
        "ef0a2c963c58ef772d8a02af1db69d21c0c5d580694b897c2ea5c5f7933581a2"
    )
    assert plaintext.startswith("loginType=801&os_sdk_version=android_35")
    assert "Dalvik%2F2.1.0+%28Linux%3B+U" in plaintext

    def fixed_random(length: int, charset: str) -> str:
        assert charset == _ANDROID_RANDOM_CHARSET
        if length == 109:
            return "A" * 109
        assert length == 8
        return "DESkey8!"

    monkeypatch.setattr("botslab360.quc._random_ascii", fixed_random)
    envelope, des_key = build_envelope(params, profile=ANDROID_360_PROFILE)
    cipher = base64.b64decode(envelope["parad"] + "==")

    assert des_key == "DESkey8!"
    assert len(cipher) == 856
    assert hashlib.sha256(cipher).hexdigest() == (
        "364d7f4bd30f474e6cd82007bf682ed121e1bcaf519ab7658da1728f12cc0df8"
    )
    assert len(envelope["parad"]) == 1142
    assert hashlib.sha256(envelope["parad"].encode("ascii")).hexdigest() == (
        "a035815e5f3b039db674ab47b72304d346265e09b09e4ebcff3665d4c1b9c6fc"
    )
    assert not envelope["parad"].endswith("=")
    assert "\n" not in envelope["parad"] and "\r" not in envelope["parad"]


def test_profile_key_lengths_and_des_key_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested: list[tuple[int, str]] = []

    def random_ascii(length: int, charset: str) -> str:
        requested.append((length, charset))
        return "A" * (length - 8) + "12345678"

    monkeypatch.setattr("botslab360.quc._random_ascii", random_ascii)

    cloud_envelope, cloud_key = build_envelope(
        {}, profile=BOTSLAB_CLOUD_PROFILE
    )
    android_envelope, android_key = build_envelope(
        {}, profile=ANDROID_360_PROFILE
    )

    assert requested == [
        (106, BOTSLAB_CLOUD_PROFILE.random_charset),
        (8, BOTSLAB_CLOUD_PROFILE.random_charset),
        (109, ANDROID_360_PROFILE.random_charset),
        (8, ANDROID_360_PROFILE.random_charset),
    ]
    assert cloud_key == "12345678"
    assert android_key == "12345678"
    assert len(cloud_envelope["key"]) == 172
    assert cloud_envelope["key"].endswith("=")
    assert cloud_envelope["parad"].endswith("=")
    assert len(android_envelope["key"]) == 171
    assert not android_envelope["key"].endswith("=")
    assert not android_envelope["parad"].endswith("=")


def test_base64_padding_lengths_wrapping_and_alphabet() -> None:
    raw_rsa_ciphertext = bytes(range(128))

    padded = _encode_base64(raw_rsa_ciphertext, padding_enabled=True)
    unpadded = _encode_base64(raw_rsa_ciphertext, padding_enabled=False)

    assert len(padded) == 172
    assert padded.endswith("=")
    assert len(unpadded) == 171
    assert not unpadded.endswith("=")
    assert "\n" not in padded
    assert "\r" not in padded
    assert _encode_base64(b"\xfb\xff", padding_enabled=True) == "+/8="
    assert _encode_base64(b"\xfb\xff", padding_enabled=False) == "+/8"


def test_android_profile_outer_form_has_only_observed_fields() -> None:
    form = QucAuth._outer_form(
        {"trace_id": "trace", "method": "UserIntf.login", "sig": "secret"},
        {"parad": "encrypted", "key": "wrapped"},
        profile=ANDROID_360_PROFILE,
    )

    assert set(form) == set(OUTER_FORM_FIELDS)
    assert form["from"] == "mpl_smarthome_and"
    assert "sig" not in form


def test_android_profile_builds_all_observed_common_keys() -> None:
    auth = QucAuth(
        httpx.AsyncClient(),
        email="account-name",
        password="synthetic-password",
        region=None,
        identity=IDENTITY,
        _profile=ANDROID_360_PROFILE,
    )
    try:
        params = auth._login_params()
    finally:
        run(auth._http_client.aclose())

    assert set(params) == {
        "androidid",
        "app",
        "device_lang",
        "device_os",
        "fields",
        "format",
        "from",
        "head_type",
        "is_keep_alive",
        "loginType",
        "mSystemVersion",
        "method",
        "mid",
        "mname",
        "needDeviceCheck",
        "oaid",
        "os_board",
        "os_manufacturer",
        "os_model",
        "os_sdk_version",
        "password",
        "qh_id",
        "quc_lang",
        "quc_sdk_version",
        "res_mode",
        "sdpi",
        "sec_type",
        "sh",
        "sig",
        "sw",
        "trace_id",
        "ua",
        "ui_ver",
        "username",
        "v",
        "vt_guid",
    }
    assert params["from"] == "mpl_smarthome_and"
    assert params["loginType"] == "801"
    assert params["needDeviceCheck"] == "1"
    assert params["app"] == "360Robot"
    assert params["quc_sdk_version"] == "v3.2.4"
    assert params["ui_ver"] == "4.2.8.1-alert-ui"
    assert params["v"] == "11.1.7"
    assert params["oaid"] == ""


def test_outer_form_encoding_matches_url_search_params() -> None:
    form = QucAuth._outer_form(
        {
            "trace_id": "src_and_1916_123",
            "method": "UserIntf.login",
        },
        {"parad": "ab+/=", "key": "xy+/="},
    )
    request = httpx.Request("POST", "https://example.invalid", data=form)

    assert request.content == (
        b"device_lang=zh-CN&trace_id=src_and_1916_123&quc_lang=en&"
        b"method=UserIntf.login&from=mpl_cloudsmartoem_and&"
        b"parad=ab%2B%2F%3D&key=xy%2B%2F%3D"
    )


def test_successful_quc_login_then_existing_smart_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        requests: list[httpx.Request] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if request.url.host == "eu1-sapp-login.botslab.com":
                assert request.headers["user-agent"] == QUC_USER_AGENT
                assert request.headers["connection"] == "close"
                outer = parse_qs(request.content.decode())
                assert outer["from"] == [QUC_FROM]
                assert outer["method"] == ["UserIntf.login"]
                params = _decrypt_request(request)
                assert params["username"] == ["user@example.invalid"]
                assert params["password"] == [md5_hex("synthetic-password")]
                assert params["loginType"] == ["801"]
                assert params["needDeviceCheck"] == ["0"]
                assert params["mid"] == [IDENTITY.mid]
                assert params["androidid"] == [IDENTITY.android_id]
                assert "m2" not in params
                signature = params.pop("sig")[0]
                flattened = {key: values[0] for key, values in params.items()}
                assert signature == compute_signature(flattened)
                return _encrypted_response(
                    {
                        "errno": 0,
                        "user": {
                            "q": quote(Q_VALUE, safe=""),
                            "t": quote(T_VALUE, safe=""),
                            "qid": QID,
                        },
                    }
                )

            assert request.url == "https://q.smart.360.cn/common/user/login"
            assert request.headers["cookie"] == f"q={Q_VALUE};t={T_VALUE};qid={QID}"
            return httpx.Response(
                200,
                json={
                    "errno": 0,
                    "data": {"sid": "synthetic-sid", "pushKey": "synthetic-key"},
                },
            )

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            client = Botslab360Client.from_credentials(
                "user@example.invalid",
                "synthetic-password",
                device_identity=IDENTITY,
                http_client=http_client,
            )
            session = await client.authenticate()

        assert session.sid == "synthetic-sid"
        assert len(requests) == 2
        assert QID not in client.account_fingerprint

    monkeypatch.setattr(
        "botslab360.quc._random_ascii",
        lambda length, charset: "A" * length,
    )
    run(scenario())


def test_quc_login_error_preserves_safe_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: _encrypted_response(
                    {"errno": 103, "errmsg": "credentials rejected"}
                )
            )
        ) as http_client:
            client = Botslab360Client.from_credentials(
                "secret-email@example.invalid",
                "secret-password",
                device_identity=IDENTITY,
                http_client=http_client,
            )
            with pytest.raises(QucAuthenticationError) as raised:
                await client.authenticate()

        error = raised.value
        rendered = str(error)
        assert isinstance(error, AuthenticationError)
        assert error.region == "eu1"
        assert error.http_status == 200
        assert error.errno == 103
        assert error.errmsg == "credentials rejected"
        assert error.user_present is False
        assert error.captcha_required is False
        assert error.captcha_type is None
        assert "secret-email" not in rendered
        assert "secret-password" not in rendered

    monkeypatch.setattr(
        "botslab360.quc._random_ascii",
        lambda length, charset: "A" * length,
    )
    run(scenario())


def test_quc_login_error_redacts_request_and_crypto_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        captured_secrets: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            outer = parse_qs(request.content.decode())
            captured_secrets.extend(
                [outer["parad"][0], outer["key"][0], "AAAAAAAA"]
            )
            unsafe_message = " | ".join(
                [
                    "secret-email@example.invalid",
                    "secret-password",
                    md5_hex("secret-password"),
                    *captured_secrets,
                ]
            )
            return _encrypted_response({"errno": 5011, "errmsg": unsafe_message})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            client = Botslab360Client.from_credentials(
                "secret-email@example.invalid",
                "secret-password",
                device_identity=IDENTITY,
                http_client=http_client,
            )
            with pytest.raises(QucAuthenticationError) as raised:
                await client.authenticate()

        diagnostic = f"{raised.value} {raised.value.errmsg}"
        assert raised.value.errno == 5011
        for secret in (
            "secret-email@example.invalid",
            "secret-password",
            md5_hex("secret-password"),
            *captured_secrets,
        ):
            assert secret not in diagnostic

    monkeypatch.setattr(
        "botslab360.quc._random_ascii",
        lambda length, charset: "A" * length,
    )
    run(scenario())


def test_captcha_challenge_and_explicit_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario() -> None:
        step = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal step
            step += 1
            if step == 1:
                return _encrypted_response(
                    {
                        "errno": 5010,
                        "errmsg": "captcha required",
                        "errdetail": {"captchaType": "graph"},
                    }
                )
            if step == 2:
                assert parse_qs(request.content.decode())["method"] == [
                    "UserIntf.getCaptcha"
                ]
                return httpx.Response(
                    200,
                    content=b"synthetic-image-bytes",
                    headers={"Sc": "opaque%2Btoken"},
                )
            if step == 3:
                params = _decrypt_request(request)
                assert params["sc"] == ["opaque+token"]
                assert params["uc"] == ["1234"]
                assert params["captchaType"] == ["graph"]
                return _encrypted_response(
                    {
                        "errno": 0,
                        "user": {"q": Q_VALUE, "t": T_VALUE, "qid": QID},
                    }
                )
            assert step == 4
            return httpx.Response(
                200,
                json={
                    "errno": 0,
                    "data": {"sid": "synthetic-sid", "pushKey": "synthetic-key"},
                },
            )

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            client = Botslab360Client.from_credentials(
                "user@example.invalid",
                "synthetic-password",
                device_identity=IDENTITY,
                http_client=http_client,
            )
            with pytest.raises(CaptchaRequired) as raised:
                await client.authenticate()

            challenge = raised.value.challenge
            assert raised.value.region == "eu1"
            assert raised.value.http_status == 200
            assert raised.value.errno == 5010
            assert raised.value.errmsg == "captcha required"
            assert raised.value.user_present is False
            assert raised.value.captcha_required is True
            assert raised.value.captcha_type == "graph"
            assert challenge.image == b"synthetic-image-bytes"
            assert challenge.sc == "opaque+token"
            assert "opaque+token" not in repr(challenge)
            session = await client.continue_authentication(challenge, "1234")

        assert session.sid == "synthetic-sid"
        assert step == 4

    monkeypatch.setattr(
        "botslab360.quc._random_ascii",
        lambda length, charset: "A" * length,
    )
    run(scenario())


def test_android_profile_5010_creates_redacted_challenge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        requests: list[httpx.Request] = []
        sc = "android-opaque-token"

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            assert request.url == "https://passport.360.cn/request.php"
            assert request.headers["user-agent"] == ANDROID_360_PROFILE.user_agent
            if len(requests) == 1:
                return _encrypted_response(
                    {
                        "errno": 5010,
                        "errmsg": "Show verification code",
                        "errdetail": {"captchaType": "graph"},
                    }
                )
            assert len(requests) == 2
            outer = parse_qs(request.content.decode())
            assert outer["from"] == [ANDROID_360_PROFILE.from_value]
            assert outer["method"] == ["UserIntf.getCaptcha"]
            return httpx.Response(
                200,
                content=b"android-captcha-image",
                headers={"sc": sc, "Content-Type": "image/png"},
            )

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            auth = QucAuth(
                http_client,
                email="account-name",
                password="synthetic-password",
                region=None,
                identity=IDENTITY,
                _profile=ANDROID_360_PROFILE,
            )
            with pytest.raises(CaptchaRequired) as raised:
                await auth.login()

        assert len(requests) == 2
        assert raised.value.challenge.image == b"android-captcha-image"
        assert raised.value.challenge.sc == sc
        assert sc not in repr(raised.value.challenge)
        assert sc not in repr(raised.value)

    monkeypatch.setattr(
        "botslab360.quc._random_ascii",
        lambda length, charset: "A" * length,
    )
    run(scenario())


def test_public_robot360_captcha_flow_mints_and_stores_smart_session(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def scenario() -> None:
        requests: list[httpx.Request] = []
        sc = "robot360-opaque-token"
        captcha_code = "2468"
        sid = "synthetic-robot360-sid"
        push_key = "synthetic-robot360-push-key"

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            step = len(requests)
            if step == 1:
                assert request.url.host == "passport.360.cn"
                return _encrypted_response(
                    {
                        "errno": 5010,
                        "errmsg": "Show verification code",
                        "errdetail": {"captchaType": "graph"},
                    }
                )
            if step == 2:
                assert request.url.host == "passport.360.cn"
                assert parse_qs(request.content.decode())["method"] == [
                    "UserIntf.getCaptcha"
                ]
                return httpx.Response(
                    200,
                    content=b"synthetic-captcha-image",
                    headers={"sc": sc, "Content-Type": "image/png"},
                )
            if step == 3:
                assert request.url.host == "passport.360.cn"
                params = _decrypt_request(request)
                assert params["sc"] == [sc]
                assert params["uc"] == [captcha_code]
                assert params["captchaType"] == ["graph"]
                return _encrypted_response(
                    {
                        "errno": 0,
                        "errmsg": "OK",
                        "user": {
                            "q": quote(Q_VALUE, safe=""),
                            "t": quote(T_VALUE, safe=""),
                            "qid": QID,
                        },
                    }
                )
            assert step == 4
            assert request.url == "https://q.smart.360.cn/common/user/login"
            assert request.headers["cookie"] == (
                f"q={Q_VALUE};t={T_VALUE};qid={QID}"
            )
            return httpx.Response(
                200,
                json={
                    "errno": 0,
                    "errmsg": "OK",
                    "data": {"sid": sid, "pushKey": push_key},
                },
            )

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            client = Botslab360Client.from_credentials(
                "user@example.invalid",
                "synthetic-password",
                backend=AuthBackend.ROBOT360,
                device_identity=IDENTITY,
                http_client=http_client,
            )
            with pytest.raises(CaptchaRequired) as raised:
                await client.authenticate()

            challenge = raised.value.challenge
            assert challenge.sc == sc
            assert sc not in repr(challenge)
            session = await client.continue_authentication(
                challenge,
                captcha_code,
            )

        assert len(requests) == 4
        assert [request.url.host for request in requests] == [
            "passport.360.cn",
            "passport.360.cn",
            "passport.360.cn",
            "q.smart.360.cn",
        ]
        assert client.session is session
        assert session.sid == sid
        assert session.push_key == push_key
        rendered = f"{challenge!r} {session!r} {caplog.text}"
        for secret in (
            "synthetic-password",
            md5_hex("synthetic-password"),
            Q_VALUE,
            T_VALUE,
            QID,
            sc,
            captcha_code,
            sid,
            push_key,
        ):
            assert secret not in rendered

    monkeypatch.setattr(
        "botslab360.quc._random_ascii",
        lambda length, charset: "A" * length,
    )
    run(scenario())


def test_robot360_authentication_never_falls_back_to_botslab(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            assert request.url.host == "passport.360.cn"
            return _encrypted_response(
                {"errno": 1036, "errmsg": "account not found"}
            )

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            client = Botslab360Client.from_credentials(
                "user@example.invalid",
                "synthetic-password",
                backend=AuthBackend.ROBOT360,
                device_identity=IDENTITY,
                http_client=http_client,
            )
            with pytest.raises(QucAuthenticationError) as raised:
                await client.authenticate()

        assert raised.value.errno == 1036
        assert len(requests) == 1

    monkeypatch.setattr(
        "botslab360.quc._random_ascii",
        lambda length, charset: "A" * length,
    )
    run(scenario())


def test_captcha_continuation_is_not_available_for_qt_client() -> None:
    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: pytest.fail("No HTTP request expected")
            )
        ) as http_client:
            client = Botslab360Client(Q_VALUE, T_VALUE, http_client=http_client)
            with pytest.raises(AuthenticationError):
                await client.continue_authentication(
                    CaptchaChallenge(b"image", "token"), "1234"
                )

    run(scenario())


def test_legacy_qt_constructor_remains_compatible() -> None:
    async def scenario() -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.host == "q.smart.360.cn"
            return httpx.Response(
                200,
                json={
                    "errno": 0,
                    "data": {"sid": "synthetic-sid", "pushKey": "synthetic-key"},
                },
            )

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            client = Botslab360Client(Q_VALUE, T_VALUE, http_client=http_client)
            assert client.device_identity is None
            assert client.auth_backend is None
            session = await client.authenticate()
            assert session.sid == "synthetic-sid"

    run(scenario())
