"""Headless Qihoo User Center (QUC) authentication."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass
from numbers import Integral
from typing import Any
from urllib.parse import quote, unquote

import httpx
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, modes

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:  # cryptography < 43
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

from .auth import normalize_cookie_value
from .exceptions import ApiError, CaptchaRequired, QucAuthenticationError
from .models import CaptchaChallenge, DeviceIdentity, QihooCredentials

QUC_CAPTCHA_ERRNO = 5010
SUPPORTED_REGIONS = frozenset({"ap1", "eu1", "na1"})

_RSA_DER = bytes.fromhex(
    "30819f300d06092a864886f70d010101050003818d0030818902818100"
    "bda0d6470d7c86c4d35f0617e4ffe580b635444f5b0b590ada0c12c7"
    "774f36d4ec38ca9ea9fb3bc707ac9749412ddbf94b556ed0d3f4551ee"
    "c67c2d83a70a61d0c89ea3339d22c82a35cf91de837dfb7c9f3f2f90"
    "e752525cd0b44dd3e1dbda6a06c7efa941181db0b8b34e5740f651c53"
    "2bd1bb6a6e2ad623803366fced1aa50203010001"
)
_ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_ANDROID_RANDOM_CHARSET = (
    "!#$%&*0123456789@ABCDEFGHIJKLMNOPQRSTUVWXYZ^abcdefghijklmnopqrstuvwxyz"
)
_ANDROID_INNER_PARAMETER_ORDER = (
    "loginType",
    "os_sdk_version",
    "mid",
    "quc_sdk_version",
    "mname",
    "ua",
    "os_manufacturer",
    "mSystemVersion",
    "head_type",
    "os_board",
    "sig",
    "os_model",
    "password",
    "quc_lang",
    "sh",
    "vt_guid",
    "is_keep_alive",
    "from",
    "needDeviceCheck",
    "oaid",
    "app",
    "trace_id",
    "ui_ver",
    "method",
    "res_mode",
    "sw",
    "format",
    "qh_id",
    "device_os",
    "device_lang",
    "sec_type",
    "v",
    "fields",
    "androidid",
    "username",
    "sdpi",
)


@dataclass(frozen=True, slots=True)
class QucLoginProfile:
    """Internal transport profile for one QUC application tenant."""

    name: str
    endpoint_template: str
    region_required: bool
    from_value: str
    user_agent: str
    login_type: str
    need_device_check: int
    full_random_key_length: int
    des_key_length: int
    random_charset: str
    rsa_base64_padding: bool
    des_base64_padding: bool
    signing_strategy: str
    signing_suffix: str
    inner_encoding_strategy: str
    inner_parameter_order: tuple[str, ...] | None
    app: str
    quc_sdk_version: str
    ui_version: str
    app_version: str
    des_mode: str
    des_iv_source: str
    native_crypto_verified: bool

    def endpoint(self, region: str | None) -> str:
        """Resolve this profile's endpoint without performing discovery."""

        if self.region_required and region is None:
            raise ValueError(f"region is required by the {self.name} profile")
        return self.endpoint_template.format(region=region or "")


BOTSLAB_CLOUD_PROFILE = QucLoginProfile(
    name="botslab_cloud",
    endpoint_template="https://{region}-sapp-login.botslab.com/request.php",
    region_required=True,
    from_value="mpl_cloudsmartoem_and",
    user_agent="360accounts andv3.2.4.6 mpl_cloudsmartoem_and",
    login_type="801",
    need_device_check=0,
    full_random_key_length=114,
    des_key_length=8,
    random_charset=_ALPHANUMERIC,
    rsa_base64_padding=True,
    des_base64_padding=True,
    signing_strategy="cloud",
    signing_suffix="",
    inner_encoding_strategy="javascript_component",
    inner_parameter_order=None,
    app="Botslab",
    quc_sdk_version="v3.2.4.6",
    ui_version="4.3.4.1-alert-ui",
    app_version="2.24.0",
    des_mode="CBC",
    des_iv_source="des_key",
    native_crypto_verified=True,
)

# Internal protocol profile selected by the public AuthBackend.ROBOT360 option.
ANDROID_360_PROFILE = QucLoginProfile(
    name="android_360",
    endpoint_template="https://passport.360.cn/request.php",
    region_required=False,
    from_value="mpl_smarthome_and",
    user_agent="360accounts andv3.2.4 mpl_smarthome_and",
    login_type="801",
    need_device_check=1,
    full_random_key_length=117,
    des_key_length=8,
    random_charset=_ANDROID_RANDOM_CHARSET,
    rsa_base64_padding=False,
    des_base64_padding=False,
    signing_strategy="android360",
    signing_suffix="i7v2m5x6q",
    inner_encoding_strategy="java_urlencoder",
    inner_parameter_order=_ANDROID_INNER_PARAMETER_ORDER,
    app="360Robot",
    quc_sdk_version="v3.2.4",
    ui_version="4.2.8.1-alert-ui",
    app_version="11.1.7",
    des_mode="CBC",
    des_iv_source="des_key",
    native_crypto_verified=True,
)

# Preserve the existing module constants for internal users and tests.
QUC_USER_AGENT = BOTSLAB_CLOUD_PROFILE.user_agent
QUC_FROM = BOTSLAB_CLOUD_PROFILE.from_value

PASSWORD_LOGIN_PARAMETER_NAMES = (
    "fields",
    "head_type",
    "is_keep_alive",
    "loginType",
    "needDeviceCheck",
    "password",
    "sec_type",
    "trace_id",
    "username",
)
OUTER_FORM_FIELDS = (
    "device_lang",
    "from",
    "key",
    "method",
    "parad",
    "quc_lang",
    "trace_id",
)


@dataclass(frozen=True, slots=True, repr=False)
class _QucLoginDiagnostic:
    """Secret-free result of exactly one QUC login request."""

    http_status: int
    errno: int
    errmsg: str | None
    captcha_required: bool
    user_present: bool
    credentials_obtained: bool
    q_present: bool
    t_present: bool
    qid_present: bool
    credentials: QihooCredentials | None


@dataclass(frozen=True, slots=True)
class _QucCaptchaDiagnostic:
    """Secret-free metadata plus an in-memory captcha challenge."""

    challenge: CaptchaChallenge
    http_status: int
    content_type: str | None


def md5_hex(value: str) -> str:
    """Return the lowercase MD5 digest used by the QUC protocol."""

    return hashlib.md5(value.encode("utf-8"), usedforsecurity=False).hexdigest()


def compute_signature(
    params: Mapping[str, object],
    *,
    profile: QucLoginProfile = BOTSLAB_CLOUD_PROFILE,
) -> str:
    """Compute a QUC signature from raw, decoded parameter values."""

    source = "".join(f"{key}={params[key]}" for key in sorted(params) if key != "sig")
    return md5_hex(source + profile.signing_suffix)


def _des_cipher(key: str) -> Cipher:
    key_bytes = key.encode("utf-8")
    if len(key_bytes) != 8:
        raise ValueError("QUC DES key must contain exactly 8 UTF-8 bytes")
    return Cipher(TripleDES(key_bytes * 3), modes.CBC(key_bytes))


def _encode_base64(value: bytes, *, padding_enabled: bool) -> str:
    """Encode standard, unwrapped Base64 with configurable trailing padding."""

    encoded = base64.b64encode(value).decode("ascii")
    return encoded if padding_enabled else encoded.rstrip("=")


def des_encrypt_base64(
    plaintext: str,
    key: str,
    *,
    base64_padding: bool = True,
) -> str:
    """Encrypt UTF-8 text with DES-CBC/PKCS7 and return Base64."""

    padder = padding.PKCS7(64).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    encryptor = _des_cipher(key).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return _encode_base64(encrypted, padding_enabled=base64_padding)


def des_decrypt_base64(ciphertext: str, key: str) -> str:
    """Decrypt Base64 DES-CBC/PKCS7 data as UTF-8."""

    decryptor = _des_cipher(key).decryptor()
    padded = decryptor.update(base64.b64decode(ciphertext)) + decryptor.finalize()
    unpadder = padding.PKCS7(64).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode("utf-8")


def _rsa_public_key() -> RSAPublicKey:
    key = serialization.load_der_public_key(_RSA_DER)
    if not isinstance(key, RSAPublicKey):
        raise TypeError("QUC public key is not an RSA key")
    return key


def rsa_encrypt_key(
    key_string: str,
    *,
    base64_padding: bool = True,
) -> str:
    """Encrypt an envelope key using the QUC RSA public key."""

    encrypted = _rsa_public_key().encrypt(
        key_string.encode("ascii"),
        asymmetric_padding.PKCS1v15(),
    )
    return _encode_base64(encrypted, padding_enabled=base64_padding)


def _random_ascii(length: int, charset: str = _ALPHANUMERIC) -> str:
    return "".join(secrets.choice(charset) for _ in range(length))


def _encode_component(value: object) -> str:
    # Matches JavaScript encodeURIComponent, including its safe punctuation.
    return quote(str(value), safe="-_.!~*'()")


def _java_urlencode_component(value: object) -> str:
    """Encode one value with Java ``URLEncoder`` UTF-8 semantics."""

    output: list[str] = []
    for byte in str(value).encode("utf-8"):
        if (
            ord("a") <= byte <= ord("z")
            or ord("A") <= byte <= ord("Z")
            or ord("0") <= byte <= ord("9")
            or byte in b".-*_"
        ):
            output.append(chr(byte))
        elif byte == 0x20:
            output.append("+")
        else:
            output.append(f"%{byte:02X}")
    return "".join(output)


def _serialize_inner_params(
    params: Mapping[str, object],
    *,
    profile: QucLoginProfile = BOTSLAB_CLOUD_PROFILE,
) -> str:
    """Serialize decoded parameters according to the selected QUC tenant."""

    if profile.inner_parameter_order is None:
        names = list(params)
    else:
        preferred = set(profile.inner_parameter_order)
        names = [name for name in profile.inner_parameter_order if name in params]
        names.extend(name for name in params if name not in preferred)

    if profile.inner_encoding_strategy == "javascript_component":
        encoder = _encode_component
    elif profile.inner_encoding_strategy == "java_urlencoder":
        encoder = _java_urlencode_component
    else:
        raise ValueError(
            "Unsupported QUC inner encoding strategy: "
            f"{profile.inner_encoding_strategy}"
        )
    return "&".join(f"{name}={encoder(params[name])}" for name in names)


def build_envelope(
    params: Mapping[str, object],
    *,
    profile: QucLoginProfile = BOTSLAB_CLOUD_PROFILE,
) -> tuple[dict[str, str], str]:
    """Build the RSA-wrapped DES transport envelope and return its DES key."""

    plaintext = _serialize_inner_params(params, profile=profile)
    prefix_length = profile.full_random_key_length - profile.des_key_length
    key_string = _random_ascii(prefix_length, profile.random_charset) + _random_ascii(
        profile.des_key_length, profile.random_charset
    )
    des_key = key_string[-profile.des_key_length :]
    return {
        "parad": des_encrypt_base64(
            plaintext,
            des_key,
            base64_padding=profile.des_base64_padding,
        ),
        "key": rsa_encrypt_key(
            key_string,
            base64_padding=profile.rsa_base64_padding,
        ),
    }, des_key


def _base_device_params(
    identity: DeviceIdentity,
    profile: QucLoginProfile = BOTSLAB_CLOUD_PROFILE,
) -> dict[str, str]:
    # Android runtime confirmed these key names, but not every value. Until
    # those values are known, the diagnostic profile reuses the existing ones.
    return {
        "os_sdk_version": "android_33",
        "mid": identity.mid,
        "quc_sdk_version": profile.quc_sdk_version,
        "mname": "",
        "ua": (
            "Dalvik/2.1.0 (Linux; U; Android 13; "
            "sdk_gphone64_arm64 Build/TE1A.240213.009)"
        ),
        "os_manufacturer": "Google",
        "mSystemVersion": "android 13",
        "os_board": "goldfish_arm64",
        "os_model": "sdk_gphone64_arm64",
        "quc_lang": "en",
        "sh": "2337.0",
        "from": profile.from_value,
        "oaid": "",
        "app": profile.app,
        "ui_ver": profile.ui_version,
        "res_mode": "1",
        "sw": "1080.0",
        "format": "json",
        "qh_id": "",
        "device_os": "android",
        "device_lang": "zh-CN",
        "v": profile.app_version,
        "androidid": identity.android_id,
        "sdpi": "2.625",
    }


def _numeric_errno(value: Any, *, status_code: int) -> int:
    if isinstance(value, bool):
        raise ApiError(
            "QUC response contains an invalid errno",
            phase="response-validation",
            status_code=status_code,
        )
    if isinstance(value, Integral):
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("+-").isdigit():
        return int(value)
    raise ApiError(
        "QUC response contains an invalid errno",
        phase="response-validation",
        status_code=status_code,
    )


def _safe_server_message(
    value: object,
    *,
    secrets_to_redact: tuple[str, ...],
) -> str | None:
    """Return a server message with concrete request secrets removed."""

    if not isinstance(value, str) or not value:
        return None
    safe_value = value
    for secret in secrets_to_redact:
        if secret:
            safe_value = safe_value.replace(secret, "<redacted>")
    return safe_value


class QucAuth:
    """Perform email/password authentication against Qihoo User Center."""

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        *,
        email: str,
        password: str,
        region: str | None,
        identity: DeviceIdentity,
        _profile: QucLoginProfile = BOTSLAB_CLOUD_PROFILE,
    ) -> None:
        self.validate_options(
            email=email,
            password=password,
            region=region,
            _profile=_profile,
        )
        self._http_client = http_client
        self._email = email.strip()
        self._password = password
        self._region = region
        self._identity = identity
        self._profile = _profile

    @staticmethod
    def validate_options(
        *,
        email: str,
        password: str,
        region: str | None,
        _profile: QucLoginProfile = BOTSLAB_CLOUD_PROFILE,
    ) -> None:
        """Validate login options before allocating an owned HTTP client."""

        if not isinstance(email, str) or not email.strip():
            raise ValueError("email must be a non-empty string")
        if not isinstance(password, str) or not password:
            raise ValueError("password must be a non-empty string")
        if _profile.region_required and region not in SUPPORTED_REGIONS:
            supported = ", ".join(sorted(SUPPORTED_REGIONS))
            raise ValueError(f"region must be one of: {supported}")
        if not _profile.region_required and region is not None:
            raise ValueError(f"region is not supported by the {_profile.name} profile")

    @property
    def url(self) -> str:
        return self._profile.endpoint(self._region)

    def _login_params(
        self,
        *,
        challenge: CaptchaChallenge | None = None,
        captcha_code: str | None = None,
        need_device_check: int | None = None,
    ) -> dict[str, str]:
        now_ms = int(time.time() * 1000)
        params = {
            **_base_device_params(self._identity, self._profile),
            "loginType": self._profile.login_type,
            "vt_guid": str(now_ms),
            "is_keep_alive": "1",
            "needDeviceCheck": str(
                self._profile.need_device_check
                if need_device_check is None
                else need_device_check
            ),
            "trace_id": f"src_and_1916_{now_ms}",
            "method": "UserIntf.login",
            "head_type": "q",
            "sec_type": "bool",
            "fields": "qid,username,nickname,loginemail,head_pic,mobile",
            "username": self._email,
            "password": md5_hex(self._password),
        }
        if challenge is not None and captcha_code is not None:
            params.update(
                {
                    "sc": challenge.sc,
                    "uc": captcha_code,
                    "captchaType": "graph",
                }
            )
        params["sig"] = compute_signature(params, profile=self._profile)
        return params

    async def login(
        self,
        *,
        challenge: CaptchaChallenge | None = None,
        captcha_code: str | None = None,
        need_device_check: int | None = None,
    ) -> QihooCredentials:
        """Authenticate, raising ``CaptchaRequired`` for a graphic challenge."""

        if (challenge is None) != (captcha_code is None):
            raise ValueError("challenge and captcha_code must be provided together")
        if captcha_code is not None and not captcha_code:
            raise ValueError("captcha_code must not be empty")

        params = self._login_params(
            challenge=challenge,
            captcha_code=captcha_code,
            need_device_check=need_device_check,
        )
        payload, status_code, envelope_secrets = await self._post_envelope(params)
        errno = _numeric_errno(payload.get("errno"), status_code=status_code)
        user_present = "user" in payload and payload["user"] is not None
        details = payload.get("errdetail")
        captcha_type = None
        if isinstance(details, dict) and isinstance(details.get("captchaType"), str):
            captcha_type = details["captchaType"] or None
        errmsg = _safe_server_message(
            payload.get("errmsg"),
            secrets_to_redact=(
                self._email,
                self._password,
                md5_hex(self._password),
                challenge.sc if challenge is not None else "",
                captcha_code or "",
                *envelope_secrets,
            ),
        )
        if errno == QUC_CAPTCHA_ERRNO:
            captcha_type = captcha_type or "graph"
            captcha = await self.get_captcha(captcha_type=captcha_type)
            raise CaptchaRequired(
                captcha,
                errno=errno,
                status_code=status_code,
                region=self._region,
                errmsg=errmsg,
                user_present=user_present,
                captcha_type=captcha_type,
            )
        if errno != 0:
            raise QucAuthenticationError(
                "QUC rejected the supplied credentials",
                region=self._region,
                errno=errno,
                errmsg=errmsg,
                status_code=status_code,
                user_present=user_present,
                captcha_required=False,
                captcha_type=captcha_type,
            )

        user = payload.get("user")
        if not isinstance(user, dict):
            raise QucAuthenticationError(
                "QUC login response is missing account credentials",
                region=self._region,
                errno=errno,
                errmsg=errmsg,
                status_code=status_code,
                user_present=user_present,
                captcha_required=False,
                captcha_type=captcha_type,
                phase="response-validation",
            )
        q = user.get("q")
        t = user.get("t")
        qid = user.get("qid")
        if (
            not isinstance(q, str)
            or not isinstance(t, str)
            or isinstance(qid, bool)
            or qid is None
        ):
            raise QucAuthenticationError(
                "QUC login response contains invalid account credentials",
                region=self._region,
                errno=errno,
                errmsg=errmsg,
                status_code=status_code,
                user_present=user_present,
                captcha_required=False,
                captcha_type=captcha_type,
                phase="response-validation",
            )
        normalized_qid = str(qid)
        if not normalized_qid:
            raise QucAuthenticationError(
                "QUC login response contains invalid account credentials",
                region=self._region,
                errno=errno,
                errmsg=errmsg,
                status_code=status_code,
                user_present=user_present,
                captcha_required=False,
                captcha_type=captcha_type,
                phase="response-validation",
            )
        return QihooCredentials(
            q=normalize_cookie_value(q, name="Q"),
            t=normalize_cookie_value(t, name="T"),
            qid=normalized_qid,
        )

    async def _diagnose_login_once(
        self,
        *,
        challenge: CaptchaChallenge | None = None,
        captcha_code: str | None = None,
    ) -> _QucLoginDiagnostic:
        """Send one login request without captcha fetching or follow-up work."""

        if (challenge is None) != (captcha_code is None):
            raise ValueError("challenge and captcha_code must be provided together")
        if captcha_code is not None and not captcha_code:
            raise ValueError("captcha_code must not be empty")
        payload, status_code, envelope_secrets = await self._post_envelope(
            self._login_params(
                challenge=challenge,
                captcha_code=captcha_code,
            )
        )
        errno = _numeric_errno(payload.get("errno"), status_code=status_code)
        user = payload.get("user")
        user_present = user is not None
        q = user.get("q") if isinstance(user, dict) else None
        t = user.get("t") if isinstance(user, dict) else None
        qid = user.get("qid") if isinstance(user, dict) else None
        q_present = isinstance(q, str) and bool(q)
        t_present = isinstance(t, str) and bool(t)
        qid_present = not isinstance(qid, bool) and qid is not None and bool(str(qid))
        credentials_obtained = errno == 0 and q_present and t_present and qid_present
        credentials = (
            QihooCredentials(
                q=normalize_cookie_value(q, name="Q"),
                t=normalize_cookie_value(t, name="T"),
                qid=str(qid),
            )
            if credentials_obtained and isinstance(q, str) and isinstance(t, str)
            else None
        )
        return _QucLoginDiagnostic(
            http_status=status_code,
            errno=errno,
            errmsg=_safe_server_message(
                payload.get("errmsg"),
                secrets_to_redact=(
                    self._email,
                    self._password,
                    md5_hex(self._password),
                    *envelope_secrets,
                ),
            ),
            captcha_required=errno == QUC_CAPTCHA_ERRNO,
            user_present=user_present,
            credentials_obtained=credentials_obtained,
            q_present=q_present,
            t_present=t_present,
            qid_present=qid_present,
            credentials=credentials,
        )

    async def get_captcha(self, *, captcha_type: str = "graph") -> CaptchaChallenge:
        """Fetch one graphic captcha and its opaque ``sc`` token."""

        result = await self._get_captcha_once(captcha_type=captcha_type)
        return result.challenge

    async def _get_captcha_once(
        self, *, captcha_type: str = "graph"
    ) -> _QucCaptchaDiagnostic:
        """Fetch one captcha and retain only safe response metadata."""

        now_ms = int(time.time() * 1000)
        params = {
            **_base_device_params(self._identity, self._profile),
            "vt_guid": str(now_ms),
            "trace_id": f"src_and_1916_{now_ms}",
            "method": "UserIntf.getCaptcha",
        }
        params["sig"] = compute_signature(params, profile=self._profile)
        envelope, _ = build_envelope(params, profile=self._profile)
        form = self._outer_form(params, envelope, profile=self._profile)
        response = await self._post(form)
        raw_sc = response.headers.get("sc", "")
        sc = unquote(raw_sc)
        if not response.content or not sc:
            raise ApiError(
                "QUC captcha response is incomplete",
                status_code=response.status_code,
                phase="response-validation",
            )
        return _QucCaptchaDiagnostic(
            challenge=CaptchaChallenge(
                image=response.content,
                sc=sc,
                captcha_type=captcha_type,
            ),
            http_status=response.status_code,
            content_type=response.headers.get("content-type"),
        )

    async def _post_envelope(
        self, params: Mapping[str, object]
    ) -> tuple[dict[str, object], int, tuple[str, str, str]]:
        envelope, des_key = build_envelope(params, profile=self._profile)
        response = await self._post(
            self._outer_form(params, envelope, profile=self._profile)
        )
        try:
            outer = response.json()
            encrypted = outer["ret"]
            if not isinstance(encrypted, str):
                raise TypeError
            decoded = json.loads(des_decrypt_base64(encrypted, des_key))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ApiError(
                "QUC login returned an invalid encrypted response",
                status_code=response.status_code,
                phase="response-validation",
            ) from exc
        if not isinstance(decoded, dict):
            raise ApiError(
                "QUC login returned an invalid response",
                status_code=response.status_code,
                phase="response-validation",
            )
        return (
            decoded,
            response.status_code,
            (
                des_key,
                envelope["parad"],
                envelope["key"],
            ),
        )

    async def _post(self, form: Mapping[str, str]) -> httpx.Response:
        try:
            response = await self._http_client.post(
                self.url,
                data=form,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": self._profile.user_agent,
                    "Connection": "close",
                },
            )
            response.raise_for_status()
            return response
        except httpx.HTTPStatusError as exc:
            raise ApiError(
                "QUC request returned an HTTP error",
                status_code=exc.response.status_code,
                phase="http",
            ) from exc
        except httpx.RequestError as exc:
            raise ApiError("QUC request failed", phase="transport") from exc

    @staticmethod
    def _outer_form(
        params: Mapping[str, object],
        envelope: Mapping[str, str],
        *,
        profile: QucLoginProfile = BOTSLAB_CLOUD_PROFILE,
    ) -> dict[str, str]:
        return {
            "device_lang": "zh-CN",
            "trace_id": str(params["trace_id"]),
            "quc_lang": "en",
            "method": str(params["method"]),
            "from": profile.from_value,
            "parad": envelope["parad"],
            "key": envelope["key"],
        }
