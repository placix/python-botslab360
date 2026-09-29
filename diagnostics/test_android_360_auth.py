"""Development-only protocol diagnostic for the Android 360 QUC profile."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import tempfile
from getpass import getpass
from pathlib import Path
from typing import Any

import httpx

from botslab360 import ApiError, DeviceIdentity
from botslab360.auth import BotslabAuth
from botslab360.quc import (
    _RSA_DER,
    ANDROID_360_PROFILE,
    OUTER_FORM_FIELDS,
    PASSWORD_LOGIN_PARAMETER_NAMES,
    QucAuth,
    build_envelope,
)

CONFIRMATION = "SEND ONE ANDROID 360 LOGIN"
CAPTCHA_CONFIRMATION = "CONTINUE ONE ANDROID 360 CAPTCHA"
MINT_CONFIRMATION = "MINT ONE ANDROID 360 SESSION"
DEFAULT_IDENTITY_PATH = (
    Path(__file__).resolve().parents[1] / ".botslab360-device-identity.json"
)
_OFFLINE_IDENTITY = DeviceIdentity(
    mid="00000000000000000000000000000000",
    android_id="0000000000000000",
    m2="00000000-0000-4000-8000-000000000000",
)


def _identity_payload(identity: DeviceIdentity) -> dict[str, str]:
    return {
        "mid": identity.mid,
        "android_id": identity.android_id,
        "m2": identity.m2,
    }


def _load_or_create_identity(path: Path) -> tuple[DeviceIdentity, bool]:
    path = path.expanduser()
    if path.exists():
        payload = json.loads(path.read_text(encoding="utf-8"))
        return DeviceIdentity(
            mid=payload["mid"],
            android_id=payload["android_id"],
            m2=payload["m2"],
        ), False

    identity = DeviceIdentity.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_identity_payload(identity), indent=2) + "\n",
        encoding="utf-8",
    )
    return identity, True


def print_dry_run() -> None:
    """Print only non-secret, statically known profile metadata."""

    profile = ANDROID_360_PROFILE
    auth = QucAuth(
        None,  # type: ignore[arg-type]  # Offline parameter construction only.
        email="offline-account",
        password="offline-password",
        region=None,
        identity=_OFFLINE_IDENTITY,
        _profile=profile,
    )
    envelope, _ = build_envelope(auth._login_params(), profile=profile)
    print(f"profile: {profile.name}")
    print(f"endpoint: {profile.endpoint(None)}")
    print(f"from: {profile.from_value}")
    print(f"user-agent: {profile.user_agent}")
    print(f"loginType: {profile.login_type}")
    print(f"needDeviceCheck: {profile.need_device_check}")
    print("inner key names: " + ", ".join(PASSWORD_LOGIN_PARAMETER_NAMES))
    print("outer key names: " + ", ".join(OUTER_FORM_FIELDS))
    print(f"full-key length: {profile.full_random_key_length}")
    print(f"DES-key length: {profile.des_key_length}")
    print(f"signature_profile: {profile.signing_strategy}")
    print(f"random_charset_size: {len(profile.random_charset)}")
    print(f"signing_suffix_present: {str(bool(profile.signing_suffix)).lower()}")
    print(
        "java_urlencoder: "
        f"{str(profile.inner_encoding_strategy == 'java_urlencoder').lower()}"
    )
    print(f"des_mode: {profile.des_mode}")
    print(f"des_iv_source: {profile.des_iv_source}")
    print(f"offline_vectors_verified: {str(profile.native_crypto_verified).lower()}")
    print(f"RSA fingerprint: {hashlib.sha256(_RSA_DER).hexdigest()}")
    print(f"key_base64_padding: {str(profile.rsa_base64_padding).lower()}")
    print(f"parad_base64_padding: {str(profile.des_base64_padding).lower()}")
    print(f"generated_key_encoded_length: {len(envelope['key'])}")
    print(f"generated_parad_encoded_length: {len(envelope['parad'])}")
    print(f"key_ends_with_padding: {str(envelope['key'].endswith('=')).lower()}")
    print(f"parad_ends_with_padding: {str(envelope['parad'].endswith('=')).lower()}")
    print("sent: false")


def _print_login_result(result: Any, *, heading: str) -> None:
    """Print only the allowlisted QUC result metadata."""

    print(heading)
    print(f"  HTTP status: {result.http_status}")
    print(f"  errno: {result.errno}")
    print(f"  message: {result.errmsg or 'not provided'}")
    print(f"  captchaRequired: {result.captcha_required}")
    print(f"  decoded.user present: {result.user_present}")
    print(f"  QUC credentials obtained: {result.credentials_obtained}")
    if result.errno == 0:
        print(f"  q present: {result.q_present}")
        print(f"  t present: {result.t_present}")
        print(f"  qid present: {result.qid_present}")


def _default_captcha_path(content_type: str | None) -> Path:
    suffix = {
        "image/gif": ".gif",
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/webp": ".webp",
    }.get((content_type or "").partition(";")[0].strip().lower(), ".img")
    return Path(tempfile.gettempdir()) / f"botslab360-android360-captcha{suffix}"


async def _mint_session_once(
    http_client: httpx.AsyncClient,
    quc_result: Any,
    *,
    enabled: bool,
) -> int:
    if quc_result.errno != 0 or quc_result.credentials is None:
        return 1
    if not enabled:
        return 0

    confirmation = input(f"Type {MINT_CONFIRMATION} to continue: ")
    if confirmation != MINT_CONFIRMATION:
        print("Smart session not requested.")
        return 1

    result = await BotslabAuth(http_client)._diagnose_login_once(quc_result.credentials)
    print("Android 360 Smart Home login result:")
    print(f"  HTTP status: {result.http_status}")
    print(f"  errno: {result.errno}")
    print(f"  message: {result.errmsg or 'not provided'}")
    print(f"  sid present: {result.sid_present}")
    print(f"  pushKey present: {result.push_key_present}")
    succeeded = result.errno == 0 and result.sid_present and result.push_key_present
    return 0 if succeeded else 1


async def send_once(
    account: str,
    password: str,
    identity: DeviceIdentity,
    *,
    http_client: httpx.AsyncClient | None = None,
    continue_captcha: bool = False,
    mint_session_once: bool = False,
    captcha_path: Path | None = None,
) -> int:
    """Run one initial login and optionally one process-local captcha retry."""

    owned_client = http_client is None
    client = http_client or httpx.AsyncClient(timeout=30.0)
    try:
        auth = QucAuth(
            client,
            email=account,
            password=password,
            region=None,
            identity=identity,
            _profile=ANDROID_360_PROFILE,
        )
        result = await auth._diagnose_login_once()
        _print_login_result(result, heading="Android 360 QUC result:")
        if not result.captcha_required:
            return await _mint_session_once(
                client,
                result,
                enabled=mint_session_once,
            )

        captcha = await auth._get_captcha_once(captcha_type="graph")
        output_path = captcha_path or _default_captcha_path(captcha.content_type)
        output_path.write_bytes(captcha.challenge.image)
        print("Android 360 captcha fetched:")
        print(f"  HTTP status: {captcha.http_status}")
        print(f"  image byte length: {len(captcha.challenge.image)}")
        print(f"  sc present: {bool(captcha.challenge.sc)}")
        print(f"  sc length: {len(captcha.challenge.sc)}")
        print(f"  content type: {captcha.content_type or 'not provided'}")
        print(f"  image path: {output_path}")
        if not continue_captcha:
            return 1

        captcha_code = getpass("Captcha code: ")
        if not captcha_code:
            print("Captcha retry not sent: empty code.")
            return 1
        retry = await auth._diagnose_login_once(
            challenge=captcha.challenge,
            captcha_code=captcha_code,
        )
        _print_login_result(retry, heading="Android 360 captcha retry result:")
        return await _mint_session_once(
            client,
            retry,
            enabled=mint_session_once,
        )
    except ApiError as error:
        print("Android 360 QUC request failed:")
        print(f"  HTTP status: {error.status_code}")
        print(f"  phase: {error.phase}")
        return 1
    except OSError as error:
        print(f"Could not save captcha image: {type(error).__name__}")
        return 1
    finally:
        if owned_client:
            await client.aclose()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="show safe request metadata without sending (default)",
    )
    mode.add_argument(
        "--send-once",
        action="store_true",
        help="send one login and fetch one captcha if required",
    )
    mode.add_argument(
        "--continue-captcha",
        action="store_true",
        help="fetch and solve one captcha in the same process",
    )
    parser.add_argument(
        "--mint-session-once",
        action="store_true",
        help="after successful QUC, confirm exactly one Smart Home login",
    )
    parser.add_argument(
        "--identity",
        type=Path,
        default=DEFAULT_IDENTITY_PATH,
        metavar="PATH",
        help=f"device identity JSON path (default: {DEFAULT_IDENTITY_PATH.name})",
    )
    return parser.parse_args()


def main() -> int:
    logging.getLogger("httpx").disabled = True
    logging.getLogger("httpcore").disabled = True
    args = _parse_args()
    print_dry_run()
    if args.mint_session_once and not args.continue_captcha:
        print("--mint-session-once requires --continue-captcha.")
        return 1
    if not args.send_once and not args.continue_captcha:
        return 0

    account = input("Account: ").strip()
    password = getpass("Password: ")
    try:
        identity, created = _load_or_create_identity(args.identity)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"Could not load device identity: {type(error).__name__}")
        return 1

    action = "Created" if created else "Loaded"
    print(f"{action} device identity: {args.identity.expanduser()}")
    confirmation_text = CAPTCHA_CONFIRMATION if args.continue_captcha else CONFIRMATION
    confirmation = input(f"Type {confirmation_text} to continue: ")
    if confirmation != confirmation_text:
        print("Not sent.")
        return 1
    return asyncio.run(
        send_once(
            account,
            password,
            identity,
            continue_captcha=args.continue_captcha,
            mint_session_once=args.mint_session_once,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
