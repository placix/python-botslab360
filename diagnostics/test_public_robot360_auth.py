"""Development-only smoke test for the public ROBOT360 authentication API."""

from __future__ import annotations

import asyncio
import json
import tempfile
from getpass import getpass
from pathlib import Path

from botslab360 import (
    AuthBackend,
    Botslab360Client,
    CaptchaRequired,
    DeviceIdentity,
    SmartSession,
)

CONFIRMATION = "CONTINUE ONE PUBLIC ROBOT360 CAPTCHA"
IDENTITY_PATH = Path(__file__).resolve().parents[1] / ".botslab360-device-identity.json"


def _identity_payload(identity: DeviceIdentity) -> dict[str, str]:
    return {
        "mid": identity.mid,
        "android_id": identity.android_id,
        "m2": identity.m2,
    }


def _load_or_create_identity(path: Path) -> tuple[DeviceIdentity, bool]:
    if path.exists():
        payload = json.loads(path.read_text(encoding="utf-8"))
        return DeviceIdentity(
            mid=payload["mid"],
            android_id=payload["android_id"],
            m2=payload["m2"],
        ), False

    identity = DeviceIdentity.generate()
    path.write_text(
        json.dumps(_identity_payload(identity), indent=2) + "\n",
        encoding="utf-8",
    )
    return identity, True


def _captcha_suffix(image: bytes) -> str:
    if image.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if image.startswith((b"GIF87a", b"GIF89a")):
        return ".gif"
    if image.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if image.startswith(b"RIFF") and image[8:12] == b"WEBP":
        return ".webp"
    return ".img"


def _default_captcha_path(image: bytes) -> Path:
    return Path(tempfile.gettempdir()) / (
        "botslab360-public-robot360-captcha" + _captcha_suffix(image)
    )


def _print_success(session: SmartSession) -> None:
    print("authenticated: true")
    print(f"backend: {AuthBackend.ROBOT360.value}")
    print("session established: true")
    print(f"sid present: {str(bool(session.sid)).lower()}")
    print(f"pushKey present: {str(bool(session.push_key)).lower()}")


async def run_auth_test(
    account: str,
    password: str,
    identity: DeviceIdentity,
    *,
    captcha_path: Path | None = None,
) -> int:
    """Run only public authentication calls and stop after session creation."""

    client = Botslab360Client.from_credentials(
        email=account,
        password=password,
        backend=AuthBackend.ROBOT360,
        device_identity=identity,
    )
    try:
        try:
            session = await client.authenticate()
        except CaptchaRequired as error:
            challenge = error.challenge
            output_path = captcha_path or _default_captcha_path(challenge.image)
            output_path.write_bytes(challenge.image)
            print(f"captcha image: {output_path}")

            confirmation = input(f"Type {CONFIRMATION} to continue: ")
            if confirmation != CONFIRMATION:
                print("Captcha continuation not requested.")
                return 1
            captcha_code = getpass("Captcha code: ")
            if not captcha_code:
                print("Captcha continuation not sent: empty code.")
                return 1
            session = await client.continue_authentication(
                challenge,
                captcha_code,
            )

        _print_success(session)
        return 0
    except Exception as error:  # noqa: BLE001 - keep diagnostics traceback-free
        print(f"Authentication failed: {type(error).__name__}")
        return 1
    finally:
        await client.close()


def main() -> int:
    try:
        identity, created = _load_or_create_identity(IDENTITY_PATH)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"Could not load device identity: {type(error).__name__}")
        return 1

    action = "Created" if created else "Loaded"
    print(f"{action} device identity: {IDENTITY_PATH}")
    account = input("Account: ").strip()
    password = getpass("Password: ")
    return asyncio.run(run_auth_test(account, password, identity))


if __name__ == "__main__":
    raise SystemExit(main())
