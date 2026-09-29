"""Development-only live smoke test for the public room API."""

from __future__ import annotations

import argparse
import asyncio
import json
import tempfile
from getpass import getpass
from pathlib import Path

from botslab360 import (
    ApiError,
    AuthBackend,
    Botslab360Client,
    CaptchaRequired,
    DeviceIdentity,
)

CAPTCHA_CONFIRMATION = "CONTINUE ONE PUBLIC ROBOT360 CAPTCHA"
CLEAN_CONFIRMATION = "CLEAN ROOM 1"
ROOM_ID = 1
EXPECTED_ROOM_NAME = "Bad"
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
        "botslab360-public-room-captcha" + _captcha_suffix(image)
    )


def _safe_error(error: Exception) -> None:
    print(f"exception: {type(error).__name__}")
    if isinstance(error, ApiError):
        print(f"phase: {error.phase}")
        print(f"HTTP status: {error.status_code}")
        print(f"errno: {error.errno}")


async def run_room_api_test(
    account: str,
    password: str,
    identity: DeviceIdentity,
    *,
    captcha_path: Path | None = None,
    rooms_only: bool = False,
) -> int:
    """Exercise only the public device, room, and cleaning APIs."""

    client = Botslab360Client.from_credentials(
        email=account,
        password=password,
        backend=AuthBackend.ROBOT360,
        device_identity=identity,
    )
    session_refreshed = False
    try:
        async with client:
            try:
                await client.authenticate()
            except CaptchaRequired as error:
                challenge = error.challenge
                output_path = captcha_path or _default_captcha_path(challenge.image)
                output_path.write_bytes(challenge.image)
                print(f"Captcha image: {output_path}")

                confirmation = input(f"Type {CAPTCHA_CONFIRMATION} to continue: ")
                if confirmation != CAPTCHA_CONFIRMATION:
                    print("Captcha continuation not requested.")
                    print("PUBLIC ROOM API LIVE STATUS: NOT RUN")
                    return 2
                captcha_code = getpass("Captcha code: ")
                if not captcha_code:
                    print("Captcha continuation not sent: empty code.")
                    print("PUBLIC ROOM API LIVE STATUS: NOT RUN")
                    return 2
                await client.continue_authentication(challenge, captcha_code)

            devices = await client.get_devices()
            if not devices:
                print("Public get_devices(): no devices")
                print("PUBLIC ROOM API LIVE STATUS: FAIL")
                return 1
            device = devices[0]

            session_before_rooms = client.session
            rooms = await client.get_rooms(device)
            session_refreshed |= client.session is not session_before_rooms

            print("Public get_rooms(): success")
            print(f"rooms: {len(rooms)}")
            print("ID / Name / room_type / mode / clean_times / fan_mode / water_pump")
            for room in rooms:
                print(
                    f"{room.id} / {room.name} / {room.room_type} / "
                    f"{room.mode} / {room.clean_times} / "
                    f"{room.fan_mode} / {room.water_pump}"
                )

            if rooms_only:
                print("Room cleaning: not requested (--rooms-only)")
                print(
                    f"Session refresh occurred: {'yes' if session_refreshed else 'no'}"
                )
                print("PUBLIC ROOM PROFILE DIAGNOSTIC STATUS: PASS")
                return 0

            selected_room = next(
                (room for room in rooms if room.id == ROOM_ID),
                None,
            )
            room_is_expected = (
                selected_room is not None and selected_room.name == EXPECTED_ROOM_NAME
            )
            print(f'Room 1 is "Bad": {"yes" if room_is_expected else "no"}')
            if not room_is_expected:
                print("Public clean_rooms([1]): not sent")
                print("PUBLIC ROOM API LIVE STATUS: FAIL")
                return 1

            confirmation = await asyncio.to_thread(
                input,
                "Type CLEAN ROOM 1 to continue: ",
            )
            if confirmation != CLEAN_CONFIRMATION:
                print("Public clean_rooms([1]): not sent")
                print("PUBLIC ROOM API LIVE STATUS: NOT RUN")
                return 2

            session_before_cleaning = client.session
            await client.clean_rooms(device, [ROOM_ID])
            session_refreshed |= client.session is not session_before_cleaning
            print("Public clean_rooms([1]): success")
            print("Physical robot behavior: confirm manually")
            print(f"Session refresh occurred: {'yes' if session_refreshed else 'no'}")
            print("PUBLIC ROOM API LIVE STATUS: PASS")
            return 0
    except Exception as error:  # noqa: BLE001 - keep diagnostics traceback-free
        _safe_error(error)
        print(f"Session refresh occurred: {'yes' if session_refreshed else 'no'}")
        print("PUBLIC ROOM API LIVE STATUS: FAIL")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rooms-only",
        action="store_true",
        help="Print public room profile values without offering to clean a room.",
    )
    args = parser.parse_args()

    try:
        identity, created = _load_or_create_identity(IDENTITY_PATH)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"Could not load device identity: {type(error).__name__}")
        return 1

    action = "Created" if created else "Loaded"
    print(f"{action} device identity: {IDENTITY_PATH}")
    account = input("Account: ").strip()
    password = getpass("Password: ")
    return asyncio.run(
        run_room_api_test(
            account,
            password,
            identity,
            rooms_only=args.rooms_only,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
