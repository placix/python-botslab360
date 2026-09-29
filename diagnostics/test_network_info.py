"""Development-only live diagnostic for S9-P station network identity."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import tempfile
from getpass import getpass
from pathlib import Path

from botslab360 import (
    ApiError,
    AuthBackend,
    Botslab360Client,
    CaptchaRequired,
    Device,
    DeviceIdentity,
    NetworkInfo,
)

CAPTCHA_CONFIRMATION = "CONTINUE ONE ROBOT360 CAPTCHA"
DEFAULT_IDENTITY_PATH = (
    Path(__file__).resolve().parents[1] / ".botslab360-device-identity.json"
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


def _captcha_path(image: bytes) -> Path:
    return Path(tempfile.gettempdir()) / (
        "botslab360-network-info-captcha" + _captcha_suffix(image)
    )


def _is_s9p(device: Device) -> bool:
    model = re.sub(r"[^a-z0-9]", "", device.model.lower())
    name = re.sub(r"[^a-z0-9]", "", device.name.lower())
    return "s9p" in model or "s9p" in name


def _select_s9p(devices: list[Device], device_id: str | None) -> Device:
    candidates = [device for device in devices if _is_s9p(device)]
    if device_id is not None:
        candidates = [device for device in candidates if device.id == device_id]
    if len(candidates) != 1:
        raise ApiError(
            "Expected exactly one matching S9-P device",
            phase="device-selection",
        )
    return candidates[0]


def _print_network_info(device: Device, network_info: NetworkInfo) -> None:
    oui = None
    if network_info.station_mac is not None:
        oui = ":".join(network_info.station_mac.split(":")[:3])
    print(f"Device: {device.model or 'unknown model'}")
    print(f"Device ID: {device.id}")
    print(f"Station IP: {network_info.station_ip or 'not returned'}")
    print(f"Station MAC: {network_info.station_mac or 'not returned'}")
    print(f"OUI: {oui or 'not available'}")
    print(
        f"SSID: {'present (redacted)' if network_info.station_ssid else 'not returned'}"
    )


def _safe_error(error: Exception) -> None:
    print(f"exception: {type(error).__name__}")
    if isinstance(error, ApiError):
        print(f"phase: {error.phase}")
        print(f"HTTP status: {error.status_code}")
        print(f"errno: {error.errno}")


async def run_network_info_test(
    account: str,
    password: str,
    identity: DeviceIdentity,
    *,
    device_id: str | None = None,
    captcha_path: Path | None = None,
    timeout: float = 30.0,
) -> int:
    """Authenticate and request the selected S9-P network identity once."""

    client = Botslab360Client.from_credentials(
        email=account,
        password=password,
        backend=AuthBackend.ROBOT360,
        device_identity=identity,
    )
    try:
        async with client:
            try:
                await client.authenticate()
            except CaptchaRequired as error:
                challenge = error.challenge
                output_path = captcha_path or _captcha_path(challenge.image)
                output_path.write_bytes(challenge.image)
                print(f"Captcha image: {output_path}")

                confirmation = input(f"Type {CAPTCHA_CONFIRMATION} to continue: ")
                if confirmation != CAPTCHA_CONFIRMATION:
                    print("Captcha continuation not requested.")
                    print("NETWORK INFO DIAGNOSTIC STATUS: NOT RUN")
                    return 2
                captcha_code = getpass("Captcha code: ")
                if not captcha_code:
                    print("Captcha continuation not sent: empty code.")
                    print("NETWORK INFO DIAGNOSTIC STATUS: NOT RUN")
                    return 2
                await client.continue_authentication(challenge, captcha_code)

            devices = await client.get_devices()
            device = _select_s9p(devices, device_id)
            network_info = await client.get_network_info(device, timeout=timeout)
            _print_network_info(device, network_info)
            if network_info.station_ip is None or network_info.station_mac is None:
                print("NETWORK INFO DIAGNOSTIC STATUS: INCOMPLETE")
                return 1
            print("NETWORK INFO DIAGNOSTIC STATUS: PASS")
            return 0
    except Exception as error:  # noqa: BLE001 - keep diagnostics traceback-free
        _safe_error(error)
        print("NETWORK INFO DIAGNOSTIC STATUS: FAIL")
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--device-id",
        help="Select one S9-P when the account contains multiple matching devices.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Seconds to wait for the command response push (default: 30).",
    )
    parser.add_argument(
        "--identity",
        type=Path,
        default=DEFAULT_IDENTITY_PATH,
        help="Reusable local DeviceIdentity JSON path.",
    )
    args = parser.parse_args()

    try:
        identity, created = _load_or_create_identity(args.identity)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"Could not load device identity: {type(error).__name__}")
        return 1

    action = "Created" if created else "Loaded"
    print(f"{action} device identity: {args.identity}")
    account = input("Account: ").strip()
    password = getpass("Password: ")
    return asyncio.run(
        run_network_info_test(
            account,
            password,
            identity,
            device_id=args.device_id,
            timeout=args.timeout,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
