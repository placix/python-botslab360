"""Development-only live diagnostic for S9-P station network identity.

This script intentionally uses private botslab360 transport helpers to verify
vendor command 21019. It is a protocol diagnostic, not part of the public API.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import re
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path
from typing import Any
from uuid import uuid4

from botslab360 import (
    ApiError,
    AuthBackend,
    AuthenticationError,
    Botslab360Client,
    CaptchaRequired,
    Device,
    DeviceIdentity,
)
from botslab360.protocol import PushClient

CAPTCHA_CONFIRMATION = "CONTINUE ONE ROBOT360 CAPTCHA"
NETWORK_INFO_TYPE = "21019"
NETWORK_INFO_EVENT = "10"
DEFAULT_IDENTITY_PATH = (
    Path(__file__).resolve().parents[1] / ".botslab360-device-identity.json"
)
_MAC_PATTERN = re.compile(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}|[0-9a-fA-F]{12}")


@dataclass(frozen=True, slots=True)
class NetworkIdentity:
    """Sanitized station identity returned by vendor command 21019."""

    station_ip: str | None
    station_mac: str | None
    ssid: str | None
    hostname: str | None

    @property
    def oui(self) -> str | None:
        """Return the MAC prefix without inferring a manufacturer."""

        if self.station_mac is None:
            return None
        return ":".join(self.station_mac.split(":")[:3])


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


def _json_object(value: object, *, field: str) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError) as error:
            raise ApiError(
                f"Network info {field} is invalid JSON",
                phase="protocol",
            ) from error
    if not isinstance(value, dict):
        raise ApiError(f"Network info {field} is invalid", phase="protocol")
    return value


def _optional_text(payload: dict[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ApiError(f"Network info field {key} is invalid", phase="protocol")
    return value


def _station_ip(payload: dict[str, Any]) -> str | None:
    value = _optional_text(payload, "staIp")
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as error:
        raise ApiError(
            "Network info field staIp is invalid",
            phase="protocol",
        ) from error


def _station_mac(payload: dict[str, Any]) -> str | None:
    value = _optional_text(payload, "staMac")
    if value is None:
        return None
    if _MAC_PATTERN.fullmatch(value) is None:
        raise ApiError("Network info field staMac is invalid", phase="protocol")
    compact = value.replace(":", "").replace("-", "").lower()
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))


def parse_network_info_event(
    event: object,
    *,
    device_id: str,
    task_id: str,
) -> NetworkIdentity | None:
    """Parse one matching event-10 response without retaining other fields."""

    if not isinstance(event, dict):
        raise ApiError("Network info push event is invalid", phase="protocol")
    if event.get("sn") != device_id or event.get("taskid") != task_id:
        return None
    if str(event.get("event")) != NETWORK_INFO_EVENT:
        return None

    protocol = _json_object(event.get("data"), field="protocol")
    if str(protocol.get("infoType")) != NETWORK_INFO_TYPE:
        return None
    payload = _json_object(protocol.get("data"), field="payload")

    hostname = _optional_text(payload, "hostname")
    if hostname is None:
        hostname = _optional_text(payload, "hostName")
    return NetworkIdentity(
        station_ip=_station_ip(payload),
        station_mac=_station_mac(payload),
        ssid=_optional_text(payload, "staId"),
        hostname=hostname,
    )


async def _wait_for_network_info(
    push: PushClient,
    *,
    device_id: str,
    task_id: str,
    timeout: float,
) -> NetworkIdentity:
    async def wait() -> NetworkIdentity:
        while True:
            event = await push.read_event()
            identity = parse_network_info_event(
                event,
                device_id=device_id,
                task_id=task_id,
            )
            if identity is not None:
                return identity

    try:
        return await asyncio.wait_for(wait(), timeout=timeout)
    except asyncio.TimeoutError as error:
        raise ApiError(
            "Timed out waiting for network info",
            phase="timeout",
        ) from error


async def _request_network_info_once(
    client: Botslab360Client,
    *,
    device_id: str,
    task_id: str,
    timeout: float,
) -> NetworkIdentity:
    session = client.session
    if session is None:
        raise AuthenticationError(
            "Authentication is required before requesting network info",
            phase="authentication",
        )

    push = PushClient(
        session.sid,
        session.push_key,
        host=client._push_host,
        port=client._push_port,
        client_version=client._push_client_version,
        heartbeat_timeout=client._push_heartbeat_timeout,
        heartbeat_interval=client._push_heartbeat_interval,
    )
    async with push:
        waiter = asyncio.create_task(
            _wait_for_network_info(
                push,
                device_id=device_id,
                task_id=task_id,
                timeout=timeout,
            )
        )
        await asyncio.sleep(0)
        try:
            await client._post_robot_request(
                device_id=device_id,
                info_type=NETWORK_INFO_TYPE,
                data="",
                task_id=task_id,
                operation="network info request",
            )
            return await waiter
        finally:
            if not waiter.done():
                waiter.cancel()
                with suppress(asyncio.CancelledError):
                    await waiter


async def _request_network_info(
    client: Botslab360Client,
    *,
    device_id: str,
    timeout: float,
) -> NetworkIdentity:
    task_id = str(uuid4())
    return await client._with_session_refresh(
        lambda: _request_network_info_once(
            client,
            device_id=device_id,
            task_id=task_id,
            timeout=timeout,
        )
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


def _print_network_identity(device: Device, identity: NetworkIdentity) -> None:
    print(f"Device: {device.model or 'unknown model'}")
    print(f"Device ID: {device.id}")
    print(f"Station IP: {identity.station_ip or 'not returned'}")
    print(f"Station MAC: {identity.station_mac or 'not returned'}")
    print(f"OUI: {identity.oui or 'not available'}")
    print(f"Hostname: {identity.hostname or 'not returned'}")
    print(f"SSID: {'present (redacted)' if identity.ssid else 'not returned'}")


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
            network_identity = await _request_network_info(
                client,
                device_id=device.id,
                timeout=timeout,
            )
            _print_network_identity(device, network_identity)
            if (
                network_identity.station_ip is None
                or network_identity.station_mac is None
            ):
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
