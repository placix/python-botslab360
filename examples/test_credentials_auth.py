"""Manual, command-free smoke test for email/password authentication."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import tempfile
from collections.abc import Sequence
from getpass import getpass
from pathlib import Path

from botslab360 import (
    ApiError,
    Botslab360Client,
    CaptchaRequired,
    DeviceIdentity,
    QucAuthenticationError,
)

ACCOUNT_NOT_FOUND_ERRNO = 1036
PROBE_REGIONS = ("eu1", "na1", "ap1")
DEFAULT_IDENTITY_PATH = (
    Path(__file__).resolve().parents[1] / ".botslab360-device-identity.json"
)


def _identity_payload(identity: DeviceIdentity) -> dict[str, str]:
    return {
        "mid": identity.mid,
        "android_id": identity.android_id,
        "m2": identity.m2,
    }


def _load_identity(path: Path) -> DeviceIdentity:
    payload = json.loads(path.expanduser().read_text(encoding="utf-8"))
    return DeviceIdentity(
        mid=payload["mid"],
        android_id=payload["android_id"],
        m2=payload["m2"],
    )


def _load_or_create_identity(path: Path) -> tuple[DeviceIdentity, bool]:
    path = path.expanduser()
    if path.exists():
        return _load_identity(path), False

    identity = DeviceIdentity.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_identity_payload(identity), indent=2) + "\n",
        encoding="utf-8",
    )
    return identity, True


def _redact(value: str | None, secrets: Sequence[str]) -> str:
    text = value or "not provided"
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<redacted>")
    return text


def _print_quc_diagnostic(
    error: QucAuthenticationError,
    *,
    secrets: Sequence[str] = (),
) -> None:
    print("QUC authentication failed:")
    print(f"  region: {error.region}")
    print(f"  HTTP status: {error.http_status}")
    print(f"  errno: {error.errno}")
    print(f"  message: {_redact(error.errmsg, secrets)}")
    print(f"  decoded.user present: {error.user_present}")
    print(f"  captchaRequired: {error.captcha_required}")
    if error.captcha_type is not None:
        print(f"  captchaType: {error.captcha_type}")
    if error.errno == 5011:
        print("  diagnosis: incorrect captcha")


def _ordered_probe_regions(initial_region: str) -> tuple[str, ...]:
    if initial_region not in PROBE_REGIONS:
        supported = ", ".join(PROBE_REGIONS)
        raise ValueError(f"region must be one of: {supported}")
    return (
        initial_region,
        *(region for region in PROBE_REGIONS if region != initial_region),
    )


def _save_captcha(image: bytes) -> Path:
    with tempfile.NamedTemporaryFile(
        prefix="botslab360-captcha-",
        suffix=".png",
        delete=False,
    ) as captcha_file:
        captcha_file.write(image)
        return Path(captcha_file.name)


async def run_login(
    email: str,
    password: str,
    region: str,
    identity: DeviceIdentity,
    *,
    probe_regions: bool = False,
) -> int:
    regions = _ordered_probe_regions(region) if probe_regions else (region,)
    if probe_regions:
        print("Region probe:")

    for candidate_region in regions:
        captcha_secrets: tuple[str, ...] = ()
        captcha_required = False
        try:
            async with Botslab360Client.from_credentials(
                email,
                password,
                region=candidate_region,
                device_identity=identity,
            ) as client:
                try:
                    await client.authenticate()
                except CaptchaRequired as error:
                    captcha_required = True
                    if probe_regions:
                        print(f"  {candidate_region} -> errno 5010 (captcha required)")
                        print(f"Selected region: {candidate_region}")
                    captcha_path = _save_captcha(error.image)
                    print(f"Captcha image: {captcha_path}")
                    captcha_code = getpass("Captcha code (one retry): ")
                    captcha_secrets = (
                        email,
                        password,
                        error.challenge.sc,
                        captcha_code,
                    )
                    await client.continue_authentication(
                        error.challenge,
                        captcha_code,
                    )

                if probe_regions and not captcha_required:
                    print(f"  {candidate_region} -> errno 0 (authenticated)")
                    print(f"Selected region: {candidate_region}")
                devices = await client.get_devices()
        except QucAuthenticationError as error:
            if (
                probe_regions
                and not captcha_required
                and error.errno == ACCOUNT_NOT_FOUND_ERRNO
            ):
                print(
                    f"  {candidate_region} -> errno {ACCOUNT_NOT_FOUND_ERRNO} "
                    "(account not found in this region)"
                )
                if candidate_region != regions[-1]:
                    # Inspired by TA2k/ioBroker.botslab360 0.2.1 (937ae5a).
                    # Our decompiled Android build does not confirm this fallback,
                    # so it remains restricted to this explicit diagnostic mode.
                    continue
            elif probe_regions:
                errno = error.errno if error.errno is not None else "unknown"
                print(f"  {candidate_region} -> errno {errno} (stopped)")
            _print_quc_diagnostic(
                error,
                secrets=(email, password, *captcha_secrets),
            )
            return 1
        except ApiError as error:
            if probe_regions:
                print(f"  {candidate_region} -> network/API error (stopped)")
            print(
                "Authentication failed: "
                f"phase={error.phase}, HTTP status={error.status_code}"
            )
            return 1
        except (OSError, ValueError) as error:
            if probe_regions:
                print(f"  {candidate_region} -> local error (stopped)")
            print(f"Authentication failed: {type(error).__name__}")
            return 1

        print(f"Devices found: {len(devices)}")
        for device in devices:
            print(f"Name: {device.name}")
            print(f"Model: {device.model}")
            print(f"Online: {device.online}")
        return 0

    return 1


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--probe-regions",
        action="store_true",
        help="try each supported region once, continuing only after errno 1036",
    )
    parser.add_argument(
        "--identity",
        type=Path,
        default=DEFAULT_IDENTITY_PATH,
        metavar="PATH",
        help=f"device identity JSON path (default: {DEFAULT_IDENTITY_PATH.name})",
    )
    parser.add_argument(
        "--region",
        choices=PROBE_REGIONS,
        help="initial region (otherwise prompted, default: eu1)",
    )
    return parser.parse_args()


def main() -> int:
    logging.getLogger("httpx").disabled = True
    logging.getLogger("httpcore").disabled = True
    args = _parse_args()

    email = input("Email: ").strip()
    password = getpass("Password: ")
    region = args.region or input("Region [eu1]: ").strip() or "eu1"
    try:
        identity, created = _load_or_create_identity(args.identity)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"Could not load device identity: {type(error).__name__}")
        return 1

    action = "Created" if created else "Loaded"
    print(f"{action} device identity: {args.identity.expanduser()}")
    return asyncio.run(
        run_login(
            email,
            password,
            region,
            identity,
            probe_regions=args.probe_regions,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
