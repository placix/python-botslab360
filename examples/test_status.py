"""Manual smoke test for one Botslab/360 robot status response."""

from __future__ import annotations

import asyncio
import logging
from getpass import getpass

from botslab360 import (
    ApiError,
    AuthenticationError,
    Botslab360Client,
    InvalidSessionError,
)

EXIT_AUTHENTICATION_ERROR = 2
EXIT_INVALID_SESSION = 3
EXIT_API_ERROR = 4


def print_diagnostic(message: str, error: ApiError) -> None:
    print(message)
    print(f"phase: {error.phase}")
    print(f"HTTP status: {error.status_code}")
    print(f"errno: {error.errno}")
    print(f"response errno: {error.response_errno}")
    print(f"errorCode: {error.error_code}")


async def read_status(q: str, t: str) -> int:
    try:
        async with Botslab360Client(q, t) as client:
            await client.authenticate()
            devices = await client.get_devices()
            if not devices:
                print("Devices found: 0")
                return 0

            device = devices[0]
            status = await client.get_status(device.id)
    except AuthenticationError as error:
        print_diagnostic("Status request failed: authentication error", error)
        return EXIT_AUTHENTICATION_ERROR
    except InvalidSessionError as error:
        print_diagnostic(
            "Status request failed: invalid or expired Smart Home session",
            error,
        )
        return EXIT_INVALID_SESSION
    except ApiError as error:
        print_diagnostic("Status request failed: API or protocol error", error)
        return EXIT_API_ERROR

    print(f"Device: {device.name}")
    print(f"Model: {device.model}")
    if status.battery is not None:
        print(f"Battery: {status.battery} %")
    if status.state is not None:
        print(f"State: {status.state}")
    if status.charging is not None:
        print(f"Charging: {status.charging}")
    if status.online is not None:
        print(f"Online: {status.online}")
    if status.fan_mode is not None:
        print(f"Fan mode: {status.fan_mode}")
    if status.cleaned_area is not None:
        print(f"Cleaned area: {status.cleaned_area}")
    if status.cleaning_time is not None:
        print(f"Cleaning time: {status.cleaning_time}")
    print(f"Error code: {status.error_code}")
    return 0


def main() -> int:
    logging.getLogger("httpx").disabled = True
    logging.getLogger("httpcore").disabled = True

    q = getpass("Q: ")
    t = getpass("T: ")
    return asyncio.run(read_status(q, t))


if __name__ == "__main__":
    raise SystemExit(main())
