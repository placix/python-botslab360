"""Interactive smoke test for verified Botslab/360 robot commands."""

from __future__ import annotations

import asyncio
import logging
from getpass import getpass

from botslab360 import (
    ApiError,
    AuthenticationError,
    Botslab360Client,
    InvalidSessionError,
    RobotStatus,
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


def print_status(status: RobotStatus) -> None:
    if status.battery is not None:
        print(f"Battery: {status.battery} %")
    if status.state is not None:
        print(f"State: {status.state}")
    if status.charging is not None:
        print(f"Charging: {status.charging}")
    if status.fan_mode is not None:
        print(f"Fan mode: {status.fan_mode}")
    print(f"Error code: {status.error_code}")


async def command_menu(q: str, t: str) -> int:
    try:
        async with Botslab360Client(q, t) as client:
            await client.authenticate()
            devices = await client.get_devices()
            if not devices:
                print("Devices found: 0")
                return 0

            device = devices[0]
            commands = {
                "1": ("Start cleaning", client.start_cleaning),
                "2": ("Pause", client.pause),
                "3": ("Resume", client.resume),
                "4": ("Return to dock", client.return_to_dock),
                "5": ("Locate", client.locate),
            }

            print(f"Device: {device.name}")
            print(f"Model: {device.model}")
            while True:
                print()
                print("1 - Start cleaning")
                print("2 - Pause")
                print("3 - Resume")
                print("4 - Return to dock")
                print("5 - Locate")
                print("0 - Exit")
                choice = input("Selection: ").strip()
                if choice == "0":
                    return 0
                selected = commands.get(choice)
                if selected is None:
                    print("Invalid selection")
                    continue

                label, command = selected
                confirmation = input(f"Send '{label}'? [y/N]: ").strip().lower()
                if confirmation not in {"y", "yes", "j", "ja"}:
                    print("Command cancelled")
                    continue

                await command(device)
                print("Command accepted by API")
                status = await client.get_status(device.id)
                print_status(status)
    except AuthenticationError as error:
        print_diagnostic("Command failed: authentication error", error)
        return EXIT_AUTHENTICATION_ERROR
    except InvalidSessionError as error:
        print_diagnostic(
            "Command failed: invalid or expired Smart Home session",
            error,
        )
        return EXIT_INVALID_SESSION
    except ApiError as error:
        print_diagnostic("Command failed: API or protocol error", error)
        return EXIT_API_ERROR


def main() -> int:
    logging.getLogger("httpx").disabled = True
    logging.getLogger("httpcore").disabled = True

    q = getpass("Q: ")
    t = getpass("T: ")
    return asyncio.run(command_menu(q, t))


if __name__ == "__main__":
    raise SystemExit(main())
