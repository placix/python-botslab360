"""Manual smoke test for the Botslab/360 authentication flow."""

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


async def login(q: str, t: str) -> int:
    try:
        async with Botslab360Client(q, t) as client:
            session = await client.authenticate()
    except AuthenticationError as error:
        print_diagnostic("Login failed: authentication error", error)
        return EXIT_AUTHENTICATION_ERROR
    except InvalidSessionError as error:
        print_diagnostic(
            "Login failed: invalid or expired Smart Home session",
            error,
        )
        return EXIT_INVALID_SESSION
    except ApiError as error:
        print_diagnostic("Login failed: API error", error)
        return EXIT_API_ERROR

    print("Login successful")
    print(f"qid present: {bool(session.qid)}")
    print(f"sid present: {bool(session.sid)}")
    print(f"pushKey present: {bool(session.push_key)}")
    return 0


def main() -> int:
    logging.getLogger("httpx").disabled = True
    logging.getLogger("httpcore").disabled = True

    q = getpass("Q: ")
    t = getpass("T: ")
    return asyncio.run(login(q, t))


if __name__ == "__main__":
    raise SystemExit(main())
