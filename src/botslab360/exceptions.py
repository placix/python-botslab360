"""Exceptions raised by botslab360."""

from __future__ import annotations


class Botslab360Error(Exception):
    """Base class for all library errors."""


class ApiError(Botslab360Error):
    """The API returned an error or an unusable response."""

    def __init__(
        self,
        message: str,
        *,
        errno: int | None = None,
        status_code: int | None = None,
        phase: str = "api",
        response_errno: int | None = None,
        error_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.errno = errno
        self.status_code = status_code
        self.phase = phase
        self.response_errno = errno if response_errno is None else response_errno
        self.error_code = error_code


class AuthenticationError(ApiError):
    """The supplied Qihoo account session is invalid or unusable."""


class InvalidSessionError(ApiError):
    """The Smart Home SID has expired and must be obtained again."""
