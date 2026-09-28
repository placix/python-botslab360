"""Exceptions raised by botslab360."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import CaptchaChallenge


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


class QucAuthenticationError(AuthenticationError):
    """QUC rejected authentication and returned safe diagnostic metadata."""

    def __init__(
        self,
        message: str,
        *,
        region: str | None,
        errno: int | None,
        errmsg: str | None,
        status_code: int | None,
        user_present: bool,
        captcha_required: bool,
        captcha_type: str | None,
        phase: str = "quc-login",
    ) -> None:
        super().__init__(
            message,
            errno=errno,
            status_code=status_code,
            phase=phase,
        )
        self.region = region
        self.errmsg = errmsg
        self.http_status = status_code
        self.user_present = user_present
        self.captcha_required = captcha_required
        self.captcha_type = captcha_type


class CaptchaRequired(QucAuthenticationError):
    """A graphic captcha must be solved before authentication can continue."""

    def __init__(
        self,
        challenge: "CaptchaChallenge",
        *,
        errno: int = 5010,
        status_code: int | None = None,
        region: str | None = None,
        errmsg: str | None = None,
        user_present: bool = False,
        captcha_type: str | None = None,
    ) -> None:
        super().__init__(
            "QUC authentication requires a graphic captcha",
            region=region,
            errno=errno,
            errmsg=errmsg,
            status_code=status_code,
            user_present=user_present,
            captcha_required=True,
            captcha_type=captcha_type or challenge.captcha_type,
            phase="captcha",
        )
        self.challenge = challenge

    @property
    def image(self) -> bytes:
        return self.challenge.image

    @property
    def sc(self) -> str:
        return self.challenge.sc


class InvalidSessionError(ApiError):
    """The Smart Home SID has expired and must be obtained again."""
