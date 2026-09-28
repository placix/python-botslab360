"""Async authentication for Botslab/360 smart-home devices."""

from .auth import BotslabAuth, credentials_from_tokens, derive_qid
from .client import Botslab360Client
from .exceptions import (
    ApiError,
    AuthenticationError,
    Botslab360Error,
    CaptchaRequired,
    InvalidSessionError,
    QucAuthenticationError,
)
from .models import (
    AuthBackend,
    CaptchaChallenge,
    Device,
    DeviceIdentity,
    QihooCredentials,
    Room,
    RobotStatus,
    SmartSession,
)

__all__ = [
    "ApiError",
    "AuthBackend",
    "AuthenticationError",
    "Botslab360Client",
    "Botslab360Error",
    "BotslabAuth",
    "CaptchaChallenge",
    "CaptchaRequired",
    "Device",
    "DeviceIdentity",
    "InvalidSessionError",
    "QihooCredentials",
    "QucAuthenticationError",
    "Room",
    "RobotStatus",
    "SmartSession",
    "credentials_from_tokens",
    "derive_qid",
]
