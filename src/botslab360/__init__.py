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
    ROOM_CLEAN_TIMES,
    AuthBackend,
    CaptchaChallenge,
    Device,
    DeviceIdentity,
    QihooCredentials,
    RobotStatus,
    Room,
    RoomCleaningMode,
    RoomCleaningSettings,
    RoomFanMode,
    RoomWaterLevel,
    SmartSession,
)

__all__ = [
    "ROOM_CLEAN_TIMES",
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
    "RobotStatus",
    "Room",
    "RoomCleaningMode",
    "RoomCleaningSettings",
    "RoomFanMode",
    "RoomWaterLevel",
    "SmartSession",
    "credentials_from_tokens",
    "derive_qid",
]
