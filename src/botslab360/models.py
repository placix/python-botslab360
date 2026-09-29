"""Authentication data models."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum, IntEnum
from uuid import UUID, uuid4

_HEX_32 = re.compile(r"[0-9a-f]{32}")
_HEX_16 = re.compile(r"[0-9a-f]{16}")


class AuthBackend(str, Enum):
    """Account backend used for headless credential authentication."""

    BOTSLAB = "botslab"
    ROBOT360 = "robot360"


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    """Stable, non-secret identity used for account risk assessment."""

    mid: str
    android_id: str
    m2: str

    def __post_init__(self) -> None:
        if _HEX_32.fullmatch(self.mid) is None:
            raise ValueError("mid must contain 32 lowercase hexadecimal characters")
        if _HEX_16.fullmatch(self.android_id) is None:
            raise ValueError(
                "android_id must contain 16 lowercase hexadecimal characters"
            )
        try:
            parsed_m2 = UUID(self.m2)
        except (ValueError, AttributeError) as exc:
            raise ValueError("m2 must be a canonical UUID") from exc
        if str(parsed_m2) != self.m2:
            raise ValueError("m2 must be a canonical UUID")

    @classmethod
    def generate(cls) -> DeviceIdentity:
        """Generate an identity that callers should persist and reuse."""

        return cls(
            mid=uuid4().hex,
            android_id=uuid4().hex[:16],
            m2=str(uuid4()),
        )


@dataclass(frozen=True, slots=True, repr=False)
class CaptchaChallenge:
    """A graphic captcha image and its opaque continuation token."""

    image: bytes
    sc: str
    captcha_type: str = "graph"

    def __repr__(self) -> str:
        return (
            "CaptchaChallenge(image=<redacted>, sc=<redacted>, "
            f"captcha_type={self.captcha_type!r})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class QihooCredentials:
    """An already authenticated Qihoo Q/T session."""

    q: str
    t: str
    qid: str

    def __repr__(self) -> str:
        return "QihooCredentials(q=<redacted>, t=<redacted>, qid=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class SmartSession:
    """Credentials issued by the Botslab Smart Home login."""

    qid: str
    sid: str
    push_key: str

    def __repr__(self) -> str:
        return "SmartSession(qid=<redacted>, sid=<redacted>, push_key=<redacted>)"


@dataclass(frozen=True, slots=True)
class Device:
    """A Botslab/360 device returned by device discovery."""

    id: str
    name: str
    model: str
    online: bool


@dataclass(frozen=True, slots=True)
class Room:
    """A room from the robot's current smart-area map."""

    id: int
    name: str
    room_type: str | None
    clean_times: int | None
    fan_mode: str | None
    water_pump: int | None
    vertices: tuple[tuple[int, int], ...] | None = None
    mode: str | None = None


class RoomFanMode(str, Enum):
    """Suction modes supported by the Android room-attribute UI."""

    QUIET = "quiet"
    AUTO = "auto"
    STRONG = "strong"
    MAX = "max"


class RoomWaterLevel(IntEnum):
    """Mopping water levels supported by the Android room-attribute UI."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3


class RoomCleaningMode(IntEnum):
    """Deprecated unverified numeric cleaning-mode values.

    Retained for import compatibility with 0.4.2. These values must not be
    written to the vendor ``SweepArea.mode`` field.
    """

    SWEEP_AND_MOP = 1
    SWEEP = 2
    MOP = 3


ROOM_CLEAN_TIMES = (1, 2)


@dataclass(frozen=True, slots=True)
class RoomCleaningSettings:
    """Optional cleaning attributes for one room.

    ``mode`` is retained for 0.4.2 API compatibility but is unsupported and
    rejected when set because the vendor request field was misidentified.
    """

    clean_times: int | None = None
    fan_mode: str | None = None
    water_pump: int | None = None
    mode: int | None = None


@dataclass(frozen=True, slots=True)
class RobotStatus:
    """Read-only status reported by a Botslab/360 robot."""

    device_id: str
    online: bool | None
    battery: int | None
    state: str | None
    charging: bool | None
    fan_mode: str | None
    cleaned_area_m2: int | None
    cleaning_time_seconds: int | None
    error_code: int

    @property
    def cleaned_area(self) -> int | None:
        """Return cleaned square meters using the pre-1.0 field name."""

        return self.cleaned_area_m2

    @property
    def cleaning_time(self) -> int | None:
        """Return cleaning seconds using the pre-1.0 field name."""

        return self.cleaning_time_seconds
