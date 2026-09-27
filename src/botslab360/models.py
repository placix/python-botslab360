"""Authentication data models."""

from __future__ import annotations

from dataclasses import dataclass


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
