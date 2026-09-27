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
