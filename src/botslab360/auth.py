"""Qihoo token handling and Botslab Smart Home authentication."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from numbers import Integral
from typing import Any
from urllib.parse import unquote
from uuid import uuid4

import httpx

from .exceptions import ApiError, AuthenticationError, InvalidSessionError
from .models import QihooCredentials, SmartSession

SMART_HOME_BASE_URL = "https://q.smart.360.cn"
SMART_LOGIN_PATH = "/common/user/login"

_QID_FROM_USER = re.compile(r"(?:^|[&;])u=360H(?P<qid>[0-9]+)(?=$|[&;])")
_QID_FROM_NUMERIC_USER = re.compile(r"(?:^|[&;])u=(?P<qid>[0-9]+)(?=$|[&;])")


def normalize_cookie_value(value: str, *, name: str) -> str:
    """Normalize one possibly URL-encoded cookie value exactly once."""

    if not isinstance(value, str) or not value.strip():
        raise AuthenticationError(
            f"{name} must be a non-empty string",
            phase="input",
        )

    normalized = value.strip()
    prefix = f"{name}="
    if normalized.startswith(prefix):
        normalized = normalized[len(prefix) :]

    normalized = unquote(normalized)
    if normalized.startswith(prefix):
        normalized = normalized[len(prefix) :]
    if not normalized:
        raise AuthenticationError(f"{name} must not be empty", phase="input")
    return normalized


def derive_qid(q: str) -> str:
    """Extract the decimal qid from the Q cookie's ``u`` field."""

    normalized_q = normalize_cookie_value(q, name="Q")
    match = _QID_FROM_USER.search(normalized_q)
    if match is None:
        match = _QID_FROM_NUMERIC_USER.search(normalized_q)
    if match is None:
        raise AuthenticationError(
            "Could not derive qid from the Q cookie",
            phase="input",
        )
    return match.group("qid")


def credentials_from_tokens(q: str, t: str) -> QihooCredentials:
    """Build normalized credentials without exposing token values."""

    qid = derive_qid(q)
    normalized_q = normalize_cookie_value(q, name="Q")
    normalized_t = normalize_cookie_value(t, name="T")
    return QihooCredentials(
        q=normalized_q,
        t=normalized_t,
        qid=qid,
    )


def _numeric_errno(value: Any, *, status_code: int) -> int:
    if isinstance(value, bool):
        raise ApiError(
            "Smart Home response contains an invalid errno",
            phase="response-validation",
            status_code=status_code,
        )
    if isinstance(value, Integral):
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"[+-]?[0-9]+", value.strip()):
        return int(value)
    raise ApiError(
        "Smart Home response contains an invalid errno",
        phase="response-validation",
        status_code=status_code,
    )


def _raise_api_error(
    errno: int,
    *,
    status_code: int,
    response_errno: int,
    error_code: int | None,
) -> None:
    details = {
        "errno": errno,
        "status_code": status_code,
        "phase": "api",
        "response_errno": response_errno,
        "error_code": error_code,
    }
    if errno == 102:
        raise InvalidSessionError("Smart Home session has expired", **details)
    if errno == 103:
        raise AuthenticationError("Qihoo Q/T session is unauthorized", **details)
    raise ApiError("Smart Home API rejected the login", **details)


class BotslabAuth:
    """Perform the Q/T to Smart Home session exchange."""

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        *,
        base_url: str = SMART_HOME_BASE_URL,
        language: str = "de_DE",
    ) -> None:
        self._http_client = http_client
        self._base_url = base_url.rstrip("/")
        self._language = language

    async def login(
        self,
        credentials: QihooCredentials,
        *,
        client_info: Mapping[str, object] | None = None,
    ) -> SmartSession:
        info = dict(
            client_info
            or {
                "release": "appstore",
                "brand": "iPhone",
                "model": "iPhone10,5",
                "notifyId": (
                    "aa0ad645269de676a5ee6a728ba13b777"
                    "ed3d4aa4d0e08a578097fbe78768b02"
                ),
                "lang": self._language,
                "imei": "f3bc82b802bd91a51d0dcc6499efeba3",
            }
        )
        form = {
            "clientInfo": json.dumps(info, separators=(",", ":")),
            "lang": self._language,
            "phoneNum": "",
            "taskid": str(uuid4()),
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "*/*",
            "Connection": "keep-alive",
            "Cookie": f"q={credentials.q};t={credentials.t};qid={credentials.qid}",
            "User-Agent": "qhsa-iphone-11.1.0",
            "Accept-Language": "de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8",
        }

        try:
            response = await self._http_client.post(
                f"{self._base_url}{SMART_LOGIN_PATH}",
                data=form,
                headers=headers,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ApiError(
                "Smart Home login returned an HTTP error",
                status_code=exc.response.status_code,
                phase="http",
            ) from exc
        except httpx.RequestError as exc:
            raise ApiError("Smart Home login request failed", phase="transport") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise ApiError(
                "Smart Home login returned invalid JSON",
                status_code=response.status_code,
                phase="json",
            ) from exc
        if not isinstance(payload, dict):
            raise ApiError(
                "Smart Home login returned an invalid response",
                status_code=response.status_code,
                phase="response-validation",
            )

        response_errno = _numeric_errno(
            payload.get("errno"),
            status_code=response.status_code,
        )
        errno = response_errno
        error_code = None
        if "errorCode" in payload:
            error_code = _numeric_errno(
                payload["errorCode"],
                status_code=response.status_code,
            )
            if error_code != 0:
                errno = error_code
        if errno != 0:
            _raise_api_error(
                errno,
                status_code=response.status_code,
                response_errno=response_errno,
                error_code=error_code,
            )

        data = payload.get("data")
        if not isinstance(data, dict):
            raise ApiError(
                "Smart Home login response is missing session data",
                status_code=response.status_code,
                phase="response-validation",
                response_errno=response_errno,
                error_code=error_code,
            )
        sid = data.get("sid")
        push_key = data.get("pushKey")
        if not isinstance(sid, str) or not sid:
            raise ApiError(
                "Smart Home login response is missing sid",
                status_code=response.status_code,
                phase="response-validation",
                response_errno=response_errno,
                error_code=error_code,
            )
        if not isinstance(push_key, str) or not push_key:
            raise ApiError(
                "Smart Home login response is missing pushKey",
                status_code=response.status_code,
                phase="response-validation",
                response_errno=response_errno,
                error_code=error_code,
            )

        return SmartSession(qid=credentials.qid, sid=sid, push_key=push_key)
