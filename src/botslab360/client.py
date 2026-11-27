"""Public asynchronous Botslab/360 client."""

from __future__ import annotations

import asyncio
import errno
import hashlib
import json
import logging
import math
import re
import socket
import ssl
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import AsyncExitStack, asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import timezone
from email.utils import parsedate_to_datetime
from numbers import Integral
from typing import Any, TypeVar
from urllib.parse import quote_plus
from uuid import uuid4

import httpx

from .auth import SMART_HOME_BASE_URL, BotslabAuth, credentials_from_tokens
from .commands import (
    LOCATE,
    MOP_ONLY_OFF,
    MOP_ONLY_ON,
    PAUSE,
    RESUME,
    RETURN_TO_DOCK,
    START_CLEANING,
    CommandSpec,
)
from .exceptions import (
    ApiError,
    AuthenticationError,
    InvalidSessionError,
    UnsupportedRoomMapError,
)
from .map_info import COMPOSITE_INFO_TYPE, LOAD_DATA, wait_for_map_info
from .models import (
    AuthBackend,
    CaptchaChallenge,
    Device,
    DeviceIdentity,
    NetworkInfo,
    OccupancyGrid,
    QihooCredentials,
    RobotStatus,
    Room,
    RoomCleaningSettings,
    SmartSession,
)
from .occupancy import parse_occupancy_grid
from .protocol import (
    ANDROID_360_PUSH_CLIENT_VERSION,
    ANDROID_360_PUSH_HEARTBEAT_INTERVAL,
    ANDROID_360_PUSH_HEARTBEAT_TIMEOUT,
    ANDROID_360_PUSH_PORT,
    DEFAULT_PUSH_CLIENT_VERSION,
    DEFAULT_PUSH_HEARTBEAT_INTERVAL,
    DEFAULT_PUSH_HEARTBEAT_TIMEOUT,
    DEFAULT_PUSH_HOST,
    DEFAULT_PUSH_PORT,
    NETWORK_INFO_TYPE,
    PUSH_READY_TIMEOUT,
    STATUS_INFO_TYPE,
    PushClient,
    _PushRegistrationClosed,
)
from .quc import ANDROID_360_PROFILE, BOTSLAB_CLOUD_PROFILE, QucAuth
from .rooms import (
    ROOM_CLEANING_PATH,
    RoomMap,
    normalize_room_settings,
    parse_room_map,
    prepare_area_setting,
)

DEVICE_LIST_PATH = "/common/dev/GetList"
COMMAND_PATH = "/clean/cmd/send"
ANDROID_APP_VERSION = "11.1.7"
ANDROID_CHANNEL_ID = "Overseas"
ANDROID_DEVICE_MANUFACTURER = "Google"
ANDROID_DEVICE_MODEL = "sdk_gphone64_x86_64"
ANDROID_ROOM_USER_AGENT = "okhttp/4.10.0"
_STATUS_RETRY_BACKOFFS = {
    "push_registration_timeout": (0.25, None),
    "push_registration_eof": (0.25, 0.5),
    "status_push_timeout": (0.0, None),
    "http_read_timeout": (0.0, None),
    "network_error": (2.0, 5.0),
    "connect_timeout": (2.0, 5.0),
    "dns_temporary": (2.0, 5.0),
    "http_server_error": (1.0, 3.0),
    "http_rate_limited": (1.0, None),
}
_TRANSIENT_NETWORK_ERRNOS = frozenset(
    getattr(errno, name)
    for name in (
        "EHOSTUNREACH",
        "ENETUNREACH",
        "ECONNREFUSED",
        "ECONNRESET",
        "ETIMEDOUT",
        "WSAEHOSTUNREACH",
        "WSAENETUNREACH",
        "WSAECONNREFUSED",
        "WSAECONNRESET",
        "WSAETIMEDOUT",
    )
    if hasattr(errno, name)
)
_ResultT = TypeVar("_ResultT")
_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class _PushProfile:
    """Transport settings for one initial push registration attempt."""

    name: str
    port: int
    client_version: str
    heartbeat_timeout: int
    heartbeat_interval: float


_LEGACY_PUSH_PROFILE = _PushProfile(
    "legacy",
    DEFAULT_PUSH_PORT,
    DEFAULT_PUSH_CLIENT_VERSION,
    DEFAULT_PUSH_HEARTBEAT_TIMEOUT,
    DEFAULT_PUSH_HEARTBEAT_INTERVAL,
)


def _numeric_api_code(value: Any, *, status_code: int) -> int:
    if isinstance(value, bool):
        raise ApiError(
            "Smart Home response contains an invalid errno",
            status_code=status_code,
            phase="response-validation",
        )
    if isinstance(value, Integral):
        return int(value)
    if isinstance(value, str):
        normalized = value.strip()
        if normalized.lstrip("+-").isdigit():
            return int(normalized)
    raise ApiError(
        "Smart Home response contains an invalid errno",
        status_code=status_code,
        phase="response-validation",
    )


def _raise_smart_api_error(
    errno: int,
    *,
    operation: str,
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
    raise ApiError(f"Smart Home API rejected {operation}", **details)


def _device_from_payload(payload: object, *, status_code: int) -> Device:
    if not isinstance(payload, dict):
        raise ApiError(
            "Device list contains an invalid device",
            status_code=status_code,
            phase="response-validation",
        )

    device_id = payload.get("sn")
    if not isinstance(device_id, str) or not device_id:
        raise ApiError(
            "Device list contains a device without an id",
            status_code=status_code,
            phase="response-validation",
        )

    name = payload.get("title", "")
    model = payload.get("hardware", "")
    online = payload.get("online", 0)
    if not isinstance(name, str) or not isinstance(model, str):
        raise ApiError(
            "Device list contains invalid device metadata",
            status_code=status_code,
            phase="response-validation",
        )
    if isinstance(online, bool):
        is_online = online
    elif isinstance(online, Integral):
        is_online = int(online) != 0
    else:
        raise ApiError(
            "Device list contains an invalid online state",
            status_code=status_code,
            phase="response-validation",
        )

    return Device(id=device_id, name=name, model=model, online=is_online)


def _device_id(device: Device | str) -> str:
    device_id = device.id if isinstance(device, Device) else device
    if not isinstance(device_id, str) or not device_id:
        raise ValueError("device must contain a non-empty id")
    return device_id


def _status_deadline_exceeded(elapsed: float) -> ApiError:
    _LOGGER.debug("Status recovery: total deadline exceeded elapsed_s=%.2f", elapsed)
    return ApiError("Status retrieval exceeded its total time budget", phase="timeout")


def _status_error_causes(error: ApiError) -> tuple[BaseException, ...]:
    causes: list[BaseException] = []
    current: BaseException = error
    # Follow explicit causes before implicit context. Bound traversal even if
    # a third-party transport supplies a cyclic exception chain.
    for _ in range(12):
        next_error = current.__cause__
        if next_error is None and not current.__suppress_context__:
            next_error = current.__context__
        if (
            next_error is None
            or next_error is error
            or any(next_error is cause for cause in causes)
        ):
            break
        causes.append(next_error)
        current = next_error
    return tuple(causes)


def _status_retry_reason(
    error: ApiError, causes: tuple[BaseException, ...]
) -> str | None:
    """Recognize eligible transient failures without logging their text."""
    if any(
        isinstance(cause, (AuthenticationError, InvalidSessionError))
        for cause in (error, *causes)
    ):
        return None
    if isinstance(error, _PushRegistrationClosed):
        return "push_registration_eof"
    if error.phase == "http":
        if error.status_code in {502, 503, 504}:
            return "http_server_error"
        if error.status_code == 429:
            return "http_rate_limited"
        return None
    if error.phase == "timeout" and isinstance(
        error.__cause__, (TimeoutError, asyncio.TimeoutError)
    ):
        if error.args == ("Timed out waiting for push registration",):
            return "push_registration_timeout"
        if error.args == ("Timed out waiting for robot status",):
            return "status_push_timeout"
    if error.phase != "transport" or any(
        isinstance(
            cause, (httpx.ProtocolError, httpx.UnsupportedProtocol, ssl.SSLError)
        )
        for cause in causes
    ):
        return None

    # DNS codes belong to a different namespace than OS socket errno.
    for cause in causes:
        if isinstance(cause, socket.gaierror):
            temporary_dns = {socket.EAI_AGAIN, getattr(socket, "WSATRY_AGAIN", None)}
            return (
                "dns_temporary"
                if cause.errno is not None and cause.errno in temporary_dns
                else None
            )
    if any(isinstance(cause, httpx.ReadTimeout) for cause in causes):
        return "http_read_timeout"
    if any(
        isinstance(cause, (httpx.ConnectTimeout, TimeoutError, asyncio.TimeoutError))
        for cause in causes
    ):
        return "connect_timeout"
    if any(
        isinstance(cause, OSError)
        and (
            cause.errno in _TRANSIENT_NETWORK_ERRNOS
            or getattr(cause, "winerror", None) in _TRANSIENT_NETWORK_ERRNOS
            or isinstance(cause, (ConnectionRefusedError, ConnectionResetError))
        )
        for cause in causes
    ):
        return "network_error"
    return None


def _status_retry_after(causes: tuple[BaseException, ...]) -> float | None:
    """Read Retry-After without retaining or emitting response headers."""
    for cause in causes:
        if isinstance(cause, httpx.HTTPStatusError):
            value = cause.response.headers.get("Retry-After", "").strip()
            if not value:
                return None
            if value.isascii() and value.isdecimal():
                # Treat impractically large waits as exceeding the budget.
                digits = value.lstrip("0")
                return float(digits or "0") if len(digits) <= 10 else math.inf
            try:
                date = parsedate_to_datetime(value)
                if date.tzinfo is None:
                    # The obsolete asctime HTTP-date form implies UTC.
                    if not re.fullmatch(
                        r"[A-Za-z]{3} [A-Za-z]{3} [ 0-9][0-9] "
                        r"[0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}",
                        value,
                    ):
                        return None
                    date = date.replace(tzinfo=timezone.utc)
                return max(0.0, date.timestamp() - time.time())
            except (OSError, OverflowError, TypeError, ValueError):
                pass
            return None
    return None


class Botslab360Client:
    """Client facade for authentication, discovery, status, and basic commands."""

    def __init__(
        self,
        q: str,
        t: str,
        *,
        http_client: httpx.AsyncClient | None = None,
        base_url: str = SMART_HOME_BASE_URL,
        language: str = "de_DE",
        timeout: float = 30.0,
        push_host: str = DEFAULT_PUSH_HOST,
        push_port: int = DEFAULT_PUSH_PORT,
    ) -> None:
        self._initialize(
            http_client=http_client,
            base_url=base_url,
            language=language,
            timeout=timeout,
            push_host=push_host,
            push_port=push_port,
            push_client_version=DEFAULT_PUSH_CLIENT_VERSION,
            push_heartbeat_timeout=DEFAULT_PUSH_HEARTBEAT_TIMEOUT,
            push_heartbeat_interval=DEFAULT_PUSH_HEARTBEAT_INTERVAL,
        )
        self._quc_auth: QucAuth | None = None
        self._auth_backend: AuthBackend | None = None
        self._device_identity: DeviceIdentity | None = None
        self._set_credentials(credentials_from_tokens(q, t))

    def _initialize(
        self,
        *,
        http_client: httpx.AsyncClient | None,
        base_url: str,
        language: str,
        timeout: float,
        push_host: str,
        push_port: int,
        push_client_version: str,
        push_heartbeat_timeout: int,
        push_heartbeat_interval: float,
        push_profile_name: str = "legacy",
    ) -> None:
        self._request_timeout = timeout
        self._status_cooldown: tuple[float, int] | None = None
        self._status_recovery_lock = asyncio.Lock()
        self._status_recovery_tasks: dict[asyncio.Task[RobotStatus], bool] = {}
        self._http_client = (
            http_client
            if http_client is not None
            else httpx.AsyncClient(timeout=timeout)
        )
        self._owns_http_client = http_client is None
        self._base_url = base_url.rstrip("/")
        self._language = language
        self._push_host = push_host
        self._push_port = push_port
        self._push_client_version = push_client_version
        self._push_heartbeat_timeout = push_heartbeat_timeout
        self._push_heartbeat_interval = push_heartbeat_interval
        self._push_profiles = (
            _PushProfile(
                push_profile_name,
                push_port,
                push_client_version,
                push_heartbeat_timeout,
                push_heartbeat_interval,
            ),
        )
        self._preferred_push_profile = self._push_profiles[0]
        self._auth = BotslabAuth(
            self._http_client,
            base_url=base_url,
            language=language,
            timeout=timeout,
        )
        self._session: SmartSession | None = None

    @classmethod
    def from_credentials(
        cls,
        email: str,
        password: str,
        *,
        backend: AuthBackend = AuthBackend.BOTSLAB,
        region: str | None = None,
        device_identity: DeviceIdentity | None = None,
        http_client: httpx.AsyncClient | None = None,
        base_url: str = SMART_HOME_BASE_URL,
        language: str = "de_DE",
        timeout: float = 30.0,
        push_host: str = DEFAULT_PUSH_HOST,
        push_port: int | None = None,
    ) -> Botslab360Client:
        """Create a client that obtains Q/T through a headless QUC login."""

        if not isinstance(backend, AuthBackend):
            raise TypeError("backend must be an AuthBackend value")
        if backend is AuthBackend.BOTSLAB:
            profile = BOTSLAB_CLOUD_PROFILE
            resolved_region = region or "eu1"
            resolved_push_port = DEFAULT_PUSH_PORT if push_port is None else push_port
            push_client_version = DEFAULT_PUSH_CLIENT_VERSION
            push_heartbeat_timeout = DEFAULT_PUSH_HEARTBEAT_TIMEOUT
            push_heartbeat_interval = DEFAULT_PUSH_HEARTBEAT_INTERVAL
        else:
            profile = ANDROID_360_PROFILE
            if region is not None:
                raise ValueError("region is not supported by the ROBOT360 backend")
            resolved_region = None
            resolved_push_port = (
                ANDROID_360_PUSH_PORT if push_port is None else push_port
            )
            push_client_version = ANDROID_360_PUSH_CLIENT_VERSION
            push_heartbeat_timeout = ANDROID_360_PUSH_HEARTBEAT_TIMEOUT
            push_heartbeat_interval = ANDROID_360_PUSH_HEARTBEAT_INTERVAL
        QucAuth.validate_options(
            email=email,
            password=password,
            region=resolved_region,
            _profile=profile,
        )
        client = cls.__new__(cls)
        client._initialize(
            http_client=http_client,
            base_url=base_url,
            language=language,
            timeout=timeout,
            push_host=push_host,
            push_port=resolved_push_port,
            push_client_version=push_client_version,
            push_heartbeat_timeout=push_heartbeat_timeout,
            push_heartbeat_interval=push_heartbeat_interval,
            push_profile_name="android"
            if backend is AuthBackend.ROBOT360
            else "legacy",
        )
        # An explicit port override remains authoritative; do not redirect it.
        if backend is AuthBackend.ROBOT360 and push_port is None:
            client._push_profiles += (_LEGACY_PUSH_PROFILE,)
        identity = device_identity or DeviceIdentity.generate()
        client._credentials = None
        client._account_fingerprint = None
        client._device_identity = identity
        client._auth_backend = backend
        client._quc_auth = QucAuth(
            client._http_client,
            email=email,
            password=password,
            region=resolved_region,
            identity=identity,
            _profile=profile,
            timeout=timeout,
        )
        return client

    def _set_credentials(self, credentials: QihooCredentials) -> None:
        self._credentials: QihooCredentials | None = credentials
        self._account_fingerprint: str | None = hashlib.sha256(
            f"botslab360:{credentials.qid}".encode()
        ).hexdigest()

    @property
    def session(self) -> SmartSession | None:
        return self._session

    @property
    def credentials(self) -> QihooCredentials | None:
        """Return reusable Q/T credentials after authentication."""

        return self._credentials

    @property
    def account_fingerprint(self) -> str:
        """Return a stable account identifier that does not expose the qid."""

        if self._account_fingerprint is None:
            raise AuthenticationError(
                "Authentication is required before the account fingerprint "
                "is available",
                phase="authentication",
            )
        return self._account_fingerprint

    @property
    def device_identity(self) -> DeviceIdentity | None:
        """Return the reusable identity for credential authentication, if any."""

        return self._device_identity

    @property
    def auth_backend(self) -> AuthBackend | None:
        """Return the selected credential backend, or ``None`` for Q/T clients."""

        return self._auth_backend

    async def authenticate(
        self,
        *,
        client_info: Mapping[str, object] | None = None,
    ) -> SmartSession:
        if self._credentials is None:
            if self._quc_auth is None:
                raise AuthenticationError(
                    "No account credentials are available",
                    phase="authentication",
                )
            self._set_credentials(await self._quc_auth.login())
        assert self._credentials is not None
        self._session = await self._auth.login(
            self._credentials,
            client_info=client_info,
        )
        return self._session

    async def continue_authentication(
        self,
        challenge: CaptchaChallenge,
        captcha_code: str,
        *,
        client_info: Mapping[str, object] | None = None,
    ) -> SmartSession:
        """Continue one credential login after a graphic captcha challenge."""

        if self._quc_auth is None:
            raise AuthenticationError(
                "Captcha continuation is only available for credential login",
                phase="authentication",
            )
        if self._credentials is not None:
            raise AuthenticationError(
                "Credential authentication has already completed",
                phase="authentication",
            )
        self._set_credentials(
            await self._quc_auth.login(
                challenge=challenge,
                captcha_code=captcha_code,
            )
        )
        assert self._credentials is not None
        self._session = await self._auth.login(
            self._credentials,
            client_info=client_info,
        )
        return self._session

    async def get_devices(self) -> list[Device]:
        task_id = str(uuid4())
        return await self._with_session_refresh(
            lambda: self._get_devices_once(task_id=task_id)
        )

    async def _get_devices_once(self, *, task_id: str) -> list[Device]:
        if self._session is None:
            raise AuthenticationError(
                "Authentication is required before device discovery",
                phase="authentication",
            )

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "*/*",
            "Connection": "keep-alive",
            "Cookie": (
                f"q={self._credentials.q};t={self._credentials.t};"
                f"qid={self._credentials.qid};sid={self._session.sid}"
            ),
            "User-Agent": "QihooSuperApp_NoPods/11.1.0 (iPhone; iOS 14.8; Scale/3.00)",
            "Accept-Language": "de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8",
        }
        form = {
            "countryId": "DE",
            "devType": "3",
            "from": "mpc_ios",
            "lang": self._language,
            "taskid": task_id,
        }

        try:
            response = await self._http_client.post(
                f"{self._base_url}{DEVICE_LIST_PATH}",
                data=form,
                headers=headers,
                timeout=self._request_timeout,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ApiError(
                "Device discovery returned an HTTP error",
                status_code=exc.response.status_code,
                phase="http",
            ) from exc
        except httpx.RequestError as exc:
            raise ApiError(
                "Device discovery request failed", phase="transport"
            ) from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise ApiError(
                "Device discovery returned invalid JSON",
                status_code=response.status_code,
                phase="json",
            ) from exc
        if not isinstance(payload, dict):
            raise ApiError(
                "Device discovery returned an invalid response",
                status_code=response.status_code,
                phase="response-validation",
            )

        response_errno = _numeric_api_code(
            payload.get("errno"),
            status_code=response.status_code,
        )
        errno = response_errno
        error_code = None
        if "errorCode" in payload:
            error_code = _numeric_api_code(
                payload["errorCode"],
                status_code=response.status_code,
            )
            if error_code != 0:
                errno = error_code
        if errno != 0:
            _raise_smart_api_error(
                errno,
                operation="device discovery",
                status_code=response.status_code,
                response_errno=response_errno,
                error_code=error_code,
            )

        data = payload.get("data")
        if not isinstance(data, dict):
            raise ApiError(
                "Device discovery response is missing data",
                status_code=response.status_code,
                phase="response-validation",
                response_errno=response_errno,
                error_code=error_code,
            )
        devices = data.get("list")
        if devices is None:
            devices = []
        if not isinstance(devices, list):
            raise ApiError(
                "Device discovery response contains an invalid device list",
                status_code=response.status_code,
                phase="response-validation",
                response_errno=response_errno,
                error_code=error_code,
            )
        return [
            _device_from_payload(device, status_code=response.status_code)
            for device in devices
        ]

    async def get_status(
        self,
        device_id: str,
        *,
        timeout: float = 30.0,
        total_timeout: float | None = None,
    ) -> RobotStatus:
        """Request status, optionally limiting the entire operation and recovery."""

        if self._session is None:
            raise AuthenticationError(
                "Authentication is required before requesting robot status",
                phase="authentication",
            )
        if not isinstance(device_id, str) or not device_id:
            raise ValueError("device_id must be a non-empty string")

        if total_timeout is None:
            task_id = str(uuid4())
            return await self._with_session_refresh(
                lambda: self._get_status_once(
                    device_id=device_id, task_id=task_id, timeout=timeout
                )
            )

        async def attempt() -> RobotStatus:
            return await self._get_status_once(
                device_id=device_id, task_id=str(uuid4()), timeout=timeout
            )

        if isinstance(total_timeout, bool) or not isinstance(
            total_timeout, (int, float)
        ):
            raise TypeError("total_timeout must be a number")
        if not math.isfinite(total_timeout) or total_timeout <= 0:
            raise ValueError("total_timeout must be finite and positive")

        self._check_status_cooldown()
        loop = asyncio.get_running_loop()
        started = loop.time()
        deadline = started + total_timeout

        async def recover() -> RobotStatus:
            async with self._status_recovery_lock:
                return await self._get_status_with_budget(
                    attempt, timeout, started, deadline
                )

        task = asyncio.create_task(recover())
        self._status_recovery_tasks[task] = True
        try:
            done, _ = await asyncio.wait({task}, timeout=max(0, deadline - loop.time()))
            if done:
                return task.result()
            raise _status_deadline_exceeded(loop.time() - started)
        finally:
            if not task.done():
                self._cancel_status_recovery(task)
                await asyncio.shield(asyncio.gather(task, return_exceptions=True))
            self._status_recovery_tasks.pop(task, None)

    def _cancel_status_recovery(self, task: asyncio.Task[RobotStatus]) -> None:
        if self._status_recovery_tasks.get(task):
            self._status_recovery_tasks[task] = False
            task.cancel()

    async def _get_status_with_budget(
        self,
        attempt: Callable[[], Awaitable[RobotStatus]],
        timeout: float,
        started: float,
        deadline: float,
    ) -> RobotStatus:
        clock = asyncio.get_running_loop().time
        session_refreshed = False

        for attempt_number in (1, 2, 3):
            # Check again after locking, sleeping, or refreshing the session.
            if clock() >= deadline:
                raise _status_deadline_exceeded(clock() - started)
            try:
                result = await attempt()
            except ApiError as error:
                if error.phase == "http-cooldown":
                    raise
                causes = _status_error_causes(error)
                reason = _status_retry_reason(error, causes)
                if attempt_number == 1 and isinstance(error, InvalidSessionError):
                    _LOGGER.debug("Status recovery: refreshing session")
                    await self.authenticate()
                    session_refreshed = True
                    continue

                backoff = None
                skipped = "permanent"
                if reason is not None:
                    skipped = "attempt_limit"
                    if not session_refreshed and attempt_number <= 2:
                        backoff = _STATUS_RETRY_BACKOFFS[reason][attempt_number - 1]
                    if backoff is not None and error.status_code in {429, 503}:
                        retry_after = _status_retry_after(causes)
                        if retry_after is not None:
                            backoff = max(backoff, retry_after)
                        elif error.status_code == 429:
                            backoff = None
                            skipped = "missing_or_invalid_retry_after"

                # Reserve a complete attempt including possible profile fallback.
                remaining = deadline - clock()
                planned_backoff = backoff
                if backoff is not None and remaining < (
                    len(self._push_profiles) * PUSH_READY_TIMEOUT
                    + self._request_timeout
                    + timeout
                    + backoff
                ):
                    backoff = None
                    skipped = "budget"

                os_error = next(
                    (cause for cause in reversed(causes) if isinstance(cause, OSError)),
                    None,
                )
                _LOGGER.debug(
                    "Status recovery: attempt=%d reason=%s phase=%s retry=%s "
                    "skip_reason=%s backoff_s=%.2f remaining_s=%.2f elapsed_s=%.2f "
                    "cause_chain=%s os_errno=%s winerror=%s http_status=%s",
                    attempt_number,
                    reason or type(error).__name__,
                    error.phase,
                    "started"
                    if backoff is not None
                    else "skipped budget"
                    if skipped == "budget"
                    else "stopped",
                    None if backoff is not None else skipped,
                    planned_backoff or 0.0,
                    remaining,
                    clock() - started,
                    " -> ".join(type(cause).__name__ for cause in causes) or None,
                    os_error.errno if os_error is not None else None,
                    getattr(os_error, "winerror", None),
                    error.status_code,
                )
                if backoff is None:
                    raise
                if backoff:
                    await asyncio.sleep(backoff)
            else:
                if attempt_number > 1:
                    _LOGGER.debug(
                        "Status recovery: attempt=%d result=succeeded elapsed_s=%.2f",
                        attempt_number,
                        clock() - started,
                    )
                return result
        raise AssertionError("Status recovery attempts exhausted")

    @asynccontextmanager
    async def _push_connection(self) -> AsyncIterator[PushClient]:
        """Try alternate profiles only before yielding an established channel."""

        if self._session is None:
            raise AuthenticationError(
                "Authentication is required before opening push",
                phase="authentication",
            )
        # Snapshot the order before awaiting: concurrent connections keep their
        # own attempts, while the last successful registration sets preference.
        preferred = self._preferred_push_profile
        profiles = (preferred,) + tuple(
            profile for profile in self._push_profiles if profile is not preferred
        )
        for index, profile in enumerate(profiles):
            push = PushClient(
                self._session.sid,
                self._session.push_key,
                host=self._push_host,
                port=profile.port,
                client_version=profile.client_version,
                heartbeat_timeout=profile.heartbeat_timeout,
                heartbeat_interval=profile.heartbeat_interval,
            )
            async with AsyncExitStack() as stack:
                try:
                    await stack.enter_async_context(push)
                except ApiError as error:
                    # Failed __aenter__ calls do not register an exit callback.
                    await push.close()
                    retry = (
                        not isinstance(
                            error, (AuthenticationError, InvalidSessionError)
                        )
                        and error.phase in {"transport", "timeout", "protocol"}
                        and index + 1 < len(profiles)
                    )
                    _LOGGER.debug(
                        "Push setup: profile=%s result=failed fallback=%s",
                        profile.name,
                        retry,
                    )
                    if not retry:
                        raise
                    continue
                # One reference assignment, without an await or tuple mutation.
                self._preferred_push_profile = profile
                _LOGGER.debug("Push setup: profile=%s result=succeeded", profile.name)
                # The operation runs outside the establishment exception handler:
                # no profile retry can replay a command or a map trigger.
                yield push
                return

    async def _get_status_once(
        self,
        *,
        device_id: str,
        task_id: str,
        timeout: float,
    ) -> RobotStatus:
        if self._session is None:
            raise AuthenticationError(
                "Authentication is required before requesting robot status",
                phase="authentication",
            )

        self._check_status_cooldown()
        async with self._push_connection() as push:
            await self._request_status(device_id=device_id, task_id=task_id)
            return await push.wait_for_status(
                device_id=device_id,
                task_id=task_id,
                timeout=timeout,
            )

    async def get_rooms(
        self,
        device: Device | str,
        *,
        timeout: float = 30.0,
    ) -> list[Room]:
        """Return current rooms, or [] for a recognized unsegmented map."""

        device_id = _device_id(device)
        try:
            room_map = await self._with_session_refresh(
                lambda: self._get_room_map_once(device_id=device_id, timeout=timeout)
            )
        except UnsupportedRoomMapError:
            return []
        return list(room_map.rooms)

    async def get_occupancy_grid(
        self,
        device: Device | str,
        *,
        timeout: float = 30.0,
    ) -> OccupancyGrid:
        """Fetch and decode a vendor grid, independently of room capability."""

        device_id = _device_id(device)
        map_info = await self._with_session_refresh(
            lambda: self._get_map_info_once(device_id=device_id, timeout=timeout)
        )
        # Bounds-checked decoding may still process up to a million cells.
        return await asyncio.to_thread(parse_occupancy_grid, map_info)

    async def get_network_info(
        self,
        device: Device | str,
        *,
        timeout: float = 30.0,
    ) -> NetworkInfo:
        """Return station network information reported by one robot."""

        device_id = _device_id(device)
        task_id = str(uuid4())
        return await self._with_session_refresh(
            lambda: self._get_network_info_once(
                device_id=device_id,
                task_id=task_id,
                timeout=timeout,
            )
        )

    async def _get_network_info_once(
        self,
        *,
        device_id: str,
        task_id: str,
        timeout: float,
    ) -> NetworkInfo:
        if self._session is None:
            raise AuthenticationError(
                "Authentication is required before requesting network info",
                phase="authentication",
            )

        async with self._push_connection() as push:
            await self._post_robot_request(
                device_id=device_id,
                info_type=NETWORK_INFO_TYPE,
                data="",
                task_id=task_id,
                operation="network info request",
            )
            return await push.wait_for_network_info(
                device_id=device_id,
                task_id=task_id,
                timeout=timeout,
            )

    async def clean_rooms(
        self,
        device: Device | str,
        room_ids: list[int],
        *,
        room_settings: Mapping[int, RoomCleaningSettings] | None = None,
        timeout: float = 30.0,
    ) -> None:
        """Start cleaning selected rooms from a freshly requested map."""

        device_id = _device_id(device)
        if not isinstance(room_ids, list):
            raise TypeError("room_ids must be a list of integers")
        if not room_ids:
            raise ValueError("room_ids must not be empty")
        if any(
            isinstance(room_id, bool) or not isinstance(room_id, int)
            for room_id in room_ids
        ):
            raise TypeError("room_ids must contain integers")
        normalized_ids = list(dict.fromkeys(room_ids))
        normalized_settings = normalize_room_settings(
            normalized_ids,
            room_settings,
        )
        await self._with_session_refresh(
            lambda: self._clean_rooms_once(
                device_id=device_id,
                room_ids=normalized_ids,
                room_settings=normalized_settings,
                timeout=timeout,
            )
        )

    async def _clean_rooms_once(
        self,
        *,
        device_id: str,
        room_ids: list[int],
        room_settings: Mapping[int, RoomCleaningSettings],
        timeout: float,
    ) -> None:
        room_map = await self._get_room_map_once(
            device_id=device_id,
            timeout=timeout,
        )
        area_setting = prepare_area_setting(
            room_map,
            room_ids,
            room_settings,
        )
        await self._post_room_cleaning(
            device_id=device_id,
            clean_id=room_map.clean_id,
            area_setting=area_setting,
            task_id=str(uuid4()),
        )

    async def _get_room_map_once(
        self,
        *,
        device_id: str,
        timeout: float,
    ) -> RoomMap:
        return parse_room_map(
            await self._get_map_info_once(
                device_id=device_id, timeout=timeout, room_request=True
            )
        )

    async def _get_map_info_once(
        self,
        *,
        device_id: str,
        timeout: float,
        room_request: bool = False,
    ) -> dict[str, Any]:
        if self._session is None:
            raise AuthenticationError(
                "Authentication is required before requesting rooms"
                if room_request
                else "Authentication is required before requesting maps",
                phase="authentication",
            )
        async with self._push_connection() as push:
            waiter = asyncio.create_task(
                wait_for_map_info(
                    push,
                    device_id=device_id,
                    http_client=self._http_client,
                    request_timeout=self._request_timeout,
                    timeout=timeout,
                    description="room map" if room_request else "map",
                )
            )
            await asyncio.sleep(0)
            try:
                await self._post_robot_request(
                    device_id=device_id,
                    info_type=COMPOSITE_INFO_TYPE,
                    data=json.dumps(LOAD_DATA, separators=(",", ":")),
                    task_id=str(uuid4()),
                    operation="room map request" if room_request else "map request",
                )
                return await waiter
            finally:
                if not waiter.done():
                    waiter.cancel()
                    with suppress(asyncio.CancelledError):
                        await waiter

    async def _post_room_cleaning(
        self,
        *,
        device_id: str,
        clean_id: str,
        area_setting: str,
        task_id: str,
    ) -> None:
        if self._session is None or self._credentials is None:
            raise AuthenticationError(
                "Authentication is required before cleaning rooms",
                phase="authentication",
            )
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "*/*",
            "Connection": "keep-alive",
            "Cookie": (
                f"q={self._credentials.q};t={self._credentials.t};"
                f"qid={self._credentials.qid};sid={quote_plus(self._session.sid)}"
            ),
            "User-Agent": ANDROID_ROOM_USER_AGENT,
        }
        form = {
            "sn": device_id,
            "cleanId": clean_id,
            "areaSetting": area_setting,
            "taskid": task_id,
            "from": "mpc_and",
            "devType": "3",
            "channel_id": ANDROID_CHANNEL_ID,
            "appVer": ANDROID_APP_VERSION,
            "lang": self._language,
            "model": ANDROID_DEVICE_MODEL,
            "manufacturer": ANDROID_DEVICE_MANUFACTURER,
        }
        try:
            response = await self._http_client.post(
                f"{self._base_url}{ROOM_CLEANING_PATH}",
                data=form,
                headers=headers,
                timeout=self._request_timeout,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ApiError(
                "Room cleaning returned an HTTP error",
                status_code=exc.response.status_code,
                phase="http",
            ) from exc
        except httpx.RequestError as exc:
            raise ApiError("Room cleaning failed", phase="transport") from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise ApiError(
                "Room cleaning returned invalid JSON",
                status_code=response.status_code,
                phase="json",
            ) from exc
        if not isinstance(payload, dict):
            raise ApiError(
                "Room cleaning returned an invalid response",
                status_code=response.status_code,
                phase="response-validation",
            )
        response_errno = _numeric_api_code(
            payload.get("errno"),
            status_code=response.status_code,
        )
        errno = response_errno
        error_code = None
        if "errorCode" in payload:
            error_code = _numeric_api_code(
                payload["errorCode"],
                status_code=response.status_code,
            )
            if error_code != 0:
                errno = error_code
        if errno != 0:
            _raise_smart_api_error(
                errno,
                operation="room cleaning",
                status_code=response.status_code,
                response_errno=response_errno,
                error_code=error_code,
            )

    async def start_cleaning(self, device: Device | str) -> None:
        """Request one whole-home smart cleaning run."""

        await self._execute_command(device, START_CLEANING, "start cleaning")

    async def pause(self, device: Device | str) -> None:
        """Pause the current cleaning run."""

        await self._execute_command(device, PAUSE, "pause cleaning")

    async def resume(self, device: Device | str) -> None:
        """Resume a paused cleaning run."""

        await self._execute_command(device, RESUME, "resume cleaning")

    async def return_to_dock(self, device: Device | str) -> None:
        """Request that the robot return to its charging dock."""

        await self._execute_command(device, RETURN_TO_DOCK, "return to dock")

    async def locate(self, device: Device | str) -> None:
        """Ask the robot to identify its location audibly."""

        await self._execute_command(device, LOCATE, "locate robot")

    async def set_mop_only(self, device: Device | str, enabled: bool) -> None:
        """Enable or disable mop-only cleaning."""

        if not isinstance(enabled, bool):
            raise TypeError("enabled must be a bool")
        command = MOP_ONLY_ON if enabled else MOP_ONLY_OFF
        await self._execute_command(device, command, "set mop-only mode")

    async def _execute_command(
        self,
        device: Device | str,
        command: CommandSpec,
        operation: str,
    ) -> None:
        task_id = str(uuid4()) if command.requires_task_id else None
        device_id = _device_id(device)
        await self._with_session_refresh(
            lambda: self._post_robot_request(
                device_id=device_id,
                info_type=command.info_type,
                data=command.data,
                task_id=task_id,
                operation=operation,
            )
        )

    async def _with_session_refresh(
        self,
        operation: Callable[[], Awaitable[_ResultT]],
    ) -> _ResultT:
        try:
            return await operation()
        except InvalidSessionError:
            await self.authenticate()
            return await operation()

    def _check_status_cooldown(self) -> None:
        if self._status_cooldown is None:
            return
        until, status_code = self._status_cooldown
        remaining = until - asyncio.get_running_loop().time()
        if remaining <= 0:
            self._status_cooldown = None
            return
        _LOGGER.debug(
            "Status cooldown: http_status=%d remaining_s=%.2f reason=retry_after",
            status_code,
            remaining,
        )
        raise ApiError(
            "Robot status request deferred by Retry-After",
            status_code=status_code,
            phase="http-cooldown",
        )

    async def _request_status(self, *, device_id: str, task_id: str) -> None:
        # Another status request could have received Retry-After while this
        # caller was establishing its push channel.
        self._check_status_cooldown()
        try:
            await self._post_robot_request(
                device_id=device_id,
                info_type=STATUS_INFO_TYPE,
                data="",
                task_id=task_id,
                operation="robot status request",
            )
        except ApiError as error:
            if error.phase == "http" and error.status_code in (429, 503):
                delay = _status_retry_after(_status_error_causes(error))
                if delay is not None and delay > 0:
                    until = asyncio.get_running_loop().time() + delay
                    if (
                        self._status_cooldown is None
                        or until > self._status_cooldown[0]
                    ):
                        self._status_cooldown = (until, error.status_code)
            raise

    async def _post_robot_request(
        self,
        *,
        device_id: str,
        info_type: str,
        data: str,
        task_id: str | None,
        operation: str,
    ) -> None:
        if self._session is None:
            raise AuthenticationError(
                "Authentication is required before communicating with a robot",
                phase="authentication",
            )

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "*/*",
            "Connection": "keep-alive",
            "Cookie": (
                f"q={self._credentials.q};t={self._credentials.t};"
                f"qid={self._credentials.qid};sid={self._session.sid}"
            ),
            "User-Agent": "QihooSuperApp_NoPods/11.1.0 (iPhone; iOS 14.8; Scale/3.00)",
            "Accept-Language": "de-DE;q=1, uk-DE;q=0.9, en-DE;q=0.8",
        }
        form = {
            "countryId": "DE",
            "data": data,
            "devType": "3",
            "from": "mpc_ios",
            "infoType": info_type,
            "lang": self._language,
            "sn": device_id,
        }
        if task_id is not None:
            form["taskid"] = task_id

        try:
            response = await self._http_client.post(
                f"{self._base_url}{COMMAND_PATH}",
                data=form,
                headers=headers,
                timeout=self._request_timeout,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ApiError(
                f"{operation.capitalize()} returned an HTTP error",
                status_code=exc.response.status_code,
                phase="http",
            ) from exc
        except httpx.RequestError as exc:
            raise ApiError(
                f"{operation.capitalize()} failed",
                phase="transport",
            ) from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise ApiError(
                f"{operation.capitalize()} returned invalid JSON",
                status_code=response.status_code,
                phase="json",
            ) from exc
        if not isinstance(payload, dict):
            raise ApiError(
                f"{operation.capitalize()} returned an invalid response",
                status_code=response.status_code,
                phase="response-validation",
            )

        response_errno = _numeric_api_code(
            payload.get("errno"),
            status_code=response.status_code,
        )
        errno = response_errno
        error_code = None
        if "errorCode" in payload:
            error_code = _numeric_api_code(
                payload["errorCode"],
                status_code=response.status_code,
            )
            if error_code != 0:
                errno = error_code
        if errno != 0:
            _raise_smart_api_error(
                errno,
                operation=operation,
                status_code=response.status_code,
                response_errno=response_errno,
                error_code=error_code,
            )

    async def close(self) -> None:
        tasks = tuple(self._status_recovery_tasks)
        for task in tasks:
            self._cancel_status_recovery(task)
        if tasks:
            await asyncio.shield(asyncio.gather(*tasks, return_exceptions=True))
        if self._owns_http_client:
            await self._http_client.aclose()

    async def __aenter__(self) -> Botslab360Client:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()
