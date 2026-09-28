"""Public asynchronous Botslab/360 client."""

from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable, Mapping
from numbers import Integral
from typing import Any, TypeVar
from uuid import uuid4

import httpx

from .auth import SMART_HOME_BASE_URL, BotslabAuth, credentials_from_tokens
from .commands import (
    LOCATE,
    PAUSE,
    RESUME,
    RETURN_TO_DOCK,
    START_CLEANING,
    CommandSpec,
)
from .exceptions import ApiError, AuthenticationError, InvalidSessionError
from .models import (
    AuthBackend,
    CaptchaChallenge,
    Device,
    DeviceIdentity,
    QihooCredentials,
    RobotStatus,
    SmartSession,
)
from .protocol import (
    DEFAULT_PUSH_HOST,
    DEFAULT_PUSH_PORT,
    STATUS_INFO_TYPE,
    PushClient,
)
from .quc import ANDROID_360_PROFILE, BOTSLAB_CLOUD_PROFILE, QucAuth

DEVICE_LIST_PATH = "/common/dev/GetList"
COMMAND_PATH = "/clean/cmd/send"
_ResultT = TypeVar("_ResultT")


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
    ) -> None:
        self._http_client = http_client or httpx.AsyncClient(timeout=timeout)
        self._owns_http_client = http_client is None
        self._base_url = base_url.rstrip("/")
        self._language = language
        self._push_host = push_host
        self._push_port = push_port
        self._auth = BotslabAuth(
            self._http_client,
            base_url=base_url,
            language=language,
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
        push_port: int = DEFAULT_PUSH_PORT,
    ) -> "Botslab360Client":
        """Create a client that obtains Q/T through a headless QUC login."""

        if not isinstance(backend, AuthBackend):
            raise ValueError("backend must be an AuthBackend value")
        if backend is AuthBackend.BOTSLAB:
            profile = BOTSLAB_CLOUD_PROFILE
            resolved_region = region or "eu1"
        else:
            profile = ANDROID_360_PROFILE
            if region is not None:
                raise ValueError("region is not supported by the ROBOT360 backend")
            resolved_region = None
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
            push_port=push_port,
        )
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
        )
        return client

    def _set_credentials(self, credentials: QihooCredentials) -> None:
        self._credentials: QihooCredentials | None = credentials
        self._account_fingerprint: str | None = hashlib.sha256(
            f"botslab360:{credentials.qid}".encode("utf-8")
        ).hexdigest()

    @property
    def session(self) -> SmartSession | None:
        return self._session

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
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise ApiError(
                "Device discovery returned an HTTP error",
                status_code=exc.response.status_code,
                phase="http",
            ) from exc
        except httpx.RequestError as exc:
            raise ApiError("Device discovery request failed", phase="transport") from exc

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
    ) -> RobotStatus:
        """Request and await one current status push for a robot."""

        if self._session is None:
            raise AuthenticationError(
                "Authentication is required before requesting robot status",
                phase="authentication",
            )
        if not isinstance(device_id, str) or not device_id:
            raise ValueError("device_id must be a non-empty string")

        task_id = str(uuid4())
        return await self._with_session_refresh(
            lambda: self._get_status_once(
                device_id=device_id,
                task_id=task_id,
                timeout=timeout,
            )
        )

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

        push = PushClient(
            self._session.sid,
            self._session.push_key,
            host=self._push_host,
            port=self._push_port,
        )
        async with push:
            await self._request_status(device_id=device_id, task_id=task_id)
            return await push.wait_for_status(
                device_id=device_id,
                task_id=task_id,
                timeout=timeout,
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

    async def _request_status(self, *, device_id: str, task_id: str) -> None:
        await self._post_robot_request(
            device_id=device_id,
            info_type=STATUS_INFO_TYPE,
            data="",
            task_id=task_id,
            operation="robot status request",
        )

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
        if self._owns_http_client:
            await self._http_client.aclose()

    async def __aenter__(self) -> "Botslab360Client":
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()
