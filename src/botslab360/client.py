"""Public asynchronous Botslab/360 client."""

from __future__ import annotations

from collections.abc import Mapping
from numbers import Integral
from typing import Any
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
from .models import Device, QihooCredentials, RobotStatus, SmartSession
from .protocol import (
    DEFAULT_PUSH_HOST,
    DEFAULT_PUSH_PORT,
    STATUS_INFO_TYPE,
    PushClient,
)

DEVICE_LIST_PATH = "/common/dev/GetList"
COMMAND_PATH = "/clean/cmd/send"


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
        self._credentials: QihooCredentials = credentials_from_tokens(q, t)
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

    @property
    def session(self) -> SmartSession | None:
        return self._session

    async def authenticate(
        self,
        *,
        client_info: Mapping[str, object] | None = None,
    ) -> SmartSession:
        self._session = await self._auth.login(
            self._credentials,
            client_info=client_info,
        )
        return self._session

    async def get_devices(self) -> list[Device]:
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
            "taskid": str(uuid4()),
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
        await self._post_robot_request(
            device_id=_device_id(device),
            info_type=command.info_type,
            data=command.data,
            task_id=task_id,
            operation=operation,
        )

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
