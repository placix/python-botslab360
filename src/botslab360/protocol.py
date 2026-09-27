"""Isolated decoding and TCP transport for Botslab/360 push messages."""

from __future__ import annotations

import asyncio
import base64
import json
import time
from contextlib import suppress
from json import JSONDecodeError
from typing import Any

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .exceptions import ApiError
from .models import RobotStatus

DEFAULT_PUSH_HOST = "47.254.151.104"
DEFAULT_PUSH_PORT = 443
PUSH_PRODUCT = "60009"
STATUS_INFO_TYPE = "20001"


def _protocol_error(message: str, *, phase: str = "protocol") -> ApiError:
    return ApiError(message, phase=phase)


def _push_key_bytes(push_key: str) -> bytes:
    if not isinstance(push_key, str) or not push_key:
        raise _protocol_error("Push key is missing", phase="decryption")
    raw_key = push_key.encode("utf-8")[:16]
    return raw_key.ljust(16, b"\x00")


def decrypt_push_data(push_key: str, encoded_data: str) -> str:
    """Decrypt one Base64 encoded AES-CBC push payload."""

    if not isinstance(encoded_data, str) or not encoded_data:
        raise _protocol_error("Encrypted push data is missing", phase="decryption")
    try:
        ciphertext = base64.b64decode(encoded_data)
        key = _push_key_bytes(push_key)
        decryptor = Cipher(algorithms.AES(key), modes.CBC(key)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
        return plaintext.decode("utf-8")
    except ApiError:
        raise
    except Exception as exc:
        raise _protocol_error(
            "Push data could not be decrypted",
            phase="decryption",
        ) from exc


def decode_push_envelope(envelope: object, push_key: str) -> dict[str, Any]:
    """Decode the outer push envelope into an event object."""

    if not isinstance(envelope, dict):
        raise _protocol_error("Push envelope is invalid")
    encoded_data = envelope.get("data")
    if not isinstance(encoded_data, str) or not encoded_data:
        raise _protocol_error("Push envelope is missing data")

    if envelope.get("encrypt", 1) in (0, "0"):
        try:
            plaintext = base64.b64decode(encoded_data).decode("utf-8")
        except Exception as exc:
            raise _protocol_error("Push data could not be decoded") from exc
    else:
        plaintext = decrypt_push_data(push_key, encoded_data)

    try:
        event = json.loads(plaintext)
    except (TypeError, JSONDecodeError) as exc:
        raise _protocol_error("Decrypted push data is invalid JSON") from exc
    if not isinstance(event, dict):
        raise _protocol_error("Decrypted push event is invalid")
    return event


def _json_object(value: object, *, field: str) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except JSONDecodeError as exc:
            raise _protocol_error(f"Push {field} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise _protocol_error(f"Push {field} is invalid")
    return value


def _optional_int(value: object, *, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise _protocol_error(f"Status field {field} is invalid")
    return value


def parse_status_event(
    event: object,
    *,
    device_id: str,
    task_id: str,
) -> RobotStatus | None:
    """Return a status only when an event matches the requested robot and task."""

    if not isinstance(event, dict):
        raise _protocol_error("Push event is invalid")
    if event.get("sn") != device_id or event.get("taskid") != task_id:
        return None

    protocol = _json_object(event.get("data"), field="protocol")
    if str(protocol.get("infoType")) != STATUS_INFO_TYPE:
        return None
    status = _json_object(protocol.get("data"), field="status data")

    state = status.get("mode")
    fan_mode = status.get("workNoisy")
    if state is not None and not isinstance(state, str):
        raise _protocol_error("Status field mode is invalid")
    if fan_mode is not None and not isinstance(fan_mode, str):
        raise _protocol_error("Status field workNoisy is invalid")

    online_value = protocol.get("online")
    if online_value is None:
        online = None
    elif isinstance(online_value, bool):
        online = online_value
    elif isinstance(online_value, int):
        online = online_value != 0
    else:
        raise _protocol_error("Status field online is invalid")

    error_state = status.get("errorState")
    if error_state is None or error_state == []:
        error_code = 0
    elif isinstance(error_state, list) and all(
        isinstance(item, int) and not isinstance(item, bool) for item in error_state
    ):
        error_code = error_state[-1]
    else:
        raise _protocol_error("Status field errorState is invalid")

    return RobotStatus(
        device_id=device_id,
        online=online,
        battery=_optional_int(status.get("elecReal"), field="elecReal"),
        state=state,
        charging=state in {"charge", "fullcharge"} if state is not None else None,
        fan_mode=fan_mode,
        cleaned_area=_optional_int(status.get("cleanArea"), field="cleanArea"),
        cleaning_time=_optional_int(status.get("cleanTime"), field="cleanTime"),
        error_code=error_code,
    )


class _JsonFrameBuffer:
    def __init__(self) -> None:
        self._buffer = b""

    def feed(self, chunk: bytes) -> list[tuple[bytes, dict[str, Any]]]:
        self._buffer += chunk
        frames: list[tuple[bytes, dict[str, Any]]] = []
        decoder = json.JSONDecoder()

        while True:
            text = self._buffer.decode("latin-1")
            start = text.find("{")
            if start < 0:
                if len(self._buffer) > 4096:
                    self._buffer = b""
                return frames
            try:
                value, length = decoder.raw_decode(text[start:])
            except JSONDecodeError:
                return frames
            end = start + length
            if isinstance(value, dict):
                frames.append((self._buffer[:start], value))
            self._buffer = self._buffer[end:]


class PushClient:
    """Minimal one-shot client for receiving encrypted robot status pushes."""

    def __init__(
        self,
        sid: str,
        push_key: str,
        *,
        host: str = DEFAULT_PUSH_HOST,
        port: int = DEFAULT_PUSH_PORT,
    ) -> None:
        self._sid = sid
        self._push_key = push_key
        self._host = host
        self._port = port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._heartbeat_task: asyncio.Task[None] | None = None
        self._frames = _JsonFrameBuffer()

    async def connect(self) -> None:
        try:
            self._reader, self._writer = await asyncio.open_connection(
                self._host,
                self._port,
            )
            timestamp = int(time.time() * 1000)
            handshake = (
                b"\x00\x05\x00\x02\x00Ecv:1.7\n"
                b"t:30\n"
                + f"u:{self._sid}@{PUSH_PRODUCT}\n".encode("utf-8")
                + f"ts:{timestamp}".encode("ascii")
            )
            self._writer.write(handshake)
            await self._writer.drain()
            self._heartbeat_task = asyncio.create_task(self._heartbeat())
        except (OSError, asyncio.TimeoutError) as exc:
            await self.close()
            raise _protocol_error("Push connection failed", phase="transport") from exc

    async def _heartbeat(self) -> None:
        try:
            while True:
                await asyncio.sleep(25)
                if self._writer is None:
                    return
                self._writer.write(b"\x00\x05\x00\x00")
                await self._writer.drain()
        except (ConnectionError, OSError):
            return

    async def wait_for_status(
        self,
        *,
        device_id: str,
        task_id: str,
        timeout: float,
    ) -> RobotStatus:
        try:
            return await asyncio.wait_for(
                self._wait_for_status(device_id=device_id, task_id=task_id),
                timeout=timeout,
            )
        except asyncio.TimeoutError as exc:
            raise _protocol_error("Timed out waiting for robot status", phase="timeout") from exc

    async def _wait_for_status(self, *, device_id: str, task_id: str) -> RobotStatus:
        if self._reader is None or self._writer is None:
            raise _protocol_error("Push client is not connected", phase="transport")

        while True:
            try:
                chunk = await self._reader.read(65536)
            except OSError as exc:
                raise _protocol_error("Push connection failed", phase="transport") from exc
            if not chunk:
                raise _protocol_error("Push connection closed", phase="transport")

            for prefix, envelope in self._frames.feed(chunk):
                await self._acknowledge(prefix)
                event = decode_push_envelope(envelope, self._push_key)
                status = parse_status_event(
                    event,
                    device_id=device_id,
                    task_id=task_id,
                )
                if status is not None:
                    return status

    async def _acknowledge(self, prefix: bytes) -> None:
        if self._writer is None:
            return
        end = prefix.find(b"\x00", 5)
        if end < 0 or end < 4:
            return
        acknowledgement = bytearray(prefix[:end])
        acknowledgement[3] = 4
        try:
            self._writer.write(acknowledgement)
            await self._writer.drain()
        except OSError as exc:
            raise _protocol_error("Push acknowledgement failed", phase="transport") from exc

    async def close(self) -> None:
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._heartbeat_task
            self._heartbeat_task = None
        if self._writer is not None:
            self._writer.close()
            with suppress(OSError):
                await self._writer.wait_closed()
        self._reader = None
        self._writer = None

    async def __aenter__(self) -> "PushClient":
        await self.connect()
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()
