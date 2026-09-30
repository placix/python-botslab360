"""Isolated decoding and TCP transport for Botslab/360 push messages."""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import re
import time
from contextlib import suppress
from dataclasses import dataclass
from json import JSONDecodeError
from typing import Any

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .exceptions import ApiError
from .models import NetworkInfo, RobotStatus

DEFAULT_PUSH_HOST = "47.254.151.104"
DEFAULT_PUSH_PORT = 443
DEFAULT_PUSH_CLIENT_VERSION = "1.7"
DEFAULT_PUSH_HEARTBEAT_TIMEOUT = 30
DEFAULT_PUSH_HEARTBEAT_INTERVAL = 25.0
ANDROID_360_PUSH_PORT = 80
ANDROID_360_PUSH_CLIENT_VERSION = "1.21"
ANDROID_360_PUSH_HEARTBEAT_TIMEOUT = 20
ANDROID_360_PUSH_HEARTBEAT_INTERVAL = 15.0
PUSH_PRODUCT = "60009"
STATUS_INFO_TYPE = "20001"
NETWORK_INFO_TYPE = "21019"
COMMAND_RESPONSE_EVENT = "10"
PUSH_PROTOCOL_VERSION = 5
PUSH_BIND_ACK_OPCODE = 6
PUSH_MESSAGE_OPCODE = 3
PUSH_READY_TIMEOUT = 15.0
_MAC_PATTERN = re.compile(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}|[0-9a-fA-F]{12}")


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


def _decode_push_payload(envelope: object, push_key: str) -> str:
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

    return plaintext


def _parse_push_payload(plaintext: str) -> dict[str, Any]:
    try:
        event = json.loads(plaintext)
    except (TypeError, JSONDecodeError) as exc:
        raise _protocol_error("Decrypted push data is invalid JSON") from exc
    if not isinstance(event, dict):
        raise _protocol_error("Decrypted push event is invalid")
    return event


def decode_push_envelope(envelope: object, push_key: str) -> dict[str, Any]:
    """Decode the outer push envelope into an event object."""

    return _parse_push_payload(_decode_push_payload(envelope, push_key))


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


def _optional_status_text(value: object, *, field: str) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise _protocol_error(f"Status field {field} is invalid")
    return value


def _optional_position(value: object) -> tuple[int | None, int | None]:
    if value in (None, []):
        return None, None
    if (
        not isinstance(value, list)
        or len(value) < 2
        or any(
            isinstance(item, bool) or not isinstance(item, int) for item in value[:2]
        )
    ):
        raise _protocol_error("Status field pos is invalid")
    return value[0], value[1]


def _optional_text(value: object, *, field: str) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise _protocol_error(f"Network info field {field} is invalid")
    return value


def _optional_ip(value: object, *, field: str) -> str | None:
    text = _optional_text(value, field=field)
    if text is None:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise _protocol_error(f"Network info field {field} is invalid") from exc


def _optional_mac(value: object, *, field: str) -> str | None:
    text = _optional_text(value, field=field)
    if text is None:
        return None
    if _MAC_PATTERN.fullmatch(text) is None:
        raise _protocol_error(f"Network info field {field} is invalid")
    compact = text.replace(":", "").replace("-", "").lower()
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))


def _optional_network_int(value: object, *, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise _protocol_error(f"Network info field {field} is invalid")
    return value


def parse_network_info_event(
    event: object,
    *,
    device_id: str,
    task_id: str,
) -> NetworkInfo | None:
    """Return network info only for a matching command response."""

    if not isinstance(event, dict):
        raise _protocol_error("Push event is invalid")
    if event.get("sn") != device_id or event.get("taskid") != task_id:
        return None
    if str(event.get("event")) != COMMAND_RESPONSE_EVENT:
        return None

    protocol = _json_object(event.get("data"), field="protocol")
    if str(protocol.get("infoType")) != NETWORK_INFO_TYPE:
        return None
    payload = _json_object(protocol.get("data"), field="network info data")

    return NetworkInfo(
        station_ip=_optional_ip(payload.get("staIp"), field="staIp"),
        station_mac=_optional_mac(payload.get("staMac"), field="staMac"),
        station_ssid=_optional_text(payload.get("staId"), field="staId"),
        station_signal=_optional_network_int(
            payload.get("staSignal"),
            field="staSignal",
        ),
        ap_id=_optional_text(payload.get("apId"), field="apId"),
        ap_ip=_optional_ip(payload.get("apIp"), field="apIp"),
        compile_version=_optional_network_int(
            payload.get("compileVer"),
            field="compileVer",
        ),
        mcu_version=_optional_text(payload.get("mcuVer"), field="mcuVer"),
        rssi=_optional_network_int(payload.get("rssi"), field="rssi"),
    )


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

    position_x, position_y = _optional_position(status.get("pos"))

    return RobotStatus(
        device_id=device_id,
        online=online,
        battery=_optional_int(status.get("elecReal"), field="elecReal"),
        state=state,
        charging=state in {"charge", "fullcharge"} if state is not None else None,
        fan_mode=fan_mode,
        cleaned_area_m2=_optional_int(status.get("cleanArea"), field="cleanArea"),
        cleaning_time_seconds=_optional_int(
            status.get("cleanTime"),
            field="cleanTime",
        ),
        error_code=error_code,
        mop_status=_optional_int(status.get("mopStatus"), field="mopStatus"),
        total_cleaned_area_raw=_optional_int(status.get("allArea"), field="allArea"),
        total_cleaning_time_seconds=_optional_int(
            status.get("allTime"),
            field="allTime",
        ),
        sub_state=_optional_status_text(status.get("subMode"), field="subMode"),
        last_sub_state=_optional_status_text(
            status.get("lastSubMode"),
            field="lastSubMode",
        ),
        position_x=position_x,
        position_y=position_y,
        heading=_optional_int(status.get("phi"), field="phi"),
        timer_status=_optional_int(
            status.get("timerStatus"),
            field="timerStatus",
        ),
        auto_boost=_optional_int(status.get("autoBoost"), field="autoBoost"),
    )


class _PushTransportFrameBuffer:
    """Split Qihoo transport frames while preserving application payloads."""

    def __init__(self) -> None:
        self._buffer = b""

    def feed(self, chunk: bytes) -> list[tuple[int, bytes]]:
        self._buffer += chunk
        frames: list[tuple[int, bytes]] = []

        while len(self._buffer) >= 4:
            version = int.from_bytes(self._buffer[0:2], "big")
            opcode = int.from_bytes(self._buffer[2:4], "big")
            if version != PUSH_PROTOCOL_VERSION:
                raise _protocol_error("Push transport version is invalid")

            if opcode in (0, 1):
                frame_length = 4
            else:
                if len(self._buffer) < 6:
                    return frames
                property_length = int.from_bytes(self._buffer[4:6], "big")
                frame_length = 6 + property_length
                if opcode == PUSH_MESSAGE_OPCODE:
                    if len(self._buffer) < frame_length + 4:
                        return frames
                    data_length = int.from_bytes(
                        self._buffer[frame_length : frame_length + 4],
                        "big",
                    )
                    frame_length += 4 + data_length

            if len(self._buffer) < frame_length:
                return frames
            frames.append((opcode, self._buffer[:frame_length]))
            self._buffer = self._buffer[frame_length:]

        return frames


@dataclass(frozen=True)
class _PushApplicationFrame:
    prefix: bytes
    payload_length: int | None
    bodies: tuple[bytes, ...]
    products: tuple[int, ...]
    classification: str
    reason: str | None = None


def _parse_push_application_frame(frame: bytes) -> _PushApplicationFrame:
    """Parse one complete opcode-3 frame using the Android SDK layout."""

    if len(frame) < 10:
        return _PushApplicationFrame(b"", None, (), (), "malformed", "short_header")

    version = int.from_bytes(frame[0:2], "big")
    opcode = int.from_bytes(frame[2:4], "big")
    if version != PUSH_PROTOCOL_VERSION or opcode != PUSH_MESSAGE_OPCODE:
        return _PushApplicationFrame(
            b"",
            None,
            (),
            (),
            "malformed",
            "unexpected_header",
        )

    property_length = int.from_bytes(frame[4:6], "big")
    property_end = 6 + property_length
    if len(frame) < property_end + 4:
        return _PushApplicationFrame(
            b"",
            None,
            (),
            (),
            "malformed",
            "invalid_property_length",
        )

    payload_length = int.from_bytes(frame[property_end : property_end + 4], "big")
    payload_start = property_end + 4
    payload_end = payload_start + payload_length
    prefix = frame[:property_end]
    if payload_end != len(frame):
        return _PushApplicationFrame(
            prefix,
            payload_length,
            (),
            (),
            "malformed",
            "invalid_payload_length",
        )
    if payload_length == 0:
        return _PushApplicationFrame(prefix, 0, (), (), "empty_payload")

    bodies: list[bytes] = []
    products: list[int] = []
    offset = payload_start
    while offset < payload_end:
        if payload_end - offset < 16:
            return _PushApplicationFrame(
                prefix,
                payload_length,
                (),
                (),
                "malformed",
                "truncated_message_header",
            )
        product = int.from_bytes(frame[offset + 8 : offset + 12], "big")
        body_length = int.from_bytes(frame[offset + 12 : offset + 16], "big")
        offset += 16
        if body_length <= 0 or offset + body_length > payload_end:
            return _PushApplicationFrame(
                prefix,
                payload_length,
                (),
                (),
                "malformed",
                "invalid_body_length",
            )
        bodies.append(frame[offset : offset + body_length])
        products.append(product)
        offset += body_length

    return _PushApplicationFrame(
        prefix,
        payload_length,
        tuple(bodies),
        tuple(products),
        "queued",
    )


class PushClient:
    """Minimal one-shot client for receiving encrypted robot status pushes."""

    def __init__(
        self,
        sid: str,
        push_key: str,
        *,
        host: str = DEFAULT_PUSH_HOST,
        port: int = DEFAULT_PUSH_PORT,
        client_version: str = DEFAULT_PUSH_CLIENT_VERSION,
        heartbeat_timeout: int = DEFAULT_PUSH_HEARTBEAT_TIMEOUT,
        heartbeat_interval: float = DEFAULT_PUSH_HEARTBEAT_INTERVAL,
    ) -> None:
        self._sid = sid
        self._push_key = push_key
        self._host = host
        self._port = port
        self._client_version = client_version
        self._heartbeat_timeout = heartbeat_timeout
        self._heartbeat_interval = heartbeat_interval
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._heartbeat_task: asyncio.Task[None] | None = None
        self._reader_task: asyncio.Task[None] | None = None
        self._reader_started_event = asyncio.Event()
        self._ready_event = asyncio.Event()
        self._reader_error: ApiError | None = None
        self._application_frames: asyncio.Queue[tuple[bytes, bytes] | ApiError] = (
            asyncio.Queue()
        )
        self._transport_frames = _PushTransportFrameBuffer()
        self._tcp_connected = False
        self._reader_started = False
        self._handshake_sent = False
        self._handshake_response_received = False
        self._ready = False
        self._diagnostics = self._new_diagnostics()

    @staticmethod
    def _new_diagnostics() -> dict[str, Any]:
        return {
            "tcpBytesReceived": 0,
            "transportFramesReceived": 0,
            "opcodeCounts": {},
            "opcode3Acknowledged": 0,
            "opcode3StructurallyValid": 0,
            "opcode3StructurallyInvalid": 0,
            "opcode3FramesQueued": 0,
            "opcode3FramesEmptyPayload": 0,
            "opcode3FramesMalformed": 0,
            "opcode3FrameClassifications": [],
            "applicationFramesQueued": 0,
            "applicationFramesDispatched": 0,
            "applicationEnvelopesParsed": 0,
            "applicationEnvelopeParseSuccess": 0,
            "applicationEnvelopeParseFailure": 0,
            "applicationProductMismatch": 0,
            "decryptSuccess": 0,
            "decryptFailure": 0,
            "jsonParseSuccess": 0,
            "jsonParseFailure": 0,
        }

    def diagnostic_counters(self) -> dict[str, Any]:
        """Return safe aggregate transport counters without payload data."""

        return {
            **self._diagnostics,
            "opcodeCounts": dict(self._diagnostics["opcodeCounts"]),
            "opcode3FrameClassifications": [
                dict(item) for item in self._diagnostics["opcode3FrameClassifications"]
            ],
        }

    async def connect(self) -> None:
        if self._reader is not None or self._writer is not None:
            raise _protocol_error("Push client is already connected", phase="transport")
        self._reader_started_event = asyncio.Event()
        self._ready_event = asyncio.Event()
        self._reader_error = None
        self._application_frames = asyncio.Queue()
        self._transport_frames = _PushTransportFrameBuffer()
        self._tcp_connected = False
        self._reader_started = False
        self._handshake_sent = False
        self._handshake_response_received = False
        self._ready = False
        self._diagnostics = self._new_diagnostics()
        try:
            self._reader, self._writer = await asyncio.open_connection(
                self._host,
                self._port,
            )
            self._tcp_connected = True
            self._reader_task = asyncio.create_task(self._read_loop())
            await self._reader_started_event.wait()
            timestamp = int(time.time() * 1000)
            handshake = (
                b"\x00\x05\x00\x02"
                + f"cv:{self._client_version}\n".encode("ascii")
                + f"t:{self._heartbeat_timeout}\n".encode("ascii")
                + f"u:{self._sid}@{PUSH_PRODUCT}\n".encode()
                + f"ts:{timestamp}".encode("ascii")
            )
            property_length = len(handshake) - 4
            handshake = (
                handshake[:4] + property_length.to_bytes(2, "big") + handshake[4:]
            )
            self._writer.write(handshake)
            await self._writer.drain()
            self._handshake_sent = True
            await self.wait_until_ready(timeout=PUSH_READY_TIMEOUT)
            self._heartbeat_task = asyncio.create_task(self._heartbeat())
        except ApiError:
            await self.close()
            raise
        except asyncio.CancelledError:
            await self.close()
            raise
        except (OSError, asyncio.TimeoutError) as exc:
            await self.close()
            raise _protocol_error("Push connection failed", phase="transport") from exc

    async def wait_until_ready(self, *, timeout: float) -> None:
        """Wait until the push server confirms the bind registration."""

        try:
            await asyncio.wait_for(self._ready_event.wait(), timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise _protocol_error(
                "Timed out waiting for push registration",
                phase="timeout",
            ) from exc
        if self._reader_error is not None:
            raise self._reader_error
        if not self._handshake_response_received:
            raise _protocol_error(
                "Push registration was not confirmed",
                phase="protocol",
            )
        self._ready = True

    async def _read_loop(self) -> None:
        self._reader_started = True
        self._reader_started_event.set()
        try:
            while True:
                if self._reader is None:
                    raise _protocol_error(
                        "Push client is not connected",
                        phase="transport",
                    )
                chunk = await self._reader.read(65536)
                if not chunk:
                    raise _protocol_error(
                        "Push connection closed",
                        phase="transport",
                    )
                self._diagnostics["tcpBytesReceived"] += len(chunk)
                transport_frames = self._transport_frames.feed(chunk)
                self._diagnostics["transportFramesReceived"] += len(transport_frames)
                opcode_counts = self._diagnostics["opcodeCounts"]
                for opcode, frame in transport_frames:
                    opcode_counts[opcode] = opcode_counts.get(opcode, 0) + 1
                    if opcode == PUSH_BIND_ACK_OPCODE:
                        self._handshake_response_received = True
                        self._ready_event.set()
                        continue
                    if opcode != PUSH_MESSAGE_OPCODE:
                        continue
                    parsed = _parse_push_application_frame(frame)
                    if parsed.classification == "malformed":
                        self._diagnostics["opcode3StructurallyInvalid"] += 1
                    else:
                        self._diagnostics["opcode3StructurallyValid"] += 1
                    classification_key = {
                        "queued": "opcode3FramesQueued",
                        "empty_payload": "opcode3FramesEmptyPayload",
                        "malformed": "opcode3FramesMalformed",
                    }[parsed.classification]
                    self._diagnostics[classification_key] += 1
                    metadata: dict[str, int | str] = {
                        "index": opcode_counts[opcode],
                        "frameLength": len(frame),
                        "payloadLength": parsed.payload_length or 0,
                        "messageCount": len(parsed.bodies),
                        "productMatches": int(
                            bool(parsed.products)
                            and all(
                                product == int(PUSH_PRODUCT)
                                for product in parsed.products
                            )
                        ),
                        "classification": parsed.classification,
                    }
                    if parsed.reason is not None:
                        metadata["reason"] = parsed.reason
                    self._diagnostics["opcode3FrameClassifications"].append(metadata)
                    if parsed.classification == "malformed":
                        continue
                    if await self._acknowledge(parsed.prefix):
                        self._diagnostics["opcode3Acknowledged"] += 1
                    for product, body in zip(parsed.products, parsed.bodies):
                        if product != int(PUSH_PRODUCT):
                            self._diagnostics["applicationProductMismatch"] += 1
                        self._diagnostics["applicationFramesQueued"] += 1
                        self._application_frames.put_nowait((parsed.prefix, body))
        except asyncio.CancelledError:
            raise
        except (ApiError, OSError) as exc:
            self._reader_error = (
                exc
                if isinstance(exc, ApiError)
                else _protocol_error("Push connection failed", phase="transport")
            )
            self._ready_event.set()
            self._application_frames.put_nowait(self._reader_error)

    async def read_frame(self) -> tuple[bytes, dict[str, Any]]:
        """Read one application frame from a server-confirmed push channel."""

        if not self._ready:
            raise _protocol_error("Push client is not ready", phase="transport")
        while True:
            frame = await self._application_frames.get()
            if isinstance(frame, ApiError):
                raise frame
            prefix, body = frame
            self._diagnostics["applicationFramesDispatched"] += 1
            try:
                envelope = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, JSONDecodeError):
                self._diagnostics["applicationEnvelopeParseFailure"] += 1
                continue
            if not isinstance(envelope, dict):
                self._diagnostics["applicationEnvelopeParseFailure"] += 1
                continue
            self._diagnostics["applicationEnvelopeParseSuccess"] += 1
            self._diagnostics["applicationEnvelopesParsed"] += 1
            return prefix, envelope

    def decode_envelope(self, envelope: object) -> dict[str, Any]:
        """Decode one envelope while updating safe diagnostic counters."""

        encrypted = not (
            isinstance(envelope, dict) and envelope.get("encrypt", 1) in (0, "0")
        )
        try:
            plaintext = _decode_push_payload(envelope, self._push_key)
        except ApiError:
            if encrypted:
                self._diagnostics["decryptFailure"] += 1
            raise
        if encrypted:
            self._diagnostics["decryptSuccess"] += 1

        try:
            event = _parse_push_payload(plaintext)
        except ApiError:
            self._diagnostics["jsonParseFailure"] += 1
            raise
        self._diagnostics["jsonParseSuccess"] += 1
        return event

    async def read_event(self) -> dict[str, Any]:
        """Read and decode the next valid acknowledged application event."""

        while True:
            _, envelope = await self.read_frame()
            try:
                return self.decode_envelope(envelope)
            except ApiError:
                continue

    async def _heartbeat(self) -> None:
        try:
            while True:
                await asyncio.sleep(self._heartbeat_interval)
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
            raise _protocol_error(
                "Timed out waiting for robot status",
                phase="timeout",
            ) from exc

    async def wait_for_network_info(
        self,
        *,
        device_id: str,
        task_id: str,
        timeout: float,
    ) -> NetworkInfo:
        """Wait for one matching network-info command response."""

        try:
            return await asyncio.wait_for(
                self._wait_for_network_info(device_id=device_id, task_id=task_id),
                timeout=timeout,
            )
        except asyncio.TimeoutError as exc:
            raise _protocol_error(
                "Timed out waiting for robot network info",
                phase="timeout",
            ) from exc

    async def _wait_for_network_info(
        self,
        *,
        device_id: str,
        task_id: str,
    ) -> NetworkInfo:
        if self._reader is None or self._writer is None:
            raise _protocol_error("Push client is not connected", phase="transport")

        while True:
            event = await self.read_event()
            network_info = parse_network_info_event(
                event,
                device_id=device_id,
                task_id=task_id,
            )
            if network_info is not None:
                return network_info

    async def _wait_for_status(
        self,
        *,
        device_id: str,
        task_id: str,
    ) -> RobotStatus:
        if self._reader is None or self._writer is None:
            raise _protocol_error("Push client is not connected", phase="transport")

        while True:
            event = await self.read_event()
            status = parse_status_event(
                event,
                device_id=device_id,
                task_id=task_id,
            )
            if status is not None:
                return status

    async def _acknowledge(self, prefix: bytes) -> bool:
        if self._writer is None:
            return False
        if len(prefix) < 6:
            return False
        version = int.from_bytes(prefix[0:2], "big")
        opcode = int.from_bytes(prefix[2:4], "big")
        property_length = int.from_bytes(prefix[4:6], "big")
        property_end = 6 + property_length
        if (
            version != PUSH_PROTOCOL_VERSION
            or opcode != PUSH_MESSAGE_OPCODE
            or len(prefix) < property_end
        ):
            return False
        property_lines = prefix[6:property_end].split(b"\n")
        if not any(
            line.partition(b":")[0] == b"ack" and line.partition(b":")[2]
            for line in property_lines
        ):
            return False
        acknowledgement = bytearray(prefix[:property_end])
        acknowledgement[2:4] = (4).to_bytes(2, "big")
        try:
            self._writer.write(acknowledgement)
            await self._writer.drain()
        except OSError as exc:
            raise _protocol_error(
                "Push acknowledgement failed",
                phase="transport",
            ) from exc
        return True

    async def close(self) -> None:
        if self._reader_task is not None:
            close_error = _protocol_error(
                "Push connection closed",
                phase="transport",
            )
            self._reader_error = close_error
            self._ready_event.set()
            self._application_frames.put_nowait(close_error)
        if self._heartbeat_task is not None:
            self._heartbeat_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._heartbeat_task
            self._heartbeat_task = None
        if self._reader_task is not None:
            self._reader_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._reader_task
            self._reader_task = None
        if self._writer is not None:
            self._writer.close()
            with suppress(OSError):
                await self._writer.wait_closed()
        self._reader = None
        self._writer = None
        self._ready = False

    async def __aenter__(self) -> PushClient:
        await self.connect()
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()
