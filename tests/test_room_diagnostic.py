from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, parse_qsl

import httpx
import pytest

import botslab360.protocol as protocol_module
from botslab360 import (
    AuthBackend,
    Botslab360Client,
    CaptchaChallenge,
    CaptchaRequired,
    DeviceIdentity,
    InvalidSessionError,
    SmartSession,
)
from botslab360.protocol import PushClient

QID = "1234567890"
Q = f"u=360H{QID}&n=synthetic&m=not-a-real-token"
T = "s=synthetic-session&t=1700000000&v=2.0"
IDENTITY = DeviceIdentity(
    mid="0123456789abcdef0123456789abcdef",
    android_id="0123456789abcdef",
    m2="12345678-1234-5678-9234-567812345678",
)


async def _async_result(value):
    return value


def _diagnostic_module():
    path = Path(__file__).parents[1] / "diagnostics" / "capture_s9p_rooms.py"
    spec = importlib.util.spec_from_file_location("capture_s9p_rooms", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _smart_area() -> dict:
    return {
        "activeIds": [],
        "autoOrder": False,
        "cleanTimes": 2,
        "isAttrOn": 1,
        "mapId": 1,
        "value": [
            {"id": 5, "name": "RW50cnk=", "vertexs": [[1, 2]]},
            {"id": 6, "name": "Q2xvc2V0", "vertexs": [[3, 4]]},
        ],
    }


def _push_event(info_type: str, data: object) -> dict:
    return {
        "sn": "synthetic-device",
        "event": 4,
        "data": json.dumps({"infoType": info_type, "data": data}),
    }


def _bind_ack() -> bytes:
    properties = b"result:ok"
    return b"\x00\x05\x00\x06" + len(properties).to_bytes(2, "big") + properties


def _application_packet(event: dict[str, object]) -> bytes:
    plaintext = json.dumps(event, separators=(",", ":")).encode()
    envelope = {
        "encrypt": 0,
        "data": base64.b64encode(plaintext).decode(),
    }
    properties = b"ack:synthetic-ack"
    body = json.dumps(envelope, separators=(",", ":")).encode()
    message = (
        (1).to_bytes(8, "big")
        + (60009).to_bytes(4, "big")
        + len(body).to_bytes(4, "big")
        + body
    )
    return (
        b"\x00\x05\x00\x03"
        + len(properties).to_bytes(2, "big")
        + properties
        + len(message).to_bytes(4, "big")
        + message
    )


@pytest.mark.parametrize(
    ("preceding_events", "expected_info_types"),
    [
        (
            [_push_event("20001", {})],
            ["20001", "20002"],
        ),
        (
            [
                _push_event(
                    "30000",
                    json.dumps(
                        {
                            "cmds": [
                                {
                                    "infoType": "21011",
                                    "data": {},
                                }
                            ]
                        }
                    ),
                )
            ],
            ["30000", "21011", "20002"],
        ),
    ],
)
def test_map_waiter_ignores_preceding_pushes_and_finds_20002(
    preceding_events,
    expected_info_types,
    monkeypatch,
) -> None:
    module = _diagnostic_module()
    map_info = {"mapId": 1, "cleanId": "synthetic-clean-id"}

    class Reader:
        def __init__(self):
            self.chunks = [
                *[[event] for event in preceding_events],
                [_push_event("20002", json.dumps(map_info))],
            ]

        async def read(self, size):
            return self.chunks.pop(0)

    class Frames:
        def feed(self, chunk):
            return [(b"", event) for event in chunk]

    class Push:
        _reader = Reader()
        _frames = Frames()
        _push_key = "synthetic-push-key"

        async def read_frame(self):
            chunk = await self._reader.read(65536)
            return self._frames.feed(chunk)[0]

        async def read_event(self):
            prefix, envelope = await self.read_frame()
            await self._acknowledge(prefix)
            return module.decode_push_envelope(envelope, self._push_key)

        async def _acknowledge(self, prefix):
            pass

    monkeypatch.setattr(
        module,
        "decode_push_envelope",
        lambda envelope, push_key: envelope,
    )
    captures = []

    result = asyncio.run(
        module._wait_for_map(
            Push(),
            device_id="synthetic-device",
            http_client=object(),
            captures=captures,
        )
    )

    assert result == (map_info, "direct")
    assert [capture["infoType"] for capture in captures] == expected_info_types


def test_map_waiter_receives_fragmented_pushes_from_central_reader(
    monkeypatch,
) -> None:
    module = _diagnostic_module()
    map_info = {"mapId": 1, "cleanId": "synthetic-clean-id"}
    status_packet = _application_packet(_push_event("20001", {}))
    map_packet = _application_packet(
        _push_event("20002", json.dumps(map_info))
    )
    acknowledgement = _bind_ack()
    handshake_written = asyncio.Event()

    class FakeReader:
        def __init__(self):
            self.chunks = [
                acknowledgement[:4],
                acknowledgement[4:] + status_packet[:13],
                status_packet[13:] + map_packet[:7],
                map_packet[7:],
            ]
            self.reading = False
            self.max_concurrent_reads = 0

        async def read(self, size):
            assert not self.reading
            self.reading = True
            self.max_concurrent_reads = max(self.max_concurrent_reads, 1)
            try:
                await handshake_written.wait()
                if self.chunks:
                    return self.chunks.pop(0)
                await asyncio.Event().wait()
            finally:
                self.reading = False

    class FakeWriter:
        def write(self, data):
            handshake_written.set()

        async def drain(self):
            pass

        def close(self):
            pass

        async def wait_closed(self):
            pass

    reader = FakeReader()
    monkeypatch.setattr(
        protocol_module.asyncio,
        "open_connection",
        lambda host, port: _async_result((reader, FakeWriter())),
    )

    async def scenario():
        captures = []
        async with PushClient("synthetic-sid", "synthetic-push-key") as push:
            result = await asyncio.wait_for(
                module._wait_for_map(
                    push,
                    device_id="synthetic-device",
                    http_client=object(),
                    captures=captures,
                ),
                timeout=1,
            )
            counters = push.diagnostic_counters()
        return result, captures, counters

    result, captures, counters = asyncio.run(scenario())

    assert result == (map_info, "direct")
    assert [capture["infoType"] for capture in captures] == ["20001", "20002"]
    assert counters["opcodeCounts"] == {6: 1, 3: 2}
    assert counters["applicationFramesQueued"] == 2
    assert counters["applicationFramesDispatched"] == 2
    assert counters["jsonParseSuccess"] == 2
    assert reader.max_concurrent_reads == 1


def test_push_transport_diagnostics_prints_only_safe_counters(capsys) -> None:
    module = _diagnostic_module()

    class Push:
        def diagnostic_counters(self):
            return {
                "tcpBytesReceived": 321,
                "transportFramesReceived": 4,
                "opcodeCounts": {6: 1, 3: 3},
                "opcode3Acknowledged": 2,
                "opcode3StructurallyValid": 2,
                "opcode3StructurallyInvalid": 1,
                "opcode3FramesQueued": 2,
                "opcode3FramesEmptyPayload": 0,
                "opcode3FramesMalformed": 1,
                "opcode3FrameClassifications": [
                    {
                        "index": 1,
                        "frameLength": 120,
                        "payloadLength": 91,
                        "messageCount": 1,
                        "productMatches": 1,
                        "classification": "queued",
                    },
                    {
                        "index": 2,
                        "frameLength": 42,
                        "payloadLength": 5,
                        "messageCount": 0,
                        "productMatches": 0,
                        "classification": "malformed",
                        "reason": "truncated_message_header",
                    },
                ],
                "applicationFramesQueued": 3,
                "applicationFramesDispatched": 2,
                "applicationEnvelopesParsed": 2,
                "applicationEnvelopeParseSuccess": 2,
                "applicationEnvelopeParseFailure": 0,
                "applicationProductMismatch": 0,
                "decryptSuccess": 2,
                "decryptFailure": 1,
                "jsonParseSuccess": 2,
                "jsonParseFailure": 0,
            }

    module._print_push_transport_diagnostics(Push())

    output = capsys.readouterr().out
    assert "tcp bytes received: 321" in output
    assert "transport frames received: 4" in output
    assert "opcode 6 frames: 1" in output
    assert "opcode 3 frames: 3" in output
    assert "opcode 3 acknowledged: 2" in output
    assert "opcode 3 structurally valid: 2" in output
    assert "opcode 3 structurally invalid: 1" in output
    assert "opcode 3 queued frames: 2" in output
    assert "opcode 3 empty payload frames: 0" in output
    assert "opcode 3 malformed frames: 1" in output
    assert "application frames queued: 3" in output
    assert "application frames dispatched: 2" in output
    assert "application envelopes parsed: 2" in output
    assert "application envelope parse success: 2" in output
    assert "application envelope parse failure: 0" in output
    assert "application product mismatch: 0" in output
    assert "decrypt success: 2" in output
    assert "decrypt failure: 1" in output
    assert "json parse success: 2" in output
    assert "json parse failure: 0" in output
    assert (
        "opcode 3 frame 1: frame length=120, payload length=91, "
        "messages=1, product matches=1, classification=queued"
    ) in output
    assert "reason=truncated_message_header" in output


def test_map_waiter_is_armed_before_trigger_and_keeps_one_push_client(
    monkeypatch,
) -> None:
    module = _diagnostic_module()
    waiter_armed = asyncio.Event()
    map_ready = asyncio.Event()
    triggers = []
    push_instances = 0

    class FakePushClient:
        _tcp_connected = True
        _reader_started = True
        _handshake_sent = True
        _handshake_response_received = True
        _ready = True

        def __init__(self, *args, **kwargs):
            nonlocal push_instances
            push_instances += 1

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    async def wait_for_map(*args, **kwargs):
        waiter_armed.set()
        await map_ready.wait()
        return {"mapId": 1}, "direct"

    class Client:
        session = SmartSession(QID, "synthetic-sid", "synthetic-push-key")
        _push_host = "synthetic-host"
        _push_port = 443
        _http_client = object()

        async def _post_robot_request(self, **kwargs):
            assert waiter_armed.is_set()
            triggers.append(kwargs)
            map_ready.set()

    monkeypatch.setattr(module, "PushClient", FakePushClient)
    monkeypatch.setattr(module, "_wait_for_map", wait_for_map)

    result = asyncio.run(
        module._capture_map(
            Client(),
            device_id="synthetic-device",
            task_id="synthetic-task-id",
            timeout=0.01,
            captures=[],
        )
    )

    assert result == ({"mapId": 1}, "direct")
    assert push_instances == 1
    assert len(triggers) == 1
    assert triggers[0]["info_type"] == "30000"
    assert triggers[0]["device_id"] == "synthetic-device"
    assert triggers[0]["task_id"] == "synthetic-task-id"
    assert json.loads(triggers[0]["data"]) == module.LOAD_DATA
    assert [
        command["infoType"] for command in module.LOAD_DATA["cmds"]
    ] == ["20001", "21014", "21011"]
    assert module.LOAD_DATA["cmds"][2]["data"] == {
        "startPos": 0,
        "userId": 0,
        "mask": 0,
    }
    assert module.LOAD_DATA["mainCmds"] == []


def test_first_map_timeout_retries_once_on_same_connection(
    monkeypatch,
    capsys,
) -> None:
    module = _diagnostic_module()
    map_ready = asyncio.Event()
    triggers = []
    push_instances = 0
    waiter_calls = 0

    class FakePushClient:
        _tcp_connected = True
        _reader_started = True
        _handshake_sent = True
        _handshake_response_received = True
        _ready = True

        def __init__(self, *args, **kwargs):
            nonlocal push_instances
            push_instances += 1

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    async def wait_for_map(*args, **kwargs):
        nonlocal waiter_calls
        waiter_calls += 1
        await map_ready.wait()
        return {"mapId": 1}, "direct"

    class Client:
        session = SmartSession(QID, "synthetic-sid", "synthetic-push-key")
        _push_host = "synthetic-host"
        _push_port = 443
        _http_client = object()

        async def _post_robot_request(self, **kwargs):
            triggers.append(kwargs)
            if len(triggers) == 2:
                map_ready.set()

    monkeypatch.setattr(module, "PushClient", FakePushClient)
    monkeypatch.setattr(module, "_wait_for_map", wait_for_map)

    result = asyncio.run(
        module._capture_map(
            Client(),
            device_id="synthetic-device",
            task_id="synthetic-task-id",
            timeout=0.001,
            captures=[],
        )
    )

    assert result == ({"mapId": 1}, "direct")
    assert push_instances == 1
    assert waiter_calls == 1
    assert len(triggers) == 2
    assert triggers[0]["task_id"] == "synthetic-task-id"
    assert triggers[1]["task_id"] != triggers[0]["task_id"]
    output = capsys.readouterr().out
    assert "tcp connected: true" in output
    assert "push reader started: true" in output
    assert "push handshake sent: true" in output
    assert "push handshake response received: true" in output
    assert "push ready: true" in output
    assert "map waiter armed: true" in output
    assert "map trigger attempt: 1" in output
    assert "retrying map discovery: true" in output
    assert "map trigger attempt: 2" in output
    assert "20002 received: true" in output


def test_second_map_timeout_aborts_without_login_cleaning_or_old_map(
    monkeypatch,
) -> None:
    module = _diagnostic_module()
    triggers = []
    push_instances = 0
    login_calls = 0
    cleaning_calls = 0

    class FakePushClient:
        _tcp_connected = True
        _reader_started = True
        _handshake_sent = True
        _handshake_response_received = True
        _ready = True

        def __init__(self, *args, **kwargs):
            nonlocal push_instances
            push_instances += 1

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    async def wait_for_map(*args, **kwargs):
        await asyncio.Event().wait()

    async def clean_room(*args, **kwargs):
        nonlocal cleaning_calls
        cleaning_calls += 1

    class Client:
        session = SmartSession(QID, "synthetic-sid", "synthetic-push-key")
        _push_host = "synthetic-host"
        _push_port = 443
        _http_client = object()

        async def authenticate(self):
            nonlocal login_calls
            login_calls += 1

        async def _post_robot_request(self, **kwargs):
            triggers.append(kwargs)

    monkeypatch.setattr(module, "PushClient", FakePushClient)
    monkeypatch.setattr(module, "_wait_for_map", wait_for_map)
    monkeypatch.setattr(module, "_post_room_cleaning", clean_room)

    with pytest.raises(module.ApiError) as raised:
        asyncio.run(
            module._capture_map(
                Client(),
                device_id="synthetic-device",
                task_id="synthetic-task-id",
                timeout=0.001,
                captures=[],
            )
        )

    assert raised.value.phase == "timeout"
    assert "two attempts" in str(raised.value)
    assert push_instances == 1
    assert login_calls == 0
    assert cleaning_calls == 0
    assert len(triggers) == 2
    assert {trigger["info_type"] for trigger in triggers} == {"30000"}


def test_map_trigger_reports_safe_http_result(capsys) -> None:
    module = _diagnostic_module()

    async def scenario() -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/clean/cmd/send"
            return httpx.Response(200, json={"errno": 0})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            client._session = SmartSession(
                qid=QID,
                sid="synthetic-sid",
                push_key="synthetic-push-key",
            )
            await module._send_map_trigger(
                client,
                device_id="synthetic-device",
                task_id="synthetic-task-id",
            )

    asyncio.run(scenario())

    output = capsys.readouterr().out
    assert "map trigger HTTP status: 200" in output
    assert "map trigger errno: 0" in output
    assert "map trigger accepted: true" in output
    assert Q not in output
    assert T not in output
    assert "synthetic-sid" not in output
    assert "synthetic-push-key" not in output


def test_map_trigger_error_stops_without_outer_discovery_retry(
    monkeypatch,
    capsys,
) -> None:
    module = _diagnostic_module()
    push_instances = 0
    waiter_calls = 0
    trigger_calls = 0
    login_calls = 0

    class FakePushClient:
        _tcp_connected = True
        _reader_started = True
        _handshake_sent = True
        _handshake_response_received = True
        _ready = True

        def __init__(self, *args, **kwargs):
            nonlocal push_instances
            push_instances += 1

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    async def wait_for_map(*args, **kwargs):
        nonlocal waiter_calls
        waiter_calls += 1
        await asyncio.Event().wait()

    class Client:
        session = SmartSession(QID, "synthetic-sid", "synthetic-push-key")
        _push_host = "synthetic-host"
        _push_port = 443
        _http_client = object()

        async def authenticate(self):
            nonlocal login_calls
            login_calls += 1

        async def _post_robot_request(self, **kwargs):
            nonlocal trigger_calls
            trigger_calls += 1
            raise InvalidSessionError(
                "Synthetic rejected map trigger",
                errno=102,
                status_code=200,
            )

    monkeypatch.setattr(module, "PushClient", FakePushClient)
    monkeypatch.setattr(module, "_wait_for_map", wait_for_map)

    with pytest.raises(InvalidSessionError):
        asyncio.run(
            module._capture_map(
                Client(),
                device_id="synthetic-device",
                task_id="synthetic-task-id",
                timeout=0.001,
                captures=[],
            )
        )

    assert push_instances == 1
    assert waiter_calls == 1
    assert trigger_calls == 1
    assert login_calls == 0
    assert "_with_session_refresh" not in module._run.__code__.co_names
    output = capsys.readouterr().out
    assert "map trigger HTTP status: 200" in output
    assert "map trigger errno: 102" in output
    assert "map trigger accepted: false" in output


def test_push_readiness_timeout_aborts_before_map_trigger(
    monkeypatch,
    capsys,
) -> None:
    module = _diagnostic_module()
    trigger_calls = 0

    class FakePushClient:
        _tcp_connected = True
        _reader_started = True
        _handshake_sent = True
        _handshake_response_received = False
        _ready = False

        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            raise module.ApiError(
                "Timed out waiting for push registration",
                phase="timeout",
            )

        async def __aexit__(self, *args):
            pass

    class Client:
        session = SmartSession(QID, "synthetic-sid", "synthetic-push-key")
        _push_host = "synthetic-host"
        _push_port = 443
        _http_client = object()

        async def _post_robot_request(self, **kwargs):
            nonlocal trigger_calls
            trigger_calls += 1

    monkeypatch.setattr(module, "PushClient", FakePushClient)

    with pytest.raises(module.ApiError) as raised:
        asyncio.run(
            module._capture_map(
                Client(),
                device_id="synthetic-device",
                task_id="synthetic-task-id",
                timeout=0.001,
                captures=[],
            )
        )

    assert raised.value.phase == "timeout"
    assert trigger_calls == 0
    output = capsys.readouterr().out
    assert "push handshake sent: true" in output
    assert "push handshake response received: false" in output
    assert "push ready: false" in output
    assert "map trigger attempt" not in output


def test_prepare_room_request_keeps_every_room() -> None:
    module = _diagnostic_module()
    smart_area = module._gson_sweep_area_list(_smart_area())

    prepared = module._prepare_room_request(
        clean_id="synthetic-clean-id",
        map_id=1,
        smart_area=smart_area,
        room_id=6,
    )

    area_setting = prepared["form"]["areaSetting"]
    assert prepared["roomName"] == "Closet"
    assert area_setting["activeIds"] == [6]
    assert [room["id"] for room in area_setting["value"]] == [5, 6]
    assert json.loads(prepared["form"]["areaSettingJson"]) == area_setting
    assert smart_area["activeIds"] == []


def test_room_post_uses_endpoint_form_fields_and_session_cookies() -> None:
    module = _diagnostic_module()

    async def scenario() -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/clean/record/setAreaAndCleaning"
            assert request.method == "POST"
            assert request.headers["content-type"] == (
                "application/x-www-form-urlencoded"
            )
            assert request.headers["user-agent"] == "okhttp/4.10.0"
            body = (await request.aread()).decode()
            form = parse_qs(body)
            assert [name for name, _ in parse_qsl(body)] == [
                "sn",
                "cleanId",
                "areaSetting",
                "taskid",
                "from",
                "devType",
                "channel_id",
                "appVer",
                "lang",
                "model",
                "manufacturer",
            ]
            assert set(form) == {
                "sn",
                "cleanId",
                "areaSetting",
                "taskid",
                "from",
                "devType",
                "channel_id",
                "appVer",
                "lang",
                "model",
                "manufacturer",
            }
            assert form["sn"] == ["synthetic-device"]
            assert form["cleanId"] == ["synthetic-clean-id"]
            assert form["areaSetting"] == ['{"activeIds":[6]}']
            assert form["taskid"] == ["synthetic-task-id"]
            assert form["from"] == ["mpc_and"]
            assert form["devType"] == ["3"]
            assert form["channel_id"] == ["Overseas"]
            assert form["appVer"] == ["11.1.7"]
            assert form["lang"] == ["de_DE"]
            assert form["model"] == ["sdk_gphone64_x86_64"]
            assert form["manufacturer"] == ["Google"]
            assert "mcc" not in form
            cookie = request.headers["cookie"]
            assert "q=" in cookie
            assert "t=" in cookie
            assert "qid=" in cookie
            assert "sid=synthetic%2Fsid%2B%3D" in cookie
            return httpx.Response(200, json={"errno": 0})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            client._session = SmartSession(
                qid=QID,
                sid="synthetic/sid+=",
                push_key="synthetic-push-key",
            )
            result = await module._post_room_cleaning(
                client,
                device_id="synthetic-device",
                clean_id="synthetic-clean-id",
                area_setting_json='{"activeIds":[6]}',
                task_id="synthetic-task-id",
            )

        assert result == {
            "httpStatus": 200,
            "errno": 0,
            "responseErrno": 0,
            "errorCode": None,
            "accepted": True,
        }

    asyncio.run(scenario())


def test_room_request_summary_redacts_request_secrets() -> None:
    module = _diagnostic_module()
    prepared = module._prepare_room_request(
        clean_id="secret-clean-id",
        map_id=1,
        smart_area=module._gson_sweep_area_list(_smart_area()),
        room_id=6,
    )

    summary = module._room_request_summary(prepared)
    serialized = json.dumps(summary)

    assert summary["cleanId"] == "present"
    assert summary["device"] == "present (redacted)"
    assert "secret-clean-id" not in serialized
    assert "areaSetting" not in serialized


def test_room_post_includes_mcc_only_when_supplied() -> None:
    module = _diagnostic_module()

    async def scenario() -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            form = parse_qs((await request.aread()).decode())
            assert form["mcc"] == ["262"]
            return httpx.Response(200, json={"errno": 0})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            client._session = SmartSession(
                qid=QID,
                sid="synthetic-sid",
                push_key="synthetic-push-key",
            )
            await module._post_room_cleaning(
                client,
                device_id="synthetic-device",
                clean_id="synthetic-clean-id",
                area_setting_json='{"activeIds":[6]}',
                task_id="synthetic-task-id",
                mcc="262",
            )

    asyncio.run(scenario())


def test_room_post_maps_errno_102_to_invalid_session() -> None:
    module = _diagnostic_module()

    async def scenario() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"errno": 102})
            )
        ) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            client._session = SmartSession(
                qid=QID,
                sid="expired-synthetic-sid",
                push_key="synthetic-push-key",
            )
            with pytest.raises(InvalidSessionError) as raised:
                await module._post_room_cleaning(
                    client,
                    device_id="synthetic-device",
                    clean_id="synthetic-clean-id",
                    area_setting_json='{"activeIds":[6]}',
                    task_id="synthetic-task-id",
                )

        assert raised.value.errno == 102
        assert raised.value.status_code == 200

    asyncio.run(scenario())


def test_room_attempt_refreshes_sid_once_and_reopens_push(monkeypatch) -> None:
    module = _diagnostic_module()

    async def scenario() -> None:
        login_count = 0
        room_count = 0
        room_cookies: list[str] = []
        room_task_ids: list[str] = []
        push_sessions: list[tuple[str, str]] = []

        class FakePushClient:
            def __init__(self, sid, push_key, **kwargs):
                push_sessions.append((sid, push_key))

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        async def capture_events(*args, **kwargs):
            return []

        monkeypatch.setattr(module, "PushClient", FakePushClient)
        monkeypatch.setattr(module, "_capture_safe_push_events", capture_events)

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal login_count, room_count
            if request.url.path == "/common/user/login":
                login_count += 1
                return httpx.Response(
                    200,
                    json={
                        "errno": 0,
                        "data": {
                            "sid": f"synthetic-sid-{login_count}",
                            "pushKey": f"synthetic-push-key-{login_count}",
                        },
                    },
                )
            room_count += 1
            room_cookies.append(request.headers["cookie"])
            form = parse_qs((await request.aread()).decode())
            room_task_ids.append(form["taskid"][0])
            return httpx.Response(
                200,
                json={"errno": 102 if room_count == 1 else 0},
            )

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            await client.authenticate()
            result, push_events, push_error = await client._with_session_refresh(
                lambda: module._send_room_cleaning_attempt(
                    client,
                    device_id="synthetic-device",
                    clean_id="synthetic-clean-id",
                    area_setting_json='{"activeIds":[6]}',
                    task_id="synthetic-task-id",
                    observation_seconds=0.01,
                )
            )

        assert result["accepted"] is True
        assert push_events == []
        assert push_error is None
        assert login_count == 2
        assert room_count == 2
        assert "sid=synthetic-sid-1" in room_cookies[0]
        assert "sid=synthetic-sid-2" in room_cookies[1]
        assert room_task_ids == ["synthetic-task-id", "synthetic-task-id"]
        assert push_sessions == [
            ("synthetic-sid-1", "synthetic-push-key-1"),
            ("synthetic-sid-2", "synthetic-push-key-2"),
        ]

    asyncio.run(scenario())


def test_room_errno_100_does_not_refresh_or_retry(monkeypatch) -> None:
    module = _diagnostic_module()

    async def scenario() -> None:
        login_count = 0
        room_count = 0

        class FakePushClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                pass

        async def capture_events(*args, **kwargs):
            return []

        monkeypatch.setattr(module, "PushClient", FakePushClient)
        monkeypatch.setattr(module, "_capture_safe_push_events", capture_events)

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal login_count, room_count
            if request.url.path == "/common/user/login":
                login_count += 1
                return httpx.Response(
                    200,
                    json={
                        "errno": 0,
                        "data": {
                            "sid": "synthetic-sid",
                            "pushKey": "synthetic-push-key",
                        },
                    },
                )
            room_count += 1
            return httpx.Response(200, json={"errno": 100})

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            client = Botslab360Client(Q, T, http_client=http_client)
            await client.authenticate()
            result, _, _ = await client._with_session_refresh(
                lambda: module._send_room_cleaning_attempt(
                    client,
                    device_id="synthetic-device",
                    clean_id="synthetic-clean-id",
                    area_setting_json='{"activeIds":[6]}',
                    task_id="synthetic-task-id",
                    observation_seconds=0.01,
                )
            )

        assert result["errno"] == 100
        assert result["accepted"] is False
        assert login_count == 1
        assert room_count == 1

    asyncio.run(scenario())


def test_wrong_confirmation_never_sends(monkeypatch) -> None:
    module = _diagnostic_module()
    prepared = module._prepare_room_request(
        clean_id="synthetic-clean-id",
        map_id=1,
        smart_area=module._gson_sweep_area_list(_smart_area()),
        room_id=6,
    )
    monkeypatch.setattr("builtins.input", lambda prompt: "CLEAN ROOM 5")

    result = asyncio.run(
        module._run_confirmed_room_test(
            object(),
            device_id="synthetic-device",
            prepared=prepared,
            observation_seconds=0.01,
            status_timeout=0.01,
        )
    )

    assert result == {
        "selectedRoomId": 6,
        "roomName": "Closet",
        "mapId": 1,
        "sent": False,
    }


def test_robot360_client_uses_public_backend_without_region(monkeypatch) -> None:
    module = _diagnostic_module()
    captured: dict[str, object] = {}
    expected_client = object()

    class ClientFactory:
        @classmethod
        def from_credentials(cls, **kwargs: object) -> object:
            captured.update(kwargs)
            return expected_client

    monkeypatch.setattr(module, "Botslab360Client", ClientFactory)

    client = module._robot360_client(
        "private-account",
        "private-password",
        IDENTITY,
    )

    assert client is expected_client
    assert captured == {
        "email": "private-account",
        "password": "private-password",
        "backend": AuthBackend.ROBOT360,
        "device_identity": IDENTITY,
    }
    assert "region" not in captured


def test_robot360_captcha_is_continued_once_without_secret_output(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    module = _diagnostic_module()
    challenge = CaptchaChallenge(b"synthetic-image", "secret-sc")
    calls: list[object] = []

    class Client:
        async def authenticate(self) -> None:
            calls.append("authenticate")
            raise CaptchaRequired(challenge)

        async def continue_authentication(
            self,
            supplied_challenge: CaptchaChallenge,
            captcha_code: str,
        ) -> None:
            calls.append(("continue", supplied_challenge, captcha_code))

    monkeypatch.setattr(
        "builtins.input",
        lambda prompt: module.CAPTCHA_CONFIRMATION,
    )
    monkeypatch.setattr(module, "getpass", lambda prompt: "secret-code")
    captcha_path = tmp_path / "captcha.img"

    result = asyncio.run(
        module._authenticate_client(Client(), captcha_path=captcha_path)
    )

    assert result is True
    assert calls == [
        "authenticate",
        ("continue", challenge, "secret-code"),
    ]
    assert captcha_path.read_bytes() == challenge.image
    output = capsys.readouterr().out
    assert "secret-sc" not in output
    assert "secret-code" not in output


def test_captcha_requires_exact_confirmation_without_retry(
    tmp_path: Path,
    monkeypatch,
) -> None:
    module = _diagnostic_module()
    challenge = CaptchaChallenge(b"synthetic-image", "secret-sc")
    calls: list[str] = []

    class Client:
        async def authenticate(self) -> None:
            calls.append("authenticate")
            raise CaptchaRequired(challenge)

        async def continue_authentication(self, *args: object) -> None:
            calls.append("continue")

    monkeypatch.setattr("builtins.input", lambda prompt: "CONTINUE")

    result = asyncio.run(
        module._authenticate_client(
            Client(),
            captcha_path=tmp_path / "captcha.img",
        )
    )

    assert result is False
    assert calls == ["authenticate"]


def test_device_identity_is_created_once_and_reused(tmp_path: Path) -> None:
    module = _diagnostic_module()
    path = tmp_path / "identity.json"

    created_identity, created = module._load_or_create_identity(path)
    loaded_identity, created_again = module._load_or_create_identity(path)

    assert created is True
    assert created_again is False
    assert loaded_identity == created_identity


def test_main_defaults_to_robot360_without_qt(
    tmp_path: Path,
    monkeypatch,
) -> None:
    module = _diagnostic_module()
    identity_path = tmp_path / "identity.json"
    client = object()
    received: dict[str, object] = {}

    monkeypatch.delenv("BOTSLAB360_Q", raising=False)
    monkeypatch.delenv("BOTSLAB360_T", raising=False)
    monkeypatch.setattr(
        module,
        "_arguments",
        lambda: SimpleNamespace(auth="robot360", identity=identity_path),
    )
    monkeypatch.setattr(
        module,
        "_load_or_create_identity",
        lambda path: (IDENTITY, False),
    )
    monkeypatch.setattr("builtins.input", lambda prompt: "private-account")
    monkeypatch.setattr(module, "getpass", lambda prompt: "private-password")
    monkeypatch.setattr(
        module,
        "_robot360_client",
        lambda account, password, identity: client,
    )

    async def fake_run(args: object, supplied_client: object) -> int:
        received["args"] = args
        received["client"] = supplied_client
        return 0

    monkeypatch.setattr(module, "_run", fake_run)

    assert module.main() == 0
    assert received["client"] is client


def test_main_retains_explicit_legacy_qt_mode(monkeypatch) -> None:
    module = _diagnostic_module()
    client = object()
    constructed: list[tuple[str, str]] = []

    class ClientFactory:
        def __new__(cls, q: str, t: str) -> object:
            constructed.append((q, t))
            return client

    monkeypatch.setenv("BOTSLAB360_Q", Q)
    monkeypatch.setenv("BOTSLAB360_T", T)
    monkeypatch.setattr(
        module,
        "_arguments",
        lambda: SimpleNamespace(auth="qt", identity=None),
    )
    monkeypatch.setattr(module, "Botslab360Client", ClientFactory)

    async def fake_run(args: object, supplied_client: object) -> int:
        assert supplied_client is client
        return 0

    monkeypatch.setattr(module, "_run", fake_run)

    assert module.main() == 0
    assert constructed == [(Q, T)]
