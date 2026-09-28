from __future__ import annotations

import asyncio
import base64
import json

import pytest
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import botslab360.protocol as protocol_module
from botslab360 import ApiError
from botslab360.protocol import (
    PushClient,
    _PushTransportFrameBuffer,
    _parse_push_application_frame,
    decode_push_envelope,
    decrypt_push_data,
    parse_status_event,
)

PUSH_KEY = "0123456789abcdef-synthetic-suffix"
CIPHERTEXT = (
    "JeuGrPwBviBIvKzDH4b+T9jXQOx7yZPOoZ3MGCqjdMerMHumejZEZFRM/l0Ngi2z"
    "dNBw10q97+/8ycoGp8BwANyxwLGFRJ9Yva8BpWytQO2pWGHPeAEaWsoyasr45yLi"
    "5hByXIgbPwJvHHnuWUphlrOH+Ip44T58mfxY1j1W+ECejPC3PnxtwACdfwHJEtuno"
    "rLbk387bJJYEKiLNly6meJJXBsI9M1U+rayce2RwraQ70DadcHXdCDh/V9IiQXs6M"
    "xIhHvZ88r3TfgJHy48Yjmof92ZbAKFDCm12Nzwdw5llqXN/mqAbobDRq9OfFePGen"
    "Cf+lK+3e1x2zmdjdLWt5zWKB7rNujnmLVx4S9U94="
)


def bind_ack(properties: bytes = b"result:ok") -> bytes:
    return (
        b"\x00\x05\x00\x06"
        + len(properties).to_bytes(2, "big")
        + properties
    )


def application_packet(
    envelope: dict[str, object],
    *,
    message_id: int = 1,
) -> tuple[bytes, bytes]:
    return application_packet_with_messages([(message_id, envelope)])


def application_packet_with_messages(
    messages: list[tuple[int, dict[str, object]]],
) -> tuple[bytes, bytes]:
    properties = b"ack:synthetic-ack"
    message_parts = []
    for message_id, envelope in messages:
        body = json.dumps(envelope).encode()
        message_parts.append(
            message_id.to_bytes(8, "big")
            + (60009).to_bytes(4, "big")
            + len(body).to_bytes(4, "big")
            + body
        )
    message = b"".join(message_parts)
    packet = (
        b"\x00\x05\x00\x03"
        + len(properties).to_bytes(2, "big")
        + properties
        + len(message).to_bytes(4, "big")
        + message
    )
    acknowledgement = (
        b"\x00\x05\x00\x04"
        + len(properties).to_bytes(2, "big")
        + properties
    )
    return packet, acknowledgement


def raw_application_packet(payload: bytes) -> tuple[bytes, bytes]:
    properties = b"ack:synthetic-ack"
    packet = (
        b"\x00\x05\x00\x03"
        + len(properties).to_bytes(2, "big")
        + properties
        + len(payload).to_bytes(4, "big")
        + payload
    )
    acknowledgement = (
        b"\x00\x05\x00\x04"
        + len(properties).to_bytes(2, "big")
        + properties
    )
    return packet, acknowledgement


def encrypted_envelope(event: dict[str, object]) -> dict[str, object]:
    key = PUSH_KEY.encode()[:16]
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(json.dumps(event).encode()) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(key)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return {"data": base64.b64encode(ciphertext).decode()}


def synthetic_event() -> dict[str, object]:
    status = {
        "elecReal": 85,
        "mode": "charge",
        "workNoisy": "quiet",
        "cleanArea": 4200,
        "cleanTime": 1800,
        "errorState": [],
    }
    protocol = {"infoType": "20001", "online": 1, "data": status}
    return {
        "event": 10,
        "sn": "synthetic-device-1",
        "taskid": "synthetic-task",
        "createTime": 1700000000,
        "data": json.dumps(protocol, separators=(",", ":")),
    }


def run(coro):
    return asyncio.run(coro)


def test_decrypt_push_data_uses_first_16_push_key_bytes_for_key_and_iv() -> None:
    plaintext = decrypt_push_data(PUSH_KEY, CIPHERTEXT)

    assert json.loads(plaintext) == synthetic_event()


def test_decode_unencrypted_push_envelope() -> None:
    plaintext = json.dumps(synthetic_event()).encode()
    envelope = {
        "encrypt": 0,
        "data": base64.b64encode(plaintext).decode(),
    }

    assert decode_push_envelope(envelope, "unused-synthetic-key") == synthetic_event()


def test_parse_status_event_returns_typed_status() -> None:
    status = parse_status_event(
        synthetic_event(),
        device_id="synthetic-device-1",
        task_id="synthetic-task",
    )

    assert status is not None
    assert status.device_id == "synthetic-device-1"
    assert status.online is True
    assert status.battery == 85
    assert status.state == "charge"
    assert status.charging is True
    assert status.fan_mode == "quiet"
    assert status.cleaned_area_m2 == 4200
    assert status.cleaning_time_seconds == 1800
    assert status.cleaned_area == 4200
    assert status.cleaning_time == 1800
    assert status.error_code == 0


def test_parse_status_event_ignores_unrelated_messages() -> None:
    assert (
        parse_status_event(
            synthetic_event(),
            device_id="another-device",
            task_id="synthetic-task",
        )
        is None
    )


def test_invalid_encrypted_data_is_redacted() -> None:
    with pytest.raises(ApiError) as raised:
        decrypt_push_data(PUSH_KEY, "not-valid-ciphertext")

    assert raised.value.phase == "decryption"
    assert PUSH_KEY not in str(raised.value)
    assert "not-valid-ciphertext" not in str(raised.value)


def test_transport_buffer_retains_fragmented_bind_and_application_frames() -> None:
    buffer = _PushTransportFrameBuffer()
    acknowledgement = bind_ack()
    packet, _ = application_packet({"data": CIPHERTEXT})

    assert buffer.feed(acknowledgement[:3]) == []
    assert buffer.feed(acknowledgement[3:] + packet[:11]) == [
        (6, acknowledgement)
    ]
    assert buffer.feed(packet[11:]) == [(3, packet)]


def test_transport_buffer_parses_bind_ack_without_application_frame() -> None:
    buffer = _PushTransportFrameBuffer()
    acknowledgement = bind_ack()

    assert buffer.feed(acknowledgement) == [(6, acknowledgement)]
    assert buffer.feed(b"") == []


def test_transport_buffer_returns_multiple_application_frames_in_order() -> None:
    buffer = _PushTransportFrameBuffer()
    first, _ = application_packet({"data": "first"})
    second, _ = application_packet({"data": "second"})

    assert buffer.feed(first + second) == [(3, first), (3, second)]


def test_application_parser_uses_lengths_when_message_id_contains_json_brace() -> None:
    message_id = int.from_bytes(b"{\x00\x00\x00\x00\x00\x00\x01", "big")
    packet, _ = application_packet(
        {"data": CIPHERTEXT},
        message_id=message_id,
    )

    parsed = _parse_push_application_frame(packet)

    assert parsed.classification == "queued"
    assert len(parsed.bodies) == 1
    assert parsed.products == (60009,)
    assert json.loads(parsed.bodies[0]) == {"data": CIPHERTEXT}


@pytest.mark.parametrize(
    ("length_delta", "expected_reason"),
    [
        (-1, "truncated_message_header"),
        (1, "invalid_body_length"),
    ],
)
def test_application_parser_rejects_incorrect_json_length(
    length_delta,
    expected_reason,
) -> None:
    packet, _ = application_packet({"data": CIPHERTEXT})
    property_length = int.from_bytes(packet[4:6], "big")
    body_length_offset = 6 + property_length + 4 + 12
    declared_length = int.from_bytes(
        packet[body_length_offset : body_length_offset + 4],
        "big",
    )
    malformed = bytearray(packet)
    malformed[body_length_offset : body_length_offset + 4] = (
        declared_length + length_delta
    ).to_bytes(4, "big")

    parsed = _parse_push_application_frame(bytes(malformed))

    assert parsed.classification == "malformed"
    assert parsed.reason == expected_reason
    assert parsed.bodies == ()


def test_push_client_registers_decodes_status_and_acknowledges(monkeypatch) -> None:
    async def scenario() -> None:
        packet, acknowledgement = application_packet({"data": CIPHERTEXT})
        handshake_written = asyncio.Event()
        events: list[str] = []

        class FakeReader:
            def __init__(self):
                self.read_count = 0

            async def read(self, size):
                events.append("reader-active")
                await handshake_written.wait()
                self.read_count += 1
                if self.read_count == 1:
                    return bind_ack()
                if self.read_count == 2:
                    return packet
                await asyncio.Event().wait()

        class FakeWriter:
            def __init__(self):
                self.writes: list[bytes] = []
                self.closed = False

            def write(self, data):
                self.writes.append(bytes(data))
                if len(self.writes) == 1:
                    events.append("bind-written")
                    handshake_written.set()

            async def drain(self):
                pass

            def close(self):
                self.closed = True

            async def wait_closed(self):
                pass

        writer = FakeWriter()

        async def open_connection(host, port):
            assert host == "push.synthetic.invalid"
            assert port == 1234
            return FakeReader(), writer

        monkeypatch.setattr(protocol_module.asyncio, "open_connection", open_connection)
        monkeypatch.setattr(protocol_module.time, "time", lambda: 1700000000.0)

        async with PushClient(
            "synthetic-sid",
            PUSH_KEY,
            host="push.synthetic.invalid",
            port=1234,
        ) as push:
            status = await push.wait_for_status(
                device_id="synthetic-device-1",
                task_id="synthetic-task",
                timeout=1,
            )
            counters = push.diagnostic_counters()

        assert status.battery == 85
        assert counters["tcpBytesReceived"] == len(bind_ack()) + len(packet)
        assert counters["transportFramesReceived"] == 2
        assert counters["opcodeCounts"] == {6: 1, 3: 1}
        assert counters["opcode3Acknowledged"] == 1
        assert counters["opcode3StructurallyValid"] == 1
        assert counters["opcode3StructurallyInvalid"] == 0
        assert counters["opcode3FramesQueued"] == 1
        assert counters["opcode3FramesEmptyPayload"] == 0
        assert counters["opcode3FramesMalformed"] == 0
        assert counters["applicationFramesQueued"] == 1
        assert counters["applicationFramesDispatched"] == 1
        assert counters["applicationEnvelopesParsed"] == 1
        assert counters["applicationEnvelopeParseSuccess"] == 1
        assert counters["applicationEnvelopeParseFailure"] == 0
        assert counters["applicationProductMismatch"] == 0
        assert counters["decryptSuccess"] == 1
        assert counters["decryptFailure"] == 0
        assert counters["jsonParseSuccess"] == 1
        assert counters["jsonParseFailure"] == 0
        properties = (
            b"cv:1.7\n"
            b"t:30\n"
            b"u:synthetic-sid@60009\n"
            b"ts:1700000000000"
        )
        assert writer.writes[0] == (
            b"\x00\x05\x00\x02"
            + len(properties).to_bytes(2, "big")
            + properties
        )
        assert events.index("reader-active") < events.index("bind-written")
        assert writer.writes[1] == acknowledgement
        assert len([item for item in writer.writes if item[2:4] == b"\x00\x02"]) == 1
        assert writer.closed is True

    run(scenario())


def test_android_profile_bind_matches_pcap_structure(monkeypatch) -> None:
    async def scenario() -> None:
        handshake_written = asyncio.Event()

        class FakeReader:
            def __init__(self):
                self.sent = False

            async def read(self, size):
                await handshake_written.wait()
                if not self.sent:
                    self.sent = True
                    return bind_ack(b"id:60009\nr:0")
                await asyncio.Event().wait()

        class FakeWriter:
            def __init__(self):
                self.writes: list[bytes] = []

            def write(self, data):
                self.writes.append(bytes(data))
                handshake_written.set()

            async def drain(self):
                pass

            def close(self):
                pass

            async def wait_closed(self):
                pass

        writer = FakeWriter()

        async def open_connection(host, port):
            assert host == "47.254.151.104"
            assert port == 80
            return FakeReader(), writer

        monkeypatch.setattr(protocol_module.asyncio, "open_connection", open_connection)
        monkeypatch.setattr(protocol_module.time, "time", lambda: 1700000000.0)

        push = PushClient(
            "synthetic-sid",
            PUSH_KEY,
            port=80,
            client_version="1.21",
            heartbeat_timeout=20,
            heartbeat_interval=15.0,
        )
        await push.connect()
        await push.close()

        properties = (
            b"cv:1.21\n"
            b"t:20\n"
            b"u:synthetic-sid@60009\n"
            b"ts:1700000000000"
        )
        assert writer.writes[0] == (
            b"\x00\x05\x00\x02"
            + len(properties).to_bytes(2, "big")
            + properties
        )

    run(scenario())


def test_opcode1_is_consumed_as_transport_before_application(monkeypatch) -> None:
    async def scenario() -> None:
        handshake_written = asyncio.Event()
        packet, acknowledgement = application_packet({"data": CIPHERTEXT})

        class FakeReader:
            def __init__(self):
                self.sent = False

            async def read(self, size):
                await handshake_written.wait()
                if not self.sent:
                    self.sent = True
                    return bind_ack() + b"\x00\x05\x00\x01" + packet
                await asyncio.Event().wait()

        class FakeWriter:
            def __init__(self):
                self.writes: list[bytes] = []

            def write(self, data):
                self.writes.append(bytes(data))
                handshake_written.set()

            async def drain(self):
                pass

            def close(self):
                pass

            async def wait_closed(self):
                pass

        writer = FakeWriter()
        monkeypatch.setattr(
            protocol_module.asyncio,
            "open_connection",
            lambda host, port: _async_result((FakeReader(), writer)),
        )

        async with PushClient("synthetic-sid", PUSH_KEY) as push:
            assert await push.read_event() == synthetic_event()
            counters = push.diagnostic_counters()

        assert counters["opcodeCounts"] == {6: 1, 1: 1, 3: 1}
        assert counters["applicationFramesQueued"] == 1
        assert writer.writes[1:] == [acknowledgement]

    run(scenario())


def test_invalid_encrypted_frame_does_not_hide_following_valid_frame(
    monkeypatch,
) -> None:
    async def scenario() -> None:
        handshake_written = asyncio.Event()
        invalid_packet, invalid_ack = application_packet(
            {"data": "not-valid-ciphertext"}
        )
        valid_packet, valid_ack = application_packet({"data": CIPHERTEXT})

        class FakeReader:
            def __init__(self):
                self.sent = False

            async def read(self, size):
                await handshake_written.wait()
                if not self.sent:
                    self.sent = True
                    return bind_ack() + invalid_packet + valid_packet
                await asyncio.Event().wait()

        class FakeWriter:
            def __init__(self):
                self.writes: list[bytes] = []

            def write(self, data):
                self.writes.append(bytes(data))
                handshake_written.set()

            async def drain(self):
                pass

            def close(self):
                pass

            async def wait_closed(self):
                pass

        writer = FakeWriter()
        monkeypatch.setattr(
            protocol_module.asyncio,
            "open_connection",
            lambda host, port: _async_result((FakeReader(), writer)),
        )

        async with PushClient("synthetic-sid", PUSH_KEY) as push:
            event = await asyncio.wait_for(push.read_event(), timeout=1)
            counters = push.diagnostic_counters()

        assert event == synthetic_event()
        assert writer.writes[1:] == [invalid_ack, valid_ack]
        assert counters["applicationFramesQueued"] == 2
        assert counters["applicationFramesDispatched"] == 2
        assert counters["decryptFailure"] == 1
        assert counters["decryptSuccess"] == 1
        assert counters["jsonParseSuccess"] == 1

    run(scenario())


def test_multiple_android_message_records_are_decrypted_in_order(
    monkeypatch,
) -> None:
    async def scenario() -> None:
        handshake_written = asyncio.Event()

        def event(info_type: str) -> dict[str, object]:
            return {
                "event": 10,
                "sn": "synthetic-device",
                "data": json.dumps(
                    {"infoType": info_type, "data": {}},
                    separators=(",", ":"),
                ),
            }

        brace_message_id = int.from_bytes(
            b"{\x00\x00\x00\x00\x00\x00\x01",
            "big",
        )
        composite_packet, acknowledgement = application_packet_with_messages(
            [
                (brace_message_id, encrypted_envelope(event("30000"))),
                (2, encrypted_envelope(event("20001"))),
            ]
        )
        map_packet, _ = application_packet(
            encrypted_envelope(event("20002")),
            message_id=3,
        )

        class FakeReader:
            def __init__(self):
                self.sent = False

            async def read(self, size):
                await handshake_written.wait()
                if not self.sent:
                    self.sent = True
                    return bind_ack() + composite_packet + map_packet
                await asyncio.Event().wait()

        class FakeWriter:
            def __init__(self):
                self.writes: list[bytes] = []

            def write(self, data):
                self.writes.append(bytes(data))
                handshake_written.set()

            async def drain(self):
                pass

            def close(self):
                pass

            async def wait_closed(self):
                pass

        writer = FakeWriter()
        monkeypatch.setattr(
            protocol_module.asyncio,
            "open_connection",
            lambda host, port: _async_result((FakeReader(), writer)),
        )

        async with PushClient("synthetic-sid", PUSH_KEY) as push:
            received = [await push.read_event() for _ in range(3)]
            counters = push.diagnostic_counters()

        info_types = [json.loads(item["data"])["infoType"] for item in received]
        assert info_types == ["30000", "20001", "20002"]
        assert writer.writes[1:] == [acknowledgement, acknowledgement]
        assert counters["opcodeCounts"][3] == 2
        assert counters["opcode3Acknowledged"] == 2
        assert counters["opcode3StructurallyValid"] == 2
        assert counters["opcode3StructurallyInvalid"] == 0
        assert counters["opcode3FramesQueued"] == 2
        assert counters["applicationFramesQueued"] == 3
        assert counters["applicationFramesDispatched"] == 3
        assert counters["applicationEnvelopeParseSuccess"] == 3
        assert counters["applicationEnvelopesParsed"] == 3
        assert counters["applicationProductMismatch"] == 0
        assert counters["decryptSuccess"] == 3
        assert counters["jsonParseSuccess"] == 3

    run(scenario())


def test_opcode3_classification_accounts_for_every_transport_frame(
    monkeypatch,
) -> None:
    async def scenario() -> None:
        handshake_written = asyncio.Event()
        empty_packet, acknowledgement = raw_application_packet(b"")
        malformed_packet, _ = raw_application_packet(b"short")
        valid_packet, _ = application_packet({"data": CIPHERTEXT})

        class FakeReader:
            def __init__(self):
                self.sent = False

            async def read(self, size):
                await handshake_written.wait()
                if not self.sent:
                    self.sent = True
                    return (
                        bind_ack()
                        + empty_packet
                        + malformed_packet
                        + valid_packet
                    )
                await asyncio.Event().wait()

        class FakeWriter:
            def __init__(self):
                self.writes: list[bytes] = []

            def write(self, data):
                self.writes.append(bytes(data))
                handshake_written.set()

            async def drain(self):
                pass

            def close(self):
                pass

            async def wait_closed(self):
                pass

        writer = FakeWriter()
        monkeypatch.setattr(
            protocol_module.asyncio,
            "open_connection",
            lambda host, port: _async_result((FakeReader(), writer)),
        )

        async with PushClient("synthetic-sid", PUSH_KEY) as push:
            assert await push.read_event() == synthetic_event()
            counters = push.diagnostic_counters()

        classified = (
            counters["opcode3FramesQueued"]
            + counters["opcode3FramesEmptyPayload"]
            + counters["opcode3FramesMalformed"]
        )
        assert counters["opcodeCounts"][3] == 3
        assert classified == counters["opcodeCounts"][3]
        assert counters["opcode3StructurallyValid"] == 2
        assert counters["opcode3StructurallyInvalid"] == 1
        assert counters["opcode3Acknowledged"] == 2
        assert counters["opcode3FramesQueued"] == 1
        assert counters["opcode3FramesEmptyPayload"] == 1
        assert counters["opcode3FramesMalformed"] == 1
        assert [
            item["classification"]
            for item in counters["opcode3FrameClassifications"]
        ] == ["empty_payload", "malformed", "queued"]
        assert counters["opcode3FrameClassifications"][1]["reason"] == (
            "truncated_message_header"
        )
        assert writer.writes[1:] == [acknowledgement, acknowledgement]

    run(scenario())


def test_heartbeat_uses_configured_android_interval(monkeypatch) -> None:
    async def scenario() -> None:
        intervals = []

        async def sleep(delay):
            intervals.append(delay)
            raise asyncio.CancelledError

        class FakeWriter:
            def write(self, data):
                raise AssertionError("Heartbeat write is not reached")

            async def drain(self):
                pass

        push = PushClient(
            "synthetic-sid",
            PUSH_KEY,
            heartbeat_interval=15.0,
        )
        push._writer = FakeWriter()
        monkeypatch.setattr(protocol_module.asyncio, "sleep", sleep)

        with pytest.raises(asyncio.CancelledError):
            await push._heartbeat()

        assert intervals == [15.0]

    run(scenario())


@pytest.mark.parametrize("application_first", [False, True])
def test_connect_waits_for_bind_ack_and_preserves_application_message(
    monkeypatch,
    application_first,
) -> None:
    async def scenario() -> None:
        handshake_written = asyncio.Event()
        release_ack = asyncio.Event()
        packet, _ = application_packet({"data": CIPHERTEXT})

        class FakeReader:
            async def read(self, size):
                await handshake_written.wait()
                await release_ack.wait()
                release_ack.clear()
                return (
                    packet + bind_ack()
                    if application_first
                    else bind_ack() + packet
                )

        class FakeWriter:
            def __init__(self):
                self.writes = []
                self.closed = False

            def write(self, data):
                self.writes.append(bytes(data))
                handshake_written.set()

            async def drain(self):
                pass

            def close(self):
                self.closed = True

            async def wait_closed(self):
                pass

        writer = FakeWriter()
        monkeypatch.setattr(
            protocol_module.asyncio,
            "open_connection",
            lambda host, port: _async_result((FakeReader(), writer)),
        )

        push = PushClient("synthetic-sid", PUSH_KEY)
        connect_task = asyncio.create_task(push.connect())
        await handshake_written.wait()
        await asyncio.sleep(0)
        assert not connect_task.done()

        release_ack.set()
        await connect_task
        assert push._ready is True
        prefix, envelope = await asyncio.wait_for(push.read_frame(), timeout=1)
        assert envelope == {"data": CIPHERTEXT}
        assert int.from_bytes(prefix[2:4], "big") == 3
        assert int.from_bytes(prefix[2:4], "big") != 6
        await push.close()

    run(scenario())


def test_connect_timeout_cleans_up_socket_and_tasks(monkeypatch) -> None:
    async def scenario() -> None:
        class FakeReader:
            async def read(self, size):
                await asyncio.Event().wait()

        class FakeWriter:
            def __init__(self):
                self.writes = []
                self.closed = False

            def write(self, data):
                self.writes.append(bytes(data))

            async def drain(self):
                pass

            def close(self):
                self.closed = True

            async def wait_closed(self):
                pass

        writer = FakeWriter()

        async def open_connection(host, port):
            return FakeReader(), writer

        monkeypatch.setattr(protocol_module.asyncio, "open_connection", open_connection)
        monkeypatch.setattr(protocol_module, "PUSH_READY_TIMEOUT", 0.001)
        push = PushClient("synthetic-sid", PUSH_KEY)

        with pytest.raises(ApiError) as raised:
            await push.connect()

        assert raised.value.phase == "timeout"
        assert str(raised.value) == "Timed out waiting for push registration"
        assert len(writer.writes) == 1
        assert writer.closed is True
        assert push._reader is None
        assert push._writer is None
        assert push._reader_task is None
        assert push._heartbeat_task is None
        assert push._tcp_connected is True
        assert push._reader_started is True
        assert push._handshake_sent is True
        assert push._handshake_response_received is False
        assert push._ready is False

    run(scenario())


def test_close_while_waiting_for_bind_ack_cancels_connect(monkeypatch) -> None:
    async def scenario() -> None:
        handshake_written = asyncio.Event()

        class FakeReader:
            async def read(self, size):
                await asyncio.Event().wait()

        class FakeWriter:
            def __init__(self):
                self.closed = False

            def write(self, data):
                handshake_written.set()

            async def drain(self):
                pass

            def close(self):
                self.closed = True

            async def wait_closed(self):
                pass

        writer = FakeWriter()

        async def open_connection(host, port):
            return FakeReader(), writer

        monkeypatch.setattr(protocol_module.asyncio, "open_connection", open_connection)
        push = PushClient("synthetic-sid", PUSH_KEY)
        connect_task = asyncio.create_task(push.connect())
        await handshake_written.wait()

        await push.close()
        with pytest.raises(ApiError) as raised:
            await connect_task

        assert raised.value.phase == "transport"
        assert writer.closed is True
        assert push._reader_task is None
        assert push._heartbeat_task is None
        assert push._ready is False

    run(scenario())


def test_close_cancels_reader_while_transport_ack_is_draining(monkeypatch) -> None:
    async def scenario() -> None:
        handshake_written = asyncio.Event()
        acknowledgement_started = asyncio.Event()
        packet, _ = application_packet({"data": CIPHERTEXT})

        class FakeReader:
            def __init__(self):
                self.read_count = 0

            async def read(self, size):
                await handshake_written.wait()
                self.read_count += 1
                if self.read_count == 1:
                    return bind_ack()
                if self.read_count == 2:
                    return packet
                await asyncio.Event().wait()

        class FakeWriter:
            def __init__(self):
                self.drain_count = 0
                self.closed = False

            def write(self, data):
                handshake_written.set()

            async def drain(self):
                self.drain_count += 1
                if self.drain_count > 1:
                    acknowledgement_started.set()
                    await asyncio.Event().wait()

            def close(self):
                self.closed = True

            async def wait_closed(self):
                pass

        writer = FakeWriter()
        monkeypatch.setattr(
            protocol_module.asyncio,
            "open_connection",
            lambda host, port: _async_result((FakeReader(), writer)),
        )
        push = PushClient("synthetic-sid", PUSH_KEY)

        await push.connect()
        await acknowledgement_started.wait()
        await push.close()

        assert writer.closed is True
        assert push._reader_task is None
        assert push._heartbeat_task is None
        assert push._reader is None
        assert push._writer is None

    run(scenario())


async def _async_result(value):
    return value
