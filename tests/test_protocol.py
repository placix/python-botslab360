from __future__ import annotations

import asyncio
import base64
import json

import pytest

import botslab360.protocol as protocol_module
from botslab360 import ApiError
from botslab360.protocol import (
    PushClient,
    _JsonFrameBuffer,
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


def test_json_frame_buffer_handles_fragmented_tcp_data() -> None:
    buffer = _JsonFrameBuffer()
    payload = b'\x00\x05\x00\x03header\x00{"data":"synthetic"}'

    assert buffer.feed(payload[:12]) == []
    frames = buffer.feed(payload[12:])

    assert frames == [(b"\x00\x05\x00\x03header\x00", {"data": "synthetic"})]


def test_push_client_registers_decodes_status_and_acknowledges(monkeypatch) -> None:
    async def scenario() -> None:
        prefix = b"\x00\x05\x00\x03head\x00"
        packet = prefix + json.dumps({"data": CIPHERTEXT}).encode()

        class FakeReader:
            async def read(self, size):
                return packet

        class FakeWriter:
            def __init__(self):
                self.writes: list[bytes] = []
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

        assert status.battery == 85
        assert writer.writes[0] == (
            b"\x00\x05\x00\x02\x00Ecv:1.7\n"
            b"t:30\n"
            b"u:synthetic-sid@60009\n"
            b"ts:1700000000000"
        )
        acknowledgement = bytearray(prefix[: prefix.find(b"\x00", 5)])
        acknowledgement[3] = 4
        assert writer.writes[1] == bytes(acknowledgement)
        assert writer.closed is True

    run(scenario())
