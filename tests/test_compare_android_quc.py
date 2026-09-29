from __future__ import annotations

import codecs
import importlib.util
import json
from pathlib import Path
from string import ascii_letters, digits
from types import ModuleType


def _load_diagnostic() -> ModuleType:
    path = Path(__file__).parents[1] / "diagnostics" / "compare_android_quc.py"
    spec = importlib.util.spec_from_file_location("compare_android_quc", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _android_common() -> dict[str, str]:
    return {
        "device_lang": "zh-CN",
        "app": "360Robot",
        "device_os": "android",
        "format": "json",
        "from": "mpl_smarthome_and",
        "mSystemVersion": "android 15",
        "method": "UserIntf.login",
        "mname": "",
        "oaid": "dummy-oaid",
        "os_board": "goldfish_x86_64",
        "os_manufacturer": "Google",
        "os_model": "sdk_gphone64_x86_64",
        "os_sdk_version": "android_35",
        "quc_lang": "en",
        "quc_sdk_version": "v3.2.4",
        "res_mode": "1",
        "sdpi": "2.75",
        "sh": "2138.0",
        "sw": "1080.0",
        "ua": (
            "Dalvik/2.1.0 (Linux; U; Android 15; "
            "sdk_gphone64_x86_64 Build/AE3A.240806.043)"
        ),
        "ui_ver": "4.2.8.1-alert-ui",
        "v": "11.1.7",
    }


def test_load_capture_ignores_unmarked_and_malformed_lines(tmp_path: Path) -> None:
    module = _load_diagnostic()
    capture = tmp_path / "capture.txt"
    capture.write_text(
        "unrelated output\n"
        f"{module.PREFIX}not-json\n"
        f"{module.PREFIX}{json.dumps({'event': 'complete', 'ok': True})}\n",
        encoding="utf-8",
    )

    assert module.load_capture(capture) == {
        "complete": {"event": "complete", "ok": True}
    }


def test_load_capture_accepts_utf8_bom(tmp_path: Path) -> None:
    module = _load_diagnostic()
    capture = tmp_path / "capture.txt"
    payload = f"{module.PREFIX}{json.dumps({'event': 'complete'})}\n"
    capture.write_bytes(codecs.BOM_UTF8 + payload.encode("utf-8"))

    assert module.load_capture(capture)["complete"]["event"] == "complete"


def test_load_capture_accepts_utf16_boms(tmp_path: Path) -> None:
    module = _load_diagnostic()
    payload = f"{module.PREFIX}{json.dumps({'event': 'complete'})}\n"
    for encoding in ("utf-16-le", "utf-16-be"):
        capture = tmp_path / f"capture-{encoding}.txt"
        bom = codecs.BOM_UTF16_LE if encoding.endswith("le") else codecs.BOM_UTF16_BE
        capture.write_bytes(bom + payload.encode(encoding))

        assert module.load_capture(capture)["complete"]["event"] == "complete"


def test_httpx_form_vector_matches_java_urlencoder_semantics() -> None:
    module = _load_diagnostic()

    assert module.httpx_form_body() == (
        "space=a+b&plus=a%2Bb&slash=a%2Fb&equals=a%3Db&"
        "percent=a%25b&unicode=Gr%C3%BC%C3%9Fe"
    )


def test_matching_synthetic_capture_reports_confirmed_results() -> None:
    module = _load_diagnostic()
    common = module.python_common_values()
    params = module.reconstruct_android_params(common)
    assert params is not None
    signature = module.compute_signature(params, profile=module.ANDROID_360_PROFILE)
    params["sig"] = signature
    order = list(params)
    plaintext = module._serialize_inner_params(
        params,
        profile=module.ANDROID_360_PROFILE,
    )
    encoded = module.des_encrypt_base64(
        plaintext,
        module.DUMMY_FULL_KEY[-8:],
        base64_padding=False,
    )
    cipher = module.base64.b64decode(encoded + "=" * (-len(encoded) % 4))
    events = {
        "common_values": {"values": common},
        "synthetic_common_values": {"values": common},
        "dummy_signature": {
            "value": signature,
            "input_names": sorted(key for key in params if key != "sig"),
        },
        "dummy_envelope": {
            "input_iteration_order": order,
            "parad_cipher_sha256": module.hashlib.sha256(cipher).hexdigest(),
        },
        "form_encoding": {"body": module.httpx_form_body()},
        "random_key": {"length": 117, "ascii_alphanumeric": True},
    }

    report = "\n".join(module.compare_capture(events))

    assert "Dummy signature: SAME" in report
    assert "Legacy envelope hash comparison: SAME" in report
    assert "Outer form encoding: SAME" in report
    assert "Random-key charset: UNKNOWN" in report


def test_android_dummy_signature_uses_exact_captured_values_and_suffix() -> None:
    module = _load_diagnostic()
    common = _android_common()
    params = module.reconstruct_android_params(common)
    assert params is not None
    target = "f7e02d0861f0a76cb4e1ceea6d22bc53"

    assert module.compute_signature(params) == "85d68fbc91eda35d0f35d3e68ffdf4fc"
    matches = module.find_signature_variants(
        params, target, iteration_order=tuple(params)
    )

    assert matches
    matching = next(
        match
        for match in matches
        if match.canonical.endswith(module.ANDROID_SIGNATURE_SUFFIX)
        and match.digest == target
        and match.names == tuple(sorted(params))
    )
    assert module.hashlib.sha256(matching.canonical.encode()).hexdigest() == (
        "58eb7a6b0d1e3d31a5e5a02e18afd0035beee87ae288a34ba1e8d9309bc6fd2a"
    )
    assert len(matching.canonical.encode()) == 766
    assert len(matching.names) == 35


def test_runtime_common_oaid_is_not_synthetic() -> None:
    module = _load_diagnostic()

    assert module.python_common_values()["oaid"] == ""


def test_confirmed_android_random_charset_metadata() -> None:
    module = _load_diagnostic()

    assert len(module.ANDROID_RANDOM_CHARSET) == 70
    assert (
        module.hashlib.sha256(module.ANDROID_RANDOM_CHARSET.encode()).hexdigest()
        == module.ANDROID_RANDOM_CHARSET_SHA256
    )
    assert set(module.ANDROID_RANDOM_CHARSET) - set(ascii_letters + digits) == set(
        "!#$%&*@^"
    )


def test_fixed_dummy_key_has_android_length_and_recognizable_des_key() -> None:
    module = _load_diagnostic()

    assert len(module.DUMMY_FULL_KEY) == 117
    assert set(module.DUMMY_FULL_KEY) <= set(module.ANDROID_RANDOM_CHARSET)
    assert module.DUMMY_FULL_KEY[-8:] == module.DUMMY_DES_KEY == "DESkey8!"


def test_first_byte_difference_reports_bytes_and_bounded_context() -> None:
    module = _load_diagnostic()

    difference = module.first_byte_difference(
        b"prefix+android-suffix", b"prefix%20python-suffix", context_size=3
    )

    assert difference is not None
    assert difference.offset == 6
    assert difference.android_byte == ord("+")
    assert difference.python_byte == ord("%")
    assert difference.android_context == b"fix+and"
    assert difference.python_context == b"fix%20p"
    assert module.first_byte_difference(b"same", b"same") is None


def test_android_plaintext_vector_matches_java_form_serialization() -> None:
    module = _load_diagnostic()
    params = module.reconstruct_android_params(_android_common())
    assert params is not None
    params["sig"] = "f7e02d0861f0a76cb4e1ceea6d22bc53"

    plaintext = module.serialize_inner_params(
        params,
        module.ANDROID_DUMMY_ITERATION_ORDER,
        encoding="java-form",
    ).encode()

    assert len(plaintext) == 854
    assert module.hashlib.sha256(plaintext).hexdigest() == (
        "ef0a2c963c58ef772d8a02af1db69d21c0c5d580694b897c2ea5c5f7933581a2"
    )
    assert b"Dalvik%2F2.1.0+%28Linux%3B+U" in plaintext
    assert plaintext.startswith(b"loginType=801&os_sdk_version=android_35")


def test_android_cipher_and_base64_vectors_match_python() -> None:
    module = _load_diagnostic()
    params = module.reconstruct_android_params(_android_common())
    assert params is not None
    params["sig"] = "f7e02d0861f0a76cb4e1ceea6d22bc53"
    plaintext = module.serialize_inner_params(
        params,
        module.ANDROID_DUMMY_ITERATION_ORDER,
        encoding="java-form",
    )

    encoded = module.des_encrypt_base64(
        plaintext, module.DUMMY_DES_KEY, base64_padding=False
    )
    cipher = module.base64.b64decode(encoded + "=" * (-len(encoded) % 4))

    assert len(cipher) == 856
    assert module.hashlib.sha256(cipher).hexdigest() == (
        "364d7f4bd30f474e6cd82007bf682ed121e1bcaf519ab7658da1728f12cc0df8"
    )
    assert len(encoded) == 1142
    assert not encoded.endswith("=")
    assert "\n" not in encoded and "\r" not in encoded


def test_missing_capture_stays_unknown() -> None:
    module = _load_diagnostic()

    assert module.compare_capture({}) == [
        "Common values: UNKNOWN (capture event missing)"
    ]
