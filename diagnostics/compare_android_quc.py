"""Compare a safe Android QUC dummy capture with the Python implementation."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import NamedTuple
from urllib.parse import quote

import httpx

from botslab360 import DeviceIdentity
from botslab360.quc import (
    ANDROID_360_PROFILE,
    _base_device_params,
    _serialize_inner_params,
    compute_signature,
    des_encrypt_base64,
    md5_hex,
)

PREFIX = "[quc-compare] "
COMMON_KEYS = (
    "device_lang",
    "app",
    "device_os",
    "format",
    "from",
    "mSystemVersion",
    "method",
    "mname",
    "oaid",
    "os_board",
    "os_manufacturer",
    "os_model",
    "os_sdk_version",
    "quc_lang",
    "quc_sdk_version",
    "res_mode",
    "sdpi",
    "sh",
    "sw",
    "ua",
    "ui_ver",
    "v",
)
SYNTHETIC_IDS = {
    "androidid": "0123456789abcdef",
    "mid": "0123456789abcdef0123456789abcdef",
    "oaid": "dummy-oaid",
    "qh_id": "dummy-qh-id",
    "vt_guid": "1700000000000",
}
DUMMY_DES_KEY = "DESkey8!"
DUMMY_FULL_KEY = "A" * 109 + DUMMY_DES_KEY
DUMMY_LOGIN_PARAMS = {
    "fields": "qid,username,nickname,loginemail,head_pic,mobile",
    "head_type": "q",
    "is_keep_alive": "1",
    "loginType": "801",
    "needDeviceCheck": "1",
    "password": md5_hex("dummy-password"),
    "sec_type": "bool",
    "trace_id": "src_and_1916_1700000000000",
    "username": "dummy@example.invalid",
    "vt_guid": SYNTHETIC_IDS["vt_guid"],
}
FORM_VECTOR = {
    "space": "a b",
    "plus": "a+b",
    "slash": "a/b",
    "equals": "a=b",
    "percent": "a%b",
    "unicode": "Gruesse".replace("ue", "ü", 1).replace("ss", "ß", 1),
}
ENCODE_COMPONENT_SAFE = "-_.!~*'()"
# Statically documented by TA2k's local ioBroker QUC implementation and
# independently confirmed by the native Android dummy signature below.
ANDROID_SIGNATURE_SUFFIX = "i7v2m5x6q"
ANDROID_RANDOM_CHARSET = (
    "!#$%&*0123456789@ABCDEFGHIJKLMNOPQRSTUVWXYZ^abcdefghijklmnopqrstuvwxyz"
)
ANDROID_RANDOM_CHARSET_SHA256 = (
    "9ca4f3450cc3052e7bc1bdb2559264a9cd2ba8b8e2669e2048f9140a1efde689"
)
ANDROID_DUMMY_ITERATION_ORDER = (
    "loginType",
    "os_sdk_version",
    "mid",
    "quc_sdk_version",
    "mname",
    "ua",
    "os_manufacturer",
    "mSystemVersion",
    "head_type",
    "os_board",
    "sig",
    "os_model",
    "password",
    "quc_lang",
    "sh",
    "vt_guid",
    "is_keep_alive",
    "from",
    "needDeviceCheck",
    "oaid",
    "app",
    "trace_id",
    "ui_ver",
    "method",
    "res_mode",
    "sw",
    "format",
    "qh_id",
    "device_os",
    "device_lang",
    "sec_type",
    "v",
    "fields",
    "androidid",
    "username",
    "sdpi",
)

APP_SDK_CONSTANTS = ("app", "quc_sdk_version", "ui_ver", "v")
DEVICE_RUNTIME_VALUES = (
    "mSystemVersion",
    "os_board",
    "os_manufacturer",
    "os_model",
    "os_sdk_version",
    "sdpi",
    "sh",
    "sw",
    "ua",
)
IDENTITY_VALUES = ("androidid", "mid", "oaid", "qh_id", "vt_guid")


class SignatureVariant(NamedTuple):
    """One reproducible synthetic signature candidate."""

    description: str
    canonical: str
    digest: str
    names: tuple[str, ...]


class ByteDifference(NamedTuple):
    """First mismatch between two synthetic byte strings."""

    offset: int
    android_byte: int | None
    python_byte: int | None
    android_context: bytes
    python_context: bytes


def load_capture(path: Path) -> dict[str, dict[str, object]]:
    """Load the last record for each event from a redacted Frida capture."""

    events: dict[str, dict[str, object]] = {}
    raw = path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16")
    else:
        text = raw.decode("utf-8-sig")
    for raw_line in text.splitlines():
        marker = raw_line.find(PREFIX)
        if marker < 0:
            continue
        try:
            record = json.loads(raw_line[marker + len(PREFIX) :])
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and isinstance(record.get("event"), str):
            events[record["event"]] = record
    return events


def python_common_values() -> dict[str, str | None]:
    """Return current Android-profile values for the comparison table."""

    identity = DeviceIdentity(
        mid=SYNTHETIC_IDS["mid"],
        android_id=SYNTHETIC_IDS["androidid"],
        m2="12345678-1234-5678-9234-567812345678",
    )
    values = _base_device_params(identity, ANDROID_360_PROFILE)
    values["method"] = "UserIntf.login"
    return {key: values.get(key) for key in COMMON_KEYS}


def reconstruct_android_params(
    common_values: Mapping[str, object],
) -> dict[str, str] | None:
    """Reconstruct the synthetic map without exposing password material."""

    if any(not isinstance(common_values.get(key), str) for key in COMMON_KEYS):
        return None
    params = {key: str(common_values[key]) for key in COMMON_KEYS}
    params.update(SYNTHETIC_IDS)
    params.update(DUMMY_LOGIN_PARAMS)
    return params


def python_parameter_order() -> tuple[str, ...]:
    """Return the insertion order currently used by QucAuth._login_params()."""

    identity = DeviceIdentity(
        mid=SYNTHETIC_IDS["mid"],
        android_id=SYNTHETIC_IDS["androidid"],
        m2="12345678-1234-5678-9234-567812345678",
    )
    base_names = tuple(_base_device_params(identity, ANDROID_360_PROFILE))
    return base_names + (
        "loginType",
        "vt_guid",
        "is_keep_alive",
        "needDeviceCheck",
        "trace_id",
        "method",
        "head_type",
        "sec_type",
        "fields",
        "username",
        "password",
        "sig",
    )


def java_urlencode(value: str) -> str:
    """Encode one value like java.net.URLEncoder with UTF-8."""

    output: list[str] = []
    for byte in value.encode("utf-8"):
        if (
            ord("a") <= byte <= ord("z")
            or ord("A") <= byte <= ord("Z")
            or ord("0") <= byte <= ord("9")
            or byte in b".-*_"
        ):
            output.append(chr(byte))
        elif byte == 0x20:
            output.append("+")
        else:
            output.append(f"%{byte:02X}")
    return "".join(output)


def serialize_inner_params(
    params: Mapping[str, str],
    order: Sequence[str],
    *,
    encoding: str,
) -> str:
    """Serialize a synthetic inner map using one known encoding rule."""

    if set(order) != set(params):
        raise ValueError("parameter order does not contain exactly all keys")
    if encoding == "python-component":
        encode = lambda value: quote(value, safe=ENCODE_COMPONENT_SAFE)
    elif encoding == "java-form":
        encode = java_urlencode
    elif encoding == "none":
        encode = lambda value: value
    else:
        raise ValueError(f"unsupported encoding: {encoding}")
    return "&".join(f"{key}={encode(params[key])}" for key in order)


def first_byte_difference(
    android: bytes, python: bytes, *, context_size: int = 32
) -> ByteDifference | None:
    """Return the first byte mismatch and bounded synthetic context."""

    common_length = min(len(android), len(python))
    offset = next(
        (index for index in range(common_length) if android[index] != python[index]),
        common_length,
    )
    if offset == common_length and len(android) == len(python):
        return None
    start = max(0, offset - context_size)
    end = offset + context_size + 1
    return ByteDifference(
        offset=offset,
        android_byte=android[offset] if offset < len(android) else None,
        python_byte=python[offset] if offset < len(python) else None,
        android_context=android[start:end],
        python_context=python[start:end],
    )


def _format_byte(value: int | None) -> str:
    return "EOF" if value is None else f"0x{value:02x} ({chr(value)!r})"


def _format_difference(difference: ByteDifference) -> str:
    return (
        f"offset={difference.offset}, "
        f"Android={_format_byte(difference.android_byte)}, "
        f"Python={_format_byte(difference.python_byte)}, "
        f"Android context={difference.android_context!r}, "
        f"Python context={difference.python_context!r}"
    )


def httpx_form_body() -> str:
    """Encode the shared form vector through HTTPX without sending it."""

    return httpx.Request(
        "POST", "https://example.invalid/", data=FORM_VECTOR
    ).content.decode("ascii")


def _ordered_names(
    params: Mapping[str, str],
    *,
    ordering: str,
    iteration_order: Sequence[str],
) -> list[str]:
    if ordering == "sorted":
        return sorted(params)
    ordered = [key for key in iteration_order if key in params]
    ordered.extend(key for key in params if key not in ordered)
    return ordered


def _signature_variant(
    params: Mapping[str, str],
    *,
    ordering: str,
    iteration_order: Sequence[str],
    pair_style: str,
    separator: str,
    include_empty: bool,
    include_sig: bool,
    encoding: str,
    suffix: str,
) -> SignatureVariant:
    candidate = dict(params)
    if include_sig:
        candidate["sig"] = ""
    names = _ordered_names(
        candidate, ordering=ordering, iteration_order=iteration_order
    )
    if not include_empty:
        names = [key for key in names if candidate[key] != ""]

    parts: list[str] = []
    for key in names:
        value = candidate[key]
        if encoding == "value":
            value = quote(value, safe=ENCODE_COMPONENT_SAFE)
        if pair_style == "key=value":
            part = f"{key}={value}"
        elif pair_style == "key+value":
            part = f"{key}{value}"
        else:
            part = value
        if encoding == "pair":
            part = quote(part, safe=ENCODE_COMPONENT_SAFE)
        parts.append(part)

    canonical = separator.join(parts) + suffix
    digest = hashlib.md5(canonical.encode("utf-8"), usedforsecurity=False).hexdigest()
    suffix_name = "android-static-suffix" if suffix else "no-suffix"
    description = ", ".join(
        (
            ordering,
            pair_style,
            f"separator={separator!r}",
            "include-empty" if include_empty else "omit-empty",
            "include-empty-sig" if include_sig else "exclude-sig",
            f"encoding={encoding}",
            "charset=utf-8",
            "md5=lowercase-hex",
            suffix_name,
        )
    )
    return SignatureVariant(description, canonical, digest, tuple(names))


def find_signature_variants(
    params: Mapping[str, str],
    target: str,
    *,
    iteration_order: Sequence[str],
) -> list[SignatureVariant]:
    """Find safe canonicalization variants matching a synthetic signature."""

    matches: list[SignatureVariant] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for ordering in ("sorted", "iteration"):
        for pair_style in ("key=value", "key+value", "value"):
            for separator in ("", "&", "|", ",", "\n"):
                for include_empty in (True, False):
                    for include_sig in (False, True):
                        for encoding in ("none", "value", "pair"):
                            for suffix in ("", ANDROID_SIGNATURE_SUFFIX):
                                variant = _signature_variant(
                                    params,
                                    ordering=ordering,
                                    iteration_order=iteration_order,
                                    pair_style=pair_style,
                                    separator=separator,
                                    include_empty=include_empty,
                                    include_sig=include_sig,
                                    encoding=encoding,
                                    suffix=suffix,
                                )
                                identity = (variant.canonical, variant.names)
                                if identity in seen:
                                    continue
                                seen.add(identity)
                                if variant.digest == target.lower():
                                    matches.append(variant)
    return matches


def _signature_metadata(variant: SignatureVariant) -> str:
    digest = hashlib.sha256(variant.canonical.encode("utf-8")).hexdigest()
    return (
        f"sha256={digest}, utf8_length={len(variant.canonical.encode('utf-8'))}, "
        f"parameter_count={len(variant.names)}"
    )


def compare_capture(events: Mapping[str, Mapping[str, object]]) -> list[str]:
    """Return a human-readable, secret-free comparison report."""

    common_event = events.get("common_values", {})
    android_values = common_event.get("values")
    if not isinstance(android_values, dict):
        return ["Common values: UNKNOWN (capture event missing)"]

    python_values = python_common_values()
    lines = [
        "parameter | Android runtime value | Python current value | result",
        "--- | --- | --- | ---",
    ]
    for key in COMMON_KEYS:
        android = android_values.get(key)
        python = python_values[key]
        result = "SAME" if android == python else "DIFFERENT"
        lines.append(f"{key} | {android!r} | {python!r} | {result}")

    synthetic_common_event = events.get("synthetic_common_values", {})
    synthetic_common_values = synthetic_common_event.get("values")
    params = (
        reconstruct_android_params(synthetic_common_values)
        if isinstance(synthetic_common_values, dict)
        else None
    )
    signature_event = events.get("dummy_signature", {})
    android_signature = signature_event.get("value")
    input_names = signature_event.get("input_names")
    expected_names = sorted(params) if params is not None else None
    signatures_match = False
    compatible_signature: str | None = None
    if (
        params is not None
        and isinstance(android_signature, str)
        and isinstance(input_names, list)
        and input_names == expected_names
    ):
        python_signature = compute_signature(params, profile=ANDROID_360_PROFILE)
        signatures_match = android_signature == python_signature
        if signatures_match:
            compatible_signature = android_signature
        python_variant = _signature_variant(
            params,
            ordering="sorted",
            iteration_order=(),
            pair_style="key=value",
            separator="",
            include_empty=True,
            include_sig=False,
            encoding="none",
            suffix="",
        )
        lines.extend(
            (
                f"Android dummy signature: {android_signature}",
                f"Python dummy signature:  {python_signature}",
                "Dummy signature: " + ("SAME" if signatures_match else "DIFFERENT"),
                "Python signature input: " + _signature_metadata(python_variant),
                "Signature parameter names: " + ", ".join(input_names),
            )
        )
        iteration_names = events.get("dummy_envelope", {}).get(
            "input_iteration_order", []
        )
        if not isinstance(iteration_names, list):
            iteration_names = []
        matches = find_signature_variants(
            params,
            android_signature,
            iteration_order=iteration_names,
        )
        if matches:
            match = matches[0]
            compatible_signature = match.digest
            lines.append("Android signature variant: " + match.description)
            lines.append("Android signature input: " + _signature_metadata(match))
            lines.append(f"Matching signature variants: {len(matches)}")
        else:
            lines.append("Android signature variant: UNKNOWN (no tested match)")
            lines.append("Android signature input: UNKNOWN")
    else:
        lines.append("Dummy signature: UNKNOWN (input set incomplete or different)")

    envelope_event = events.get("dummy_envelope", {})
    order = envelope_event.get("input_iteration_order")
    android_cipher_hash = envelope_event.get("parad_cipher_sha256")
    envelope_params = (
        {**params, "sig": compatible_signature}
        if params is not None and compatible_signature is not None
        else None
    )
    des_event = events.get("des_stage", {})
    if compatible_signature is None:
        lines.append("Signature pipeline: DIFFERENT (no Android-compatible variant)")
        lines.append("Pre-DES plaintext: NOT TESTED")
        lines.append("DES raw cipher: NOT TESTED")
        lines.append("Base64: NOT TESTED")
        lines.append("Final envelope: DIFFERENT")
    elif (
        envelope_params is not None
        and isinstance(order, list)
        and all(isinstance(key, str) and key in envelope_params for key in order)
        and set(order) == set(envelope_params)
        and des_event.get("synthetic") is True
        and isinstance(des_event.get("plaintext_base64"), str)
        and isinstance(des_event.get("cipher_hex"), str)
    ):
        lines.append("Signature pipeline: SAME (confirmed Android variant)")
        android_plaintext = base64.b64decode(str(des_event["plaintext_base64"]))
        current_plaintext = _serialize_inner_params(
            envelope_params,
            profile=ANDROID_360_PROFILE,
        ).encode("utf-8")
        matched_plaintext = serialize_inner_params(
            envelope_params,
            order,
            encoding="java-form",
        ).encode("utf-8")
        current_difference = first_byte_difference(android_plaintext, current_plaintext)
        current_encoding_same_order = serialize_inner_params(
            envelope_params,
            order,
            encoding="python-component",
        ).encode("utf-8")
        encoding_difference = first_byte_difference(
            android_plaintext, current_encoding_same_order
        )
        matched_difference = first_byte_difference(android_plaintext, matched_plaintext)
        lines.extend(
            (
                (
                    f"Android pre-DES length/SHA-256: {len(android_plaintext)} / "
                    f"{hashlib.sha256(android_plaintext).hexdigest()}"
                ),
                (
                    f"Python current pre-DES length/SHA-256: {len(current_plaintext)} / "
                    f"{hashlib.sha256(current_plaintext).hexdigest()}"
                ),
                "Python current first difference: "
                + (
                    "none"
                    if current_difference is None
                    else _format_difference(current_difference)
                ),
                "After matching parameter order, encoding first difference: "
                + (
                    "none"
                    if encoding_difference is None
                    else _format_difference(encoding_difference)
                ),
                "Pre-DES plaintext: "
                + ("SAME" if matched_difference is None else "DIFFERENT"),
                (
                    "Matched serialization: Android HashMap iteration order, "
                    "key=value pairs joined by &, Java URLEncoder UTF-8 values, "
                    "empty values included, no trailing separator"
                ),
            )
        )
        if matched_difference is not None:
            lines.append(
                "Matched plaintext first difference: "
                + _format_difference(matched_difference)
            )
            lines.append("DES raw cipher: NOT TESTED")
            lines.append("Base64: NOT TESTED")
            lines.append("Final envelope: DIFFERENT")
        else:
            lines.append("Android plaintext: " + android_plaintext.decode("utf-8"))
            lines.append("Python plaintext:  " + matched_plaintext.decode("utf-8"))
            encoded = des_encrypt_base64(
                matched_plaintext.decode("utf-8"),
                DUMMY_DES_KEY,
                base64_padding=False,
            )
            python_cipher = base64.b64decode(encoded + "=" * (-len(encoded) % 4))
            android_cipher = bytes.fromhex(str(des_event["cipher_hex"]))
            cipher_difference = first_byte_difference(android_cipher, python_cipher)
            lines.extend(
                (
                    (
                        f"DES transformation: {des_event.get('transformation')}, "
                        f"key={des_event.get('key_ascii')!r}, "
                        f"IV hex={des_event.get('iv_hex')}"
                    ),
                    (
                        f"Android raw cipher length/SHA-256: {len(android_cipher)} / "
                        f"{hashlib.sha256(android_cipher).hexdigest()}"
                    ),
                    (
                        f"Python raw cipher length/SHA-256: {len(python_cipher)} / "
                        f"{hashlib.sha256(python_cipher).hexdigest()}"
                    ),
                    "DES raw cipher: "
                    + ("SAME" if cipher_difference is None else "DIFFERENT"),
                )
            )
            if cipher_difference is not None:
                lines.append(
                    "Cipher first difference: " + _format_difference(cipher_difference)
                )
                lines.append("Base64: NOT TESTED")
                lines.append("Final envelope: DIFFERENT")
            else:
                android_base64 = des_event.get("cipher_base64_unpadded")
                base64_same = android_base64 == encoded
                lines.append("Android raw cipher hex: " + android_cipher.hex())
                lines.append("Python raw cipher hex:  " + python_cipher.hex())
                lines.append("Base64: " + ("SAME" if base64_same else "DIFFERENT"))
                lines.append(f"Android Base64: {android_base64}")
                lines.append(f"Python Base64:  {encoded}")
                parad_matches = (
                    isinstance(android_cipher_hash, str)
                    and android_cipher_hash == hashlib.sha256(python_cipher).hexdigest()
                )
                lines.append(
                    "Final envelope: "
                    + (
                        "SAME deterministic parad; RSA key ciphertext is "
                        "non-deterministic PKCS#1 v1.5"
                        if base64_same and parad_matches
                        else "DIFFERENT"
                    )
                )
    elif (
        envelope_params is not None
        and isinstance(order, list)
        and all(isinstance(key, str) and key in envelope_params for key in order)
        and set(order) == set(envelope_params)
        and isinstance(android_cipher_hash, str)
    ):
        # Compatibility with older captures that only contain the final hash.
        plaintext = _serialize_inner_params(
            envelope_params,
            profile=ANDROID_360_PROFILE,
        )
        encoded = des_encrypt_base64(
            plaintext,
            DUMMY_DES_KEY,
            base64_padding=False,
        )
        cipher = base64.b64decode(encoded + "=" * (-len(encoded) % 4))
        python_cipher_hash = hashlib.sha256(cipher).hexdigest()
        lines.append(
            "Legacy envelope hash comparison: "
            + ("SAME" if android_cipher_hash == python_cipher_hash else "DIFFERENT")
        )
    else:
        lines.append("Pre-DES plaintext: UNKNOWN (stage capture unavailable)")
        lines.append("DES raw cipher: NOT TESTED")
        lines.append("Base64: NOT TESTED")
        lines.append("Final envelope: UNKNOWN")

    form_event = events.get("form_encoding", {})
    android_form = form_event.get("body")
    python_form = httpx_form_body()
    if isinstance(android_form, str):
        lines.append(
            "Outer form encoding: "
            + ("SAME" if android_form == python_form else "DIFFERENT")
        )
        if android_form != python_form:
            lines.append(f"Android dummy form: {android_form}")
            lines.append(f"Python dummy form:  {python_form}")
    else:
        lines.append("Outer form encoding: UNKNOWN (capture event missing)")

    random_event = events.get("random_key", {})
    charset = events.get("random_charset", {})
    if isinstance(charset.get("observed_characters"), str):
        charset_result = (
            "MATCHES confirmed 70-character Android set"
            if charset.get("observed_characters") == ANDROID_RANDOM_CHARSET
            and charset.get("sha256") == ANDROID_RANDOM_CHARSET_SHA256
            else "DIFFERENT from confirmed Android set"
        )
        lines.append(
            "Random-key observed charset: "
            f"{charset['observed_characters']!r} "
            f"(size={charset.get('observed_size')}, "
            f"sha256={charset.get('sha256')}, {charset_result})"
        )
    elif random_event.get("ascii_alphanumeric") is False:
        lines.append(
            "Random-key charset: DIFFERENT from Python [A-Za-z0-9]; "
            "exact native alphabet remains UNKNOWN"
        )
    else:
        lines.append("Random-key charset: UNKNOWN")

    lines.extend(
        (
            "App/SDK constants: " + ", ".join(APP_SDK_CONSTANTS),
            "Device/runtime values: " + ", ".join(DEVICE_RUNTIME_VALUES),
            "Identity values: " + ", ".join(IDENTITY_VALUES),
        )
    )
    return lines


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare a redacted Android QUC dummy capture locally."
    )
    parser.add_argument("capture", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    events = load_capture(args.capture)
    print("\n".join(compare_capture(events)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
