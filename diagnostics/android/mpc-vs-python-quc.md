# Android MPC vs current Python QUC

This offline comparison records only protocol metadata from the captured
Android 11.1.7 password login. No request was sent for this analysis.

## Current Python flow

- Endpoint: `https://<region>-sapp-login.botslab.com/request.php`
- `from`: `mpl_cloudsmartoem_and`
- User-Agent: `360accounts andv3.2.4.6 mpl_cloudsmartoem_and`
- `loginType=801`; `needDeviceCheck=0` by default
- Password: lowercase MD5 of its UTF-8 bytes
- Signature: sort decoded names, omit `sig`, concatenate `name=value` without
  separators, then lowercase MD5
- Plaintext: insertion-ordered `name=encodeURIComponent(value)` pairs joined
  with `&`
- Key string: 114 alphanumeric characters (`106 + 8`); final eight bytes are
  the DES key
- DES: single-DES-equivalent TripleDES with repeated key, CBC, IV=key,
  PKCS#7 padding, standard Base64
- RSA: embedded 1024-bit X.509 key, PKCS#1 v1.5, standard Base64
- Outer fields: `device_lang`, `trace_id`, `quc_lang`, `method`, `from`,
  `parad`, `key`, sent as an URL-encoded form
- Response: parse outer JSON, DES-decrypt `ret`, parse inner JSON

The normal Python login's final signed set contains all 36 Android common-map
names. Python builds login and common fields together; Android adds common
fields in `BasicParamsTools.buildCommonParams()`.

On errno 5010 Python fetches `UserIntf.getCaptcha`, reads `sc` from the header,
and raises `CaptchaRequired`. Explicit continuation adds `sc`, `uc`, and
`captchaType=graph`. Errno 5011 is preserved without automatic retry.

## Comparison

`UNKNOWN` means neither the safe capture nor visible Java establishes equality.

| Property | Current Python | Android | Result |
| --- | --- | --- | --- |
| Endpoint | regional Botslab host | `passport.360.cn/request.php` | DIFFERENT |
| `from` | `mpl_cloudsmartoem_and` | `mpl_smarthome_and` | DIFFERENT |
| User-Agent | `andv3.2.4.6 ...cloudsmartoem...` | `andv3.2.4 ...smarthome...` | DIFFERENT |
| `loginType` | `801` | `801` | SAME |
| `needDeviceCheck` | `0` | `1` | DIFFERENT |
| Login-specific names | captured nine names present | nine captured names | SAME |
| Final common names | all 36 names present | 36 captured names | SAME |
| `sig` position | encrypted inner map | common map; absent outside | SAME |
| Outer names | seven fields | same seven fields | SAME |
| RSA fingerprint | `17ee...3c` | `17ee...3c`, default | SAME |
| RSA padding | PKCS#1 v1.5 | visible utility uses it; envelope call native | UNKNOWN |
| DES mode/padding | CBC, IV=key, PKCS#7 | `DES/CBC/PKCS5Padding`, IV=key | SAME |
| Random full key | 114 characters | 117 from native `a(117)` | DIFFERENT |
| DES-key selection | final 8 bytes | `substring(109)` of 117 | SAME |
| Signature canonicalization | sorted raw names, no suffix | sorted `key=value`, no separator, suffix `i7v2m5x6q` | DIFFERENT |
| Inner parameter order | Python insertion order | captured `HashMap` iteration order | DIFFERENT |
| Inner value encoding | `encodeURIComponent` equivalent | Java `URLEncoder` UTF-8 | DIFFERENT |
| Outer encoding | URL-encoded form | Java `URLEncoder` form | SAME transport |
| RSA Base64 | standard, padded, unwrapped | standard alphabet, flag 3 (`NO_PADDING | NO_WRAP`), runtime length 171 | DIFFERENT |
| DES Base64 | standard, optionally unpadded, unwrapped | standard, unpadded, unwrapped | SAME when Python padding is disabled |
| Captcha login fields | `sc`, `uc`, `captchaType` | same fields | SAME |

The RSA fingerprint and map shapes do not prove byte-identical RSA ciphertext:
PKCS#1 v1.5 encryption is randomized. The deterministic `parad` side of the
synthetic envelope is byte-identical after reproducing Android's signature and
inner serialization. Signature suffix, parameter order, inner encoding,
full-key length, random alphabet, and outgoing Base64 padding are confirmed
production differences; the DES primitive itself is not different.

## Base64 evidence

Python uses `base64.b64encode()`: standard `+`/`/` alphabet, trailing `=`
padding, and no line wrapping. A 128-byte RSA ciphertext therefore produces
172 characters and ends in one `=`.

Android's visible `RSAUtil.encryptByPublic()` calls `Base64.encode(..., 3)`.
Its local Base64 implementation defines `NO_PADDING=1`, `NO_WRAP=2`, and
`URL_SAFE=8`; flag 3 therefore selects the standard `+`/`/` alphabet without
padding or wrapping. This statically agrees with the captured 171-character
`key`.

The `parad` encoder remains native. An unpadded Base64 length of 1110 maps to
832 raw bytes; 832 is divisible by DES's 8-byte block size. Padded Base64 for
832 bytes would be 1112 characters ending in `==`. Thus the captured length is
strongly consistent with removed padding, but does not independently prove the
native alphabet. Length 1110 is specific to that request, not a constant.

## Common parameters

No captured Android key is missing from Python. Matching names do not prove
matching values.

| Android key | Python source | Android source/equality |
| --- | --- | --- |
| `androidid` | persisted identity | device metadata; UNKNOWN |
| `app` | `Botslab` | native; UNKNOWN |
| `device_lang` | `zh-CN` | SDK/device config; UNKNOWN |
| `device_os` | `android` | native; UNKNOWN |
| `fields` | login literal | login builder; value not captured |
| `format` | `json` | native; UNKNOWN |
| `from` | profile literal | captured different value |
| `head_type` | `q` | login builder; value not captured |
| `is_keep_alive` | `1` | login builder; value not captured |
| `loginType` | `801` | captured SAME |
| `mSystemVersion` | emulated-device literal | device metadata; UNKNOWN |
| `method` | `UserIntf.login` | RPC method; SAME |
| `mid` | persisted identity | SDK identity; UNKNOWN |
| `mname` | empty | native; UNKNOWN |
| `needDeviceCheck` | `0` | captured `1`; DIFFERENT |
| `oaid` | empty | device provider; UNKNOWN |
| `os_board` | emulated-device literal | build metadata; UNKNOWN |
| `os_manufacturer` | emulated-device literal | build metadata; UNKNOWN |
| `os_model` | emulated-device literal | build metadata; UNKNOWN |
| `os_sdk_version` | `android_33` | SDK metadata; UNKNOWN |
| `password` | lowercase MD5 | `MD5Util.getMD5code`; SAME transformation |
| `qh_id` | empty | SDK/account state; UNKNOWN |
| `quc_lang` | `en` | SDK config; UNKNOWN |
| `quc_sdk_version` | `v3.2.4.6` | field value UNKNOWN; UA differs |
| `res_mode` | `1` | native; UNKNOWN |
| `sdpi`, `sh`, `sw` | emulated display literals | display metrics; UNKNOWN |
| `sig` | Python canonicalization | native; UNKNOWN |
| `trace_id` | timestamp-derived | SDK-generated; UNKNOWN |
| `ua` | Dalvik/device literal | device metadata; UNKNOWN |
| `ui_ver` | `4.3.4.1-alert-ui` | SDK UI version; UNKNOWN |
| `username` | stripped email | UI account identifier; value redacted |
| `v` | `2.24.0` | native; UNKNOWN |
| `vt_guid` | epoch milliseconds | native; UNKNOWN |

### Common-value confidence

The offline runtime capture confirmed equal values for `device_lang`,
`device_os`, `format`, `from`, `method`, `mname`, `oaid`, `os_manufacturer`,
`quc_lang`, `res_mode`, and `sw`. It confirmed different current Python values
for `app`, `mSystemVersion`, `os_board`, `os_model`, `os_sdk_version`,
`quc_sdk_version`, `sdpi`, `sh`, `ua`, `ui_ver`, and `v`.

The differing device/runtime values describe the captured emulator and are not
portable profile constants. The App/SDK values are Android 11.1.7 profile
candidates, but remain diagnostic data until the complete request pipeline is
resolved.

## Android RSA-key lifecycle

`UserCenterRsaManager` starts with the embedded default. `initPubKey()` loads a
private SharedPreferences value; missing or invalid X.509 data falls back to
the default. `updatePubKey()` decrypts a supplied value with a second embedded
public key and synchronously persists the result.

The protected preference file and entry constants are
`fgsProtected.b("1113")` and `fgsProtected.b("5")`; their plaintext names are
UNKNOWN. No Java call site for `updatePubKey()` exists. Response decryption is
native, and request wrappers retry exactly once when it returns `RET_RETRY`.
Together with `RSA_KEY_INVALID_ERRONO=1021001`, this suggests a native key
update/retry path, but its response field and exact trigger are not visible.

A fresh installation can use the default key, as the capture confirms. The
server text `key不正确` may be compatible with a stale default key, but its errno
and native branch are unknown. It is not evidence of an account/password error.

## Proposed profiles

Shared transport, parsing, redaction, and captcha control flow should be
parameterized through an internal `QucLoginProfile` containing an endpoint
resolver, `from`, User-Agent, login type, device-check setting, common-parameter
provider, random-key length, and RSA-key policy.

The confirmed Android profile portion is:

```text
endpoint = https://passport.360.cn/request.php
from = mpl_smarthome_and
user_agent = 360accounts andv3.2.4 mpl_smarthome_and
login_type = 801
need_device_check = 1
random_key_length = 117
des_key = final 8 bytes
rsa_base64_padding = false
des_base64_padding = false
```

The table above describes the unchanged default cloud profile. The confirmed
Android 11.1.7 values below are implemented by the internal
`ANDROID_360_PROFILE`, selected explicitly by the public API through
`AuthBackend.ROBOT360`. There is no automatic backend fallback.

## Offline differential results

The network-free synthetic runtime probe established that Android and Python
were using the same 35 dummy parameter names and values for the signature
comparison. The pre-patch Python canonical input was 757 UTF-8 bytes with SHA-256
`49b271ae1fb53b5a586e67b5c42192ce418a4060da26bce4af31ca48f630bbb3` and
produces MD5 `85d68fbc91eda35d0f35d3e68ffdf4fc`.

The native Android dummy signature is
`f7e02d0861f0a76cb4e1ceea6d22bc53`. Exactly one tested canonicalization
reproduces it: lexicographically sorted keys, `key=value`, no separator, empty
values included, `sig` excluded, no URL encoding, UTF-8, lowercase MD5, and the
static `i7v2m5x6q` suffix already documented by TA2k's QUC implementation. That
Android input is 766 UTF-8 bytes with SHA-256
`58eb7a6b0d1e3d31a5e5a02e18afd0035beee87ae288a34ba1e8d9309bc6fd2a`.

The observed Android 11.1.7 App/SDK constants are:

| Parameter | Android value |
| --- | --- |
| `app` | `360Robot` |
| `quc_sdk_version` | `v3.2.4` |
| `ui_ver` | `4.2.8.1-alert-ui` |
| `v` | `11.1.7` |

`mSystemVersion`, `os_board`, `os_manufacturer`, `os_model`,
`os_sdk_version`, `sdpi`, `sh`, `sw`, and `ua` are device/runtime values and
must not be frozen to the emulator capture. `androidid`, `mid`, `oaid`,
`qh_id`, and `vt_guid` are identity values. Runtime `oaid` was empty; the
literal `dummy-oaid` belongs only to the synthetic crypto vector.

A direct native generator sample of 65,536 characters observed this sorted
70-character alphabet:

```text
!#$%&*0123456789@ABCDEFGHIJKLMNOPQRSTUVWXYZ^abcdefghijklmnopqrstuvwxyz
```

Its SHA-256 is
`9ca4f3450cc3052e7bc1bdb2559264a9cd2ba8b8e2669e2048f9140a1efde689`.
The extra characters compared with the cloud profile's alphabet are
`!#$%&*@^`. The internal Android profile now uses this captured alphabet; the
cloud profile remains alphanumeric.

The fixed synthetic full key is 117 characters: 109 `A` characters followed by
`DESkey8!`. Android's pre-DES plaintext is 854 UTF-8 bytes with SHA-256
`ef0a2c963c58ef772d8a02af1db69d21c0c5d580694b897c2ea5c5f7933581a2`.
The pre-patch Python plaintext was 864 bytes with SHA-256
`53556528e4922e9a5a4478972c015a4935586d6b5a57e071a53d90da05a62150`.
Its first difference is byte 0 because Python's insertion order starts with
`os_sdk_version`, while Android's captured `HashMap` order starts with
`loginType`.

After imposing Android's parameter order, the first remaining difference is at
byte 124. Java `URLEncoder` represents the space in the synthetic user agent as
`+`; Python's current component encoder emits `%20` and leaves parentheses
unescaped. Android serializes `key=value` pairs joined by `&`, retains empty
values, and emits no trailing separator.

With this exact Android plaintext, Android and Python produce the same 856-byte
raw ciphertext, SHA-256
`364d7f4bd30f474e6cd82007bf682ed121e1bcaf519ab7658da1728f12cc0df8`.
The captured transformation is `DES/CBC/PKCS5Padding`; key and IV are both the
ASCII bytes `DESkey8!` (`4445536b65793821`). Python's existing CBC operation,
repeated-key single-DES equivalent, and PKCS#7 padding produce that exact
vector. Standard Base64 without padding or wrapping is also byte-identical.
The outer form test remains byte-identical.

Consequently, no DES primitive change was needed. The internal Android profile
now supplies the confirmed signature suffix, random alphabet and 117-character
key length, Java form-style inner value encoding, captured parameter ordering,
and App/SDK constants. Device/runtime values remain separate from those profile
constants, and runtime `oaid` remains empty.

## Next controlled test

The deterministic synthetic pipeline is resolved through signature, pre-DES
serialization, raw DES ciphertext, Base64, and outer form encoding. The
targeted internal-profile patch now passes those offline vectors and the cloud
regression suite. No login or network request was performed while applying or
validating it.
