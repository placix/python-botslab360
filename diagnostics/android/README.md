# MPC login metadata capture

`capture_mpc_login.js` passively observes the first manually initiated
`mpc_smarthome_and` password login in the Android app. It does not initiate,
retry, modify, or decrypt requests.

## Recommended setup

Use a rooted Android emulator with the unmodified APK. This avoids TLS
interception and permanent APK modification. A rooted test device also works.
Attaching Frida to an unmodified production app on a non-rooted device is
normally not possible; Frida Gadget would require repackaging and resigning the
APK and is therefore not the preferred route here.

Requirements:

- Android platform tools (`adb`)
- Python and `frida-tools` on Windows
- a `frida-server` build matching both the desktop Frida version and Android ABI
- the Android package `com.qihoo.smarthome` installed and running

## Prepare Frida from PowerShell

```powershell
py -m pip install --upgrade frida-tools
frida --version
adb devices
adb shell getprop ro.product.cpu.abi
```

Download the matching official `frida-server` release for the reported ABI,
extract it, and substitute its local filename below:

```powershell
adb root
adb push .\frida-server-<version>-android-<abi> /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"
frida-ps -Uai | Select-String com.qihoo.smarthome
```

## Perform the single capture

1. Open the official app and navigate to the normal account/password login
   screen without pressing the login button.
2. Attach the script:

```powershell
$Capture = Join-Path $env:TEMP "botslab360-mpc-login-metadata.txt"
frida -U -N com.qihoo.smarthome -l .\diagnostics\android\capture_mpc_login.js |
    Tee-Object -FilePath $Capture
```

3. Wait for the `ready` line.
4. Enter the account and password in the app and press Login exactly once.
5. Do not continue a captcha, retry, or switch region during this capture.
6. Stop Frida with `Ctrl+C` after `capture_complete` appears.

The script activates when one `UserCenterRpc` contains the parameter names
`username`, `password`, and `loginType`. The fixed target
`passport.360.cn/request.php` is an independent fallback. Attaching after the
login screen is visible avoids capturing an automatic login during app startup.

The required completion events are `inner_params`, `request_uri`,
`outer_params`, and `http_request`. `common_params`, `rsa_key`, and
`client_auth_from` are additional diagnostics and do not block
`capture_complete`. `client_auth_initialize` is only expected when the script
is attached before SDK initialization. `hook_called` records the concrete
overload without exposing arguments, while `capture_debug` contains only a
stage and a fixed reason.

## Redaction guarantees

Maps are emitted only as sorted key names. The only parameter values permitted
by the script are a numeric `loginType`, boolean/numeric `needDeviceCheck`, and
an alphanumeric `captchaType`. `parad` and `key` are represented only by their
character lengths. The RSA public key is represented only by its SHA-256 DER
fingerprint.

The script does not print account identifiers, passwords, password hashes,
Q/T/qid, sid, push keys, captcha data, cookies, authorization headers, request
bodies, response bodies, complete envelope values, or complete RSA keys.

Before sharing, extract only lines beginning with `[mpc-capture]`:

```powershell
$SafeCapture = Join-Path $env:TEMP "botslab360-mpc-login-metadata-safe.txt"
Get-Content $Capture |
    Where-Object { $_.StartsWith("[mpc-capture]") } |
    Set-Content $SafeCapture
```

Review and share `$SafeCapture`. It should contain only JSON records such as
`capture_activated`, `client_auth_from`, `inner_params`, `common_params`,
`crypted_transition`, `rsa_key`, `request_uri`, `outer_params`,
`http_request`, and `capture_complete`.

## Offline Android/Python comparison

`compare_android_quc.js` invokes only local parameter and crypto helpers with
fixed dummy login data. It does not instantiate `UserCenterRpc`,
`HttpPostRequest`, or another network request class. Put the emulator in
airplane mode and leave the app idle before attaching it; do not press Login.
The script verifies Android's global airplane-mode setting and exits before the
probe unless it is enabled.

```powershell
$Capture = Join-Path $env:TEMP "botslab360-quc-dummy-compare.txt"
frida -U -N com.qihoo.smarthome -l .\diagnostics\android\compare_android_quc.js |
    Tee-Object -FilePath $Capture
```

The script first calls `BasicParamsTools.buildCommonParams()` with dummy login
fields and emits only the explicitly whitelisted runtime common values. Real
`androidid`, `mid`, `vt_guid`, and `qh_id` values are never emitted; only their
Java type and length are retained. It then repeats the operation with a second
map, intercepts writes of `androidid`, `mid`, `oaid`, `qh_id`, and `vt_guid`,
and verifies every synthetic replacement before disclosing the dummy signature
or invoking `getCryptedParams()`. A failed replacement stops the sensitive part
of the probe. The fixed 117-character key consists of 109 `A` characters plus
the synthetic DES key `DESkey8!`; both values contain only characters from the
observed Android key alphabet. The key is installed reflectively and verified
before encryption. Production code never uses this fixed key.

Only records prefixed with `[quc-compare]` belong to this probe. They contain
the explicitly allowed common values, type/length/synthetic markers for IDs,
the synthetic signature, the verified synthetic pre-DES plaintext, and the
corresponding DES boundary data. Full plaintext and ciphertext are disclosed
only after every identity replacement and the fixed key have been verified.
The generated runtime random key itself is withheld; only its length and
character-class observations are emitted. No RSA envelope value is printed.

Run the Python comparison locally against the capture:

```powershell
py .\diagnostics\compare_android_quc.py $Capture
```

This prints the common-value table and compares each deterministic stage with
the internal Python Android profile. The captured Android serialization is the
`HashMap` iteration order, `key=value` pairs joined by `&`, Java
`URLEncoder` UTF-8 values, retained empty values, and no trailing separator.
The report includes the first differing byte and at most 32 bytes of context on
either side for synthetic values only.

Before the profile-specific patch, Python first differed at offset 0 because
its insertion order was different. With the Android order imposed, the first
encoding difference was at offset 124: Android writes a space as `+`, while the
old `encodeURIComponent`-equivalent path wrote `%20` and left parentheses
unescaped. The internal Android profile now uses the captured ordering and Java
encoding. Its pre-DES plaintext, raw ciphertext, and unpadded, unwrapped
standard Base64 all match the Android vector. Android reported
`DES/CBC/PKCS5Padding`, with the final eight ASCII bytes of the full key used as
both key and IV; Python's PKCS#7 padding is equivalent for DES's eight-byte
block size.

The form vector deliberately contains spaces, `+`, `/`, `=`, `%`, and UTF-8
text. The native random generator was sampled with 65,536 characters and
observed the complete 70-character alphabet documented in the comparison
report. The protocol profile remains an implementation detail selected publicly
through `AuthBackend.ROBOT360`; the existing Botslab cloud profile is unchanged.

## Android 360 captcha diagnostic

The Android-profile credential diagnostic deliberately keeps a captcha token
in memory only. A normal one-shot performs one login request and, on errno
5010, one `UserIntf.getCaptcha` request. It writes only the returned image to a
temporary file, prints safe response metadata, and exits:

```powershell
py .\diagnostics\test_android_360_auth.py --send-once
```

Because `sc` is discarded when that process exits, it cannot be continued by a
later invocation. To solve a captcha, start the explicit process-local mode:

```powershell
py .\diagnostics\test_android_360_auth.py --continue-captcha
```

After the exact confirmation `CONTINUE ONE ANDROID 360 CAPTCHA`, this mode
performs one initial login and one captcha fetch, displays the image path, and
waits for the captcha code using hidden terminal input. It then sends exactly
one login retry with `sc`, `uc`, and `captchaType=graph`. It never performs a
second captcha fetch, an automatic retry, Smart Home login, or device discovery.
The same persisted `DeviceIdentity`, account, client, endpoint, and internal
Android profile are used throughout that single process. The image file does
not contain the `sc` token.

After the QUC retry has returned complete Q/T/qid credentials, one additional
diagnostic Smart Home session mint can be enabled explicitly:

```powershell
py .\diagnostics\test_android_360_auth.py `
    --continue-captcha `
    --mint-session-once
```

The script then requires the additional exact confirmation
`MINT ONE ANDROID 360 SESSION`. Only after that confirmation does it pass the
in-memory, once-normalized Q/T values and separate qid to the existing
`BotslabAuth.login` request path. It sends at most one request to
`q.smart.360.cn/common/user/login`, prints only HTTP/errno/message and SID/push
key presence flags, and exits. Q, T, qid, SID, push key, cookies, and request
bodies are neither printed nor persisted. No device request, push connection,
or robot command follows.
