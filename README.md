# botslab360

Async Python client for Botslab / 360 robot vacuums.

This project provides an unofficial Python interface for selected 360 robot vacuum cleaners and is intended as a reusable library for integrations such as Home Assistant.

> [!WARNING]
> This project is unofficial and not affiliated with Botslab, Qihoo 360 or 360 Smart Home.
> Version `0.2.0` should be considered experimental.

## Features

Currently implemented:

- Qihoo `Q` / `T` session authentication
- Optional headless Qihoo email/password authentication
- Automatic `qid` derivation
- Smart Home login and session handling
- Automatic Smart Home SID refresh
- Device discovery
- Robot status retrieval
- TCP / push protocol communication
- AES decryption of push messages
- Start cleaning
- Pause cleaning
- Resume cleaning
- Return to dock
- Locate robot

Currently tested with:

- 360 S9-P / X90

Other models may work but have not yet been verified.

## Installation

```bash
pip install botslab360
```

Python 3.10 or newer is required.

## Authentication

The existing authentication path uses Qihoo 360 account session tokens:

- `Q`
- `T`

These tokens can be obtained from an authenticated 360 web session.

They must be treated like credentials.

Never publish or log:

- `Q`
- `T`
- `qid`
- `sid`
- `pushKey`

Alternatively, the library can obtain Q/T with an email/password QUC login.
There are two separate account backends, selected explicitly with
`AuthBackend`. They are never tried as automatic fallbacks for each other.

For a Botslab / CloudSmart account, the existing regional backend remains the
default. Omitting `backend` is equivalent to `AuthBackend.BOTSLAB`, and omitting
`region` continues to select `eu1`:

```python
from botslab360 import AuthBackend, Botslab360Client, DeviceIdentity

identity = DeviceIdentity.generate()
client = Botslab360Client.from_credentials(
    "user@example.com",
    "YOUR_PASSWORD",
    backend=AuthBackend.BOTSLAB,
    region="eu1",
    device_identity=identity,
)
```

For an account from the original 360Robot application, select the non-regional
backend. Passing `region` with this backend is rejected:

```python
client = Botslab360Client.from_credentials(
    "user@example.com",
    "YOUR_PASSWORD",
    backend=AuthBackend.ROBOT360,
    device_identity=identity,
)
```

After creating a new identity, store its `mid`, `android_id`, and `m2` values
in the application's secure configuration and reconstruct the same
`DeviceIdentity` for later logins. These identifiers are not account secrets,
but they should not be rotated on every login.

The library does not solve captchas automatically. `authenticate()` raises
`CaptchaRequired` with image bytes and a challenge object. Present the image
to the user, collect the code without logging it, then explicitly call
`continue_authentication(challenge, code)`. Each retry is caller initiated.

```python
from botslab360 import CaptchaRequired

try:
    session = await client.authenticate()
except CaptchaRequired as exc:
    show_captcha_to_user(exc.challenge.image)
    captcha_code = await read_captcha_code_without_logging()
    session = await client.continue_authentication(
        exc.challenge,
        captcha_code,
    )
```

On success, both methods return a ready `SmartSession`; callers never need to
handle Q, T, or qid themselves.

## Basic usage

```python
import asyncio

from botslab360 import Botslab360Client


async def main() -> None:
    q = "YOUR_Q_TOKEN"
    t = "YOUR_T_TOKEN"

    async with Botslab360Client(q, t) as client:
        await client.authenticate()

        devices = await client.get_devices()

        for device in devices:
            print(device.name)
            print(device.model)

            status = await client.get_status(device)

            print(f"Battery: {status.battery}%")
            print(f"State: {status.state}")
            print(f"Charging: {status.charging}")


asyncio.run(main())
```

For real applications, do not hard-code credentials. Load them securely from configuration or environment-specific secret storage.

## Robot control

```python
async with Botslab360Client(q, t) as client:
    await client.authenticate()

    devices = await client.get_devices()
    robot = devices[0]

    await client.start_cleaning(robot)
    await client.pause(robot)
    await client.resume(robot)
    await client.return_to_dock(robot)
    await client.locate(robot)
```

## Status information

Depending on the robot model, status information may include:

- Battery level
- Robot state
- Charging state
- Fan mode
- Cleaned area in square metres
- Cleaning time in seconds
- Error code
- Online state

Example:

```text
Device: 360 Saugroboter
Model: S9-P
Battery: 100 %
State: fullcharge
Charging: True
Fan mode: strong
Cleaned area: 5
Cleaning time: 157
Error code: 0
```

## Session handling

The library distinguishes between the Qihoo account session and the Smart Home session.

Conceptually:

```text
Q + T
  ↓
qid
  ↓
Smart Home login
  ↓
sid + pushKey
  ↓
Device communication
```

If the Smart Home SID expires, the library performs one automatic re-authentication attempt using the existing `Q` and `T` tokens.

If the underlying Qihoo account session is no longer valid, the caller must provide new `Q` and `T` tokens.

The email/password path first obtains Q/T from QUC and then uses this same
Smart Home login path. The newer signed `/v1` API is not used.

## Development

Clone the repository:

```bash
git clone https://github.com/placix/python-botslab360.git
cd python-botslab360
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install in editable mode:

```bash
python -m pip install -e .
```

Install test dependencies:

```bash
python -m pip install -e ".[test]"
```

Run the test suite:

```bash
pytest
```

Files under `diagnostics/` are development and protocol-verification tools.
Normal applications should use the public `Botslab360Client` API instead.

## Project status

The library is currently under active development.

The current focus is providing a clean protocol layer that can later be used by a native Home Assistant integration.

Planned future work may include:

- Additional robot models
- Persistent push connection
- Fan speed control
- Room cleaning
- Zone cleaning
- Map support

## Security

Authentication and session values must be treated as secrets.

Do not include real credentials in:

- bug reports
- screenshots
- logs
- test fixtures
- Git commits

## Acknowledgements

`python-botslab360` is an independent Python project and is not affiliated
with or maintained by TA2k or the ioBroker.botslab360 project.

The headless 360/Botslab QUC authentication flow in this project is based in
part on protocol research and implementation work by TA2k in
[ioBroker.botslab360](https://github.com/TA2k/ioBroker.botslab360), in
particular its
[`lib/quc.js`](https://github.com/TA2k/ioBroker.botslab360/blob/main/lib/quc.js)
implementation. Relevant parts of the protocol were additionally verified
against the decompiled Android application where possible. The Python
implementation and public API in this project were developed independently.

See [ATTRIBUTION.md](ATTRIBUTION.md) for license and attribution details.

## License

MIT

## Links

- Source: https://github.com/placix/python-botslab360
- Issues: https://github.com/placix/python-botslab360/issues
