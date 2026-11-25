# botslab360

[![PyPI](https://img.shields.io/pypi/v/botslab360.svg)](https://pypi.org/project/botslab360/)
[![Python](https://img.shields.io/pypi/pyversions/botslab360.svg)](https://pypi.org/project/botslab360/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![AI Assisted Codex](https://img.shields.io/badge/AI%20Assisted-Codex-blue?logo=openai&logoColor=white)

`botslab360` is an asynchronous Python client for selected Botslab / 360 robot
vacuums. It provides a reusable protocol layer for applications such as the
[`home-assistant-botslab360`](https://github.com/placix/home-assistant-botslab360)
custom integration.

> [!WARNING]
> This project is unofficial, experimental, and not affiliated with Botslab,
> Qihoo 360, or 360 Smart Home.

## Features

- Qihoo Q/T session authentication and optional headless email/password login;
- explicit Botslab / CloudSmart and 360Robot account backends;
- captcha continuation controlled by the calling application;
- Smart Home login, session handling, and one automatic SID refresh;
- device discovery and robot status retrieval;
- station network-information retrieval;
- TCP/push communication and AES decryption of push messages;
- room discovery from the current robot map;
- single-room and multi-room cleaning;
- start, pause, resume, return-to-dock, locate, and mop-only controls.

The current device-control and room features have been verified with a 360 S9-P
using the 360Robot backend. Other models may work but have not been verified.

## Installation

Install the published package from PyPI:

```bash
python -m pip install botslab360
```

Python 3.10 or newer is required.

## Authentication

Existing integrations can authenticate with Qihoo 360 `Q` and `T` session
tokens. New applications can instead let the library obtain those tokens from
an email/password login. Botslab / CloudSmart and original 360Robot accounts
use separate backends and are never tried as automatic fallbacks.

For a Botslab / CloudSmart account, the regional backend is the default.
Omitting `region` selects `eu1`:

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

For an account created in the original 360Robot application, select the
non-regional backend. Supplying `region` for this backend is rejected:

```python
client = Botslab360Client.from_credentials(
    "user@example.com",
    "YOUR_PASSWORD",
    backend=AuthBackend.ROBOT360,
    device_identity=identity,
)
```

Persist the generated identity's `mid`, `android_id`, and `m2` values in secure
application configuration and reconstruct the same `DeviceIdentity` for later
logins. These identifiers are not account secrets, but should not be rotated on
every login.

The library does not solve captchas automatically. `authenticate()` raises
`CaptchaRequired` with image bytes and a challenge. Present the image to the
user, collect the code without logging it, and continue explicitly:

```python
from botslab360 import CaptchaRequired

try:
    session = await client.authenticate()
except CaptchaRequired as exc:
    show_captcha_to_user(exc.challenge.image)
    captcha_code = await read_captcha_code_without_logging()
    session = await client.continue_authentication(exc.challenge, captcha_code)
```

Both successful authentication methods return a ready `SmartSession`; callers
do not need to handle Q, T, or qid themselves.

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
        robot = devices[0]
        status = await client.get_status(robot.id)

        print(robot.name, robot.model)
        print(f"Battery: {status.battery}%")
        print(f"State: {status.state}")


asyncio.run(main())
```

Real applications should load credentials from secure configuration or
environment-specific secret storage instead of hard-coding them.

## Robot control

```python
async with Botslab360Client(q, t) as client:
    await client.authenticate()
    robot = (await client.get_devices())[0]

    await client.start_cleaning(robot)
    await client.pause(robot)
    await client.resume(robot)
    await client.return_to_dock(robot)
    await client.locate(robot)
```

Mop-only mode is also available. Disabling it selects sweep, or sweep and mop
when wiping hardware is installed; enabling it selects mop only:

```python
await client.set_mop_only(robot, False)
await client.set_mop_only(robot, True)
```

The known status payload does not report the current mop-only switch. The
library therefore does not invent a synchronized state or derived cleaning
mode. Water level remains an independent room setting.

## Room cleaning

Room cleaning fetches the current map before validating and sending a
selection. Room IDs belong to a particular device and map; always read the
current room list rather than hard-coding them.

```python
rooms = await client.get_rooms(robot)

for room in rooms:
    print(room.id, room.name, room.vertices)

await client.clean_rooms(robot, [1, 6])
```

`get_rooms()` returns `[]` for the recognized map structure without room
segmentation: an integer `mapId`, absent `cleanId` and `smartArea`, and an empty
`area` list. This is a capability difference, not a connection failure.
Malformed maps, authentication errors and transport failures still raise errors.
Calling `clean_rooms()` on that structure raises the public
`UnsupportedRoomMapError` (an `ApiError` subclass with `phase="unsupported"`)
without sending a room-cleaning command. Room-capable maps still require a valid
`cleanId`.

Verified per-run settings can override pass count, suction, and water level for
selected rooms:

```python
from botslab360 import RoomCleaningSettings, RoomFanMode, RoomWaterLevel

await client.clean_rooms(
    robot,
    [1],
    room_settings={
        1: RoomCleaningSettings(
            clean_times=2,
            fan_mode=RoomFanMode.STRONG,
            water_pump=RoomWaterLevel.MEDIUM,
        )
    },
)
```

Omitted settings retain their freshly fetched vendor values. The supported
suction values are `quiet`, `auto`, `strong`, and `max`; water levels are `1`,
`2`, and `3`. An existing `waterPump=0` is preserved when not overridden, but
is not exposed as an off choice because that meaning is unverified.

`Room.mode` preserves the optional raw `SweepArea.mode` string. It is a
carpet-related value, not a verified room sweep/mop selector. New code must not
use the deprecated `RoomCleaningMode` compatibility enum or
`RoomCleaningSettings.mode`; attempts to set the latter are rejected.

## Status request time budget

`get_status(device_id, timeout=30.0)` retains its existing behaviour. The
`timeout` controls the wait for the matching status push after registration
and the HTTP request. Callers can explicitly opt into an overall deadline and
bounded recovery with `get_status(device_id, total_timeout=125.0)`.

The total time budget includes TCP setup, profile fallback, HTTP, the status
push, and any recovery. The library cancels outstanding work at the deadline
and waits for cleanup, so the call may return after the deadline. At most one
additional attempt is allowed. A transient push registration timeout, HTTP
read timeout, or matching status push timeout can use that attempt if enough
time remains for the configured waits. Session expiry uses the same recovery
slot for reauthentication. Each attempt uses a fresh task ID and push channel.

The reserve for a transient retry is 15 seconds per configured push profile
plus the configured HTTP timeout and the status push timeout. TCP setup and
HTTP phases may take additional time, which the overall deadline bounds.
Robot commands and other read operations retain their existing behaviour.

With the default phase timeouts, this reserve is 75 seconds with one profile
or 90 seconds with two. A 120-second deadline leaves about 89 seconds after a
30–31 second failure, so it can skip a retry when two profiles are configured.
The reserve is an admission check for the configured waits, not a prediction
of how long a successful attempt will take.

For a controlled Home Assistant trial, 125 seconds per robot covers that
observed failure range with either profile count. An earlier profile fallback
on the first attempt can still use up the margin. Home Assistant schedules
its regular poll roughly one interval after the previous refresh finishes.
With a 60-second interval, a refresh using the full 125-second budget can
therefore start the next poll about 185 seconds after the previous start,
plus cleanup. For entries with multiple robots, the coordinator currently
polls them in sequence, so this per-robot budget can accumulate. Evaluate
recovery rate and refresh latency before enabling it broadly.

DEBUG logs from `botslab360.client` record retry decisions and successful
recovery. Deadline expiry raises `ApiError` with phase `timeout` and the
fixed message `Status retrieval exceeded its total time budget`.


## Occupancy grids

The public API can fetch the vendor occupancy grid independently of room
segmentation:

```python
from botslab360 import OccupancyGrid, UnsupportedOccupancyGridError

grid: OccupancyGrid = await client.get_occupancy_grid(robot, timeout=30.0)
print(grid.map_id, grid.width, grid.height, grid.resolution)
cells: bytes = grid.cells
dock: tuple[int, int] | None = grid.dock_position
```

`robot` may be a `Device` or device-ID string. The frozen, slotted
`OccupancyGrid` contains `map_id`, `width`, `height`, `resolution`, `x_min`,
`y_min`, `cells`, and optional `dock_position`. It contains no images, rendering
state, timestamps or raw vendor dictionary. Decoding is offloaded from the
async event loop; the timeout controls the wait for the current MapInfo.

This format is based on confirmed 360 S6 behavior and the reference in
[Home Assistant PR #6](https://github.com/placix/home-assistant-botslab360/pull/6)
by [DrLabel](https://github.com/DrLabel). It is not a claim that every
360/Botslab model uses this format:

- Dimensions are cell counts, resolution is metres per cell, and `x_min` and
  `y_min` are the origin in metres.
- `cells` contains exactly `width * height` vendor bytes in row-major order;
  row zero is at `y_min`. No mirroring, rotation, palette or image scaling is
  applied. Confirmed S6 values are `0` for wall/obstacle, `127` for unknown,
  and `255` for floor. Other byte values are preserved unchanged.
- Dock coordinates are an integer `(x, y)` pair in millimetres in the same
  frame. As with status `pos`, an absent, `null` or empty position is `None`;
  otherwise the first two strict integers are used, without interpreting extra
  entries. A reported `(0, 0)` is preserved. On this S6,
  `RobotStatus.position_x`/`position_y` use the same millimetre frame; this
  does not establish position units for every other model.

The parser validates field types without converting arbitrary strings or
floats to integers. Geometry must be finite, resolution positive, and the grid
is limited to 1,000,000 cells. Base64 spaces are repaired to `+`, missing
padding is restored, and decoding is strict; encoded input is also bounded.
The input bound scales with the declared cell count as well as the global
limit, so tiny grids cannot cause large Base64 allocations.
The raw LZ4 block must decode to exactly the grid size. Optional `lz4_len`, if
present, must be an integer matching the compressed block length.

After validating `mapId`, a MapInfo with no grid geometry/payload metadata raises
`UnsupportedOccupancyGridError`, an `ApiError` subclass with `phase="unsupported"`.
It describes the current map only, not a permanent device capability. Partial or
malformed grids remain `ApiError(phase="protocol")`; transport and authentication
failures retain their existing classifications. An empty room list is not treated
as a grid capability signal: a room-capable robot may
simply have no configured rooms. Existing `get_rooms()`/`clean_rooms()`
semantics are unchanged, and `cleanId` remains required for room cleaning.
Only successful grid retrieval confirms a currently usable occupancy grid.

Public `GRID_CELL_OCCUPIED`, `GRID_CELL_UNKNOWN` and `GRID_CELL_FREE` constants
name the observed S6 values 0, 127 and 255. They do not impose a model-independent
palette or restrict other cell bytes. There is no `room_segmentation` boolean:
absence of a recognized no-room structure does not establish room capability.

The 1,000,000-cell limit is about 65 times the observed 166-by-92 S6 grid and
corresponds to 50-by-50 metres at 5 cm/cell. It bounds allocation without a
speculative fourfold increase for larger maps not yet evidenced.

`chargeHandlePhi`, `chargeHandleState`, and `base64_len` are not interpreted or
exposed because their required semantics are not established by the reference.
Applications remain responsible for rendering, overlays, caching and refresh
policy. No Pillow or LZ4 dependency is added.

## Status and network information

`RobotStatus` exposes common values such as battery level, robot and charging
state, fan mode, cleaned area, cleaning time, error code, online state, and raw
wiping-assembly status. It also carries optional raw diagnostic counters,
states, map position, heading, timer status, and auto-boost state. Values with
unknown units or meanings remain raw, and missing fields remain `None`.

Station network identity is available separately:

```python
network_info = await client.get_network_info(robot)

print(network_info.station_ip)
print(network_info.station_mac)
print(network_info.station_signal)
```

MAC addresses are normalized to lowercase colon-separated form. Treat SSIDs as
potentially sensitive when displaying or logging `network_info.station_ssid`.

## Session handling and security

The authentication chain is:

```text
Q + T → qid → Smart Home login → sid + pushKey → device communication
```

If the Smart Home SID expires, the library retries authentication once with the
current Q/T tokens. If the underlying Qihoo session is invalid, the caller must
provide fresh credentials. The email/password path obtains Q/T first and then
uses this same Smart Home login path; the newer signed `/v1` API is not used.

Treat passwords, captcha codes, Q, T, qid, sid, and push keys as secrets. Never
include real credentials in bug reports, screenshots, logs, test fixtures, or
Git commits.

## Known limitations

- Only the 360Robot S9-P has been verified with the current control and room
  functionality.
- Captcha challenges require interaction by the calling application.
- Several diagnostic values intentionally remain raw because their physical
  units or model-independent meanings are not established.
- Room polygons use vendor map coordinates, and malformed or missing polygons
  are exposed as `None`.

## Development

```bash
git clone https://github.com/placix/python-botslab360.git
cd python-botslab360
python -m venv .venv
python -m pip install -e ".[test]"
python -m pip install build ruff twine

ruff check .
ruff format --check .
python -m pytest -p no:cacheprovider
python -m compileall -q src tests diagnostics
python -m build
python -m twine check dist/*
```

Activate the virtual environment before installing dependencies when desired.
Files under `diagnostics/` are development and protocol-verification tools;
applications should use the public `Botslab360Client` API instead.

This independent project builds in part on protocol research by
[TA2k](https://github.com/TA2k) in
[ioBroker.botslab360](https://github.com/TA2k/ioBroker.botslab360). See
[ATTRIBUTION.md](ATTRIBUTION.md) for details.

## AI-Assisted Development

This project is developed with the assistance of OpenAI Codex. AI tools support
code development, refactoring, testing, and documentation.

AI-generated contributions are reviewed and validated before being incorporated
into the project.

This project is licensed under the [MIT License](LICENSE).
