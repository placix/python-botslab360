# Attribution

`python-botslab360` is an independent Python project. TA2k is not an author or
maintainer of this project, and the two projects are not officially
affiliated.

The headless Qihoo User Center authentication flow was implemented in Python
using protocol details researched, documented, and implemented by TA2k in
[TA2k/ioBroker.botslab360](https://github.com/TA2k/ioBroker.botslab360),
particularly its
[`lib/quc.js`](https://github.com/TA2k/ioBroker.botslab360/blob/main/lib/quc.js).
Relevant behavior was also compared with the decompiled Android application
where possible.

The Python authentication code, API design, models, error handling, and tests
are this project's own implementation. The referenced authentication protocol
work remains attributed to TA2k under its MIT license.

The source project is available at:

https://github.com/TA2k/ioBroker.botslab360

## Occupancy-grid reference

The raw LZ4 block decoder and its basic synthetic test vectors were adapted
from the real-device-tested 360 S6 reference implementation contributed by
[DrLabel](https://github.com/DrLabel) in
[home-assistant-botslab360 PR #6](https://github.com/placix/home-assistant-botslab360/pull/6),
specifically `grid_map.py` and `tests/test_grid_map.py` at commit
`6e396166d7ae95584cfb674dcab5ab263648540c` in
[DrLabel/home-assistant-botslab360](https://github.com/DrLabel/home-assistant-botslab360).
That source is MIT-licensed with `Copyright (c) 2026 placix`; its required
notice and permission text are included in this project's [LICENSE](LICENSE).

Strict protocol validation, the typed public API and the shared transport
refactor were implemented here. Fixtures are synthetic; no captured home map
or private coordinates are redistributed. This attribution does not imply
that DrLabel maintains this Python library.

Reconciliation also uses DrLabel's parallel library implementation in
[python-botslab360 PR #3](https://github.com/placix/python-botslab360/pull/3),
commit `37d0e3483ad0862dc03ffff5311a87ed0360a54d` in
[DrLabel/python-botslab360](https://github.com/DrLabel/python-botslab360),
under the same MIT notice. Its optimized repeating-match approach, extended
match/trailing-literal and exact-cell-limit vectors, status-compatible dock
handling, cell constants and room-message regression checks informed this
implementation. The typed unsupported-grid error and conservative validation
remain library API decisions here.

## Upstream license

MIT License

Copyright (c) 2022 TA2k

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
