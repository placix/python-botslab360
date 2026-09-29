# AGENTS.md

## Repository purpose

`python-botslab360` is the reusable asynchronous Python library for Botslab / 360 robot vacuums.

Keep protocol, authentication, map/room parsing, and robot communication logic in this library rather than duplicating it in downstream integrations.

## Supported Python

The project supports Python 3.10 and newer.

Do not:
- raise the minimum Python version merely to satisfy a lint rule
- add runtime dependencies solely for typing convenience without a clear need

`PYI034` is intentionally ignored because `typing.Self` is unavailable on Python 3.10 without an additional dependency.

## Versioning

The package version belongs in:

```toml
[project]
version = "X.Y.Z"
```

inside `pyproject.toml`.

Do not place a package version under:

```toml
[tool.pytest.ini_options]
```

or any unrelated tool configuration.

Only change the project version when the task explicitly calls for a release/version bump or when a target version has already been specified.

## Security

Never commit, print, log, or expose real:

- Q tokens
- T tokens
- qid
- SID
- pushKey
- account passwords
- captcha codes

Keep diagnostic output sanitized.

Do not add `.botslab360-device-identity.json`, temporary diagnostics, or ignored `tmp/` content to commits.

Do not perform real account logins, robot commands, or network diagnostics unless the task explicitly requests live testing.

## Error handling

Use:
- `TypeError` when an argument has the wrong type
- `ValueError` when the type is valid but the supplied value is invalid

Preserve the existing public exception hierarchy and authentication/session semantics.

Do not catch broad exceptions unless there is a deliberate boundary-layer reason. Where a diagnostic script intentionally catches `Exception`, document it locally rather than disabling the lint rule globally.

## Scope discipline

Do not perform unrelated refactors, formatting sweeps, dependency upgrades, or line-ending normalization.

Preserve existing behavior unless the requested task explicitly changes it.

Do not modify protocol behavior based only on assumptions. Vendor/protocol behavior should be backed by existing tests, captured diagnostics, or verified behavior.

## Validation

Before considering a code task complete, run as applicable:

```text
ruff check .
ruff format --check .
python -m pytest -p no:cacheprovider
python -m compileall src tests diagnostics
git diff --check
```

Expected result:
- Ruff passes
- formatting check passes
- all tests pass
- compileall succeeds
- git diff check succeeds

LF/CRLF informational warnings on Windows are not by themselves a reason to rewrite files or normalize the repository.

## Git workflow

At the beginning:
- inspect `git status`
- preserve existing user changes
- never discard or overwrite unrelated work

At the end:
1. Review `git diff`.
2. Verify that no secrets or unrelated files are included.
3. Run the required validation.
4. Commit only when the user explicitly requests it.
5. When a commit is requested, stage only the intended changes and create one
   focused commit using a concise Conventional Commit style message.
6. Report as applicable:
   - commit hash
   - commit message
   - validation results
   - whether the working tree contains pre-existing or unrelated changes

Do not:
- commit unless explicitly requested by the user
- push
- create tags
- create GitHub releases
- publish to PyPI
- rewrite remote history

unless explicitly requested by the user.

## Relationship to Home Assistant

`home-assistant-botslab360` consumes this library.

Public functionality needed by the Home Assistant integration should be exposed through a clean public API. Do not make the HA integration depend on private attributes such as `_credentials`, `_session`, or internal protocol helpers.
