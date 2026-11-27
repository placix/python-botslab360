# Changelog

## 0.7.6-beta.3

This prerelease extends opt-in recovery for robot status requests.

- Recover from selected socket errors, connect timeouts and temporary DNS
  resolution failures with 2- and 5-second backoffs.
- Recover from HTTP 502, 503 and 504 with 1- and 3-second backoffs. Honour
  a longer valid Retry-After for 503. Retry HTTP 429 at most once, only on
  the first failure with a valid Retry-After that fits the deadline.
- Keep a valid Retry-After from either HTTP 429 or 503 across status calls
  on the same client. While the cooldown is active, later status polls
  fail promptly without opening another push connection or sending HTTP.
- Keep the original push registration and read-timeout recovery. Limit
  mixed failures to three status attempts within the shared budget.
- Keep permanent errors visible, including HTTP 500. Add transport
  exception types, OS errno, HTTP status and retry decisions to DEBUG logs.
- Preserve cancellation, per-client serialization and command behaviour.
  Automatic retries continue to require a status budget.

## 0.7.6-beta.2

This prerelease is intended for testing recovery from intermittent transport
failures during robot status retrieval.

## What's changed

- Wait 250 ms before retrying a push registration timeout or remote EOF during
  registration. If that retry ends in EOF during registration, allow one final
  attempt after 500 ms, subject to the same overall budget.
- Open a fresh push stream for each attempt and finish cleanup before retrying.
- Serialize budgeted status queries per client. Time spent waiting counts toward
  the deadline, and expired queued requests do not start transport.
- Add safe DEBUG diagnostics for transport failures, cleanup, backoff, and
  recovery outcomes.

## Compatibility

- Existing HTTP read and status-push timeout recovery remain supported.
- Existing calls without an overall timeout retain their behaviour.
- Robot control commands receive no new automatic retries.
- The cause of the observed early disconnect and the effect of the backoff
  still need real-world validation.
