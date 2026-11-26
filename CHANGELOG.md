# python-botslab360 0.7.6-beta.2

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
