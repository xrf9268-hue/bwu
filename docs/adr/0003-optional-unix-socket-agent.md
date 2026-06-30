# ADR 0003: Optional Unix socket agent

## Status

Accepted.

## Context

Repeated decrypt and passkey signing operations benefit from an agent, but a
mandatory long-running process would complicate first use and widen the local
attack surface.

## Decision

Use a hybrid architecture. The CLI supports one-shot unlock and operation
execution. `bwu-agent` is optional and listens only on a local Unix socket in an
owner-only runtime directory. The default unlock timeout is 900 seconds.

## Consequences

- macOS and Linux are the only v1 targets.
- HTTP and browser integration are deferred.
- Agent IPC must be small, typed, versioned, and covered by timeout and
  permissions tests.
