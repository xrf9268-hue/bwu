# ADR 0002: New CLI and storage namespace

## Status

Accepted.

## Context

Reusing another client's command names or on-disk directories would make early
testing convenient but increases the risk of reading or mutating existing user
state unexpectedly.

## Decision

Use a new CLI design and a fresh `bwu` config/cache/runtime namespace. Do not
reuse `rbw` config, cache, sockets, or environment variable names in v1.

## Consequences

- Migration is explicit and can be designed later.
- Tests can assert no accidental dependency on `rbw` paths.
- Existing scripts for other clients will not work without deliberate adapters.
