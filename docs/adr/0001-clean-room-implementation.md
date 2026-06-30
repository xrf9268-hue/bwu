# ADR 0001: Clean-room implementation

## Status

Accepted.

## Context

The project is inspired by existing Bitwarden-compatible command-line clients,
but it is a private new implementation. Copying code from existing clients would
inherit their structure, compatibility assumptions, and maintenance history.

## Decision

Implement `bwu` from scratch using official Bitwarden, W3C, IETF, OWASP, Rust,
and RustSec references as design inputs. Do not copy source from `rbw` or
`bitwarden-use`.

## Consequences

- The first milestones emphasize documentation, tests, fixtures, and small
  protocol modules over rapid feature parity.
- Issues must cite official references rather than copied implementation
  behavior.
- Any later decision to vendor or port code requires a new ADR and license
  review.
