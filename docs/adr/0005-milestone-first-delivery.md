# ADR 0005: Milestone-first delivery

## Status

Accepted.

## Context

The project scope is broad: CLI UX, Bitwarden-compatible auth and sync, local
cryptography, mutation flows, an agent, and passkey signing. Implementing these
as one large change would make review shallow and security drift likely.

## Decision

Use ordered GitHub milestones and issue-level acceptance criteria. Each
implementation PR must map to one issue and one milestone unless a maintainer
explicitly documents why a boundary crossing is necessary.

## Consequences

- Best-practice and security work is not optional setup; it is M0.
- Later work can proceed slowly without losing the project direction.
- Reviewers can reject code that satisfies functionality but violates milestone
  scope or security controls.
