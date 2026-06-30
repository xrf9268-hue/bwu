# Development Best Practices

## Work style

- Implement through milestone issues, one reviewable slice at a time.
- Write failing tests before production code for behavior changes.
- Keep cryptographic and protocol code small, reviewed, and isolated.
- Do not copy source from `rbw` or `bitwarden-use`; use official docs and
  clean-room behavior tests.
- Prefer narrow public interfaces over shared mutable state.

## Rust baseline

- Minimum Rust version: 1.95 unless an ADR changes it.
- CI must run formatting, clippy, tests, docs, and dependency advisory checks
  before feature work is considered merge-ready.
- `unsafe` is forbidden by default. Any proposed `unsafe` requires a dedicated
  ADR, tests, and a security review.
- Use typed wrappers for secrets so redaction and zeroization are hard to skip.
- Keep release profiles explicit before shipping binaries.

## Testing baseline

- Unit tests for KDF, encrypted string parsing, key derivation, TOTP, base64url,
  WebAuthn data construction, and redaction.
- CLI tests must run with temporary config/cache/runtime directories.
- API tests must use mock servers or fixtures; no CI test may require a real
  Bitwarden account.
- Passkey tests must use synthetic keys and verify signatures using public keys.
- Regression tests must prove ordinary commands do not print private keys.

## Documentation baseline

- Every milestone issue must link to the official references it depends on.
- Every public command must have documented input, output, failure modes, and
  examples before implementation is considered complete.
- ADRs are required for auth flow, crypto design, local storage, agent IPC,
  passkey signing, and release/distribution.

## Pull request baseline

Each implementation PR must include:

- The milestone issue it implements.
- A short threat-model note when the change touches secrets, auth, crypto,
  passkeys, local storage, or agent behavior.
- Test evidence.
- A statement that no live secrets or real vault data were added.

## Repository protection

Desired protection for `main`:

- Require pull requests for implementation work.
- Require at least one review.
- Require the Governance workflow before merge.
- Block force pushes and branch deletion.

As of 2026-06-30, GitHub rejects both repository rulesets and classic branch
protection for this private personal repository unless the account upgrades to
GitHub Pro or the repository is made public. Until that changes, treat direct
pushes to `main` as reserved for governance bootstrap only; all implementation
work should use issues, branches, pull requests, and local verification.
