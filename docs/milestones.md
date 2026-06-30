# Milestones

The project is intentionally split into ordered milestones. Later milestones
must not start until their prerequisites are merged unless a new ADR changes
the dependency map.

## M0: Governance and security baseline

Goal: make future implementation hard to steer off course.

Deliverables:

- Architecture, security model, official references, and development practice
  docs.
- ADRs for core v1 decisions.
- GitHub issue templates, labels, milestones, and initial issue backlog.
- CI that validates repository hygiene before real implementation begins.

## M1: Rust workspace and CLI skeleton

Goal: establish a testable Rust workspace with command shape and no real secret
handling yet.

Deliverables:

- `bwu` and `bwu-agent` binaries.
- Command tree and help output.
- Config/cache/runtime path module using the `bwu` namespace.
- Error and redaction types.
- CLI integration tests with temporary directories.

## M2: Auth and sync read path

Goal: support login, token refresh, and encrypted vault sync against official
and self-hosted endpoints.

Deliverables:

- API client with official cloud, EU cloud, and custom base URL support.
- Password login, API key login, and supported 2FA paths.
- Encrypted local cache written with owner-only permissions.
- Mock API tests; no real account required in CI.

## M3: Crypto core and read-only vault commands

Goal: decrypt synced vault data locally and expose safe read-only commands.

Deliverables:

- KDF, encrypted string parsing, account key, org key, and item key handling.
- `item list`, `item get`, `item search`, and `otp code`.
- Tests for encrypted fixtures, TOTP vectors, and secret redaction.

## M4: Write operations

Goal: add item mutation without losing unknown or passkey fields.

Deliverables:

- `item add`, `item edit`, and `item delete`.
- Fixture tests proving unmodeled passkey fields survive edits.
- Conflict and refresh-token behavior documented and tested.

## M5: Optional local agent

Goal: provide bounded local decrypt/sign service for repeated operations.

Deliverables:

- `bwu-agent` Unix socket protocol.
- `agent start`, `agent stop`, and `agent status`.
- Unlock timeout defaulting to 900 seconds.
- Timeout, permissions, and redaction tests.

## M6: Passkey export and headless signing

Goal: explicitly export stored passkeys and produce constrained WebAuthn
assertions.

Deliverables:

- `passkey list`, `passkey get`, `passkey export`, and `passkey sign`.
- WebAuthn request/response JSON schemas.
- rpId and credential id match enforcement.
- Signature verification tests using synthetic passkeys.

## M7: Packaging and release artifacts

Goal: produce reproducible macOS and Linux build artifacts with explicit release
gating.

Deliverables:

- GitHub Actions build artifacts for macOS and Linux.
- Checksums and build provenance notes.
- Install instructions for maintainer-approved use.
- Release checklist and rollback notes.
