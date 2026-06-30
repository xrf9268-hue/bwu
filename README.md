# bwu

Public-source Rust command-line client for Bitwarden and Vaultwarden, with a
security-first path toward passkey export and headless WebAuthn signing.

This repository is intentionally starting with governance, architecture, and
milestone issues before implementation. The project handles password vault
material and passkey private keys, so implementation must follow the documented
security model instead of growing organically around convenience.

## Current status

Planning baseline only. Do not treat this repository as a usable password
manager until the milestone issues are implemented and verified.

## License

No open-source license has been granted yet. The repository is public for
design transparency and issue tracking, but the code remains all rights
reserved until a license is added intentionally.

## Product intent

`bwu` is a new CLI design, not an `rbw`-compatible clone. It will use a fresh
`bwu` config/cache/runtime namespace and will not reuse `rbw` on-disk state.

Target capabilities:

- Account login, logout, status, and Bitwarden/Vaultwarden endpoint selection.
- Vault sync, unlock, lock, purge, and encrypted local cache management.
- Item list, get, search, add, edit, and delete.
- TOTP code generation.
- Optional local Unix socket agent for repeated decrypt/sign operations.
- Passkey list, get, explicit export, and headless WebAuthn assertion signing.

## Non-goals for v1

- Browser integration or localhost HTTP API.
- Windows support.
- Duo or WebAuthn as Bitwarden account two-step-login mechanisms.
- Copying source from `rbw` or the `bitwarden-use` repository.
- Printing private key material through ordinary list/get commands.

## Required reading

- [Architecture](docs/architecture.md)
- [Security model](docs/security-model.md)
- [Development best practices](docs/development-best-practices.md)
- [Milestones](docs/milestones.md)
- [Official references](docs/references.md)
- [ADR index](docs/adr/README.md)

## Implementation rule

Every implementation issue must cite the relevant official references and must
include tests for the behavior it introduces. For security-sensitive code, the
review must check the security model before approving the code shape.
