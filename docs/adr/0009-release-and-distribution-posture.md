# ADR 0009: Release and distribution posture

## Status

Accepted.

## Milestone issue

Refs #18.

## Official references

- [GitHub Actions workflow artifacts](https://docs.github.com/en/actions/using-workflows/storing-workflow-data-as-artifacts)
- [GitHub Actions security hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [Cargo Book: Profiles](https://doc.rust-lang.org/cargo/reference/profiles.html)
- [RustSec Advisory Database](https://rustsec.org/)

References were verified on 2026-06-30 before accepting this ADR.

## Context

M7 will eventually build public macOS and Linux artifacts. The repository is
public but has no open-source license yet, and the product will handle vault
secrets and passkey private keys. Release policy must define artifact
visibility, checksums, provenance, advisory checks, secret review, and rollback
before implementation work adds packaging automation.

## Decision

Public release artifacts are allowed only from a maintainer-approved release
workflow after M7 accepts the concrete build implementation. Routine pull
request workflows may upload short-lived test artifacts only when they are
needed for review and contain no secrets, vault data, private keys, or
production screenshots.

Every maintainer-approved release artifact must have:

- A SHA-256 checksum published next to the artifact.
- Build provenance notes that include commit SHA, tag, target triple, Rust
  toolchain, workflow name, workflow run URL, and build profile.
- A documented release profile covering optimization, debug information,
  stripping, panic strategy, and overflow-check posture.
- A maintainer approval record.

Release workflows must gate artifact publication on:

- Formatting, linting, unit tests, integration tests, and documentation checks.
- Dependency advisory review through RustSec-backed tooling.
- Secret scanning and manual review for accidental tokens, vault exports,
  private keys, production screenshots, and CI log leaks.
- Confirmation that the release does not add a license or package-manager
  publication without a dedicated ADR.

Installation guidance must state that early artifacts are maintainer-approved
test builds, not a stable package-manager distribution. Instructions must warn
users not to run commands against production vaults until the relevant
milestone issue is implemented, reviewed, and released.

Rollback policy:

- Remove or mark bad artifacts as withdrawn.
- Publish a short rollback note identifying the affected version, commit, and
  reason.
- If a secret may have leaked, rotate the secret, preserve only redacted
  evidence, and use private vulnerability reporting for sensitive details.
- Do not overwrite historical checksums; publish a new corrected artifact or a
  new release.

## Consequences

- Issue #12 must cite this ADR before implementation starts.
- M7 release work must include advisory checks and secret-leak checks before
  public artifacts are approved.
- Package-manager publishing, Windows artifacts, release signing, and public
  GitHub Releases before maintainer approval remain out of scope unless a later
  ADR accepts them.
