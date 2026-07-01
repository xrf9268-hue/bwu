# ADR 0006: Crypto core and local storage model

## Status

Accepted.

## Milestone issue

Refs #16.

## Official references

- [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/)
- [Bitwarden Encryption Protocols](https://bitwarden.com/help/what-encryption-is-used/)
- [Bitwarden Encryption Key Derivation](https://bitwarden.com/help/kdf-algorithms/)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

References were verified on 2026-06-30 before accepting this ADR.

## Context

`bwu` will decrypt Bitwarden-compatible vault data locally. The security model
already requires a fresh `bwu` namespace, encrypted local cache files,
owner-only permissions, memory-only unlocked keys, zeroizing wrappers, redacted
logs, and synthetic fixtures. M1 and M3 implementation needs a policy boundary
before code chooses crates, fixture formats, or cache layout.

## Decision

Implement only Bitwarden-compatible cryptographic behavior described by
official Bitwarden documentation or confirmed through clean-room investigation
of official Bitwarden repositories. Do not invent new vault encryption formats,
custom modes, custom padding, or homegrown KDF behavior.

Allowed cryptographic crate categories are:

- Maintained Rust crates for the Bitwarden KDFs, including PBKDF2-SHA256 and
  Argon2id.
- Maintained Rust crates for the symmetric encryption, HMAC, hashing, random
  number generation, base64/base64url, and PEM or DER parsing needed to match
  Bitwarden data formats.
- Maintained zeroization, secrecy, or redaction crates for secret wrapper
  types.

Unsupported KDFs, unknown encrypted string versions, malformed encrypted
strings, and unknown key hierarchy entries must fail closed with redacted error
messages.

The implementation must model the Bitwarden key hierarchy explicitly:

- User secrets derive or unlock account-level key material.
- Organization and item keys stay encrypted until they are needed for a
  specific operation.
- Decrypted account keys, organization keys, item keys, API key client secrets,
  master password bytes, and passkey private keys use secret wrapper types that
  zeroize on drop and do not expose raw values through `Debug`, `Display`,
  logs, errors, or snapshots.

Local storage must use the `bwu` namespace from ADR 0002:

- Config files may contain non-secret endpoint and account metadata.
- Cache files may contain server tokens and encrypted vault sync data only when
  written with owner-only file permissions where the platform supports them.
- Runtime directories and sockets must be owner-only on Unix.
- Unlocked keys, decrypted item fields, and decrypted passkey private keys must
  never be written to config, cache, runtime files, logs, or CI artifacts.

Test fixtures for encrypted vault data must be synthetic. Fixture generation
may use deterministic test inputs, but those inputs must be created for this
repository and must not come from a real Bitwarden or Vaultwarden account.
Fixture tests must include negative cases for malformed encrypted strings,
unsupported KDF parameters, unknown key entries, permission failures, and
redaction regressions.

## Consequences

- Issues #3 and #6 must cite this ADR before implementation starts.
- M1 path and redaction primitives must be shaped so M3 crypto code can reuse
  the same wrappers and permission checks.
- Any later change to support a new Bitwarden encryption format, new KDF, or
  persistent decrypted cache requires a new ADR or an explicit amendment to
  this ADR.
