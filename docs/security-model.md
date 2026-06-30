# Security Model

## Goals

- Preserve Bitwarden's local, end-to-end decryption model.
- Keep decrypted vault data and key material out of persistent storage.
- Make private key export explicit, auditable, and test-covered.
- Make agent behavior bounded by local access, timeout, and command scope.
- Keep logs useful for debugging without exposing secrets.

## Threat model

In scope:

- Accidental leakage through stdout, stderr, logs, test snapshots, or CI.
- Reuse of stale local state from another password manager client.
- Overbroad passkey signing that ignores relying party or credential scoping.
- Agent sockets accessible by unintended local users.
- Regression risks in item edit flows that could clear unmodeled passkey data.
- Dependency vulnerabilities in cryptographic or parsing crates.

Out of scope for v1:

- A fully compromised local OS account.
- Malicious kernel, hypervisor, debugger, or memory scraper with equivalent
  privileges to the user.
- Browser integration security.
- Remote multi-user service hardening.

## Non-negotiable controls

- Use a fresh `bwu` config/cache/runtime namespace.
- Store server tokens and encrypted vault cache only in files with owner-only
  permissions where the platform supports it.
- Store unlocked keys only in process memory.
- Use zeroizing memory wrappers for master password bytes, account keys,
  organization keys, item keys, passkey private keys, and API key secrets.
- Agent default timeout is 900 seconds.
- Agent listens only on a local Unix socket under the `bwu` runtime directory.
- Agent socket files must be created in an owner-only directory.
- Ordinary `item get`, `item list`, and `passkey get` must not print private key
  material.
- `passkey export` must require an explicit selector and output format.
- `passkey sign` must match `rpId` and credential id before signing.
- Logs and error messages must redact access tokens, refresh tokens, master
  passwords, API key client secrets, item passwords, TOTP seeds, and passkey
  private keys.

## WebAuthn signing rules

`passkey sign` is a constrained command-line authenticator for automation, not
a general replacement for browser-mediated user consent.

- Input is explicit JSON, not ambient browser state.
- The command must reject requests whose `rpId` does not match the stored
  credential.
- The command must reject unknown credential ids unless a future milestone
  designs discoverable credential selection.
- The command must emit WebAuthn-shaped assertion JSON with binary fields
  encoded as base64url without padding.
- The command must never sign arbitrary bytes through the passkey API.

## Review gates

Before merging implementation in any milestone, reviewers must check:

- The issue cites the relevant official references.
- Tests cover secret redaction and ordinary-output non-disclosure.
- Tests cover negative paths for auth, unlock, agent timeout, and passkey rpId
  or credential mismatch where applicable.
- No real vault data or live secrets are present in fixtures.
