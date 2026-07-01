# ADR 0004: Explicit passkey export and constrained signing

## Status

Accepted. Refined by [ADR 0008](0008-passkey-export-and-signing-edge-policy.md).

## Context

Stored passkeys contain private key material. Export and signing are powerful
operations that can bypass browser-mediated user interaction if designed too
broadly.

## Decision

Expose passkey private key material only through `passkey export`. Implement
`passkey sign` as a constrained WebAuthn assertion command that accepts explicit
request JSON and signs only after matching the stored credential id and rpId.

## Consequences

- Ordinary list/get commands must not print private key material.
- The signing command must reject arbitrary byte signing.
- WebAuthn assertion output follows W3C WebAuthn-shaped JSON with base64url
  no-padding binary fields.
- Browser integration requires a separate ADR.
