# ADR 0008: Passkey export and signing edge policy

## Status

Accepted.

## Milestone issue

Refs #17.

## Official references

- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)
- [RFC 4648: Base-N Encodings](https://www.rfc-editor.org/rfc/rfc4648)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

References were verified on 2026-06-30 before accepting this ADR.

## Context

ADR 0004 accepts explicit passkey export and constrained signing. M6 still
needs edge-case policy for export schema, file permissions, WebAuthn assertion
construction, relying party matching, counters, and negative tests before any
signing code is written.

## Decision

This ADR refines ADR 0004. ADR 0004 remains the high-level product decision;
this ADR controls M6 edge behavior.

`passkey export` must produce an explicit, versioned export document. The
schema must include at least:

- An export schema identifier such as `bwu-passkey-export-v1`.
- The credential id encoded as base64url without padding.
- The relying party id.
- The public key metadata needed to verify later assertions.
- The private key encoded as PEM using a standard private-key container.
- A creation timestamp or export timestamp that does not reveal account
  secrets.

Export files must be created with owner-only permissions where the platform
supports them. The command must refuse to overwrite an existing file unless the
user passes an explicit overwrite option. Ordinary `passkey list`,
`passkey get`, and item commands must not print passkey private keys.

`passkey sign` must construct WebAuthn assertion output from explicit request
JSON. It must not infer browser state, read ambient origins, or accept arbitrary
bytes for signing. The request must include an expected origin, challenge,
rpId, and credential id. Binary fields in request and response JSON must use
base64url without padding unless a future ADR chooses another encoding.

For v1 signing:

- `clientDataJSON` must use WebAuthn `webauthn.get` semantics and include the
  exact challenge and origin accepted by the command.
- The requested rpId must match the stored credential rpId exactly.
- The requested credential id must match one stored credential exactly.
- Ambiguous discoverable credential selection is rejected.
- Authenticator data flags must be derived from explicit command policy, not
  caller-supplied raw bytes.
- User presence is asserted only when the signing request includes explicit
  per-request user confirmation; unattended signing must not silently claim user
  presence.
- User verification is always false in v1 because the CLI has no accepted
  local user-verification ceremony.
- Sign counters must follow the stored credential model. If a synced passkey
  uses a zero counter, the output remains zero; if a mutable counter is stored,
  it is updated only after a successful assertion is produced.

Negative tests are required for arbitrary byte signing, rpId mismatch, origin
mismatch, challenge encoding errors, credential mismatch, ambiguous
discoverable credentials, private-key output through ordinary commands, and
unsafe export-file permissions.

## Consequences

- Issues #10 and #11 must cite this ADR before implementation starts.
- M6 acceptance criteria must include the schema, permissions, and negative
  tests from this ADR.
- Browser extension, native messaging, new passkey creation, and broader
  authenticator UX remain out of scope until a separate ADR accepts them.
