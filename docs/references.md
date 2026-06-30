# Official References

This project treats the links below as the starting authority for design and
implementation. If a behavior is not covered here, add a new official reference
before implementing it.

## Bitwarden behavior and protocol surface

- [Bitwarden Password Manager CLI](https://bitwarden.com/help/cli/) - command
  model, login/unlock distinction, sync behavior, and official CLI semantics.
- [Bitwarden CLI Authentication via API Key](https://bitwarden.com/help/personal-api-key/) -
  API key login behavior and machine-oriented authentication constraints.
- [Bitwarden CLI Authentication Challenges](https://bitwarden.com/help/cli-auth-challenges/) -
  challenge flow for command-line clients when bot protection is triggered.
- [Bitwarden Password Manager APIs](https://bitwarden.com/help/bitwarden-apis/) -
  official API entry point and scope boundaries.
- [Bitwarden Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/) -
  zero-knowledge model, local encryption, account keys, organization keys, and
  vault item encryption.
- [Bitwarden Encryption Protocols](https://bitwarden.com/help/what-encryption-is-used/) -
  encryption algorithms and protocol-level expectations.
- [Bitwarden Encryption Key Derivation](https://bitwarden.com/help/kdf-algorithms/) -
  PBKDF2 and Argon2id KDF behavior.
- [Bitwarden SSH Agent](https://bitwarden.com/help/ssh-agent/) - reference
  behavior for exposing vault SSH keys through an agent.

## WebAuthn, passkeys, and OTP

- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/) -
  PublicKeyCredential request/response shapes, authenticator data, assertion
  signatures, user consent expectations, and relying party scoping.
- [RFC 6238: TOTP](https://www.rfc-editor.org/rfc/rfc6238) - time-based OTP
  algorithm.
- [RFC 4226: HOTP](https://www.rfc-editor.org/rfc/rfc4226) - HMAC-based OTP
  algorithm used by TOTP.

## Security and engineering practice

- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) -
  cryptographic storage, key management, and avoiding custom algorithms.
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) -
  secret lifecycle, handling, and exposure controls.
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) -
  authentication hardening and logging guidance.
- [OWASP Application Security Verification Standard](https://owasp.org/www-project-application-security-verification-standard/) -
  verification checklist vocabulary for security-sensitive features.
- [GitHub Private Vulnerability Reporting](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/configuring-private-vulnerability-reporting-for-a-repository) -
  private reporting workflow for public repositories.
- [Cargo Book: Continuous Integration](https://doc.rust-lang.org/cargo/guide/continuous-integration.html) -
  Rust CI baseline.
- [Cargo Book: Profiles](https://doc.rust-lang.org/cargo/reference/profiles.html) -
  release profile, debug info, strip, overflow, and panic strategy settings.
- [RustSec Advisory Database](https://rustsec.org/) - Rust dependency advisory
  tracking.
- [Rust Clippy](https://github.com/rust-lang/rust-clippy) - Rust linting
  baseline.

## Reference policy

- Prefer official Bitwarden, W3C, IETF/RFC, OWASP, Rust, or RustSec sources.
- Blog posts, copied source, and community examples can inform investigation
  but cannot be the sole basis for an implementation decision.
- Any issue touching cryptography, authentication, local secrets, passkeys, or
  agent behavior must cite the specific references it relies on.
