# Security Policy

This is a private repository for a security-sensitive command-line client.

## Supported versions

No released versions exist yet. Security work currently targets the `main`
branch only.

## Reporting

Open a private GitHub issue in this repository for design or implementation
security concerns. Do not include real vault exports, master passwords, access
tokens, refresh tokens, passkey private keys, or production account data in
issues, commits, logs, or screenshots.

## Secret handling rules

- Never commit real Bitwarden credentials, vault exports, tokens, or passkeys.
- Tests must use synthetic fixtures generated specifically for tests.
- Logs must not contain decrypted item values, private key material, master
  passwords, access tokens, refresh tokens, or API key client secrets.
- Commands that intentionally export private key material must be explicit,
  narrowly named, and covered by regression tests proving ordinary commands do
  not emit the same material.
