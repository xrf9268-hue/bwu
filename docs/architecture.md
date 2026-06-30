# Architecture

## Mental model

`bwu` is a local-first Bitwarden/Vaultwarden client. The server stores and
syncs encrypted vault data; the local client performs key derivation,
decryption, item encryption, passkey export, and WebAuthn signing.

The project uses a new command model and a new `bwu` on-disk namespace. It is
not an `rbw` compatibility layer.

## Components

- `bwu` CLI: command parsing, user prompts, local config, one-shot unlock flow,
  item operations, passkey export, and WebAuthn signing.
- `bwu-agent`: optional Unix socket process that stores unlocked keys in memory
  for a bounded timeout and serves decrypt/sign requests.
- API client: Bitwarden/Vaultwarden HTTP client for login, token refresh, sync,
  and item write operations.
- Crypto core: KDF, Bitwarden encrypted string handling, account key handling,
  organization key handling, item key handling, TOTP, and WebAuthn signatures.
- Local store: encrypted cache, account metadata, endpoint configuration, and
  runtime socket paths under a `bwu` namespace.
- Test fixtures: synthetic encrypted vault data and synthetic passkeys only.

## Data flow

1. Login obtains server tokens and encrypted key material using an official
   Bitwarden-compatible flow.
2. Sync stores encrypted vault data locally without decrypting all item values.
3. Unlock derives local keys from the user's secret and protected key material.
4. Ordinary item commands decrypt only the selected fields needed for output.
5. Passkey export requires an explicit `passkey export` command.
6. Passkey signing builds WebAuthn assertion output from request JSON, matched
   credential data, authenticator data, client data JSON, and the private key.

## Boundaries

- No browser extension, native messaging host, or localhost HTTP API in v1.
- Agent IPC is local Unix socket only.
- The agent is optional; the CLI must support one-shot commands without a
  running agent.
- Windows support is deferred until the Unix socket and key-storage model has a
  separate Windows design.

## Compatibility policy

`bwu` follows Bitwarden/Vaultwarden vault semantics, not `rbw` command syntax.
Any compatibility shim must be a separate documented milestone and must not
change the default config/cache/runtime namespace.
