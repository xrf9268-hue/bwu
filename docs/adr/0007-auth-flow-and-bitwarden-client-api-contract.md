# ADR 0007: Auth flow and Bitwarden client API contract

## Status

Accepted.

## Milestone issue

Refs #15.

## Official references

- [Bitwarden Password Manager CLI](https://bitwarden.com/help/cli/)
- [Bitwarden CLI Authentication via API Key](https://bitwarden.com/help/personal-api-key/)
- [Bitwarden CLI Authentication Challenges](https://bitwarden.com/help/cli-auth-challenges/)
- [Bitwarden Password Manager APIs](https://bitwarden.com/help/bitwarden-apis/)
- [Bitwarden authentication architecture](https://contributing.bitwarden.com/architecture/deep-dives/authentication/)
- [Bitwarden clients repository](https://github.com/bitwarden/clients)
- [Bitwarden server repository](https://github.com/bitwarden/server)

References were verified on 2026-06-30 before accepting this ADR.

## Context

M2 will add login, API key authentication, token refresh, endpoint selection,
and encrypted sync cache behavior. Public Bitwarden documentation describes
official CLI semantics and API boundaries, but not every wire shape needed for
a compatible clean-room client. The project needs a source-of-truth policy
before any endpoint implementation starts.

## Decision

Use this source-of-truth order for Bitwarden-compatible auth and sync behavior:

1. Public Bitwarden help and contributing documentation.
2. Official Bitwarden API documentation.
3. Official Bitwarden `clients` and `server` repositories for behavior
   investigation only.
4. Maintainer-reviewed mock-server fixtures derived from the sources above.

Do not guess, scrape, or reverse-engineer wire shapes from unofficial clients.
Do not copy source from official Bitwarden repositories. Source investigation
must produce local notes, tests, or fixture descriptions in this repository,
not copied implementation code.

The following categories are sufficiently documented for product policy and
user-facing behavior:

- CLI login, unlock, lock, sync, and session distinctions.
- API key login as a machine-oriented authentication option.
- Auth challenge behavior when command-line clients encounter bot protection.
- Public API boundary expectations and the existence of official cloud,
  EU cloud, and self-hosted endpoints.

The following categories require source-of-truth investigation and maintainer
review before implementation:

- Prelogin request and response fields.
- Identity token exchange fields for password login and supported two-step
  login paths.
- API key token exchange fields.
- Refresh token request, response, retry, and failure behavior.
- Sync envelope request parameters, response shape, revision handling, and
  self-hosted compatibility details.

M2 implementation may support only the two-step login methods explicitly
accepted by its milestone issue. Unsupported two-step methods must fail closed
with a redacted message that does not print credentials, tokens, device
identifiers, or challenge material.

Fixtures for auth, refresh, and sync tests must use mock servers and synthetic
accounts. CI must not require a live Bitwarden account, a production API key, a
real refresh token, or captured production traffic.

## Consequences

- Issues #4 and #5 must cite this ADR before implementation starts.
- A PR that adds an undocumented endpoint field must cite the official source
  and include maintainer-reviewed fixture evidence.
- Wire-shape uncertainty blocks implementation until resolved in an issue,
  ADR amendment, or maintainer review note.
