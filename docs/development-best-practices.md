# Development Best Practices

## Work style

- Implement through milestone issues, one reviewable slice at a time.
- Write failing tests before production code for behavior changes.
- Keep cryptographic and protocol code small, reviewed, and isolated.
- Do not copy source from `rbw` or `bitwarden-use`; use official docs and
  clean-room behavior tests.
- Prefer narrow public interfaces over shared mutable state.

## Rust baseline

- Minimum Rust version: 1.95 unless an ADR changes it.
- CI must run formatting, clippy, tests, docs, and dependency advisory checks
  before feature work is considered merge-ready.
- `unsafe` is forbidden by default. Any proposed `unsafe` requires a dedicated
  ADR, tests, and a security review.
- Use typed wrappers for secrets so redaction and zeroization are hard to skip.
- Keep release profiles explicit before shipping binaries.

## Testing baseline

- Unit tests for KDF, encrypted string parsing, key derivation, TOTP, base64url,
  WebAuthn data construction, and redaction.
- CLI tests must run with temporary config/cache/runtime directories.
- API tests must use mock servers or fixtures; no CI test may require a real
  Bitwarden account.
- Passkey tests must use synthetic keys and verify signatures using public keys.
- Regression tests must prove ordinary commands do not print private keys.

## Documentation baseline

- Every milestone issue must link to the official references it depends on.
- Every public command must have documented input, output, failure modes, and
  examples before implementation is considered complete.
- ADRs are required for auth flow, crypto design, local storage, agent IPC,
  passkey signing, and release/distribution.
- Issues for implementation milestones must list their prerequisite issues with
  `Blocked by #...` lines when earlier design, ADR, or security-control work is
  required.

## Pull request baseline

Each implementation PR must include:

- The milestone issue it implements.
- A short threat-model note when the change touches secrets, auth, crypto,
  passkeys, local storage, or agent behavior.
- Test evidence.
- A statement that no live secrets or real vault data were added.

## Public repository and license posture

- The repository is public for design transparency and issue tracking.
- No open-source license has been granted yet; do not add a license without a
  dedicated ADR.
- Public issues, comments, commits, logs, and CI artifacts must never contain
  live credentials, real vault exports, production tokens, or real passkeys.
- GitHub secret scanning, push protection, Dependabot security updates, and
  private vulnerability reporting must stay enabled where GitHub supports them.

Current repository security-control evidence, verified with owner/admin
permission on 2026-06-30:

```json
{
  "dependabot_security_updates": { "status": "enabled" },
  "secret_scanning": { "status": "enabled" },
  "secret_scanning_non_provider_patterns": { "status": "disabled" },
  "secret_scanning_push_protection": { "status": "enabled" },
  "secret_scanning_validity_checks": { "status": "disabled" }
}
```

`gh api repos/xrf9268-hue/bwu/private-vulnerability-reporting --method GET`
returned `{"enabled":true}`.

The two disabled advanced secret scanning controls were also submitted through
the repository update API:

```text
gh api repos/xrf9268-hue/bwu --method PATCH \
  -F 'security_and_analysis[secret_scanning_non_provider_patterns][status]=enabled' \
  -F 'security_and_analysis[secret_scanning_validity_checks][status]=enabled' \
  --jq .security_and_analysis
```

GitHub accepted the request but returned both fields as `disabled`. Treat
`secret_scanning_non_provider_patterns` and
`secret_scanning_validity_checks` as unavailable for this user-owned public
repository unless a future account, plan, or repository setting makes the API
return `enabled`.

## Repository protection

Active protection for `main`, verified through repository ruleset
`Protect main with governance checks` on 2026-07-01:

- Applies to the default branch only.
- Enforcement is active.
- Blocks branch deletion and non-fast-forward updates.
- Requires pull requests before merge.
- Does not require an approving review while the repository has only a small
  maintainer/collaborator pool; manual review remains expected by process.
- Requires all review threads to be resolved.
- Requires the `Docs baseline` status check with strict up-to-date policy.
- Has no bypass actors, and the current admin user cannot bypass the ruleset.

The required `Docs baseline` check is provided by the Governance workflow.
