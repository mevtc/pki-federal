# Security Policy

For the full incident response process, severity classification, response
timelines, and disclosure policy, see
[oss.mevtc.com/security](https://oss.mevtc.com/security).

## Reporting a Vulnerability

**Do not open a public GitHub issue.** Email **info.security@mevtc.com**.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.6.x   | Yes       |
| 0.5.x   | No        |
| 0.4.x   | No        |
| 0.3.x   | No        |

0.4.2 was the previous release on PyPI — upgrade to 0.6.x to remain on a
supported version. 0.6.x requires `pki-core>=0.6.0`.

## Security Testing

This project uses [Hypothesis](https://hypothesis.readthedocs.io/) for
property-based fuzz testing. Fuzz tests run in CI on every push and merge
request, with higher iteration counts on nightly schedules.

Fuzz test coverage includes CN parsers (CAC dot-format, PIV flexible, ECA
human-readable) with arbitrary unicode input, federal provider OID matching
with random OID sets, heuristic matching with arbitrary strings, and identity
extraction postconditions for all credential types.

## Security Boundaries

This section is for consumers of pki-federal. It states plainly what this
library does and does not guarantee, so integrators don't assume coverage
that isn't there. See `SECURITY_TODO.md` (High Priority section) and
`docs/adr/0001-fpki-trust-anchor-and-policy-scope.md` for the full analysis.

- **Policy-OID enforcement is not automatic.** `AuthProvider` definitions in
  `providers.py` declare `auth_oids` (e.g. `id-fpki-common-authentication`
  for PIV), but nothing in pki-federal or the pki-core validation pipeline
  it calls into will *reject* a certificate whose policy OID doesn't match.
  When no policy OID matches, identity extraction silently falls back to
  CN/organization heuristics and still returns a usable identity. If your
  credential type requires FIPS 201-3 §6.2.3.1 PKI-AUTH assurance (or
  equivalent DoD assurance), **you must independently check the returned
  identity's `policy_oids` against the provider's `auth_oids` yourself**
  before treating the identity as trustworthy for that purpose.

- **The trust-anchor bundle does not distinguish roots from bridge
  cross-certificates.** `build_ca_bundle()` merges true root CAs (e.g. the
  Federal Common Policy CA) with Federal Bridge cross-certificates (certs
  issued to/by `fbcag4`) into one flat PEM bundle, with no separate
  `intermediates` list. The Federal Bridge trust model relies on
  cross-certificates being constrained intermediates, not unconstrained
  roots; as built today, name and policy constraints intended by that
  model are not enforced.

- **RFC 5280 policy mapping, policy constraints, and inhibitAnyPolicy are
  not processed at all.** This is a dependency limitation, not a pki-federal
  or pki-core bug: the underlying `cryptography` library's path validator
  does not implement the RFC 5280 §6.1.1 policy-processing inputs. Do not
  assume policy constraints expressed in the certificate chain are being
  honored.

If your deployment treats pki-federal-validated certificates as PIV or CAC
assured for access control decisions, review the ADR above before relying
on this library in a high-assurance context.

## Static Analysis Suppressions

The following static analysis checks are suppressed project-wide. Each
suppression is documented here with its justification.

### Bandit

Configured in `pyproject.toml` under `[tool.bandit]`.

| Rule | Description | Justification |
|------|-------------|---------------|
| B101 | `assert` used outside tests | Asserts are used only in test code. Bandit scans `src/` only (`exclude_dirs = ["tests"]`), but the suppression avoids false positives from shared fixtures. |
| B110 | `try`/`except`/`pass` (bare exception handling) | Inherited from pki-core defaults. Not currently triggered in pki-federal source. |

### Ruff

Configured in `pyproject.toml` under `[tool.ruff.lint]`.

| Rule | Description | Justification |
|------|-------------|---------------|
| E501 | Line too long | Line length is enforced by `ruff format`, not the linter. Suppressing the lint rule avoids conflicts between the formatter and linter. |
