# Security Policy

For the full incident response process, severity classification, response
timelines, and disclosure policy, see
[oss.mevtc.com/security](https://oss.mevtc.com/security).

## Reporting a Vulnerability

**Do not open a public GitHub issue.** Email **info.security@mevtc.com**.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.3.x   | Yes       |

## Security Testing

This project uses [Hypothesis](https://hypothesis.readthedocs.io/) for
property-based fuzz testing. Fuzz tests run in CI on every push and merge
request, with higher iteration counts on nightly schedules.

Fuzz test coverage includes CN parsers (CAC dot-format, PIV flexible, ECA
human-readable) with arbitrary unicode input, federal provider OID matching
with random OID sets, heuristic matching with arbitrary strings, and identity
extraction postconditions for all credential types.

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
