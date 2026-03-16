# Security Remediation Backlog — federal-pki

Generated from red team assessment (2026-03-16).

---

## Completed

- [x] **Use HTTPS for FPKI trust store downloads** `SC-8`
  All `repo.fpki.gov` URLs changed from HTTP to HTTPS to prevent MITM
  injection of rogue CA certificates.

- [x] **Reject ZIP entries with path traversal sequences** `SI-10`
  ZIP filenames containing `..` or starting with `/` are now rejected
  before extraction.

- [x] **Enforce download size limits** `SC-5`
  Trust store downloads capped at 50 MB, CRL downloads at 10 MB to
  prevent memory exhaustion from a malicious repository.

- [x] **Fix TOCTOU race and harden CRL cache permissions** `AC-6`, `SC-28`
  Replaced exists()/stat()/read_bytes() sequence with atomic try/except.
  Cache directory created with mode 0o700, temp files with mode 0o600.

- [x] **Validate UUID format from certificate SAN** `SI-10`
  UUIDs extracted from `urn:uuid:` SAN URIs are now validated against
  the standard 8-4-4-4-12 hex format before returning.

---

## Medium Priority

- [x] **Use proper DN comparison instead of string matching** `IA-5(2)`
  `crl.py` now uses `Name.__eq__()` to compare CRL issuers to CA
  certificate subjects, handling attribute ordering and encoding
  differences correctly.

- [x] **Log exceptions from background CRL refresh thread** `AU-3`
  Background CRL refresh now wraps `refresh_crl()` in
  `_refresh_crl_background()` which logs at ERROR level and raises
  `CRLRefreshError`. Callers using custom thread pools can observe
  the failure.

- [x] **Guard against ReDoS in heuristic regex matching** `SI-10`
  `ProviderRegistry.register()` now validates regex patterns at
  registration time via `re.compile()`. Pattern complexity remains the
  caller's responsibility — see DEVELOPER_NOTES.md.

---

## Low Priority

- [ ] **Sanitize exception messages in CertificateError** `SI-11`
  `certificate.py` `load_certificate()` includes the raw exception string
  in `CertificateError`, which may leak cryptographic library internals.
  Use a generic message and log the full error:
  ```python
  raise CertificateError("Failed to parse certificate") from e
  ```

- [ ] **Use non-daemon thread for CRL refresh or handle cleanup** `SI-17`
  Daemon threads are killed on process exit, potentially leaving partial
  `.tmp` cache files. Either use a non-daemon thread with `atexit`
  cleanup, or add a startup routine that removes stale `.tmp` files.
