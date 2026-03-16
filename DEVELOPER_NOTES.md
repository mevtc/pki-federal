# Developer Notes — federal-pki

Implementation notes for developers building applications on top of this library.

## Custom Providers and Regex Patterns

When registering custom providers via `ProviderRegistry.register()`, heuristic
rules with `is_regex=True` are validated at registration time (syntax check via
`re.compile()`). However, **pattern complexity is the caller's responsibility**.

Regex patterns are executed against certificate CN, Org, and OU fields during
`match_heuristic()`. Patterns with catastrophic backtracking (e.g., `(a+)+b`)
will block the calling thread. If your patterns come from configuration files
or external input:

- Use simple anchored patterns: `^EXACT_MATCH$` or `^PREFIX`
- Avoid nested quantifiers: `(a+)+`, `(a|b)*c*`
- Prefer `is_regex=False` (substring match) when possible
- Consider validating patterns with a regex complexity tool before registration

The built-in CAC, PIV, and ECA providers use simple, linear-time patterns.

## CRL Caching and Background Refresh

The stale-while-revalidate strategy in `crl.py` spawns a daemon thread to
refresh expired CRLs in the background while serving the stale cached copy.

Key behavior:

- **First request for a CRL**: blocking fetch (no cache to serve)
- **Subsequent requests with valid cache**: served from cache, no network call
- **Expired cache**: stale cache served immediately, background thread refreshes
- **Background refresh failure**: raises `CRLRefreshError` — callers should
  handle this or configure logging to capture it

If your application has strict revocation requirements, set `strict=True` in
`CRLConfig`. In strict mode, a CRL that cannot be fetched or verified raises
`CertificateError` rather than silently falling back.

Daemon threads are killed on process exit, which may leave `.tmp` files in the
cache directory. Long-running services should periodically clean stale `.tmp`
files, or use `atexit` handlers.

## DN Comparison

CRL issuer matching uses `Name.__eq__()` from the cryptography library, which
compares the parsed RDN sequence. This is more reliable than string comparison
and handles attribute ordering differences correctly.

## Trust Store Downloads

All trust store downloads enforce:

- **HTTPS only** — no HTTP fallback
- **50 MB size limit** for trust store bundles
- **10 MB size limit** for individual CRLs
- **Explicit timeouts** (60s for trust stores, 10s for CRLs)

If your environment requires a proxy, configure it via `HTTPS_PROXY` or
`ALL_PROXY` environment variables (respected by httpx).

## Certificate Identity Parsing

`parse_identity()` returns a `CertIdentity` dataclass. The `credential_type`
field is determined by:

1. **OID matching** (most reliable): policy OIDs in the certificate are matched
   against the provider registry
2. **Heuristic matching** (fallback): CN, Org, OU fields matched against
   provider heuristic rules

If neither matches, `credential_type` is `"UNKNOWN"` and `primary_id` falls
back to `dn:<subject DN>`. Applications should handle the UNKNOWN case — it
does not indicate an error, just that the certificate doesn't match any
registered provider.

## FIPS Considerations

This library uses the Python `cryptography` package for certificate parsing,
CRL verification, and fingerprinting. The `cryptography` package from PyPI is
**not** FIPS-validated.

If your deployment requires FIPS-validated cryptographic modules (NIST 800-171
control 3.13.11), you must either:

- Use a system-provided `cryptography` package linked against a FIPS-validated
  OpenSSL (e.g., from RHEL or FreeBSD ports)
- Delegate cryptographic operations to a FIPS-validated OpenSSL binary via
  subprocess (this is what fpki-verify-milter does for S/MIME verification)

The library's certificate parsing and CRL signature verification are
informational operations — the trust decision should ultimately be made by a
FIPS-validated module in production.

## Error Handling

All library errors are subclasses of `CertificateError`. Catch this at the
boundary of your application:

```python
from federal_pki.certificate import CertificateError

try:
    identity = parse_identity(cert)
    check_revocation(cert, crl_config)
except CertificateError as e:
    # Handle: revoked, expired, unparseable, CRL fetch failure, etc.
    logger.error("Certificate validation failed: %s", e)
```

Exception messages may contain certificate field values (CN, serial, issuer DN).
If you log these, ensure your logging pipeline handles PII appropriately.
