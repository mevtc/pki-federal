# pki-federal

DoD CAC, Federal PIV, and ECA provider pack for [pki-core](https://github.com/mevtc/pki-core).

## What's included

- **Providers** — `CAC_PROVIDER`, `PIV_PROVIDER`, `ECA_PROVIDER` with OID matching, CN parsers, and trust store sources
- **OID registries** — DoD authentication, FPKI PIV authentication, and ECA policy OIDs
- **CN parsers** — CAC dot-format, PIV flexible, and ECA human-readable name parsing
- **Trust store fetchers** — download and parse CA bundles from DISA and repo.fpki.gov
- **Algorithm policy** — `SP800_78_ALGORITHM_POLICY` with NIST SP 800-78-5 approved algorithms
- **Federal CRLConfig** — `CRLConfig` subclass with federal default cache directory
- **Federal parse_identity** — defaults to the CAC + PIV registry

Generic PKI utilities (certificate loading, chain validation, revocation checking, algorithm enforcement) are imported from [pki.core](https://github.com/mevtc/pki-core).

## Installation

```bash
pip install pki-federal
```

This installs `pki-core` as a dependency.

## Examples

### Minimal — parse identity from a Federal PKI certificate

```python
from pki.core.certificate import load_certificate
from pki.federal.identity import parse_identity

cert = load_certificate(pem_bytes)
identity = parse_identity(cert)

print(identity.credential_type)  # "CAC" or "PIV"
print(identity.primary_id)       # "edipi:1234567890" or "uuid:..."
print(identity.firstname, identity.lastname)
```

### Full — FIPS 201-3 compliant validation pipeline

A production configuration implementing PKI-AUTH (FIPS 201-3 §6.2.3.1)
with chain validation, SP 800-78 algorithm enforcement, and CRL + OCSP
revocation checking.

```python
from pki.core.certificate import load_certificate
from pki.core.crl import load_ca_certs_from_pem
from pki.core.revocation import CRL, OCSP, RevocationPolicy
from pki.core.validation import CertificatePolicy, ValidationStatus, validate_certificate
from pki.federal import SP800_78_ALGORITHM_POLICY, default_registry
from pki.federal.crl import CRLConfig
from pki.federal.trust_store import build_ca_bundle

# Build or load the Federal PKI CA bundle
pem_bundle, stats = build_ca_bundle(output_path="/etc/pki/dod-fpki-bundle.pem")
ca_certs = load_ca_certs_from_pem(pem_bundle)

# Load the client certificate (e.g., from mTLS header)
cert = load_certificate(pem_bytes)

# Configure the full validation pipeline
policy = CertificatePolicy(
    # Chain validation against Federal PKI trust anchors
    check_chain=True,
    trust_store=ca_certs,

    # SP 800-78 algorithm enforcement (RSA 2048+, P-256/P-384, SHA-256+)
    algorithm_policy=SP800_78_ALGORITHM_POLICY,

    # Federal PKI identity extraction (CAC + PIV)
    registry=default_registry(),

    # Revocation — CRL first, OCSP fallback, federal defaults
    # (strict=True, 20 MB max CRL, 18-hour max age per FIPS 201-3)
    revocation=RevocationPolicy(
        checks=(CRL, OCSP),
        issuer_certs=ca_certs,
        crl_config=CRLConfig(cache_dir="/var/cache/pki/crls"),
    ),
)

result = validate_certificate(cert, policy)

if result.status == ValidationStatus.VALID:
    identity = result.identity
    print(f"Authenticated: {identity.credential_type} — {identity.primary_id}")
    print(f"Name: {identity.firstname} {identity.lastname}")
    print(f"Chain length: {len(result.chain)}")
else:
    print(f"Rejected: {result.status} — {result.error}")
    if result.identity:
        print(f"Certificate CN: {result.identity.cn}")
```

### Build a CA trust bundle

```python
from pki.federal.trust_store import build_ca_bundle

pem_bundle, stats = build_ca_bundle(output_path="/etc/ssl/dod-fpki-bundle.pem")
print(f"Loaded {stats['total']} certificates, {stats['unique']} unique")
```

### Use with custom providers

See the [pki-core README](https://github.com/mevtc/pki-core) for how to combine federal providers with custom provider packs.

```python
from pki.core.providers import ProviderRegistry
from pki.federal import CAC_PROVIDER, PIV_PROVIDER

registry = ProviderRegistry()
registry.register(CAC_PROVIDER)
registry.register(PIV_PROVIDER)
registry.register(my_custom_provider)
```

### Stricter algorithm policy

`SP800_78_ALGORITHM_POLICY` matches SP 800-78-5 requirements. Override
for stricter deployments:

```python
from pki.core.algorithms import AlgorithmPolicy

# ECC P-384 only, no RSA, SHA-384+ only
ecc_only = AlgorithmPolicy(
    min_rsa_bits=0,
    allowed_curves=frozenset({"secp384r1"}),
    allowed_hashes=frozenset({"sha384", "sha512"}),
)
```

## Security

### FIPS 140 cryptographic module status

pki-federal does not implement cryptographic primitives. All cryptographic
operations are delegated to [pki-core](https://github.com/mevtc/pki-core),
which uses the [cryptography](https://cryptography.io/) library (OpenSSL
backend).

**pki-federal is not FIPS 140 validated.** FIPS 140 validation applies to
the underlying OpenSSL cryptographic module, not to application libraries.
To deploy in a FIPS 140 compliant environment, use an OpenSSL build with a
FIPS 140 validation certificate and ensure the FIPS provider is active.

`SP800_78_ALGORITHM_POLICY` enforces SP 800-78-5 approved algorithms at
the application level. The federal `CRLConfig` enforces an 18-hour maximum
CRL age per FIPS 201-3 §2.9.1. These are application-layer controls that
complement (but do not replace) FIPS 140 module validation.

### NIST SP 800-53 controls

See pki-core's [SP800-53-CONTROLS.md](https://github.com/mevtc/pki-core/blob/main/SP800-53-CONTROLS.md)
for the full controls mapping across the pki ecosystem.

pki-federal directly implements:

- **IA-2(12)** — PIV credential acceptance (policy OID matching, CN parsing, identity extraction)
- **IA-8 / IA-8(1)** — non-organizational user authentication (ECA provider), cross-agency PIV acceptance (FPKI trust store sources)
- **SC-13** — `SP800_78_ALGORITHM_POLICY` enforces SP 800-78 approved algorithms
- **SC-17** — policy OID registries for DoD, FPKI, and ECA certificate policies

**Handled by pki-core** (inherited dependency): chain validation, CRL/OCSP
revocation, trust store management, input validation.

**Must be handled higher in the stack** (by the deploying application):

- **IA-2** — user account mapping (e.g., smartcard-auth maps primary_id to LLDAP)
- **SC-23** — session management
- **AU-2 / AU-3** — audit logging
- TLS termination and challenge-response (nginx/ALB)

### SBOM

CycloneDX SBOMs are generated in CI on every pipeline run.

### Security testing and static analysis

See [SECURITY.md](SECURITY.md) for vulnerability reporting, fuzz testing
coverage, and static analysis suppressions.

## License

BSD-3-Clause — see [LICENSE](LICENSE).
