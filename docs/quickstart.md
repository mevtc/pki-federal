# Getting Started

## Parse identity from a Federal PKI certificate

The simplest use case: extract identity information from a CAC or PIV
certificate.

```python
from pki.core.certificate import load_certificate
from pki.federal.identity import parse_identity

cert = load_certificate(pem_bytes)
identity = parse_identity(cert)

print(identity.credential_type)  # "CAC" or "PIV"
print(identity.primary_id)       # "edipi:1234567890" or "uuid:..."
print(identity.firstname, identity.lastname)
```

`parse_identity` uses the default CAC + PIV provider registry. It matches
the certificate's policy OIDs against the registered providers, then
extracts identity fields using the matching provider's CN parser.

## Using providers directly

Providers define the OID matching, CN parsing, and trust store sources for
a credential type. You can use the built-in providers or register custom ones.

```python
from pki.core.providers import ProviderRegistry
from pki.federal import CAC_PROVIDER, PIV_PROVIDER, ECA_PROVIDER

# Default registry (CAC + PIV)
from pki.federal import default_registry
registry = default_registry()

# Full registry (CAC + PIV + ECA)
from pki.federal import full_registry
registry = full_registry()

# Custom registry
registry = ProviderRegistry()
registry.register(CAC_PROVIDER)
registry.register(PIV_PROVIDER)
registry.register(ECA_PROVIDER)
```

## Building a trust store

Download and merge CA bundles from DISA and the Federal PKI into a single
PEM file for chain validation.

```python
from pki.federal.trust_store import build_ca_bundle

pem_bundle, stats = build_ca_bundle(output_path="/etc/ssl/dod-fpki-bundle.pem")
print(f"Loaded {stats['total']} certificates, {stats['unique']} unique")
```

## Algorithm policy

`SP800_78_ALGORITHM_POLICY` enforces NIST SP 800-78-5 approved algorithms:
RSA 2048+, ECDSA P-256/P-384, and SHA-256 or stronger hashes.

```python
from pki.federal import SP800_78_ALGORITHM_POLICY

# Use in a CertificatePolicy for validation
from pki.core.validation import CertificatePolicy

policy = CertificatePolicy(
    algorithm_policy=SP800_78_ALGORITHM_POLICY,
)
```

For stricter deployments, create a custom `AlgorithmPolicy`:

```python
from pki.core.algorithms import AlgorithmPolicy

ecc_only = AlgorithmPolicy(
    min_rsa_bits=0,
    allowed_curves=frozenset({"secp384r1"}),
    allowed_hashes=frozenset({"sha384", "sha512"}),
)
```

## Full FIPS 201-3 validation pipeline

A production configuration implementing PKI-AUTH (FIPS 201-3) with chain
validation, SP 800-78 algorithm enforcement, and CRL + OCSP revocation
checking.

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
    check_chain=True,
    trust_store=ca_certs,
    algorithm_policy=SP800_78_ALGORITHM_POLICY,
    registry=default_registry(),
    revocation=RevocationPolicy(
        checks=(CRL, OCSP),
        issuer_certs=ca_certs,
        crl_config=CRLConfig(cache_dir="/var/cache/pki/crls"),
    ),
)

result = validate_certificate(cert, policy)

if result.status == ValidationStatus.VALID:
    identity = result.identity
    print(f"Authenticated: {identity.credential_type} -- {identity.primary_id}")
    print(f"Name: {identity.firstname} {identity.lastname}")
else:
    print(f"Rejected: {result.status} -- {result.error}")
```

## CRL configuration

The federal `CRLConfig` provides sensible defaults for DoD/FPKI environments:
strict mode, 20 MB max CRL size (DoD CRLs are large), and 18-hour max age
per FIPS 201-3.

```python
from pki.federal.crl import CRLConfig

config = CRLConfig(cache_dir="/var/cache/pki/crls")
```
