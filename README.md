# federal-pki

Python utilities for working with DoD CAC and Federal PKI certificates.

## Features

- **Certificate parsing** — load PEM/DER x509 certificates, extract policy OIDs, emails, SAN URIs/UUIDs, FASC-N, and fingerprints
- **Identity extraction** — parse CAC (EDIPI-based) and PIV (UUID/FASC-N-based) identities from client certificates
- **CRL checking** — revocation checking with stale-while-revalidate file-backed cache and background refresh
- **Trust store management** — download, merge, and deduplicate DoD (DISA) and Federal PKI CA bundles into a single PEM bundle
- **OID registries** — known policy OIDs for DoD authentication, PIV authentication, and email signing certificates

## Architecture

federal-pki is a thin federal-specific layer built on [pki-core](https://github.com/mevtc/pki-core), which provides the generic X.509 infrastructure (certificate parsing, CRL caching, identity extraction, validation pipeline). If you're working with non-federal PKI, use pki-core directly.

All `from federal_pki.*` imports continue to work — federal-pki re-exports the full pki-core API alongside its own DoD CAC, Federal PIV, and ECA provider definitions.

## Installation

```bash
pip install federal-pki
```

## Quick start

```python
from federal_pki.certificate import load_certificate, is_expired
from federal_pki.identity import parse_identity
from federal_pki.crl import CRLConfig, check_revocation

# Load and inspect a certificate
cert = load_certificate(pem_bytes)
identity = parse_identity(cert)

print(identity.credential_type)  # "CAC" or "PIV"
print(identity.primary_id)       # "edipi:1234567890" or "uuid:..."

# Check revocation (CRL cache defaults to platform cache dir)
config = CRLConfig()
check_revocation(cert, config)

# Or override the cache location
config = CRLConfig(cache_dir="/var/cache/my-app/crls", cache_ttl=7200)
```

### Build a CA trust bundle

```python
from federal_pki.trust_store import build_ca_bundle

pem_bundle, stats = build_ca_bundle(output_path="/etc/ssl/dod-fpki-bundle.pem")
print(stats)  # {"DoD": 38, "FPKI": 12, "total": 50}
```

## License

BSD-3-Clause — see [LICENSE](LICENSE).