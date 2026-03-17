# pki-federal

DoD CAC, Federal PIV, and ECA provider pack for [pki-core](https://github.com/mevtc/pki-core).

## What's included

- **Providers** — `CAC_PROVIDER`, `PIV_PROVIDER`, `ECA_PROVIDER` with OID matching, CN parsers, and trust store sources
- **OID registries** — DoD authentication, FPKI PIV authentication, and ECA policy OIDs
- **CN parsers** — CAC dot-format, PIV flexible, and ECA human-readable name parsing
- **Trust store fetchers** — download and parse CA bundles from DISA and repo.fpki.gov
- **Federal CRLConfig** — `CRLConfig` subclass with federal default cache directory
- **Federal parse_identity** — defaults to the CAC + PIV registry

Generic PKI utilities (certificate loading, CRL checking, validation) are imported from [pki.core](https://github.com/mevtc/pki-core).

## Installation

```bash
pip install pki-federal
```

This installs `pki-core` as a dependency.

## Usage

```python
from pki.core.certificate import load_certificate
from pki.core.crl import check_revocation
from pki.federal.identity import parse_identity
from pki.federal.crl import CRLConfig

cert = load_certificate(pem_bytes)
identity = parse_identity(cert)

print(identity.credential_type)  # "CAC" or "PIV"
print(identity.primary_id)       # "edipi:1234567890" or "uuid:..."

config = CRLConfig()
check_revocation(cert, config)
```

### Build a CA trust bundle

```python
from pki.federal.trust_store import build_ca_bundle

pem_bundle, stats = build_ca_bundle(output_path="/etc/ssl/dod-fpki-bundle.pem")
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

## License

BSD-3-Clause — see [LICENSE](LICENSE).
