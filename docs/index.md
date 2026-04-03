# pki-federal

DoD CAC, Federal PIV, and ECA provider pack for [pki-core](https://github.com/mevtc/pki-core).

## Overview

pki-federal provides the federal-specific layer for PKI certificate validation
and identity extraction. It implements DoD and Federal PKI policy for CAC, PIV,
and ECA credentials on top of the generic utilities in pki-core.

## Features

- **Providers** -- `CAC_PROVIDER`, `PIV_PROVIDER`, `ECA_PROVIDER` with OID matching, CN parsers, and trust store sources
- **OID registries** -- DoD authentication, FPKI PIV authentication, and ECA policy OIDs
- **CN parsers** -- CAC dot-format, PIV flexible, and ECA human-readable name parsing
- **Trust store fetchers** -- download and parse CA bundles from DISA and repo.fpki.gov
- **Algorithm policy** -- `SP800_78_ALGORITHM_POLICY` with NIST SP 800-78-5 approved algorithms
- **Federal CRLConfig** -- `CRLConfig` subclass with federal default cache directory
- **Federal parse_identity** -- defaults to the CAC + PIV registry

## Installation

```bash
pip install pki-federal
```

This installs `pki-core` as a dependency. Generic PKI utilities (certificate
loading, chain validation, revocation checking, algorithm enforcement) are
provided by [pki-core](https://github.com/mevtc/pki-core).

## Relationship to pki-core

pki-federal is a **provider pack** that plugs into pki-core's provider
framework. pki-core provides the generic PKI engine: certificate loading,
chain validation, revocation checking, and algorithm enforcement. pki-federal
adds the federal-specific policy: DoD/FPKI OID registries, CN parsers for
CAC/PIV/ECA name formats, trust store fetchers for DISA and FPKI CA bundles,
and the SP 800-78-5 algorithm policy.

```
pki-core          (generic PKI engine)
  |
  +-- pki-federal (DoD/FPKI/ECA providers, OIDs, trust stores)
        |
        +-- smartcard-auth (application-layer: mTLS, LDAP mapping)
```

## License

BSD-3-Clause -- see [LICENSE](https://github.com/mevtc/pki-federal/blob/main/LICENSE).
