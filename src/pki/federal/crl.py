"""Federal CRL configuration with FIPS 201-3 compliant defaults.

Provides sensible defaults for DoD and Federal PKI environments:

- ``strict=True`` — always verify CRL signatures.
- ``max_crl_bytes=20 MB`` — DoD CRLs can be significantly larger than
  typical enterprise CRLs.
- ``max_acceptable_age=64800`` (18 hours) — FIPS 201-3 Section 2.9.1
  requires that revocation procedures for lost, stolen, or compromised
  cards be completed within 18 hours of notification.  A CRL older than
  this is too stale to trust even as a fallback.
"""

from dataclasses import dataclass

from pki.core.crl import CRLConfig as _BaseCRLConfig


@dataclass
class CRLConfig(_BaseCRLConfig):
    """CRLConfig with Federal PKI defaults.

    Overrides:
        app_name: ``pki-federal`` (cache at ``~/.cache/pki-federal/crls``).
        strict: ``True`` — CRL signature verification required.
        max_crl_bytes: 20 MB — accommodates large DoD CRLs.
        max_acceptable_age: 64800 seconds (18 hours) — per FIPS 201-3
            Section 2.9.1 revocation timeliness requirement.
    """

    app_name: str = "pki-federal"
    strict: bool = True
    max_crl_bytes: int = 20 * 1024 * 1024  # 20 MB
    max_acceptable_age: int = 64800  # 18 hours
