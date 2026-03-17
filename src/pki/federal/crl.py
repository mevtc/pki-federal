"""Federal CRL configuration with default cache directory."""

from dataclasses import dataclass

from pki.core.crl import CRLConfig as _BaseCRLConfig


@dataclass
class CRLConfig(_BaseCRLConfig):
    """CRLConfig with pki-federal default cache directory."""

    app_name: str = "pki-federal"
