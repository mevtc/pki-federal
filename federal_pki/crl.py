"""Backward-compatible CRL re-exports from pki-core."""

from dataclasses import dataclass

from pki_core.crl import MAX_CRL_BYTES as MAX_CRL_BYTES
from pki_core.crl import CRLConfig as _BaseCRLConfig
from pki_core.crl import CRLRefreshError as CRLRefreshError
from pki_core.crl import check_revocation as check_revocation
from pki_core.crl import get_crl as get_crl
from pki_core.crl import get_crl_distribution_points as get_crl_distribution_points
from pki_core.crl import get_crl_max_age as get_crl_max_age
from pki_core.crl import load_ca_certs_from_pem as load_ca_certs_from_pem
from pki_core.crl import parse_crl_bytes as parse_crl_bytes
from pki_core.crl import prefetch_crls as prefetch_crls
from pki_core.crl import refresh_crl as refresh_crl
from pki_core.crl import verify_crl as verify_crl


@dataclass
class CRLConfig(_BaseCRLConfig):
    """CRLConfig with federal-pki default cache directory."""

    app_name: str = "federal-pki"
