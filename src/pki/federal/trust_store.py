"""DoD and Federal PKI CA trust store management.

Thin facade over pki-core's trust store utilities, scoped to Federal PKI
providers.  Delegates all certificate fetching, parsing, and deduplication
to ``pki.core.trust_store``.

Controls: SC-12 (Cryptographic Key Management), IA-5(2) (PKI-Based Auth)
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from cryptography import x509

from pki.core.trust_store import (
    build_ca_bundle_for_providers,
    fetch_trust_store_source,
)

logger = logging.getLogger(__name__)


def fetch_dod_certs() -> list[x509.Certificate]:
    """Fetch DoD CA certificates from DISA PKCS7 ZIP.

    Returns:
        List of cryptography x509.Certificate objects.
    """
    from .providers import CAC_PROVIDER

    certs: list[x509.Certificate] = []
    for source in CAC_PROVIDER.trust_store_sources:
        certs.extend(fetch_trust_store_source(source))
    logger.info("Total DoD CA certificates: %d", len(certs))
    return certs


def fetch_fpki_certs() -> list[x509.Certificate]:
    """Fetch Federal PKI CA certificates.

    Returns:
        List of cryptography x509.Certificate objects.
    """
    from .providers import PIV_PROVIDER

    certs: list[x509.Certificate] = []
    for source in PIV_PROVIDER.trust_store_sources:
        certs.extend(fetch_trust_store_source(source))
    logger.info("Total FPKI CA certificates: %d", len(certs))
    return certs


def build_ca_bundle(
    output_path: str | None = None,
    filter_fn: Callable[[x509.Certificate], bool] | None = None,
) -> tuple[str, dict]:
    """Fetch DoD + FPKI certs, merge, deduplicate, and optionally write to file.

    Delegates to ``pki.core.trust_store.build_ca_bundle_for_providers()``
    using the default federal registry (CAC + PIV).

    Args:
        output_path: If provided, write the PEM bundle to this path.
        filter_fn: Optional callable(cert) -> bool for filtering.

    Returns:
        Tuple of (pem_bundle_string, stats_dict).
    """
    from .providers import default_registry

    return build_ca_bundle_for_providers(
        default_registry(),
        output_path=output_path,
        filter_fn=filter_fn,
    )
