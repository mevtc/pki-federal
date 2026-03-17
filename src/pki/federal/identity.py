"""Federal identity extraction with default registry."""

from __future__ import annotations

from cryptography import x509

from pki.core.identity import CertIdentity
from pki.core.identity import parse_identity as _core_parse_identity
from pki.core.providers import ProviderRegistry


def parse_identity(
    cert: x509.Certificate,
    registry: ProviderRegistry | None = None,
) -> CertIdentity:
    """Parse an x509 certificate into a CertIdentity.

    Defaults to the federal default_registry (CAC + PIV) if no registry
    is provided.
    """
    if registry is None:
        from .providers import default_registry

        registry = default_registry()
    return _core_parse_identity(cert, registry=registry)
