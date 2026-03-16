"""Backward-compatible identity re-exports from pki-core."""

from __future__ import annotations

from cryptography import x509
from pki_core.identity import CertIdentity
from pki_core.identity import parse_identity as _pki_core_parse_identity
from pki_core.providers import ProviderRegistry


def parse_identity(
    cert: x509.Certificate,
    registry: ProviderRegistry | None = None,
) -> CertIdentity:
    """Parse an x509 certificate into a CertIdentity.

    Defaults to the federal default_registry (CAC + PIV) if no registry
    is provided. This preserves backward compatibility with federal-pki
    0.1.x where parse_identity always used the federal registry.
    """
    if registry is None:
        from .providers import default_registry

        registry = default_registry()
    return _pki_core_parse_identity(cert, registry=registry)


def parse_cac_identity(identity: CertIdentity) -> None:
    """Deprecated: use provider.cn_parser directly."""
    from .cn_parsers import _parse_cac_dot

    _parse_cac_dot(identity)


def parse_piv_identity(identity: CertIdentity) -> None:
    """Deprecated: use provider.cn_parser directly."""
    from .cn_parsers import _parse_piv_flexible

    _parse_piv_flexible(identity)


def guess_credential_type(cn: str | None, org: str | None) -> str:
    """Deprecated: use ProviderRegistry.match_heuristic()."""
    from .providers import default_registry

    reg = default_registry()
    provider = reg.match_heuristic(cn, org, None)
    return provider.name if provider else "PIV"
