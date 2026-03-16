"""CAC, PIV, and ECA identity extraction from x509 certificates.

Controls: IA-2 (Identification), IA-5(2) (PKI-Based Auth)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography import x509
from cryptography.x509.oid import NameOID

from .certificate import (
    extract_email,
    extract_san_fascn,
    extract_san_uuid,
    get_name_attr,
    get_policy_oids,
)
from .cn_parsers import parse_cn
from .providers import (
    PrimaryIDStrategy,
    ProviderRegistry,
    default_registry,
)


@dataclass
class CertIdentity:
    """Parsed identity from a client certificate."""

    primary_id: str | None = None
    credential_type: str | None = None  # "CAC", "PIV", "ECA", etc.
    cn: str | None = None
    firstname: str | None = None
    lastname: str | None = None
    organization: str | None = None
    ou: str | None = None
    email: str | None = None
    edipi: str | None = None
    piv_uuid: str | None = None
    fascn: str | None = None
    cert_serial: str | None = None
    cert_not_after: str | None = None
    cert_issuer_dn: str | None = None
    subject_dn: str | None = None
    policy_oids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "primary_id": self.primary_id,
            "credential_type": self.credential_type,
            "cn": self.cn,
            "firstname": self.firstname,
            "lastname": self.lastname,
            "organization": self.organization,
            "ou": self.ou,
            "email": self.email,
            "edipi": self.edipi,
            "piv_uuid": self.piv_uuid,
            "fascn": self.fascn,
            "cert_serial": self.cert_serial,
            "cert_not_after": self.cert_not_after,
            "cert_issuer_dn": self.cert_issuer_dn,
            "subject_dn": self.subject_dn,
            "policy_oids": self.policy_oids,
        }


def parse_identity(
    cert: x509.Certificate,
    registry: ProviderRegistry | None = None,
) -> CertIdentity:
    """Parse an x509 certificate into a CertIdentity.

    Args:
        cert: The x509 client certificate.
        registry: Provider registry to match against. Defaults to
            CAC + PIV (backward compatible).
    """
    if registry is None:
        registry = default_registry()

    identity = CertIdentity()

    # Subject fields
    identity.cn = get_name_attr(cert.subject, NameOID.COMMON_NAME)
    identity.organization = get_name_attr(cert.subject, NameOID.ORGANIZATION_NAME)
    identity.ou = get_name_attr(cert.subject, NameOID.ORGANIZATIONAL_UNIT_NAME)
    identity.subject_dn = cert.subject.rfc4514_string()
    identity.cert_issuer_dn = cert.issuer.rfc4514_string()

    # Certificate metadata
    identity.cert_serial = format(cert.serial_number, "x")
    identity.cert_not_after = cert.not_valid_after_utc.isoformat()

    # Email from SAN or subject
    identity.email = extract_email(cert)

    # Policy OIDs
    identity.policy_oids = get_policy_oids(cert)

    # Match provider by OID, then heuristic fallback
    policy_set = set(identity.policy_oids)
    provider = registry.match_oids(policy_set)
    if provider is None:
        provider = registry.match_heuristic(identity.cn, identity.organization, identity.ou)
    if provider is None:
        # Fall back to last provider in registry
        all_providers = registry.all()
        provider = all_providers[-1] if all_providers else None

    if provider:
        identity.credential_type = provider.name
        parse_cn(identity, provider.cn_parse_strategy)
    else:
        identity.credential_type = "UNKNOWN"

    # Extract UUID and FASC-N from SAN (all types may have them)
    identity.piv_uuid = identity.piv_uuid or extract_san_uuid(cert)
    identity.fascn = identity.fascn or extract_san_fascn(cert)

    # Build stable primary key based on provider strategy
    if provider:
        identity.primary_id = _select_primary_id(identity, provider.primary_id_strategy)
    else:
        identity.primary_id = f"dn:{identity.subject_dn}"

    return identity


def _select_primary_id(identity: CertIdentity, strategy: PrimaryIDStrategy) -> str:
    """Select the primary identifier based on provider strategy."""
    if strategy == PrimaryIDStrategy.EDIPI_FIRST:
        if identity.edipi:
            return f"edipi:{identity.edipi}"
        if identity.piv_uuid:
            return f"uuid:{identity.piv_uuid}"
        if identity.fascn:
            return f"fascn:{identity.fascn}"
        return f"dn:{identity.subject_dn}"

    elif strategy == PrimaryIDStrategy.UUID_FIRST:
        if identity.piv_uuid:
            return f"uuid:{identity.piv_uuid}"
        if identity.fascn:
            return f"fascn:{identity.fascn}"
        if identity.edipi:
            return f"edipi:{identity.edipi}"
        return f"dn:{identity.subject_dn}"

    elif strategy == PrimaryIDStrategy.EMAIL_FIRST:
        if identity.email:
            return f"email:{identity.email}"
        return f"dn:{identity.subject_dn}"

    return f"dn:{identity.subject_dn}"


# ---------------------------------------------------------------------------
# Backward-compatible aliases (deprecated — use providers + cn_parsers)
# ---------------------------------------------------------------------------


def parse_cac_identity(identity: CertIdentity) -> None:
    """Deprecated: use parse_cn() with provider."""
    from .cn_parsers import _parse_cac_dot

    _parse_cac_dot(identity)


def parse_piv_identity(identity: CertIdentity) -> None:
    """Deprecated: use parse_cn() with provider."""
    from .cn_parsers import _parse_piv_flexible

    _parse_piv_flexible(identity)


def guess_credential_type(cn: str | None, org: str | None) -> str:
    """Deprecated: use ProviderRegistry.match_heuristic()."""
    reg = default_registry()
    provider = reg.match_heuristic(cn, org, None)
    return provider.name if provider else "PIV"
