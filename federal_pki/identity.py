"""CAC and PIV identity extraction from x509 certificates."""

import re
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
from .oids import DOD_AUTH_OIDS, FPKI_PIV_AUTH_OIDS


@dataclass
class CertIdentity:
    """Parsed identity from a CAC or PIV client certificate."""

    primary_id: str | None = None
    credential_type: str | None = None  # "CAC" or "PIV"
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


def parse_identity(cert: x509.Certificate) -> CertIdentity:
    """Parse an x509 certificate into a CertIdentity."""
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

    # Determine credential type
    policy_set = set(identity.policy_oids)
    if policy_set & DOD_AUTH_OIDS:
        identity.credential_type = "CAC"
    elif policy_set & FPKI_PIV_AUTH_OIDS:
        identity.credential_type = "PIV"
    else:
        identity.credential_type = guess_credential_type(
            identity.cn, identity.organization
        )

    # Extract identifiers based on type
    if identity.credential_type == "CAC":
        parse_cac_identity(identity)
    else:
        parse_piv_identity(identity)

    # Extract UUID and FASC-N from SAN (both types may have them)
    identity.piv_uuid = identity.piv_uuid or extract_san_uuid(cert)
    identity.fascn = identity.fascn or extract_san_fascn(cert)

    # Build stable primary key
    if identity.edipi:
        identity.primary_id = f"edipi:{identity.edipi}"
    elif identity.piv_uuid:
        identity.primary_id = f"uuid:{identity.piv_uuid}"
    elif identity.fascn:
        identity.primary_id = f"fascn:{identity.fascn}"
    else:
        identity.primary_id = f"dn:{identity.subject_dn}"

    return identity


def parse_cac_identity(identity: CertIdentity) -> None:
    """Parse CAC-specific fields from the Common Name.

    CAC CN format: LASTNAME.FIRSTNAME.MIDDLEINITIAL.EDIPI
    Example: SMITH.JOHN.A.1234567890
    """
    if not identity.cn:
        return

    parts = identity.cn.split(".")
    if len(parts) >= 4 and parts[-1].isdigit() and len(parts[-1]) == 10:
        identity.edipi = parts[-1]
        identity.lastname = parts[0]
        identity.firstname = parts[1]
    elif len(parts) >= 2:
        identity.lastname = parts[0]
        identity.firstname = parts[1]
    else:
        identity.lastname = identity.cn


def parse_piv_identity(identity: CertIdentity) -> None:
    """Parse PIV-specific fields from the Common Name.

    PIV CN varies by agency. Common formats:
      - "John A. Smith"
      - "SMITH, JOHN A"
      - "John Smith"
    """
    if not identity.cn:
        return

    cn = identity.cn.strip()

    # "LASTNAME, FIRSTNAME MIDDLE" format
    if "," in cn:
        parts = [p.strip() for p in cn.split(",", 1)]
        identity.lastname = parts[0]
        if len(parts) > 1:
            first_parts = parts[1].split()
            identity.firstname = first_parts[0] if first_parts else None
        return

    # "LAST.FIRST.MI.NUMBER" — some PIV certs use CAC-like format
    dot_parts = cn.split(".")
    if len(dot_parts) >= 3 and dot_parts[-1].isdigit():
        identity.lastname = dot_parts[0]
        identity.firstname = dot_parts[1]
        if len(dot_parts[-1]) == 10:
            identity.edipi = dot_parts[-1]
        return

    # "Firstname [Middle] Lastname" format
    parts = cn.split()
    if len(parts) >= 2:
        identity.firstname = parts[0]
        identity.lastname = parts[-1]
    else:
        identity.lastname = cn


def guess_credential_type(cn: str | None, org: str | None) -> str:
    """Heuristic fallback when policy OIDs don't match known sets."""
    if org and "department of defense" in org.lower():
        return "CAC"
    if cn and re.match(r"^[A-Z]+\.[A-Z]+\.[A-Z]*\.\d{10}$", cn or ""):
        return "CAC"
    if org and any(k in org.lower() for k in ["energy", "nnsa", "doe"]):
        return "PIV"
    return "PIV"  # Default to PIV for civilian agencies