"""CN parsing strategies for different credential types.

Each strategy extracts first/last name and identifiers from the certificate
Subject CN field according to the conventions of that credential ecosystem.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pki.core.identity import CertIdentity


def _parse_cac_dot(identity: CertIdentity) -> None:
    """Parse CAC-format CN: LASTNAME.FIRSTNAME.MI.EDIPI."""
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


def _parse_piv_flexible(identity: CertIdentity) -> None:
    """Parse PIV-format CN: comma, space, or dot-separated."""
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


def _parse_eca_human(identity: CertIdentity) -> None:
    """Parse ECA-format CN: human-readable "First M. Last" or "First Last"."""
    if not identity.cn:
        return

    cn = identity.cn.strip()

    # "LASTNAME, FIRSTNAME MIDDLE" format (some ECA vendors)
    if "," in cn:
        parts = [p.strip() for p in cn.split(",", 1)]
        identity.lastname = parts[0]
        if len(parts) > 1:
            first_parts = parts[1].split()
            identity.firstname = first_parts[0] if first_parts else None
        return

    # "Firstname [Middle] Lastname" — standard ECA format
    parts = cn.split()
    if len(parts) >= 2:
        identity.firstname = parts[0]
        identity.lastname = parts[-1]
    else:
        identity.lastname = cn


# Public aliases
parse_cac_dot = _parse_cac_dot
parse_piv_flexible = _parse_piv_flexible
parse_eca_human = _parse_eca_human
