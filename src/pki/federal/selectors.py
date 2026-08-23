"""Primary-ID selectors specific to federal NPE / device credentials.

``pki.core.selectors`` provides person-oriented selectors (EDIPI-first,
UUID-first, email-first).  Non-person entities (devices, services, content
signers) have no EDIPI/UUID/email; their stable identifier is the subject
Common Name (typically an FQDN or service name) or, failing that, the full
subject DN.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pki.core.identity import CertIdentity


def select_cn_first(identity: CertIdentity) -> str:
    """CN > DN.

    Suitable for NPE / device / content-signing certificates whose subject is
    a machine identity (e.g. ``CN=athocalerts.com``) rather than a person.
    """
    if identity.cn:
        return f"cn:{identity.cn}"
    return f"dn:{identity.subject_dn}"


def select_card_token_id(identity: CertIdentity) -> str:
    """Token identifier, namespaced so it cannot collide with a person ID.

    Card-authentication certificates carry the *same* subject identifier as the
    personal-authentication certificate on the same card — verified on a real
    DoD CAC, where both assert an identical ``urn:uuid:`` SAN.  Returning the
    bare ``uuid:`` form that ``select_uuid_first`` produces would make the two
    indistinguishable to any consumer keying on ``primary_id`` alone, so a
    PIN-less card read would resolve to the cardholder's account.

    ``intended_use`` is the real boundary and callers must enforce it; this
    prefix is defence in depth for callers that do not.
    """
    if identity.piv_uuid:
        return f"card:uuid:{identity.piv_uuid}"
    if identity.fascn:
        return f"card:fascn:{identity.fascn}"
    return f"card:dn:{identity.subject_dn}"
