"""DoDI 8520.02 trust levels and credential types.

Trust levels map authentication methods to assurance levels per
DoDI 8520.02 (Public Key Infrastructure and Public Key Enabling).
PKI authentication is mandatory for DoD systems; password fallback
is only permitted when PKI is "not technically feasible" and must
be documented in the system authorization package (ATO).
"""

from enum import IntEnum, StrEnum


class TrustLevel(IntEnum):
    """Authentication assurance level per DoDI 8520.02.

    Ordered from lowest to highest assurance.  Supports comparison
    natively via integer values::

        if user.trust_level < TrustLevel.HIGH:
            raise HTTPException(403, "Requires smartcard")
    """

    NONE = 0  # Unauthenticated / unknown
    BASIC = 1  # Password-authenticated (fallback only)
    MEDIUM = 2  # Software certificate or derived PIV credential
    HIGH = 3  # Hardware PKI token (CAC/PIV smartcard)


class CredentialType(StrEnum):
    """Federal PKI credential types.

    Corresponds to the ``name`` field on ``AuthProvider`` instances
    in pki-federal's provider registry.
    """

    CAC = "CAC"  # DoD Common Access Card
    PIV = "PIV"  # Federal Personal Identity Verification
    ECA = "ECA"  # External Certificate Authority
