"""DoDI 8520.02 trust levels and credential types.

Trust levels map authentication methods to assurance levels per
DoDI 8520.02 (Public Key Infrastructure and Public Key Enabling).
PKI authentication is mandatory for DoD systems; password fallback
is only permitted when PKI is "not technically feasible" and must
be documented in the system authorization package (ATO).
"""

from enum import StrEnum


class TrustLevel(StrEnum):
    """Authentication assurance level per DoDI 8520.02.

    Ordered from highest to lowest assurance.  Supports comparison::

        if user.trust_level < TrustLevel.HIGH:
            raise HTTPException(403, "Requires smartcard")
    """

    HIGH = "high"  # Hardware PKI token (CAC/PIV smartcard)
    MEDIUM = "medium"  # Software certificate or derived PIV credential
    BASIC = "basic"  # Password-authenticated (fallback only)
    NONE = "none"  # Unauthenticated / unknown

    def __lt__(self, other):
        """Compare trust levels by assurance ordering."""
        if not isinstance(other, TrustLevel):
            return NotImplemented
        order = [TrustLevel.NONE, TrustLevel.BASIC, TrustLevel.MEDIUM, TrustLevel.HIGH]
        return order.index(self) < order.index(other)

    def __le__(self, other):
        """Return True if this trust level is equal or lower assurance."""
        return self == other or self < other

    def __gt__(self, other):
        """Return True if this trust level is higher assurance."""
        if not isinstance(other, TrustLevel):
            return NotImplemented
        return not self <= other

    def __ge__(self, other):
        """Return True if this trust level is equal or higher assurance."""
        return self == other or self > other


class CredentialType(StrEnum):
    """Federal PKI credential types.

    Corresponds to the ``name`` field on ``AuthProvider`` instances
    in pki-federal's provider registry.
    """

    CAC = "CAC"  # DoD Common Access Card
    PIV = "PIV"  # Federal Personal Identity Verification
    ECA = "ECA"  # External Certificate Authority
