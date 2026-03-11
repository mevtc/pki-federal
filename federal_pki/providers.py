"""Authentication provider definitions and registry.

Each AuthProvider encapsulates the certificate-matching OIDs, CN parsing
strategy, primary-ID selection, heuristic detection rules, and trust-store
source URLs for a single credential ecosystem (CAC, PIV, ECA, etc.).

Controls: IA-2 (Identification), IA-5(2) (PKI-Based Auth), IA-8 (Non-Org Users),
          CM-6 (Configuration Settings), SC-12 (Cryptographic Key Management)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from .oids import DOD_AUTH_OIDS, ECA_AUTH_OIDS, FPKI_PIV_AUTH_OIDS


class CNParseStrategy(Enum):
    """How to extract first/last name and identifiers from the Subject CN."""

    CAC_DOT = "cac_dot"  # LASTNAME.FIRSTNAME.MI.EDIPI
    PIV_FLEXIBLE = "piv_flexible"  # Comma, space, or dot-separated
    ECA_HUMAN = "eca_human"  # Human-readable "First M. Last"


class PrimaryIDStrategy(Enum):
    """Ordered priority for selecting the stable primary identifier."""

    EDIPI_FIRST = "edipi_first"  # edipi > uuid > fascn > dn
    UUID_FIRST = "uuid_first"  # uuid > fascn > edipi > dn
    EMAIL_FIRST = "email_first"  # email > dn


@dataclass(frozen=True)
class HeuristicRule:
    """A single heuristic for guessing credential type from cert fields."""

    field: str  # "org", "cn", or "ou"
    pattern: str  # Substring (case-insensitive) or regex
    is_regex: bool = False


@dataclass(frozen=True)
class TrustStoreSource:
    """A CA certificate download source."""

    url: str
    format: str = "pkcs7_zip"  # "pkcs7_zip", "pkcs7_der", "der", "pem"
    label: str = ""


@dataclass(frozen=True)
class AuthProvider:
    """A credential ecosystem definition.

    Instances are immutable (frozen) so they can be safely shared across
    threads and used as dict values without defensive copies.
    """

    name: str  # "CAC", "PIV", "ECA"
    display_name: str  # "DoD CAC", "Federal PIV", "ECA"
    auth_oids: frozenset[str]  # Policy OIDs that identify this type
    cn_parse_strategy: CNParseStrategy
    primary_id_strategy: PrimaryIDStrategy
    heuristics: tuple[HeuristicRule, ...] = ()
    trust_store_sources: tuple[TrustStoreSource, ...] = ()
    email_signing_oids: frozenset[str] = frozenset()
    # NIST 800-63 Authenticator Assurance Level (informational/policy).
    min_aal: int = 2
    # NIST 800-53 controls this provider satisfies (informational).
    controls: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Built-in providers
# ---------------------------------------------------------------------------

CAC_PROVIDER = AuthProvider(
    name="CAC",
    display_name="DoD CAC",
    auth_oids=frozenset(DOD_AUTH_OIDS),
    cn_parse_strategy=CNParseStrategy.CAC_DOT,
    primary_id_strategy=PrimaryIDStrategy.EDIPI_FIRST,
    heuristics=(
        HeuristicRule(field="org", pattern="department of defense"),
        HeuristicRule(
            field="cn",
            pattern=r"^[A-Z]+\.[A-Z]+\.[A-Z]*\.\d{10}$",
            is_regex=True,
        ),
    ),
    trust_store_sources=(
        TrustStoreSource(
            url="https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_DoD.zip",
            format="pkcs7_zip",
            label="DoD",
        ),
    ),
    min_aal=3,
    controls=("IA-2", "IA-2(1)", "IA-2(12)"),
)

PIV_PROVIDER = AuthProvider(
    name="PIV",
    display_name="Federal PIV",
    auth_oids=frozenset(FPKI_PIV_AUTH_OIDS),
    cn_parse_strategy=CNParseStrategy.PIV_FLEXIBLE,
    primary_id_strategy=PrimaryIDStrategy.UUID_FIRST,
    heuristics=(
        HeuristicRule(field="org", pattern="energy"),
        HeuristicRule(field="org", pattern="nnsa"),
        HeuristicRule(field="org", pattern="doe"),
    ),
    trust_store_sources=(
        TrustStoreSource(
            url="http://repo.fpki.gov/fcpca/fcpcag2.crt",
            format="der",
            label="FPKI",
        ),
        TrustStoreSource(
            url="http://repo.fpki.gov/bridge/caCertsIssuedTofbcag4.p7c",
            format="pkcs7_der",
            label="FPKI",
        ),
        TrustStoreSource(
            url="http://repo.fpki.gov/bridge/caCertsIssuedByfbcag4.p7c",
            format="pkcs7_der",
            label="FPKI",
        ),
    ),
    min_aal=3,
    controls=("IA-2", "IA-2(1)", "IA-2(12)"),
)

ECA_PROVIDER = AuthProvider(
    name="ECA",
    display_name="ECA",
    auth_oids=frozenset(ECA_AUTH_OIDS),
    cn_parse_strategy=CNParseStrategy.ECA_HUMAN,
    primary_id_strategy=PrimaryIDStrategy.EMAIL_FIRST,
    heuristics=(HeuristicRule(field="ou", pattern="eca"),),
    trust_store_sources=(
        TrustStoreSource(
            url="https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_ECA.zip",
            format="pkcs7_zip",
            label="ECA",
        ),
    ),
    min_aal=2,
    controls=("IA-2", "IA-8"),
)

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

BUILTIN_PROVIDERS: dict[str, AuthProvider] = {
    "CAC": CAC_PROVIDER,
    "PIV": PIV_PROVIDER,
    "ECA": ECA_PROVIDER,
}


@dataclass
class ProviderRegistry:
    """Ordered collection of active authentication providers.

    Providers are matched in insertion order: the first provider whose
    auth_oids intersect the certificate's policy OIDs wins.
    """

    _providers: dict[str, AuthProvider] = field(default_factory=dict)

    def register(self, provider: AuthProvider) -> None:
        """Add or replace a provider."""
        self._providers[provider.name] = provider

    def get(self, name: str) -> AuthProvider | None:
        """Look up a provider by name."""
        return self._providers.get(name)

    def all(self) -> list[AuthProvider]:
        """Return all providers in registration order."""
        return list(self._providers.values())

    def names(self) -> list[str]:
        """Return provider names in registration order."""
        return list(self._providers.keys())

    def match_oids(self, policy_oids: set[str]) -> AuthProvider | None:
        """Return the first provider whose auth_oids intersect policy_oids."""
        for provider in self._providers.values():
            if policy_oids & provider.auth_oids:
                return provider
        return None

    def match_heuristic(
        self,
        cn: str | None,
        org: str | None,
        ou: str | None,
    ) -> AuthProvider | None:
        """Return the first provider matched by heuristic rules."""
        for provider in self._providers.values():
            for rule in provider.heuristics:
                value = {"cn": cn, "org": org, "ou": ou}.get(rule.field)
                if value is None:
                    continue
                if rule.is_regex:
                    if re.match(rule.pattern, value):
                        return provider
                else:
                    if rule.pattern in value.lower():
                        return provider
        return None

    def __len__(self) -> int:
        return len(self._providers)


def default_registry() -> ProviderRegistry:
    """Create a registry with CAC + PIV enabled (backward-compatible default)."""
    reg = ProviderRegistry()
    reg.register(CAC_PROVIDER)
    reg.register(PIV_PROVIDER)
    return reg


def full_registry() -> ProviderRegistry:
    """Create a registry with all built-in providers."""
    reg = ProviderRegistry()
    for provider in BUILTIN_PROVIDERS.values():
        reg.register(provider)
    return reg