"""Federal PKI authentication provider instances and registries."""

from __future__ import annotations

from enum import Enum

from pki.core.providers import (
    AuthProvider,
    HeuristicRule,
    ProviderRegistry,
    TrustStoreSource,
)
from pki.core.selectors import select_edipi_first, select_email_first, select_uuid_first

from .cn_parsers import _parse_cac_dot, _parse_eca_human, _parse_piv_flexible
from .oids import DOD_AUTH_OIDS, ECA_AUTH_OIDS, FPKI_PIV_AUTH_OIDS


# Deprecated enums — kept for backward compatibility
class CNParseStrategy(Enum):
    """Deprecated: AuthProvider now uses cn_parser callable."""

    CAC_DOT = "cac_dot"
    PIV_FLEXIBLE = "piv_flexible"
    ECA_HUMAN = "eca_human"


class PrimaryIDStrategy(Enum):
    """Deprecated: AuthProvider now uses primary_id_selector callable."""

    EDIPI_FIRST = "edipi_first"
    UUID_FIRST = "uuid_first"
    EMAIL_FIRST = "email_first"


CAC_PROVIDER = AuthProvider(
    name="CAC",
    display_name="DoD CAC",
    auth_oids=frozenset(DOD_AUTH_OIDS),
    cn_parser=_parse_cac_dot,
    primary_id_selector=select_edipi_first,
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
    cn_parser=_parse_piv_flexible,
    primary_id_selector=select_uuid_first,
    heuristics=(
        HeuristicRule(field="org", pattern="energy"),
        HeuristicRule(field="org", pattern="nnsa"),
        HeuristicRule(field="org", pattern="doe"),
    ),
    trust_store_sources=(
        TrustStoreSource(
            url="https://repo.fpki.gov/fcpca/fcpcag2.crt",
            format="der",
            label="FPKI",
        ),
        TrustStoreSource(
            url="https://repo.fpki.gov/bridge/caCertsIssuedTofbcag4.p7c",
            format="pkcs7_der",
            label="FPKI",
        ),
        TrustStoreSource(
            url="https://repo.fpki.gov/bridge/caCertsIssuedByfbcag4.p7c",
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
    cn_parser=_parse_eca_human,
    primary_id_selector=select_email_first,
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

BUILTIN_PROVIDERS: dict[str, AuthProvider] = {
    "CAC": CAC_PROVIDER,
    "PIV": PIV_PROVIDER,
    "ECA": ECA_PROVIDER,
}


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
