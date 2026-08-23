"""Federal PKI authentication provider instances and registries.

Providers are organised on two axes: the credential *hierarchy* (DoD CAC,
Federal PIV, ECA) and the *intended use* declared by the certificate policy
OID it asserts (personal authentication, non-person-entity/device
authentication, or content/object signing).  The ``intended_use`` flag on each
provider comes from ``pki.core.providers.IntendedUse`` and is populated
strictly from the certificate-policy citations recorded in
``docs/cp-policy-table.md`` — if a CP does not grant a use, the bit is not set.

Person providers (CAC/PIV/ECA) remain ``PERSONAL_AUTH`` only.  The certificate
policies for their OIDs cover human authentication and human digital signature
(S/MIME); they do NOT authorise content/code signing (the FPKI Common CP even
forbids the id-kp-codeSigning EKU on Subscriber certificates), so no
``OBJECT_SIGNING`` bit is set on them.
"""

from __future__ import annotations

from pki.core.providers import (
    AuthProvider,
    HeuristicRule,
    IntendedUse,
    ProviderRegistry,
    TrustStoreSource,
)
from pki.core.selectors import select_edipi_first, select_email_first, select_uuid_first

from .cn_parsers import _parse_cac_dot, _parse_device_cn, _parse_eca_human, _parse_piv_flexible
from .oids import (
    CARD_AUTH_OIDS,
    DOD_NPE_OIDS,
    DOD_PE_OIDS,
    ECA_NPE_OIDS,
    ECA_PE_OIDS,
    FEDERAL_NPE_OIDS,
    FEDERAL_PE_OIDS,
    OBJECT_SIGNING_OIDS,
)
from .selectors import select_card_token_id, select_cn_first

# Reusable trust-store sources ------------------------------------------------

_DOD_TRUST = TrustStoreSource(
    url="https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_DoD.zip",
    format="pkcs7_zip",
    label="DoD",
)
_ECA_TRUST = TrustStoreSource(
    url="https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_ECA.zip",
    format="pkcs7_zip",
    label="ECA",
)
_FPKI_TRUST = (
    TrustStoreSource(url="https://repo.fpki.gov/fcpca/fcpcag2.crt", format="der", label="FPKI"),
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
)


# A person credential never asserts a device or card-authentication policy.
# DoD CP v11 Section 1.2 permits the converse — a Medium NPE certificate "may
# also assert any Medium Software or Medium Hardware OID" — so the presence of
# an NPE or card-auth OID is definitional and must rule out the person
# providers even in a registry where no device provider is registered.
_NON_PERSON_OIDS: frozenset[str] = frozenset(
    set(DOD_NPE_OIDS) | set(FEDERAL_NPE_OIDS) | set(ECA_NPE_OIDS) | set(CARD_AUTH_OIDS)
)

# ---------------------------------------------------------------------------
# Person (PE) providers — PERSONAL_AUTH
# ---------------------------------------------------------------------------

CAC_PROVIDER = AuthProvider(
    name="CAC",
    display_name="DoD CAC",
    auth_oids=frozenset(DOD_PE_OIDS),
    # DoD does not distinguish S/MIME signing certificates from identity
    # certificates by policy OID; a human Subscriber's signature certificate
    # asserts the same Medium / Medium-Hardware person OIDs.
    email_signing_oids=frozenset(DOD_PE_OIDS),
    cn_parser=_parse_cac_dot,
    primary_id_selector=select_edipi_first,
    heuristics=(
        HeuristicRule(field="org", pattern="department of defense"),
        # Intentionally uppercase-only: DoD CAs issue CNs in uppercase per
        # DISA PKI naming conventions.  Case sensitivity is a high-confidence
        # signal that the certificate came from a real DoD CA.
        HeuristicRule(
            field="cn",
            pattern=r"^[A-Z]+\.[A-Z]+\.[A-Z]*\.\d{10}$",
            is_regex=True,
        ),
    ),
    trust_store_sources=(_DOD_TRUST,),
    min_aal=3,
    controls=("IA-2", "IA-2(1)", "IA-2(12)"),
    intended_use=IntendedUse.PERSONAL_AUTH,
    disqualifying_oids=_NON_PERSON_OIDS,
)

PIV_PROVIDER = AuthProvider(
    name="PIV",
    display_name="Federal PIV",
    auth_oids=frozenset(FEDERAL_PE_OIDS),
    email_signing_oids=frozenset(FEDERAL_PE_OIDS),
    cn_parser=_parse_piv_flexible,
    primary_id_selector=select_uuid_first,
    heuristics=(
        HeuristicRule(field="org", pattern="energy"),
        HeuristicRule(field="org", pattern="nnsa"),
        HeuristicRule(field="org", pattern="doe"),
    ),
    trust_store_sources=_FPKI_TRUST,
    min_aal=3,
    controls=("IA-2", "IA-2(1)", "IA-2(12)"),
    intended_use=IntendedUse.PERSONAL_AUTH,
    disqualifying_oids=_NON_PERSON_OIDS,
)

ECA_PROVIDER = AuthProvider(
    name="ECA",
    display_name="ECA",
    auth_oids=frozenset(ECA_PE_OIDS),
    email_signing_oids=frozenset(ECA_PE_OIDS),
    cn_parser=_parse_eca_human,
    primary_id_selector=select_email_first,
    heuristics=(HeuristicRule(field="ou", pattern="eca"),),
    trust_store_sources=(_ECA_TRUST,),
    min_aal=2,
    controls=("IA-2", "IA-8"),
    intended_use=IntendedUse.PERSONAL_AUTH,
    disqualifying_oids=_NON_PERSON_OIDS,
)

# ---------------------------------------------------------------------------
# Non-Person Entity (device) providers — NPE_AUTH
# ---------------------------------------------------------------------------
# Matched by policy OID only (no name heuristics): a device CN is a hostname /
# FQDN and must never be routed to a person provider by heuristic guessing.

DOD_NPE_PROVIDER = AuthProvider(
    name="DOD-NPE",
    display_name="DoD Non-Person Entity",
    auth_oids=frozenset(DOD_NPE_OIDS),
    cn_parser=_parse_device_cn,
    primary_id_selector=select_cn_first,
    trust_store_sources=(_DOD_TRUST,),
    min_aal=2,
    controls=("IA-3",),
    intended_use=IntendedUse.NPE_AUTH,
)

FPKI_DEVICE_PROVIDER = AuthProvider(
    name="FPKI-DEVICE",
    display_name="Federal Device (FPKI/FBCA)",
    auth_oids=frozenset(FEDERAL_NPE_OIDS),
    cn_parser=_parse_device_cn,
    primary_id_selector=select_cn_first,
    trust_store_sources=_FPKI_TRUST,
    min_aal=2,
    controls=("IA-3",),
    intended_use=IntendedUse.NPE_AUTH,
)

ECA_DEVICE_PROVIDER = AuthProvider(
    name="ECA-DEVICE",
    display_name="ECA Device",
    auth_oids=frozenset(ECA_NPE_OIDS),
    cn_parser=_parse_device_cn,
    primary_id_selector=select_cn_first,
    trust_store_sources=(_ECA_TRUST,),
    min_aal=2,
    controls=("IA-3", "IA-8"),
    intended_use=IntendedUse.NPE_AUTH,
)

# ---------------------------------------------------------------------------
# Content / object signing provider — OBJECT_SIGNING
# ---------------------------------------------------------------------------
# Covers the PIV / PIV-I content-signing policies across FPKI, FBCA and ECA.
# Subject is a card-management system (an NPE), not a person.

CONTENT_SIGNING_PROVIDER = AuthProvider(
    name="CONTENT-SIGNING",
    display_name="PIV/PIV-I Content Signing",
    auth_oids=frozenset(OBJECT_SIGNING_OIDS),
    cn_parser=_parse_device_cn,
    primary_id_selector=select_cn_first,
    trust_store_sources=(*_FPKI_TRUST, _ECA_TRUST),
    min_aal=2,
    controls=("SC-17",),
    intended_use=IntendedUse.OBJECT_SIGNING,
)

# ---------------------------------------------------------------------------
# Card / token-presence provider — CARD_AUTH
# ---------------------------------------------------------------------------
# Covers the PIV / PIV-I Card Authentication policies across FPKI, FBCA and
# ECA.  Every CP defining one of these forbids treating it as authenticating
# the holder — FPKI Common v2.13 Section 1.4.2 and FBCA v3.9 Section 1.4.2 both
# state that such certificates "must only be used to authenticate the hardware
# token containing the associated private key and must not be interpreted as
# authenticating the presenter or holder of the token."
#
# These OIDs previously sat in the person sets, so a card-authentication
# certificate — whose private key needs no PIN — matched a PERSONAL_AUTH
# provider.
#
# Note for future reviewers: FPKI Common groups id-fpki-common-cardAuth under
# "PIV Device Subscriber Certificates", which looks like an argument for
# NPE_AUTH.  It is not.  That heading separates non-person subscribers from
# person ones; content-signing shares it and is OBJECT_SIGNING here for the
# same reason.  NPE_AUTH means device/service authentication, while Section
# 1.4.2 says this authenticates *the token* — neither a person nor a service.

CARD_AUTH_PROVIDER = AuthProvider(
    name="CARD-AUTH",
    display_name="PIV/PIV-I Card Authentication",
    auth_oids=frozenset(CARD_AUTH_OIDS),
    cn_parser=_parse_device_cn,
    primary_id_selector=select_card_token_id,
    trust_store_sources=(*_FPKI_TRUST, _ECA_TRUST, _DOD_TRUST),
    min_aal=1,  # no activation data — proves token presence only
    controls=("IA-3", "PE-3"),
    intended_use=IntendedUse.CARD_AUTH,
)

BUILTIN_PROVIDERS: dict[str, AuthProvider] = {
    "CAC": CAC_PROVIDER,
    "PIV": PIV_PROVIDER,
    "ECA": ECA_PROVIDER,
    "DOD-NPE": DOD_NPE_PROVIDER,
    "FPKI-DEVICE": FPKI_DEVICE_PROVIDER,
    "ECA-DEVICE": ECA_DEVICE_PROVIDER,
    "CONTENT-SIGNING": CONTENT_SIGNING_PROVIDER,
    "CARD-AUTH": CARD_AUTH_PROVIDER,
}

# Providers whose intended_use is PERSONAL_AUTH — the backward-compatible set.
PERSON_PROVIDERS: tuple[AuthProvider, ...] = (CAC_PROVIDER, PIV_PROVIDER, ECA_PROVIDER)


def default_registry() -> ProviderRegistry:
    """Create a registry with CAC + PIV enabled (backward-compatible default).

    Person-only.  Constrained to ``IntendedUse.PERSONAL_AUTH`` so that a future
    attempt to register a non-person provider here fails at registration time
    rather than silently widening the authentication boundary.
    """
    reg = ProviderRegistry(intended_use=IntendedUse.PERSONAL_AUTH)
    reg.register(CAC_PROVIDER)
    reg.register(PIV_PROVIDER)
    return reg


def full_registry() -> ProviderRegistry:
    """Create a registry with all built-in providers (person + NPE + signing)."""
    reg = ProviderRegistry()
    for provider in BUILTIN_PROVIDERS.values():
        reg.register(provider)
    return reg
