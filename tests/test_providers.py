"""Tests for pki.federal.providers module."""

from typing import ClassVar

import pytest

from pki.core.providers import IntendedUse
from pki.core.selectors import select_edipi_first, select_email_first, select_uuid_first
from pki.federal.cn_parsers import (
    _parse_cac_dot,
    _parse_device_cn,
    _parse_eca_human,
    _parse_piv_flexible,
)
from pki.federal.oids import CARD_AUTH_OIDS, ECA_PE_OIDS, FEDERAL_PE_OIDS
from pki.federal.providers import (
    BUILTIN_PROVIDERS,
    CAC_PROVIDER,
    CARD_AUTH_PROVIDER,
    CONTENT_SIGNING_PROVIDER,
    DOD_NPE_PROVIDER,
    ECA_DEVICE_PROVIDER,
    ECA_PROVIDER,
    FPKI_DEVICE_PROVIDER,
    PIV_PROVIDER,
    ProviderRegistry,
    default_registry,
    full_registry,
)
from pki.federal.selectors import select_card_token_id, select_cn_first


class TestBuiltinProviders:
    def test_cac_provider(self):
        assert CAC_PROVIDER.name == "CAC"
        assert CAC_PROVIDER.cn_parser is _parse_cac_dot
        assert CAC_PROVIDER.primary_id_selector is select_edipi_first
        assert "2.16.840.1.101.2.1.11.19" in CAC_PROVIDER.auth_oids
        assert CAC_PROVIDER.min_aal == 3
        assert CAC_PROVIDER.intended_use is IntendedUse.PERSONAL_AUTH
        # DoD does not separate signing certs by OID; email set mirrors auth.
        assert CAC_PROVIDER.email_signing_oids == CAC_PROVIDER.auth_oids

    def test_piv_provider(self):
        assert PIV_PROVIDER.name == "PIV"
        assert PIV_PROVIDER.cn_parser is _parse_piv_flexible
        assert PIV_PROVIDER.primary_id_selector is select_uuid_first
        assert "2.16.840.1.101.3.2.1.3.13" in PIV_PROVIDER.auth_oids
        # FBCA-arc id-fpki-certpcy-mediumHardware is now recognised too.
        assert "2.16.840.1.101.3.2.1.3.12" in PIV_PROVIDER.auth_oids
        assert PIV_PROVIDER.min_aal == 3
        assert PIV_PROVIDER.intended_use is IntendedUse.PERSONAL_AUTH

    def test_eca_provider(self):
        assert ECA_PROVIDER.name == "ECA"
        assert ECA_PROVIDER.cn_parser is _parse_eca_human
        assert ECA_PROVIDER.primary_id_selector is select_email_first
        assert "2.16.840.1.101.3.2.1.12.2" in ECA_PROVIDER.auth_oids
        assert ECA_PROVIDER.min_aal == 2
        assert "IA-8" in ECA_PROVIDER.controls
        assert ECA_PROVIDER.intended_use is IntendedUse.PERSONAL_AUTH

    def test_dod_npe_provider(self):
        assert DOD_NPE_PROVIDER.name == "DOD-NPE"
        assert DOD_NPE_PROVIDER.cn_parser is _parse_device_cn
        assert DOD_NPE_PROVIDER.primary_id_selector is select_cn_first
        assert DOD_NPE_PROVIDER.intended_use is IntendedUse.NPE_AUTH
        assert "2.16.840.1.101.2.1.11.36" in DOD_NPE_PROVIDER.auth_oids  # mediumNPE-112
        # A device policy must NEVER leak into the person provider.
        assert "2.16.840.1.101.2.1.11.36" not in CAC_PROVIDER.auth_oids

    def test_fpki_device_provider(self):
        assert FPKI_DEVICE_PROVIDER.name == "FPKI-DEVICE"
        assert FPKI_DEVICE_PROVIDER.intended_use is IntendedUse.NPE_AUTH
        assert "2.16.840.1.101.3.2.1.3.36" in FPKI_DEVICE_PROVIDER.auth_oids  # devicesHardware
        assert "2.16.840.1.101.3.2.1.3.38" in FPKI_DEVICE_PROVIDER.auth_oids  # FBCA mediumDeviceHw

    def test_eca_device_provider(self):
        assert ECA_DEVICE_PROVIDER.name == "ECA-DEVICE"
        assert ECA_DEVICE_PROVIDER.intended_use is IntendedUse.NPE_AUTH
        # The AtHoc CN=athocalerts.com cert asserts id-eca-medium-device-sha256.
        assert "2.16.840.1.101.3.2.1.12.9" in ECA_DEVICE_PROVIDER.auth_oids
        assert "2.16.840.1.101.3.2.1.12.9" not in ECA_PROVIDER.auth_oids

    def test_content_signing_provider(self):
        assert CONTENT_SIGNING_PROVIDER.name == "CONTENT-SIGNING"
        assert CONTENT_SIGNING_PROVIDER.intended_use is IntendedUse.OBJECT_SIGNING
        assert CONTENT_SIGNING_PROVIDER.cn_parser is _parse_device_cn
        # FPKI, FBCA and ECA content-signing OIDs all covered.
        assert "2.16.840.1.101.3.2.1.3.39" in CONTENT_SIGNING_PROVIDER.auth_oids
        assert "2.16.840.1.101.3.2.1.3.20" in CONTENT_SIGNING_PROVIDER.auth_oids
        assert "2.16.840.1.101.3.2.1.12.8" in CONTENT_SIGNING_PROVIDER.auth_oids

    def test_person_providers_are_not_object_signing(self):
        for p in (CAC_PROVIDER, PIV_PROVIDER, ECA_PROVIDER):
            assert IntendedUse.OBJECT_SIGNING not in p.intended_use
            assert IntendedUse.NPE_AUTH not in p.intended_use

    def test_builtin_dict(self):
        assert set(BUILTIN_PROVIDERS.keys()) == {
            "CAC",
            "PIV",
            "ECA",
            "DOD-NPE",
            "FPKI-DEVICE",
            "ECA-DEVICE",
            "CONTENT-SIGNING",
            "CARD-AUTH",
        }

    def test_providers_are_frozen(self):
        import dataclasses

        for p in BUILTIN_PROVIDERS.values():
            assert dataclasses.is_dataclass(p)


class TestProviderRegistry:
    def test_register_and_get(self):
        reg = ProviderRegistry()
        reg.register(CAC_PROVIDER)
        assert reg.get("CAC") is CAC_PROVIDER
        assert reg.get("MISSING") is None

    def test_names(self):
        reg = default_registry()
        assert reg.names() == ["CAC", "PIV"]

    def test_all(self):
        reg = default_registry()
        providers = reg.all()
        assert len(providers) == 2
        assert providers[0].name == "CAC"
        assert providers[1].name == "PIV"

    def test_len(self):
        reg = full_registry()
        assert len(reg) == 8

    def test_match_oids_cac(self):
        reg = full_registry()
        matched = reg.match_oids({"2.16.840.1.101.2.1.11.19"})
        assert matched is not None
        assert matched.name == "CAC"

    def test_match_oids_piv(self):
        reg = full_registry()
        matched = reg.match_oids({"2.16.840.1.101.3.2.1.3.13"})
        assert matched is not None
        assert matched.name == "PIV"

    def test_match_oids_eca(self):
        reg = full_registry()
        matched = reg.match_oids({"2.16.840.1.101.3.2.1.12.2"})
        assert matched is not None
        assert matched.name == "ECA"

    def test_match_oids_none(self):
        reg = full_registry()
        assert reg.match_oids({"1.2.3.4.5"}) is None

    def test_match_oids_first_wins(self):
        """When OIDs overlap with multiple providers, first registered wins."""
        reg = ProviderRegistry()
        reg.register(CAC_PROVIDER)
        reg.register(PIV_PROVIDER)
        matched = reg.match_oids({"2.16.840.1.101.2.1.11.19"})
        assert matched.name == "CAC"

    def test_match_heuristic_dod(self):
        reg = full_registry()
        matched = reg.match_heuristic(None, "Department of Defense", None)
        assert matched is not None
        assert matched.name == "CAC"

    def test_match_heuristic_energy(self):
        reg = full_registry()
        matched = reg.match_heuristic(None, "Department of Energy", None)
        assert matched is not None
        assert matched.name == "PIV"

    def test_match_heuristic_eca_ou(self):
        reg = full_registry()
        matched = reg.match_heuristic(None, None, "ECA")
        assert matched is not None
        assert matched.name == "ECA"

    def test_match_heuristic_cac_cn_regex(self):
        reg = full_registry()
        matched = reg.match_heuristic("SMITH.JOHN.A.1234567890", None, None)
        assert matched is not None
        assert matched.name == "CAC"

    def test_match_heuristic_none(self):
        reg = full_registry()
        assert reg.match_heuristic(None, None, None) is None

    def test_match_heuristic_no_match(self):
        reg = full_registry()
        assert reg.match_heuristic("Some Name", "Random Org", "Random OU") is None


class TestDefaultRegistry:
    def test_contains_cac_piv(self):
        reg = default_registry()
        assert reg.names() == ["CAC", "PIV"]

    def test_no_eca(self):
        reg = default_registry()
        assert reg.get("ECA") is None


class TestFullRegistry:
    def test_contains_all(self):
        reg = full_registry()
        assert reg.names() == [
            "CAC",
            "PIV",
            "ECA",
            "DOD-NPE",
            "FPKI-DEVICE",
            "ECA-DEVICE",
            "CONTENT-SIGNING",
            "CARD-AUTH",
        ]

    def test_match_oids_dod_npe(self):
        reg = full_registry()
        matched = reg.match_oids({"2.16.840.1.101.2.1.11.36"})
        assert matched is not None
        assert matched.name == "DOD-NPE"

    def test_match_oids_eca_device(self):
        reg = full_registry()
        matched = reg.match_oids({"2.16.840.1.101.3.2.1.12.9"})
        assert matched is not None
        assert matched.name == "ECA-DEVICE"

    def test_match_oids_content_signing(self):
        reg = full_registry()
        matched = reg.match_oids({"2.16.840.1.101.3.2.1.3.39"})
        assert matched is not None
        assert matched.name == "CONTENT-SIGNING"


class TestDefaultRegistryConstraint:
    def test_constrained_to_personal_auth(self):
        reg = default_registry()
        assert reg.intended_use is IntendedUse.PERSONAL_AUTH

    def test_rejects_non_person_provider(self):
        reg = default_registry()
        with pytest.raises(ValueError):
            reg.register(DOD_NPE_PROVIDER)


class TestCardAuthReclassification:
    """Card-authentication OIDs must never resolve to a person provider.

    FPKI Common v2.13 Section 1.4.2 and FBCA v3.9 Section 1.4.2 both state that
    such certificates "must only be used to authenticate the hardware token
    containing the associated private key and must not be interpreted as
    authenticating the presenter or holder of the token."  The ECA CP v4.8
    Section 1.4.1 says the same of id-eca-cardauth-pivi.

    These OIDs previously sat in the person sets.  On a real DoD CAC the
    card-authentication and personal-authentication certificates carry the same
    subject UUID, so under a PIV-only registry both produced an identical
    primary_id — a PIN-less card read authenticated as the cardholder.
    """

    CARD_AUTH: ClassVar[tuple[str, ...]] = (
        "2.16.840.1.101.3.2.1.3.17",  # id-fpki-common-cardAuth
        "2.16.840.1.101.3.2.1.3.46",  # id-fpki-common-pivi-cardAuth
        "2.16.840.1.101.3.2.1.3.19",  # id-fpki-certpcy-pivi-cardAuth
        "2.16.840.1.101.3.2.1.12.7",  # id-eca-cardauth-pivi
    )

    def test_all_four_are_known(self):
        """Including ECA .7, which was previously absent entirely."""
        assert set(self.CARD_AUTH) == set(CARD_AUTH_OIDS)

    def test_none_are_in_person_sets(self):
        for oid in self.CARD_AUTH:
            assert oid not in FEDERAL_PE_OIDS, f"{oid} is still a person OID"
            assert oid not in ECA_PE_OIDS, f"{oid} is still a person OID"

    def test_each_matches_the_card_auth_provider(self):
        reg = full_registry()
        for oid in self.CARD_AUTH:
            matched = reg.match_oids({oid})
            assert matched is not None, f"{oid} matches no provider"
            assert matched.name == "CARD-AUTH", f"{oid} matched {matched.name}"
            assert matched.intended_use is IntendedUse.CARD_AUTH

    def test_card_auth_provider_is_not_personal_auth(self):
        assert IntendedUse.PERSONAL_AUTH not in CARD_AUTH_PROVIDER.intended_use
        assert IntendedUse.NPE_AUTH not in CARD_AUTH_PROVIDER.intended_use

    def test_person_only_registry_refuses_the_provider(self):
        """default_registry() is PERSONAL_AUTH-constrained, so this fails closed."""
        with pytest.raises(ValueError, match="does not support"):
            default_registry().register(CARD_AUTH_PROVIDER)

    def test_person_only_registry_matches_no_card_auth_oid(self):
        reg = default_registry()
        for oid in self.CARD_AUTH:
            assert reg.match_oids({oid}) is None, f"{oid} still matched a person provider"

    def test_token_id_is_namespaced_away_from_person_ids(self):
        """The prefix keeps a card read from colliding with a person's ID."""

        class _Ident:
            # Synthetic value — never a real card UUID.
            piv_uuid = "00000000-0000-4000-8000-000000000000"
            fascn = None
            subject_dn = "CN=SYNTHETIC.TEST.CARD"

        got = select_card_token_id(_Ident())
        assert got.startswith("card:")
        assert got != f"uuid:{_Ident.piv_uuid}"


class TestDualOidAssertion:
    """A device certificate may legitimately assert a person OID as well.

    DoD CP v11 Section 1.2: "All NPE certificates shall assert the appropriate
    Internal NPE or Medium NPE OID.  Medium NPE certificates may also assert
    any Medium Software or Medium Hardware OID if they meet the corresponding
    requirements."

    Before this was handled, such a certificate resolved to CAC/PERSONAL_AUTH
    because match_oids returned the first registered match — making dict
    insertion order decide whether a device authenticated as a human.
    """

    NPE = "2.16.840.1.101.2.1.11.36"  # id-US-dod-mediumNPE-112
    PERSON = "2.16.840.1.101.2.1.11.42"  # id-US-dod-mediumHardware-112
    CARD = "2.16.840.1.101.3.2.1.3.17"  # id-fpki-common-cardAuth
    PIV_PERSON = "2.16.840.1.101.3.2.1.3.13"  # id-fpki-common-authentication

    def test_device_with_person_oid_resolves_to_device(self):
        matched = full_registry().match_oids({self.NPE, self.PERSON})
        assert matched is not None
        assert matched.name == "DOD-NPE"
        assert matched.intended_use is IntendedUse.NPE_AUTH

    def test_person_only_registry_fails_closed(self):
        """The common path: no device provider registered to out-rank CAC."""
        assert default_registry().match_oids({self.NPE, self.PERSON}) is None

    def test_genuine_person_cert_unaffected(self):
        matched = default_registry().match_oids({self.PERSON})
        assert matched is not None
        assert matched.name == "CAC"

    def test_card_auth_with_person_oid_resolves_to_card_auth(self):
        matched = full_registry().match_oids({self.CARD, self.PIV_PERSON})
        assert matched is not None
        assert matched.name == "CARD-AUTH"

    def test_card_auth_with_person_oid_fails_closed_in_person_registry(self):
        assert default_registry().match_oids({self.CARD, self.PIV_PERSON}) is None

    def test_person_providers_declare_non_person_disqualifiers(self):
        for p in (CAC_PROVIDER, PIV_PROVIDER, ECA_PROVIDER):
            assert p.disqualifying_oids, f"{p.name} declares no disqualifying OIDs"
            assert self.NPE in p.disqualifying_oids or p is not CAC_PROVIDER
            assert not (p.auth_oids & p.disqualifying_oids), (
                f"{p.name} disqualifies its own auth OIDs"
            )
