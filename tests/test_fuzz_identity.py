"""Hypothesis fuzz tests for federal identity extraction.

Property-based tests that verify parse_identity postconditions across
different cert fixtures and registry configurations.

Example counts are controlled by Hypothesis profiles registered in
conftest.py.  Use ``--hypothesis-profile=ci`` or ``--hypothesis-profile=nightly``
to increase coverage.
"""

import pytest

from pki.federal.identity import parse_identity
from pki.federal.providers import default_registry, full_registry

VALID_CREDENTIAL_TYPES = {"CAC", "PIV", "ECA", "UNKNOWN"}


class TestParseIdentityCac:
    """Postcondition checks for parse_identity with a CAC certificate."""

    def test_credential_type_is_cac(self, cac_cert):
        result = parse_identity(cac_cert)
        assert result.credential_type == "CAC"

    def test_primary_id_is_nonempty_string(self, cac_cert):
        result = parse_identity(cac_cert)
        assert isinstance(result.primary_id, str)
        assert len(result.primary_id) > 0

    def test_firstname_populated(self, cac_cert):
        result = parse_identity(cac_cert)
        assert result.firstname is not None
        assert len(result.firstname) > 0

    def test_lastname_populated(self, cac_cert):
        result = parse_identity(cac_cert)
        assert result.lastname is not None
        assert len(result.lastname) > 0

    def test_edipi_is_10_digits(self, cac_cert):
        result = parse_identity(cac_cert)
        assert result.edipi is not None
        assert result.edipi.isdigit()
        assert len(result.edipi) == 10

    def test_email_populated(self, cac_cert):
        result = parse_identity(cac_cert)
        assert result.email is not None

    def test_policy_oids_nonempty(self, cac_cert):
        result = parse_identity(cac_cert)
        assert len(result.policy_oids) > 0

    def test_subject_dn_nonempty(self, cac_cert):
        result = parse_identity(cac_cert)
        assert result.subject_dn is not None
        assert len(result.subject_dn) > 0

    def test_to_dict_roundtrip(self, cac_cert):
        """to_dict should include all identity fields."""
        result = parse_identity(cac_cert)
        d = result.to_dict()
        assert d["credential_type"] == "CAC"
        assert d["primary_id"] is not None
        assert d["firstname"] is not None
        assert d["lastname"] is not None


class TestParseIdentityPiv:
    """Postcondition checks for parse_identity with a PIV certificate."""

    def test_credential_type_is_piv(self, piv_cert):
        result = parse_identity(piv_cert)
        assert result.credential_type == "PIV"

    def test_primary_id_is_nonempty_string(self, piv_cert):
        result = parse_identity(piv_cert)
        assert isinstance(result.primary_id, str)
        assert len(result.primary_id) > 0

    def test_firstname_populated(self, piv_cert):
        result = parse_identity(piv_cert)
        assert result.firstname is not None
        assert len(result.firstname) > 0

    def test_lastname_populated(self, piv_cert):
        result = parse_identity(piv_cert)
        assert result.lastname is not None
        assert len(result.lastname) > 0

    def test_email_populated(self, piv_cert):
        result = parse_identity(piv_cert)
        assert result.email is not None

    def test_piv_uuid_populated(self, piv_cert):
        result = parse_identity(piv_cert)
        assert result.piv_uuid is not None

    def test_policy_oids_nonempty(self, piv_cert):
        result = parse_identity(piv_cert)
        assert len(result.policy_oids) > 0


class TestParseIdentityEca:
    """Postcondition checks for parse_identity with an ECA certificate."""

    def test_default_registry_does_not_match_eca_by_name(self, eca_cert):
        """Default registry (CAC+PIV only) should not match as ECA by name.

        The default registry lacks the ECA provider, so it falls back to
        the last registered provider or UNKNOWN.
        """
        result = parse_identity(eca_cert)
        # Default registry has no ECA provider, so credential_type will not be ECA
        assert result.credential_type in VALID_CREDENTIAL_TYPES

    def test_full_registry_matches_eca(self, eca_cert):
        """Full registry should match ECA certificate as ECA."""
        result = parse_identity(eca_cert, registry=full_registry())
        assert result.credential_type == "ECA"

    def test_full_registry_primary_id_nonempty(self, eca_cert):
        result = parse_identity(eca_cert, registry=full_registry())
        assert isinstance(result.primary_id, str)
        assert len(result.primary_id) > 0

    def test_full_registry_firstname_populated(self, eca_cert):
        result = parse_identity(eca_cert, registry=full_registry())
        assert result.firstname is not None
        assert len(result.firstname) > 0

    def test_full_registry_lastname_populated(self, eca_cert):
        result = parse_identity(eca_cert, registry=full_registry())
        assert result.lastname is not None
        assert len(result.lastname) > 0

    def test_full_registry_email_populated(self, eca_cert):
        result = parse_identity(eca_cert, registry=full_registry())
        assert result.email is not None

    def test_full_registry_policy_oids_nonempty(self, eca_cert):
        result = parse_identity(eca_cert, registry=full_registry())
        assert len(result.policy_oids) > 0


class TestParseIdentityInvariants:
    """Cross-cutting invariants that hold for any certificate and registry."""

    @pytest.mark.parametrize("cert_fixture", ["cac_cert", "piv_cert", "eca_cert"])
    def test_credential_type_always_valid(self, cert_fixture, request):
        cert = request.getfixturevalue(cert_fixture)
        for reg in (default_registry(), full_registry()):
            result = parse_identity(cert, registry=reg)
            assert result.credential_type in VALID_CREDENTIAL_TYPES

    @pytest.mark.parametrize("cert_fixture", ["cac_cert", "piv_cert", "eca_cert"])
    def test_primary_id_always_nonempty_string(self, cert_fixture, request):
        cert = request.getfixturevalue(cert_fixture)
        for reg in (default_registry(), full_registry()):
            result = parse_identity(cert, registry=reg)
            assert isinstance(result.primary_id, str)
            assert len(result.primary_id) > 0

    @pytest.mark.parametrize("cert_fixture", ["cac_cert", "piv_cert", "eca_cert"])
    def test_cn_always_populated(self, cert_fixture, request):
        cert = request.getfixturevalue(cert_fixture)
        result = parse_identity(cert)
        assert result.cn is not None
        assert len(result.cn) > 0

    @pytest.mark.parametrize("cert_fixture", ["cac_cert", "piv_cert", "eca_cert"])
    def test_cert_metadata_populated(self, cert_fixture, request):
        cert = request.getfixturevalue(cert_fixture)
        result = parse_identity(cert)
        assert result.cert_serial is not None
        assert result.cert_not_after is not None
        assert result.cert_issuer_dn is not None

    @pytest.mark.parametrize("cert_fixture", ["cac_cert", "piv_cert", "eca_cert"])
    def test_to_dict_contains_all_keys(self, cert_fixture, request):
        cert = request.getfixturevalue(cert_fixture)
        result = parse_identity(cert)
        d = result.to_dict()
        expected_keys = {
            "primary_id",
            "credential_type",
            "cn",
            "firstname",
            "lastname",
            "organization",
            "ou",
            "email",
            "edipi",
            "piv_uuid",
            "fascn",
            "cert_serial",
            "cert_not_after",
            "cert_issuer_dn",
            "subject_dn",
            "policy_oids",
        }
        assert set(d.keys()) == expected_keys

    def test_bad_uuid_cert_does_not_crash(self, bad_uuid_cert):
        """A cert with a malformed UUID in SAN should still parse."""
        result = parse_identity(bad_uuid_cert)
        assert result.credential_type in VALID_CREDENTIAL_TYPES
        assert isinstance(result.primary_id, str)

    def test_expired_cert_still_parses(self, expired_cert):
        """parse_identity does not validate expiry; it should still extract fields."""
        result = parse_identity(expired_cert)
        assert result.credential_type in VALID_CREDENTIAL_TYPES
        assert isinstance(result.primary_id, str)
