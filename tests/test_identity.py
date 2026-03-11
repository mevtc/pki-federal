"""Tests for federal_pki.identity module."""

from federal_pki.identity import (
    CertIdentity,
    guess_credential_type,
    parse_cac_identity,
    parse_identity,
    parse_piv_identity,
)
from federal_pki.providers import full_registry


class TestParseIdentity:
    def test_cac_cert(self, cac_cert):
        identity = parse_identity(cac_cert)
        assert identity.credential_type == "CAC"
        assert identity.cn == "SMITH.JOHN.A.1234567890"
        assert identity.edipi == "1234567890"
        assert identity.firstname == "JOHN"
        assert identity.lastname == "SMITH"
        assert identity.email == "john.smith@mail.mil"
        assert identity.primary_id == "edipi:1234567890"
        assert "2.16.840.1.101.2.1.11.19" in identity.policy_oids

    def test_piv_cert(self, piv_cert):
        identity = parse_identity(piv_cert)
        assert identity.credential_type == "PIV"
        assert identity.cn == "JONES, ALICE M"
        assert identity.firstname == "ALICE"
        assert identity.lastname == "JONES"
        assert identity.email == "alice.jones@doe.gov"
        assert identity.piv_uuid == "12345678-abcd-ef01-2345-6789abcdef01"
        assert identity.primary_id == "uuid:12345678-abcd-ef01-2345-6789abcdef01"

    def test_eca_cert(self, eca_cert):
        registry = full_registry()
        identity = parse_identity(eca_cert, registry=registry)
        assert identity.credential_type == "ECA"
        assert identity.cn == "John A. Smith"
        assert identity.firstname == "John"
        assert identity.lastname == "Smith"
        assert identity.email == "john.smith@contractor.com"
        assert identity.primary_id == "email:john.smith@contractor.com"
        assert "2.16.840.1.101.3.2.1.12.2" in identity.policy_oids

    def test_eca_not_matched_by_default_registry(self, eca_cert):
        """Default registry (CAC+PIV only) should not identify as ECA."""
        identity = parse_identity(eca_cert)
        assert identity.credential_type != "ECA"

    def test_to_dict(self, cac_cert):
        identity = parse_identity(cac_cert)
        d = identity.to_dict()
        assert d["edipi"] == "1234567890"
        assert d["credential_type"] == "CAC"
        assert isinstance(d["policy_oids"], list)


class TestParseCacIdentity:
    def test_standard_format(self):
        identity = CertIdentity(cn="DOE.JANE.B.9876543210")
        parse_cac_identity(identity)
        assert identity.edipi == "9876543210"
        assert identity.lastname == "DOE"
        assert identity.firstname == "JANE"

    def test_short_cn(self):
        identity = CertIdentity(cn="LASTNAME.FIRSTNAME")
        parse_cac_identity(identity)
        assert identity.edipi is None
        assert identity.lastname == "LASTNAME"
        assert identity.firstname == "FIRSTNAME"

    def test_single_name(self):
        identity = CertIdentity(cn="ONLYNAME")
        parse_cac_identity(identity)
        assert identity.lastname == "ONLYNAME"

    def test_none_cn(self):
        identity = CertIdentity(cn=None)
        parse_cac_identity(identity)
        assert identity.lastname is None


class TestParsePivIdentity:
    def test_comma_format(self):
        identity = CertIdentity(cn="SMITH, JOHN A")
        parse_piv_identity(identity)
        assert identity.lastname == "SMITH"
        assert identity.firstname == "JOHN"

    def test_space_format(self):
        identity = CertIdentity(cn="John Adam Smith")
        parse_piv_identity(identity)
        assert identity.firstname == "John"
        assert identity.lastname == "Smith"

    def test_dot_format_with_number(self):
        identity = CertIdentity(cn="SMITH.JOHN.A.1234567890")
        parse_piv_identity(identity)
        assert identity.lastname == "SMITH"
        assert identity.firstname == "JOHN"
        assert identity.edipi == "1234567890"

    def test_single_name(self):
        identity = CertIdentity(cn="Mononym")
        parse_piv_identity(identity)
        assert identity.lastname == "Mononym"


class TestGuessCredentialType:
    def test_dod_org(self):
        assert guess_credential_type(None, "Department of Defense") == "CAC"

    def test_cac_cn_pattern(self):
        assert guess_credential_type("SMITH.JOHN.A.1234567890", None) == "CAC"

    def test_doe_org(self):
        assert guess_credential_type(None, "Department of Energy") == "PIV"

    def test_nnsa_org(self):
        assert guess_credential_type(None, "NNSA Labs") == "PIV"

    def test_default_piv(self):
        assert guess_credential_type("Some User", "Some Agency") == "PIV"
