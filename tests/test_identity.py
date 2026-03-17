"""Tests for pki.federal.identity module."""

from pki.federal.identity import parse_identity
from pki.federal.providers import full_registry


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
