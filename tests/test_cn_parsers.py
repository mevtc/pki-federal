"""Tests for federal_pki.cn_parsers module."""

from federal_pki.cn_parsers import (
    _parse_cac_dot,
    _parse_eca_human,
    _parse_piv_flexible,
    parse_cn,
)
from federal_pki.identity import CertIdentity
from federal_pki.providers import CNParseStrategy


class TestParseCnDispatch:
    def test_dispatch_cac(self):
        identity = CertIdentity(cn="DOE.JANE.B.9876543210")
        parse_cn(identity, CNParseStrategy.CAC_DOT)
        assert identity.edipi == "9876543210"
        assert identity.lastname == "DOE"

    def test_dispatch_piv(self):
        identity = CertIdentity(cn="SMITH, JOHN A")
        parse_cn(identity, CNParseStrategy.PIV_FLEXIBLE)
        assert identity.lastname == "SMITH"
        assert identity.firstname == "JOHN"

    def test_dispatch_eca(self):
        identity = CertIdentity(cn="John A. Smith")
        parse_cn(identity, CNParseStrategy.ECA_HUMAN)
        assert identity.firstname == "John"
        assert identity.lastname == "Smith"


class TestParseCacDot:
    def test_standard_format(self):
        identity = CertIdentity(cn="DOE.JANE.B.9876543210")
        _parse_cac_dot(identity)
        assert identity.edipi == "9876543210"
        assert identity.lastname == "DOE"
        assert identity.firstname == "JANE"

    def test_short_cn(self):
        identity = CertIdentity(cn="LASTNAME.FIRSTNAME")
        _parse_cac_dot(identity)
        assert identity.edipi is None
        assert identity.lastname == "LASTNAME"
        assert identity.firstname == "FIRSTNAME"

    def test_single_name(self):
        identity = CertIdentity(cn="ONLYNAME")
        _parse_cac_dot(identity)
        assert identity.lastname == "ONLYNAME"

    def test_none_cn(self):
        identity = CertIdentity(cn=None)
        _parse_cac_dot(identity)
        assert identity.lastname is None


class TestParsePivFlexible:
    def test_comma_format(self):
        identity = CertIdentity(cn="SMITH, JOHN A")
        _parse_piv_flexible(identity)
        assert identity.lastname == "SMITH"
        assert identity.firstname == "JOHN"

    def test_space_format(self):
        identity = CertIdentity(cn="John Adam Smith")
        _parse_piv_flexible(identity)
        assert identity.firstname == "John"
        assert identity.lastname == "Smith"

    def test_dot_format_with_number(self):
        identity = CertIdentity(cn="SMITH.JOHN.A.1234567890")
        _parse_piv_flexible(identity)
        assert identity.lastname == "SMITH"
        assert identity.firstname == "JOHN"
        assert identity.edipi == "1234567890"

    def test_single_name(self):
        identity = CertIdentity(cn="Mononym")
        _parse_piv_flexible(identity)
        assert identity.lastname == "Mononym"

    def test_none_cn(self):
        identity = CertIdentity(cn=None)
        _parse_piv_flexible(identity)
        assert identity.lastname is None


class TestParseEcaHuman:
    def test_first_middle_last(self):
        identity = CertIdentity(cn="John A. Smith")
        _parse_eca_human(identity)
        assert identity.firstname == "John"
        assert identity.lastname == "Smith"

    def test_first_last(self):
        identity = CertIdentity(cn="Jane Doe")
        _parse_eca_human(identity)
        assert identity.firstname == "Jane"
        assert identity.lastname == "Doe"

    def test_comma_format(self):
        identity = CertIdentity(cn="SMITH, JOHN")
        _parse_eca_human(identity)
        assert identity.lastname == "SMITH"
        assert identity.firstname == "JOHN"

    def test_single_name(self):
        identity = CertIdentity(cn="Mononym")
        _parse_eca_human(identity)
        assert identity.lastname == "Mononym"

    def test_none_cn(self):
        identity = CertIdentity(cn=None)
        _parse_eca_human(identity)
        assert identity.lastname is None