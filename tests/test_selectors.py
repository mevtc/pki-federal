"""Tests for pki.federal.selectors module."""

from pki.core.identity import CertIdentity
from pki.federal.selectors import select_cn_first


class TestSelectCnFirst:
    def test_prefers_cn(self):
        identity = CertIdentity(cn="athocalerts.com", subject_dn="CN=athocalerts.com,OU=ECA")
        assert select_cn_first(identity) == "cn:athocalerts.com"

    def test_falls_back_to_dn_when_no_cn(self):
        identity = CertIdentity(cn=None, subject_dn="OU=Devices,O=Example")
        assert select_cn_first(identity) == "dn:OU=Devices,O=Example"

    def test_ignores_person_fields(self):
        """A device selector must not key off EDIPI / email / UUID."""
        identity = CertIdentity(
            cn="host.example.mil",
            edipi="1234567890",
            email="ignored@example.mil",
            subject_dn="CN=host.example.mil",
        )
        assert select_cn_first(identity) == "cn:host.example.mil"
