"""Tests for federal_pki.crl module."""

import time
from pathlib import Path

from federal_pki.certificate import CertificateError
from federal_pki.crl import (
    CRLConfig,
    get_crl_distribution_points,
    get_crl_max_age,
    parse_crl_bytes,
)


class TestGetCrlDistributionPoints:
    def test_cert_with_cdp(self, cac_cert):
        urls = get_crl_distribution_points(cac_cert)
        assert urls == ["http://crl.test.example/test.crl"]

    def test_cert_without_cdp(self, ca_cert):
        urls = get_crl_distribution_points(ca_cert)
        assert urls == []


class TestParseCrlBytes:
    def test_parse_der(self, test_crl_der):
        crl = parse_crl_bytes(test_crl_der)
        assert crl is not None

    def test_parse_pem(self, test_crl_pem):
        crl = parse_crl_bytes(test_crl_pem)
        assert crl is not None

    def test_parse_garbage_raises(self):
        try:
            parse_crl_bytes(b"not a crl")
            assert False, "Should have raised"
        except CertificateError:
            pass


class TestCrlRevocation:
    def test_revoked_serial_in_crl(self, test_crl, revoked_serial):
        entry = test_crl.get_revoked_certificate_by_serial_number(revoked_serial)
        assert entry is not None

    def test_non_revoked_serial(self, test_crl):
        entry = test_crl.get_revoked_certificate_by_serial_number(999999)
        assert entry is None


class TestGetCrlMaxAge:
    def test_no_cdp(self, ca_cert):
        config = CRLConfig(cache_dir="/tmp/test-crls")
        result = get_crl_max_age(ca_cert, config)
        assert result is None

    def test_no_cache_returns_inf(self, cac_cert, tmp_path):
        config = CRLConfig(cache_dir=str(tmp_path / "empty"))
        result = get_crl_max_age(cac_cert, config)
        assert result == float("inf")

    def test_cached_crl_returns_age(self, cac_cert, tmp_path, test_crl_der):
        import hashlib

        config = CRLConfig(cache_dir=str(tmp_path))
        url = "http://crl.test.example/test.crl"
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
        cache_file = tmp_path / f"{url_hash}.crl"
        cache_file.write_bytes(test_crl_der)

        age = get_crl_max_age(cac_cert, config)
        assert age is not None
        assert age >= 0
        assert age < 5  # just written