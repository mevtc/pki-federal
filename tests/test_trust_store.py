"""Tests for pki.federal.trust_store module.

All network calls are mocked — no real downloads occur.
"""

from unittest.mock import patch

import pytest

from pki.federal.trust_store import (
    build_ca_bundle,
    fetch_dod_certs,
    fetch_fpki_certs,
)

# ---------------------------------------------------------------------------
# fetch_dod_certs
# ---------------------------------------------------------------------------


class TestFetchDodCerts:
    """Test DoD cert fetching via pki-core's fetch_trust_store_source."""

    @patch("pki.federal.trust_store.fetch_trust_store_source")
    def test_returns_certs_from_cac_sources(self, mock_fetch, ca_cert):
        mock_fetch.return_value = [ca_cert]

        certs = fetch_dod_certs()

        assert len(certs) == 1
        assert certs[0].serial_number == ca_cert.serial_number
        mock_fetch.assert_called_once()

    @patch("pki.federal.trust_store.fetch_trust_store_source")
    def test_empty_source_returns_empty(self, mock_fetch):
        mock_fetch.return_value = []

        certs = fetch_dod_certs()

        assert len(certs) == 0


# ---------------------------------------------------------------------------
# fetch_fpki_certs
# ---------------------------------------------------------------------------


class TestFetchFpkiCerts:
    """Test Federal PKI cert fetching."""

    @patch("pki.federal.trust_store.fetch_trust_store_source")
    def test_fetches_all_piv_sources(self, mock_fetch, ca_cert):
        mock_fetch.return_value = [ca_cert]

        certs = fetch_fpki_certs()

        # PIV_PROVIDER has 3 trust_store_sources
        assert mock_fetch.call_count == 3
        assert len(certs) == 3

    @patch("pki.federal.trust_store.fetch_trust_store_source")
    def test_multiple_certs_per_source(self, mock_fetch, ca_cert, cac_cert):
        mock_fetch.return_value = [ca_cert, cac_cert]

        certs = fetch_fpki_certs()

        # 2 certs x 3 sources = 6
        assert len(certs) == 6


# ---------------------------------------------------------------------------
# build_ca_bundle
# ---------------------------------------------------------------------------


class TestBuildCaBundle:
    """Test the convenience bundle builder."""

    @patch("pki.federal.trust_store.build_ca_bundle_for_providers")
    def test_delegates_to_core(self, mock_build):
        pem_text = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
        mock_build.return_value = (pem_text, {"total": 1, "unique": 1})

        pem, stats = build_ca_bundle()

        assert "BEGIN CERTIFICATE" in pem
        assert stats["total"] == 1
        mock_build.assert_called_once()

    @patch("pki.federal.trust_store.build_ca_bundle_for_providers")
    def test_passes_output_path(self, mock_build):
        mock_build.return_value = ("pem", {"total": 1})

        build_ca_bundle(output_path="/tmp/test.pem")

        call_kwargs = mock_build.call_args
        assert call_kwargs[1]["output_path"] == "/tmp/test.pem"

    @patch("pki.federal.trust_store.build_ca_bundle_for_providers")
    def test_passes_filter_fn(self, mock_build):
        mock_build.return_value = ("pem", {"total": 1})

        def my_filter(cert):
            return True

        build_ca_bundle(filter_fn=my_filter)

        call_kwargs = mock_build.call_args
        assert call_kwargs[1]["filter_fn"] is my_filter

    @patch("pki.federal.trust_store.build_ca_bundle_for_providers")
    def test_raises_when_core_raises(self, mock_build):
        mock_build.side_effect = RuntimeError("No certificates fetched")

        with pytest.raises(RuntimeError, match="No certificates fetched"):
            build_ca_bundle()
