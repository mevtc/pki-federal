"""Tests for pki.federal.oids — structure and CP-classification invariants.

These assert that the OID-to-use partitioning matches the certificate-policy
citations in docs/cp-policy-table.md and, critically, that no device (NPE) or
content-signing policy leaks into a person (PE) set.
"""

from pki.federal.oids import (
    DOD_NPE_OIDS,
    DOD_PE_OIDS,
    ECA_NPE_OIDS,
    ECA_OBJECT_SIGNING_OIDS,
    ECA_PE_OIDS,
    FBCA_NPE_OIDS,
    FBCA_OBJECT_SIGNING_OIDS,
    FBCA_PE_OIDS,
    FEDERAL_NPE_OIDS,
    FEDERAL_PE_OIDS,
    FPKI_NPE_OIDS,
    FPKI_OBJECT_SIGNING_OIDS,
    FPKI_PE_OIDS,
    OBJECT_SIGNING_OIDS,
)

DOD_ARC = "2.16.840.1.101.2.1.11."
FPKI_ARC = "2.16.840.1.101.3.2.1.3."
ECA_ARC = "2.16.840.1.101.3.2.1.12."


class TestArcMembership:
    def test_dod_sets_use_dod_arc(self):
        for oid in DOD_PE_OIDS | DOD_NPE_OIDS:
            assert oid.startswith(DOD_ARC), oid

    def test_fpki_fbca_sets_use_fpki_arc(self):
        federal = (
            FPKI_PE_OIDS
            | FPKI_NPE_OIDS
            | FPKI_OBJECT_SIGNING_OIDS
            | FBCA_PE_OIDS
            | FBCA_NPE_OIDS
            | FBCA_OBJECT_SIGNING_OIDS
        )
        for oid in federal:
            assert oid.startswith(FPKI_ARC), oid

    def test_eca_sets_use_eca_arc(self):
        for oid in ECA_PE_OIDS | ECA_NPE_OIDS | ECA_OBJECT_SIGNING_OIDS:
            assert oid.startswith(ECA_ARC), oid


class TestDisjointness:
    def test_dod_pe_and_npe_disjoint(self):
        assert DOD_PE_OIDS.isdisjoint(DOD_NPE_OIDS)

    def test_fpki_uses_disjoint(self):
        assert FPKI_PE_OIDS.isdisjoint(FPKI_NPE_OIDS)
        assert FPKI_PE_OIDS.isdisjoint(FPKI_OBJECT_SIGNING_OIDS)
        assert FPKI_NPE_OIDS.isdisjoint(FPKI_OBJECT_SIGNING_OIDS)

    def test_fpki_and_fbca_suffixes_disjoint(self):
        """FPKI id-fpki-common-* and FBCA id-fpki-certpcy-* share the numeric
        arc but must use disjoint suffixes."""
        fpki = FPKI_PE_OIDS | FPKI_NPE_OIDS | FPKI_OBJECT_SIGNING_OIDS
        fbca = FBCA_PE_OIDS | FBCA_NPE_OIDS | FBCA_OBJECT_SIGNING_OIDS
        assert fpki.isdisjoint(fbca)

    def test_eca_uses_disjoint(self):
        assert ECA_PE_OIDS.isdisjoint(ECA_NPE_OIDS)
        assert ECA_PE_OIDS.isdisjoint(ECA_OBJECT_SIGNING_OIDS)
        assert ECA_NPE_OIDS.isdisjoint(ECA_OBJECT_SIGNING_OIDS)

    def test_person_sets_have_no_device_or_signing_oids(self):
        all_pe = DOD_PE_OIDS | FEDERAL_PE_OIDS | ECA_PE_OIDS
        all_non_pe = DOD_NPE_OIDS | FEDERAL_NPE_OIDS | set(OBJECT_SIGNING_OIDS) | ECA_NPE_OIDS
        assert all_pe.isdisjoint(all_non_pe)


class TestKnownOids:
    def test_dod_npe_112_present(self):
        # id-US-dod-mediumNPE-112 was previously mislabeled as a person policy.
        assert "2.16.840.1.101.2.1.11.36" in DOD_NPE_OIDS

    def test_fbca_medium_hardware_present(self):
        # id-fpki-certpcy-mediumHardware (FBCA CP) — previously mislabeled.
        assert "2.16.840.1.101.3.2.1.3.12" in FBCA_PE_OIDS

    def test_fpki_content_signing_is_39_not_40(self):
        assert "2.16.840.1.101.3.2.1.3.39" in FPKI_OBJECT_SIGNING_OIDS
        # .40 is id-fpki-common-derived-pivAuth, a PERSON auth policy.
        assert "2.16.840.1.101.3.2.1.3.40" in FPKI_PE_OIDS
        assert "2.16.840.1.101.3.2.1.3.40" not in FPKI_OBJECT_SIGNING_OIDS

    def test_eca_device_and_content_signing_split(self):
        assert "2.16.840.1.101.3.2.1.12.9" in ECA_NPE_OIDS
        assert "2.16.840.1.101.3.2.1.12.8" in ECA_OBJECT_SIGNING_OIDS

    def test_eca_suffix_7_unassigned(self):
        all_eca = ECA_PE_OIDS | ECA_NPE_OIDS | ECA_OBJECT_SIGNING_OIDS
        assert "2.16.840.1.101.3.2.1.12.7" not in all_eca

    def test_aggregate_sets(self):
        assert frozenset(FPKI_PE_OIDS | FBCA_PE_OIDS) == FEDERAL_PE_OIDS
        assert frozenset(FPKI_NPE_OIDS | FBCA_NPE_OIDS) == FEDERAL_NPE_OIDS
        assert (
            frozenset(FPKI_OBJECT_SIGNING_OIDS | FBCA_OBJECT_SIGNING_OIDS | ECA_OBJECT_SIGNING_OIDS)
            == OBJECT_SIGNING_OIDS
        )
