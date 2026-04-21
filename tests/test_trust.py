"""Tests for pki.federal.trust module — TrustLevel comparisons."""

from pki.federal.trust import CredentialType, TrustLevel


class TestTrustLevelComparisons:
    """Cover ordering via IntEnum integer values."""

    def test_high_gt_medium(self):
        assert TrustLevel.HIGH > TrustLevel.MEDIUM

    def test_medium_gt_basic(self):
        assert TrustLevel.MEDIUM > TrustLevel.BASIC

    def test_basic_gt_none(self):
        assert TrustLevel.BASIC > TrustLevel.NONE

    def test_none_lt_basic(self):
        assert TrustLevel.NONE < TrustLevel.BASIC

    def test_basic_lt_medium(self):
        assert TrustLevel.BASIC < TrustLevel.MEDIUM

    def test_medium_lt_high(self):
        assert TrustLevel.MEDIUM < TrustLevel.HIGH

    def test_high_ge_high(self):
        assert TrustLevel.HIGH >= TrustLevel.HIGH

    def test_high_ge_medium(self):
        assert TrustLevel.HIGH >= TrustLevel.MEDIUM

    def test_none_le_none(self):
        assert TrustLevel.NONE <= TrustLevel.NONE

    def test_none_le_basic(self):
        assert TrustLevel.NONE <= TrustLevel.BASIC

    def test_equal_not_lt(self):
        assert not (TrustLevel.HIGH < TrustLevel.HIGH)

    def test_equal_not_gt(self):
        assert not (TrustLevel.HIGH > TrustLevel.HIGH)

    def test_le_with_equal(self):
        assert TrustLevel.MEDIUM <= TrustLevel.MEDIUM

    def test_ge_with_equal(self):
        assert TrustLevel.MEDIUM >= TrustLevel.MEDIUM

    def test_integer_values(self):
        assert TrustLevel.NONE == 0
        assert TrustLevel.BASIC == 1
        assert TrustLevel.MEDIUM == 2
        assert TrustLevel.HIGH == 3


class TestCredentialType:
    def test_values(self):
        assert CredentialType.CAC == "CAC"
        assert CredentialType.PIV == "PIV"
        assert CredentialType.ECA == "ECA"
