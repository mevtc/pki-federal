"""Hypothesis fuzz tests for CN parsers.

Property-based tests that throw thousands of random strings at each CN
parser to verify they never crash, always leave the identity in a valid
state, and satisfy invariants about the relationship between input and
output.

Example counts are controlled by Hypothesis profiles registered in
conftest.py.  Use ``--hypothesis-profile=ci`` or ``--hypothesis-profile=nightly``
to increase coverage.
"""

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pki.core.identity import CertIdentity
from pki.federal.cn_parsers import (
    _parse_cac_dot,
    _parse_eca_human,
    _parse_piv_flexible,
)

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Arbitrary unicode text (the broadest case)
any_cn = st.one_of(st.none(), st.text(max_size=500))

# Text biased toward the separators the parsers actually use
structured_cn = st.one_of(
    # CAC-like: parts joined by dots, last part sometimes a 10-digit number
    st.builds(
        ".".join,
        st.lists(
            st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", min_size=0, max_size=20),
            min_size=0,
            max_size=6,
        ),
    ),
    # Comma-separated (PIV/ECA)
    st.builds(
        ", ".join,
        st.lists(st.text(min_size=0, max_size=30), min_size=1, max_size=4),
    ),
    # Space-separated
    st.builds(
        " ".join,
        st.lists(
            st.text(
                alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.",
                min_size=0,
                max_size=20,
            ),
            min_size=1,
            max_size=5,
        ),
    ),
    # With a trailing 10-digit EDIPI
    st.builds(
        lambda parts, edipi: ".".join([*parts, edipi]),
        st.lists(
            st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ", min_size=1, max_size=15),
            min_size=1,
            max_size=4,
        ),
        st.from_regex(r"[0-9]{10}", fullmatch=True),
    ),
)

cn_strategy = st.one_of(any_cn, structured_cn)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _identity_with_cn(cn: str | None) -> CertIdentity:
    return CertIdentity(cn=cn)


def _assert_common_postconditions(identity: CertIdentity, cn: str | None) -> None:
    """Invariants that must hold after any parser runs."""
    # firstname and lastname must be str or None
    assert identity.firstname is None or isinstance(identity.firstname, str)
    assert identity.lastname is None or isinstance(identity.lastname, str)
    assert identity.edipi is None or isinstance(identity.edipi, str)

    # If CN was None, nothing should have been set
    if cn is None:
        assert identity.firstname is None
        assert identity.lastname is None
        assert identity.edipi is None

    # If EDIPI was set, it must be a 10-digit string
    if identity.edipi is not None:
        assert identity.edipi.isdigit() and len(identity.edipi) == 10


# ---------------------------------------------------------------------------
# _parse_cac_dot
# ---------------------------------------------------------------------------


class TestFuzzParseCacDot:
    @given(cn=cn_strategy)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_never_crashes(self, cn):
        identity = _identity_with_cn(cn)
        _parse_cac_dot(identity)
        _assert_common_postconditions(identity, cn)

    @given(cn=st.text(min_size=1, max_size=300))
    def test_non_empty_cn_sets_lastname(self, cn):
        """Any non-empty CN should result in at least a lastname."""
        identity = _identity_with_cn(cn)
        _parse_cac_dot(identity)
        assert identity.lastname is not None

    @given(
        last=st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ", min_size=1, max_size=20),
        first=st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ", min_size=1, max_size=20),
        mi=st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ", min_size=1, max_size=3),
        edipi=st.from_regex(r"[0-9]{10}", fullmatch=True),
    )
    def test_valid_cac_format_extracts_all_fields(self, last, first, mi, edipi):
        """A well-formed CAC CN should always parse correctly."""
        cn = f"{last}.{first}.{mi}.{edipi}"
        identity = _identity_with_cn(cn)
        _parse_cac_dot(identity)
        assert identity.lastname == last
        assert identity.firstname == first
        assert identity.edipi == edipi


# ---------------------------------------------------------------------------
# _parse_piv_flexible
# ---------------------------------------------------------------------------


class TestFuzzParsePivFlexible:
    @given(cn=cn_strategy)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_never_crashes(self, cn):
        identity = _identity_with_cn(cn)
        _parse_piv_flexible(identity)
        _assert_common_postconditions(identity, cn)

    @given(
        last=st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ", min_size=1, max_size=20),
        first=st.text(
            alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", min_size=1, max_size=20
        ),
        middle=st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ", min_size=0, max_size=5),
    )
    def test_comma_format_extracts_lastname(self, last, first, middle):
        """Comma-separated CN should always extract lastname."""
        cn = f"{last}, {first} {middle}".rstrip()
        identity = _identity_with_cn(cn)
        _parse_piv_flexible(identity)
        assert identity.lastname == last
        assert identity.firstname == first

    @given(
        first=st.text(
            alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", min_size=1, max_size=20
        ),
        last=st.text(
            alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", min_size=1, max_size=20
        ),
    )
    def test_space_format_roundtrips(self, first, last):
        """'First Last' should extract both names."""
        cn = f"{first} {last}"
        identity = _identity_with_cn(cn)
        _parse_piv_flexible(identity)
        assert identity.firstname == first
        assert identity.lastname == last


# ---------------------------------------------------------------------------
# _parse_eca_human
# ---------------------------------------------------------------------------


class TestFuzzParseEcaHuman:
    @given(cn=cn_strategy)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_never_crashes(self, cn):
        identity = _identity_with_cn(cn)
        _parse_eca_human(identity)
        _assert_common_postconditions(identity, cn)

    @given(
        first=st.text(
            alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", min_size=1, max_size=20
        ),
        middle=st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ.", min_size=0, max_size=5),
        last=st.text(
            alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", min_size=1, max_size=20
        ),
    )
    def test_human_name_extracts_first_and_last(self, first, middle, last):
        """'First [Middle] Last' should extract first and last."""
        parts = [first] + ([middle] if middle else []) + [last]
        cn = " ".join(parts)
        identity = _identity_with_cn(cn)
        _parse_eca_human(identity)
        assert identity.firstname == first
        assert identity.lastname == last

    @given(
        last=st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ", min_size=1, max_size=20),
        first=st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ", min_size=1, max_size=20),
    )
    def test_comma_format_extracts_names(self, last, first):
        """Comma-separated CN should extract lastname and firstname."""
        cn = f"{last}, {first}"
        identity = _identity_with_cn(cn)
        _parse_eca_human(identity)
        assert identity.lastname == last
        assert identity.firstname == first


# ---------------------------------------------------------------------------
# Cross-parser: no parser should mutate fields it doesn't own
# ---------------------------------------------------------------------------


class TestFuzzCrossConcerns:
    @given(cn=cn_strategy)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_parsers_dont_touch_unrelated_fields(self, cn):
        """Parsers should only set firstname, lastname, and edipi."""
        for parser in (_parse_cac_dot, _parse_piv_flexible, _parse_eca_human):
            identity = _identity_with_cn(cn)
            # Set sentinel values on fields parsers should not touch
            identity.email = "SENTINEL"
            identity.piv_uuid = "SENTINEL"
            identity.fascn = "SENTINEL"
            identity.primary_id = "SENTINEL"
            identity.credential_type = "SENTINEL"

            parser(identity)

            assert identity.email == "SENTINEL"
            assert identity.piv_uuid == "SENTINEL"
            assert identity.fascn == "SENTINEL"
            assert identity.primary_id == "SENTINEL"
            assert identity.credential_type == "SENTINEL"
