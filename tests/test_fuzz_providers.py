"""Hypothesis fuzz tests for provider registry matching.

Property-based tests that throw random OID sets and arbitrary strings at the
provider registry to verify match_oids and match_heuristic never crash and
always satisfy postconditions.

Example counts are controlled by Hypothesis profiles registered in
conftest.py.  Use ``--hypothesis-profile=ci`` or ``--hypothesis-profile=nightly``
to increase coverage.
"""

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pki.federal.oids import DOD_AUTH_OIDS, ECA_AUTH_OIDS, FPKI_PIV_AUTH_OIDS
from pki.federal.providers import (
    BUILTIN_PROVIDERS,
    CAC_PROVIDER,
    ECA_PROVIDER,
    PIV_PROVIDER,
    default_registry,
    full_registry,
)

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# OID-like dotted-decimal strings (e.g. "2.16.840.1.101.3.2.1.12.6")
oid_component = st.integers(min_value=0, max_value=65535).map(str)
random_oid = st.builds(
    ".".join,
    st.lists(oid_component, min_size=3, max_size=12),
)

# Sets of OID-like strings, sometimes including real OIDs
random_oid_set = st.frozensets(random_oid, min_size=0, max_size=10).map(set)

# Arbitrary text for heuristic fields
heuristic_text = st.one_of(st.none(), st.text(max_size=200))


# ---------------------------------------------------------------------------
# match_oids with random OID sets
# ---------------------------------------------------------------------------


class TestFuzzMatchOids:
    @given(oid_set=random_oid_set)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_default_registry_never_crashes(self, oid_set):
        """match_oids should return a provider or None, never raise."""
        reg = default_registry()
        result = reg.match_oids(oid_set)
        assert result is None or result.name in {"CAC", "PIV", "ECA"}

    @given(oid_set=random_oid_set)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_full_registry_never_crashes(self, oid_set):
        """match_oids should return a provider or None, never raise."""
        reg = full_registry()
        result = reg.match_oids(oid_set)
        assert result is None or result.name in {"CAC", "PIV", "ECA"}

    @given(subset=st.frozensets(st.sampled_from(sorted(DOD_AUTH_OIDS)), min_size=1))
    def test_dod_oids_always_match_cac(self, subset):
        """Any non-empty subset of DoD auth OIDs must match CAC."""
        reg = full_registry()
        result = reg.match_oids(set(subset))
        assert result is not None
        assert result.name == "CAC"

    @given(subset=st.frozensets(st.sampled_from(sorted(FPKI_PIV_AUTH_OIDS)), min_size=1))
    def test_fpki_oids_always_match_piv(self, subset):
        """Any non-empty subset of FPKI PIV auth OIDs must match PIV."""
        reg = full_registry()
        result = reg.match_oids(set(subset))
        assert result is not None
        assert result.name == "PIV"

    @given(subset=st.frozensets(st.sampled_from(sorted(ECA_AUTH_OIDS)), min_size=1))
    def test_eca_oids_always_match_eca(self, subset):
        """Any non-empty subset of ECA auth OIDs must match ECA."""
        reg = full_registry()
        result = reg.match_oids(set(subset))
        assert result is not None
        assert result.name == "ECA"

    def test_empty_oid_set_matches_nothing(self):
        """An empty OID set should never match any provider."""
        reg = full_registry()
        assert reg.match_oids(set()) is None

    @given(oid_set=random_oid_set)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_match_result_is_registered_provider(self, oid_set):
        """If match_oids returns a provider, it must be one of the registered ones."""
        reg = full_registry()
        result = reg.match_oids(oid_set)
        if result is not None:
            assert result in reg.all()


# ---------------------------------------------------------------------------
# match_heuristic with arbitrary strings
# ---------------------------------------------------------------------------


class TestFuzzMatchHeuristic:
    @given(cn=heuristic_text, org=heuristic_text, ou=heuristic_text)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_never_crashes(self, cn, org, ou):
        """match_heuristic should return a provider or None, never raise."""
        reg = full_registry()
        result = reg.match_heuristic(cn, org, ou)
        assert result is None or result.name in {"CAC", "PIV", "ECA"}

    @given(
        org=st.from_regex(r".*[Dd]epartment of [Dd]efense.*", fullmatch=True).filter(
            lambda s: len(s) <= 200
        )
    )
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_dod_org_matches_cac(self, org):
        """Organization containing 'department of defense' should match CAC."""
        reg = full_registry()
        result = reg.match_heuristic(None, org, None)
        assert result is not None
        assert result.name == "CAC"

    @given(org=st.from_regex(r".*[Ee]nergy.*", fullmatch=True).filter(lambda s: len(s) <= 200))
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_energy_org_matches_piv(self, org):
        """Organization containing 'energy' should match PIV."""
        reg = full_registry()
        result = reg.match_heuristic(None, org, None)
        assert result is not None
        assert result.name == "PIV"

    @given(ou=st.from_regex(r".*[Ee][Cc][Aa].*", fullmatch=True).filter(lambda s: len(s) <= 200))
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_eca_ou_matches_eca(self, ou):
        """OU containing 'eca' (case-insensitive) should match ECA."""
        reg = full_registry()
        result = reg.match_heuristic(None, None, ou)
        assert result is not None
        assert result.name == "ECA"

    @given(cn=heuristic_text, org=heuristic_text, ou=heuristic_text)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_match_result_is_registered_provider(self, cn, org, ou):
        """If match_heuristic returns a provider, it must be registered."""
        reg = full_registry()
        result = reg.match_heuristic(cn, org, ou)
        if result is not None:
            assert result in reg.all()


# ---------------------------------------------------------------------------
# Provider immutability
# ---------------------------------------------------------------------------


class TestProvidersFrozen:
    def test_cac_provider_is_frozen(self):
        """Setting an attribute on a frozen provider must raise."""
        try:
            CAC_PROVIDER.name = "HACKED"  # type: ignore[misc]
            raise AssertionError("Expected FrozenInstanceError")
        except AttributeError:
            pass

    def test_piv_provider_is_frozen(self):
        try:
            PIV_PROVIDER.name = "HACKED"  # type: ignore[misc]
            raise AssertionError("Expected FrozenInstanceError")
        except AttributeError:
            pass

    def test_eca_provider_is_frozen(self):
        try:
            ECA_PROVIDER.name = "HACKED"  # type: ignore[misc]
            raise AssertionError("Expected FrozenInstanceError")
        except AttributeError:
            pass

    def test_all_builtin_providers_frozen(self):
        """Every provider in BUILTIN_PROVIDERS must reject attribute mutation."""
        for name, provider in BUILTIN_PROVIDERS.items():
            try:
                provider.display_name = "mutated"  # type: ignore[misc]
                raise AssertionError(f"Provider {name} is not frozen")
            except AttributeError:
                pass
