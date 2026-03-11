"""Tests for federal_pki.providers module."""

from federal_pki.providers import (
    AuthProvider,
    BUILTIN_PROVIDERS,
    CAC_PROVIDER,
    CNParseStrategy,
    ECA_PROVIDER,
    HeuristicRule,
    PIV_PROVIDER,
    PrimaryIDStrategy,
    ProviderRegistry,
    default_registry,
    full_registry,
)


class TestBuiltinProviders:
    def test_cac_provider(self):
        assert CAC_PROVIDER.name == "CAC"
        assert CAC_PROVIDER.cn_parse_strategy == CNParseStrategy.CAC_DOT
        assert CAC_PROVIDER.primary_id_strategy == PrimaryIDStrategy.EDIPI_FIRST
        assert "2.16.840.1.101.2.1.11.19" in CAC_PROVIDER.auth_oids
        assert CAC_PROVIDER.min_aal == 3

    def test_piv_provider(self):
        assert PIV_PROVIDER.name == "PIV"
        assert PIV_PROVIDER.cn_parse_strategy == CNParseStrategy.PIV_FLEXIBLE
        assert PIV_PROVIDER.primary_id_strategy == PrimaryIDStrategy.UUID_FIRST
        assert "2.16.840.1.101.3.2.1.3.13" in PIV_PROVIDER.auth_oids
        assert PIV_PROVIDER.min_aal == 3

    def test_eca_provider(self):
        assert ECA_PROVIDER.name == "ECA"
        assert ECA_PROVIDER.cn_parse_strategy == CNParseStrategy.ECA_HUMAN
        assert ECA_PROVIDER.primary_id_strategy == PrimaryIDStrategy.EMAIL_FIRST
        assert "2.16.840.1.101.3.2.1.12.2" in ECA_PROVIDER.auth_oids
        assert ECA_PROVIDER.min_aal == 2
        assert "IA-8" in ECA_PROVIDER.controls

    def test_builtin_dict(self):
        assert set(BUILTIN_PROVIDERS.keys()) == {"CAC", "PIV", "ECA"}

    def test_providers_are_frozen(self):
        import dataclasses

        for p in BUILTIN_PROVIDERS.values():
            assert dataclasses.is_dataclass(p)


class TestProviderRegistry:
    def test_register_and_get(self):
        reg = ProviderRegistry()
        reg.register(CAC_PROVIDER)
        assert reg.get("CAC") is CAC_PROVIDER
        assert reg.get("MISSING") is None

    def test_names(self):
        reg = default_registry()
        assert reg.names() == ["CAC", "PIV"]

    def test_all(self):
        reg = default_registry()
        providers = reg.all()
        assert len(providers) == 2
        assert providers[0].name == "CAC"
        assert providers[1].name == "PIV"

    def test_len(self):
        reg = full_registry()
        assert len(reg) == 3

    def test_match_oids_cac(self):
        reg = full_registry()
        matched = reg.match_oids({"2.16.840.1.101.2.1.11.19"})
        assert matched is not None
        assert matched.name == "CAC"

    def test_match_oids_piv(self):
        reg = full_registry()
        matched = reg.match_oids({"2.16.840.1.101.3.2.1.3.13"})
        assert matched is not None
        assert matched.name == "PIV"

    def test_match_oids_eca(self):
        reg = full_registry()
        matched = reg.match_oids({"2.16.840.1.101.3.2.1.12.2"})
        assert matched is not None
        assert matched.name == "ECA"

    def test_match_oids_none(self):
        reg = full_registry()
        assert reg.match_oids({"1.2.3.4.5"}) is None

    def test_match_oids_first_wins(self):
        """When OIDs overlap with multiple providers, first registered wins."""
        reg = ProviderRegistry()
        reg.register(CAC_PROVIDER)
        reg.register(PIV_PROVIDER)
        matched = reg.match_oids({"2.16.840.1.101.2.1.11.19"})
        assert matched.name == "CAC"

    def test_match_heuristic_dod(self):
        reg = full_registry()
        matched = reg.match_heuristic(None, "Department of Defense", None)
        assert matched is not None
        assert matched.name == "CAC"

    def test_match_heuristic_energy(self):
        reg = full_registry()
        matched = reg.match_heuristic(None, "Department of Energy", None)
        assert matched is not None
        assert matched.name == "PIV"

    def test_match_heuristic_eca_ou(self):
        reg = full_registry()
        matched = reg.match_heuristic(None, None, "ECA")
        assert matched is not None
        assert matched.name == "ECA"

    def test_match_heuristic_cac_cn_regex(self):
        reg = full_registry()
        matched = reg.match_heuristic("SMITH.JOHN.A.1234567890", None, None)
        assert matched is not None
        assert matched.name == "CAC"

    def test_match_heuristic_none(self):
        reg = full_registry()
        assert reg.match_heuristic(None, None, None) is None

    def test_match_heuristic_no_match(self):
        reg = full_registry()
        assert reg.match_heuristic("Some Name", "Random Org", "Random OU") is None


class TestDefaultRegistry:
    def test_contains_cac_piv(self):
        reg = default_registry()
        assert reg.names() == ["CAC", "PIV"]

    def test_no_eca(self):
        reg = default_registry()
        assert reg.get("ECA") is None


class TestFullRegistry:
    def test_contains_all(self):
        reg = full_registry()
        assert reg.names() == ["CAC", "PIV", "ECA"]