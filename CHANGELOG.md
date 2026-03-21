# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.4.0] - 2026-03-21

### Added

- `SP800_78_ALGORITHM_POLICY` — `AlgorithmPolicy` constant with NIST SP 800-78-5
  approved algorithms (RSA 2048+, P-256/P-384, SHA-256+).
- `SECURITY.md` with static analysis suppressions, fuzz testing documentation,
  and link to centralized incident response at oss.mevtc.com.
- Hypothesis fuzz tests for CN parsers, federal providers, and identity extraction.
- CycloneDX SBOM generation in CI.

### Changed

- `CRLConfig` now provides meaningful federal defaults: `strict=True`,
  `max_crl_bytes=20 MB` (DoD CRLs are large), `max_acceptable_age=64800`
  (18 hours per FIPS 201-3 §2.9.1 revocation timeliness requirement).
- Depends on `pki-core>=0.3.0` for `RevocationPolicy`, `AlgorithmPolicy`,
  and chain validation.

## [0.3.0] - 2026-03-17

### Changed

- Renamed project from `federal-pki` to `pki-federal`
- Restructured to `pki.federal` namespace package (`src/pki/federal/` layout)
- All imports changed from `federal_pki.*` to `pki.federal.*`
- Internal imports updated from `pki_core.*` to `pki.core.*`
- Depends on `pki-core>=0.1.0` (shared `pki` namespace)

### Added

- ECA (External Certificate Authority) provider definitions
- Callable-based CN parsing and primary ID selection on provider instances
- Pre-release checklist in publishing workflow

## [0.2.0] - 2026-03-16

### Changed

- Thinned to federal-specific layer on top of pki-core
- Refactored providers to use callable cn_parser and primary_id_selector
- Re-exports pki-core API for backward compatibility

## [0.1.0] - 2025-01-01

### Added

- X.509 certificate parsing with PEM/DER auto-detection
- CAC identity extraction (EDIPI from CN dot-format)
- PIV identity extraction (UUID from SAN, FASC-N, multiple CN formats)
- CRL revocation checking with stale-while-revalidate file-backed cache
- DoD and Federal PKI CA trust store download, merge, and deduplication
- Certificate policy OID registries for DoD and FPKI authentication and email signing