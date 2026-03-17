# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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