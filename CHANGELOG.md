# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2025-01-01

### Added

- X.509 certificate parsing with PEM/DER auto-detection
- CAC identity extraction (EDIPI from CN dot-format)
- PIV identity extraction (UUID from SAN, FASC-N, multiple CN formats)
- CRL revocation checking with stale-while-revalidate file-backed cache
- DoD and Federal PKI CA trust store download, merge, and deduplication
- Certificate policy OID registries for DoD and FPKI authentication and email signing