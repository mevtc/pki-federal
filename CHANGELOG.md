# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.6.0] - 2026-08-23

> ### ⚠ Behavioural change — read before upgrading
>
> Certificates that previously authenticated as a **person** may now be
> classified differently or refused. This is deliberate: each case was a
> credential being accepted as a human when its certificate policy says it is
> not one. Deployments should re-test authentication before rolling this out,
> particularly anything using `default_registry()`.
>
> Requires **`pki-core>=0.6.0`**.

### Security

- **Card-authentication certificates no longer classify as `PERSONAL_AUTH`.**
  Four policy OIDs moved out of the person sets into a new `CARD_AUTH` class:

  | OID | Policy |
  |---|---|
  | `2.16.840.1.101.3.2.1.3.17` | `id-fpki-common-cardAuth` |
  | `2.16.840.1.101.3.2.1.3.46` | `id-fpki-common-pivi-cardAuth` |
  | `2.16.840.1.101.3.2.1.3.19` | `id-fpki-certpcy-pivi-cardAuth` |
  | `2.16.840.1.101.3.2.1.12.7` | `id-eca-cardauth-pivi` (previously unrecognised) |

  Every governing CP forbids the old reading. FPKI Common v2.13 §1.4.2 and
  FBCA v3.9 §1.4.2, under *Prohibited Certificate Uses*: such certificates
  *"must only be used to authenticate the hardware token containing the
  associated private key and **must not be interpreted as authenticating the
  presenter or holder of the token**."* ECA CP v4.8 §1.4.1 says the same.

  It matters because the private key needs **no PIN**. Verified on a real DoD
  CAC: the card-authentication and PIV-authentication certificates carry the
  same subject UUID, so under a PIV-only registry both produced an identical
  `primary_id` — a contactless read authenticated as the cardholder. That
  certificate now resolves to the `CARD-AUTH` provider, or to nothing at all
  in a person-constrained registry.

- **Device certificates asserting a person OID no longer classify as a
  person.** DoD CP v11 §1.2 permits it: *"Medium NPE certificates may also
  assert any Medium Software or Medium Hardware OID if they meet the
  corresponding requirements."* Such a certificate previously matched the CAC
  provider because it was registered first. The person providers now declare
  the NPE and card-auth sets as `disqualifying_oids` (pki-core 0.6.0), so they
  rule themselves out even when no device provider is registered. Latent
  rather than observed — found by reading CP v11.

  **Residual gap.** This closes the *policy-OID* path only. `parse_identity()`
  falls back to CN/organization heuristics whenever OID matching yields no
  provider, and cannot distinguish "no OID matched" from "matched but
  disqualified" — so a disqualified certificate whose subject trips a
  heuristic can still be classified as a person. Realistic DoD device subjects
  (`O=U.S. Government, OU=DoD`) do not trip one, but `O=Department of Defense`
  does. This is the pre-existing limitation recorded under *Security
  Boundaries* in `SECURITY.md` and tracked as *"Enforce the authentication
  policy OID as a hard gate, not a fallback signal"* in `SECURITY_TODO.md`;
  it is not introduced here, but it does bound the fix. Callers requiring a
  hard guarantee must check `policy_oids` against the provider's `auth_oids`
  themselves, as `SECURITY.md` already instructs.

### Added

- `CARD_AUTH_PROVIDER` — covers PIV / PIV-I card authentication across FPKI,
  FBCA and ECA, with `intended_use=CARD_AUTH` and `min_aal=1` (no activation
  data). Registered in `full_registry()`; `default_registry()` is
  `PERSONAL_AUTH`-constrained and refuses it by construction.
- `select_card_token_id()` — namespaces the token identifier as
  `card:uuid:…` rather than the bare `uuid:…` that `select_uuid_first()`
  returns. `intended_use` is the real boundary, but this stops a card read
  colliding with a person's ID for callers that key on `primary_id` alone.
- `CARD_AUTH_OIDS`, `FPKI_CARD_AUTH_OIDS`, `FBCA_CARD_AUTH_OIDS`,
  `ECA_CARD_AUTH_OIDS`.
- `2.16.840.1.101.3.2.1.12.7` (`id-eca-cardauth-pivi`), which was absent
  entirely — a comment asserted it was unassigned in the ECA CP. It is
  registered in §1.2, so an ECA PIV-I card-authentication certificate
  previously matched no provider at all.

### Changed

- **Requires `pki-core>=0.6.0`** (was `>=0.4.0`) for `IntendedUse.CARD_AUTH`,
  `AuthProvider.disqualifying_oids`, and least-privilege OID resolution.
- `docs/cp-policy-table.md` rewritten: every one of the 59 recognised OIDs in
  one table with its CP name, `IntendedUse`, and subject type, plus a sources
  block recording exactly which document version each was verified against.

### Fixed

- Certificate-policy citations corrected against the current documents. All
  four hierarchies were re-read in full on 2026-08-23 and every OID compared
  to its registration section: **DoD 20/20, FPKI Common 13/13, FBCA 10/10,
  ECA 16/16** — all labels match.
  - DoD citations moved from **v10.7 to v11** (15 Dec 2025). The v11 URL was
    thought unreachable; the interoperability file prints it with `+` for
    spaces, which 404s, and works when re-encoded as `%20`.
  - `2.16.840.1.101.2.1.11.9` was labelled `id-US-dod-mediumhardware`; the CP
    spells it `id-US-dod-mediumHardware`.
  - `2.16.840.1.101.2.1.11.31` (`id-US-dod-peerInterop`) documented as
    deliberately excluded. It is registered in v11 §1.2 and appears in the DoD
    approved-assurance list, so it reads as a missing OID — but v11 states it
    *"is only asserted in cross certificates"*, and adding it would let a
    CA-to-CA policy match a Subscriber credential.
  - FBCA `.1`/`.2` exclusion re-cited. The previous comment implied the DoD
    interoperability file enumerates excluded assurance levels; it does not.
    The authority is its preamble: *"DoD PKI only maps OIDs determined to be
    equivalent to DoD or FBCA medium hardware assurance level or higher."*

### Security / review note

- The review status recorded in 0.5.0 is now discharged. The OID-to-use
  mappings were produced by an automated research pass and carried a
  **"must be reviewed by a human policy owner before operational reliance"**
  warning. That review is complete — all four hierarchies verified
  name-by-name against the primary CPs on 2026-08-23, with per-OID citations
  in `docs/cp-policy-table.md`. It found one omission and one classification
  error, both fixed above.

## [0.5.0] - 2026-08-13

Dated to actual release. The 0.5.0 work was tagged 2026-07-16 but never
published — it declares `pki-core>=0.4.0`, and 0.4.0 was itself tagged and
never uploaded, so the package would not have installed. pki-core 0.5.0
(2026-08-13) closed that, and the tooling added since is folded in here
rather than split into a second release nobody would install separately.

### Added

- `scripts/validate-card.py` — manual hardware test that reads every
  certificate off an inserted CAC / PIV / ECA card via OpenSC and runs each
  through the full validation pipeline twice: once expecting `clientAuth`
  and once expecting `emailProtection`.  Certificates whose result differs
  are flagged EKU-SENSITIVE.

  Verified against a real DoD CAC: the **Email Signature** certificate
  (DOD EMAIL CA-62) asserts `emailProtection` and MS Document Signing but
  **not** `clientAuth`, so it validates only under the S/MIME expectation.
  Any caller enabling `check_chain` for S/MIME must set
  `expected_eku=ExtendedKeyUsageOID.EMAIL_PROTECTION`.  Requires a physical
  card, and `pki-core>=0.5.0` for `expected_eku` — checked at startup, since
  the library floor of `>=0.4.0` can be satisfied while the script is not.
  Not shipped in the wheel; `scripts/` is outside the packaged source.

- **Intended-use classification (PE / NPE / content-signing).**  Providers now
  set the `IntendedUse` flag from `pki-core` 0.4.0, and `parse_identity()`
  surfaces it on `CertIdentity.intended_use`.  New non-person-entity providers:
  `DOD_NPE_PROVIDER`, `FPKI_DEVICE_PROVIDER`, `ECA_DEVICE_PROVIDER`
  (`NPE_AUTH`), and `CONTENT_SIGNING_PROVIDER` (`OBJECT_SIGNING`, covering the
  PIV/PIV-I content-signing policies across FPKI, FBCA and ECA).  `full_registry()`
  now returns all seven providers; `default_registry()` remains CAC + PIV.
- New device/service CN parser `_parse_device_cn`: leaves `firstname`/`lastname`
  as `None` for FQDN-style subjects (e.g. `CN=athocalerts.com`) instead of
  mis-parsing a hostname as a person's name.
- New NPE primary-ID selector `select_cn_first` (`pki.federal.selectors`).
- FBCA (`id-fpki-certpcy-*`) and additional FPKI/ECA/DoD NPE and content-signing
  OIDs enumerated in `oids.py`.
- `docs/cp-policy-table.md` filled in from primary certificate-policy sources,
  with per-section `CP-VERIFIED 2026-07-16` markers.

### Changed

- **Requires `pki-core>=0.4.0`** (was `>=0.3.4`) for the `IntendedUse` enum,
  the `AuthProvider.intended_use` field, and the `ProviderRegistry`
  intended-use registration constraint.
- **`oids.py` reorganized by intended use.**  The flat `DOD_AUTH_OIDS`,
  `FPKI_PIV_AUTH_OIDS`, `ECA_AUTH_OIDS`, `DOD_EMAIL_SIGNING_OIDS`,
  `FPKI_EMAIL_SIGNING_OIDS` sets are **removed** and replaced with
  per-hierarchy, per-use sets (`DOD_PE_OIDS`, `DOD_NPE_OIDS`, `FPKI_PE_OIDS`,
  `FPKI_NPE_OIDS`, `FPKI_OBJECT_SIGNING_OIDS`, `FBCA_*_OIDS`, `ECA_PE_OIDS`,
  `ECA_NPE_OIDS`, `ECA_OBJECT_SIGNING_OIDS`, plus aggregate `FEDERAL_PE_OIDS`,
  `FEDERAL_NPE_OIDS`, `OBJECT_SIGNING_OIDS`).  Importers of the old names must
  migrate.
- `default_registry()` is now constrained to `IntendedUse.PERSONAL_AUTH`, so a
  future attempt to register a non-person provider in the default (person-only)
  path fails at registration time.  The returned providers (CAC + PIV) are
  unchanged.
- Person providers (`CAC`/`PIV`/`ECA`) carry `intended_use=PERSONAL_AUTH` only.
  Per the CPs, their policies cover human auth and human S/MIME signature but do
  **not** authorise content/code signing, so `OBJECT_SIGNING` is deliberately
  not set.

### Fixed

- **Corrected substantial OID mislabeling in `oids.py`.**  Comment labels did
  not match the CP §1.2 registration text.  Most consequential:
  `2.16.840.1.101.2.1.11.36` was labelled `dodMediumHardware2048` (a person
  policy) but is **`id-US-dod-mediumNPE-112`, a device/NPE policy**, and was
  sitting in the DoD "email signing" set — a device cert would have been
  matched as a person credential.  `2.16.840.1.101.3.2.1.3.40` was labelled as
  content-signing but is `id-fpki-common-derived-pivAuth` (person auth); the
  real FPKI content-signing OID is `.39`.  See the correction table in
  `docs/cp-policy-table.md`.

### Security / review note

- The certificate-policy citations in `docs/cp-policy-table.md` and the
  OID-to-`IntendedUse` mappings in `oids.py`/`providers.py` were produced by an
  automated primary-source research pass on 2026-07-16.  They drive a
  person-vs-NPE authentication/authorization boundary in a DoD-adjacent mail
  system and **must be reviewed by a human policy owner before operational
  reliance.**  EKU columns for non-content-signing policies are marked
  `NEEDS HUMAN REVIEW`; DoD rows are cited to CP v10.7 because the interop-cited
  v11 document URL was unreachable.

## [0.4.2] - 2026-04-21

### Security

- Bump `cryptography` minimum from `>=44.0` to `>=46.0.7` to resolve
  CVE-2026-26007, CVE-2026-34073, and CVE-2026-39892.
- Bump `pki-core` minimum from `>=0.3.0` to `>=0.3.4` for hardened zip
  path traversal, OCSP signature verification, and cryptography CVE fixes.
- Remove `DOD_PKI_URL` environment variable override from `trust_store.py`
  to eliminate trust store poisoning vector.

### Changed

- **Breaking**: `TrustLevel` is now an `IntEnum` instead of `StrEnum`.
  Comparisons work identically but values are integers (0-3) instead of
  strings.  Code comparing with string literals (e.g., `== "high"`) must
  be updated to use enum members (e.g., `== TrustLevel.HIGH`).
- Refactor `trust_store.py` to delegate to `pki.core.trust_store` instead
  of reimplementing ZIP parsing.  Public API (`fetch_dod_certs`,
  `fetch_fpki_certs`, `build_ca_bundle`) is unchanged.
- Extract shared `_parse_comma_format()` helper in `cn_parsers.py`.
- Use per-module mypy overrides for `pki.core` instead of global relaxation.
- Replace global Bandit B110 skip with targeted inline suppression.

### Removed

- Dead `CNParseStrategy` and `PrimaryIDStrategy` enums from `providers.py`.

## [0.4.1] - 2026-04-03

### Added

- `TrustLevel` and `CredentialType` StrEnums for DoDI 8520.02 trust levels
  and federal PKI credential types.
- Automated PyPI publishing via trusted publisher (OIDC) in release workflow.

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