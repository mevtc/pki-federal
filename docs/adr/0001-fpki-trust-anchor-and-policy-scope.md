# 0001. FPKI Trust-Anchor Construction and Policy Enforcement Scope

## Status

Accepted, with known gaps.

This reflects real current behavior of pki-federal (and the pki-core
functions it delegates to) that needs to be documented explicitly rather
than left implicit. Some of the gaps below are inherent to the `cryptography`
dependency and cannot be fixed by a small patch to this codebase; others are
simplifications made when trust-store construction was first implemented
and never revisited against the Federal Bridge's actual trust model.

## Context

The Federal PKI (FPKI) is not a single hierarchy under one root. The
Federal Common Policy CA (FCPCA) is cross-certified with the Federal
Bridge CA (FBCA), which in turn is cross-certified with individual agency
PKIs (DoD PKI among them). Trust between two PKIs in this model is carried
by **cross-certificates** — certificates issued *to* and *by* the bridge —
which are exactly the kind of certificate RFC 5280 expects to be
constrained intermediates: subject to name constraints, policy constraints,
and policy mapping that scope how far trust extends and under what policy
OIDs it may be asserted.

This matters concretely for PIV/CAC-style authentication: FIPS 201-3
§6.2.3.1 (footnote 39) requires that a relying party confirm the presented
certificate carries the expected PIV-authentication policy OID
(`id-fpki-common-authentication`, `id-fpki-common-derived-pivAuth`, or the
DoD equivalents pki-federal defines in `oids.py`) before trusting the
identity for PKI-AUTH-level assurance. Policy OIDs, and whether/how they
are mapped across a bridge cross-certification boundary, are the
mechanism by which the FPKI model distinguishes "this cert chains to a
technically trusted root" from "this cert is asserted, under an agreed
policy, to meet a specific assurance level."

pki-federal supplies FPKI/DoD-specific inputs to pki-core's
general-purpose validation pipeline: `AuthProvider` definitions with
`trust_store_sources` (URLs to fetch root and bridge certificates from)
and `auth_oids` (the policy OIDs expected for each credential type), plus
CN parsers and a federal `CRLConfig`. Actual chain verification,
trust-anchor bundling, and identity extraction are implemented in
pki-core and simply invoked by pki-federal.

## Decision

Document, precisely, what pki-federal + pki-core currently do:

1. **Trust-anchor bundle is flat.** `pki_federal.trust_store.build_ca_bundle()`
   calls pki-core's `build_ca_bundle_for_providers()`, which calls
   `merge_and_deduplicate()`. For `PIV_PROVIDER`, this fetches the FCPCA
   root (`fcpcag2.crt`) *and* both Federal Bridge cross-certificate
   bundles (`caCertsIssuedTofbcag4.p7c`, `caCertsIssuedByfbcag4.p7c`) from
   `repo.fpki.gov`, deduplicates them by fingerprint, and merges them into
   a single PEM bundle with no distinction between "root" and
   "cross-certificate." That bundle is passed to pki-core's
   `verify_chain()` as the `trust_store` argument, with no corresponding
   `intermediates` argument populated. `cryptography`'s `ClientVerifier`
   therefore treats every cross-certificate as an equally-trusted anchor,
   not as a constrained intermediate in a path being built and validated
   up to the true FCPCA root.

2. **No policy OID check is performed by the validation pipeline.**
   pki-core's `parse_identity()` records `policy_oids` on the returned
   `CertIdentity` and uses `ProviderRegistry.match_oids()` to *identify*
   which provider (CAC/PIV/ECA) a certificate most likely belongs to, but
   if no `auth_oids` intersect, it falls back to CN/org/OU heuristic
   matching (`match_heuristic()`) and still returns a populated,
   ostensibly-usable identity. Neither `validate_certificate()` nor any
   known caller (including the smartcard-auth family) fails validation
   when the expected policy OID is absent. Policy OID matching is
   informational, not a gate.

3. **No RFC 5280 policy-processing is performed.** Policy mapping, policy
   constraints, and inhibitAnyPolicy (RFC 5280 §6.1.1) are not evaluated
   anywhere in the stack. This is documented in pki-core's
   `validation.py` module docstring and is a limitation of the
   `cryptography` library's path validator, which implements chain
   signature/validity/basic-constraints/key-usage/name-constraints
   checking but not the policy-graph algorithm from RFC 5280 §6.1.1-6.1.5.

None of the above are being changed by this ADR. This ADR documents the
status quo so it is an explicit, reviewable decision rather than an
undocumented gap.

## Consequences

- **A certificate that chains to a Federal Bridge cross-certificate is
  currently trusted exactly as much as one that chains directly to the
  FCPCA root.** Any restriction the bridge model intended to place on
  that trust via name constraints or policy constraints on the
  cross-certificate is not enforced. See `SECURITY_TODO.md` — "Separate
  Federal Bridge cross-certificates from root trust anchors."

- **Callers cannot rely on pki-federal/pki-core to reject a certificate
  for lacking the expected assurance-level policy OID.** A certificate
  that fails OID matching but happens to satisfy a CN/org heuristic (e.g.
  `"department of defense"` in the Organization field) will still produce
  a usable `CertIdentity`. Any deployment that needs FIPS 201-3 §6.2.3.1
  PKI-AUTH assurance, or an equivalent DoD assurance guarantee, **must
  independently check `identity.policy_oids` against the expected
  provider's `auth_oids` before relying on the identity**, until the
  pipeline gains an enforced gate. See `SECURITY_TODO.md` — "Enforce the
  authentication policy OID as a hard gate, not a fallback signal."

- **Policy mapping/constraints from the certificate chain are invisible to
  this library and always will be, absent an upstream `cryptography`
  change or a replacement path validator.** This should be treated as a
  permanent constraint on what pki-federal can promise, not a bug to be
  fixed in a future release. See `SECURITY_TODO.md` — "Known limitation —
  RFC 5280 policy mapping / policy constraints / inhibitAnyPolicy are not
  processed."

- **Recommendation:** any deployment that treats pki-federal-validated
  certificates as PIV- or CAC-assured for access control MUST perform its
  own policy-OID check on the returned identity (see SECURITY.md
  "Security Boundaries") and should consider restructuring the trust
  store construction to separate roots from cross-certificates — feeding
  cross-certificates to `verify_chain()` as `intermediates` rather than as
  part of `trust_store` — before this library is used in a high-assurance
  context. Until then, treat FPKI/bridge-issued identities as
  "cryptographically valid chain, policy assurance unverified."

- Related, but out of scope for this ADR: revocation fail-open behavior
  when a certificate has no CRL distribution point is inherited from
  pki-core and tracked there (pki-core's `TODO.md` and
  `docs/adr/0001-revocation-fail-open-by-default.md`), not duplicated
  here.
