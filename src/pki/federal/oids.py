"""DoD and Federal PKI certificate policy OID registries.

Two-dimensional ``<HIERARCHY>-<USE>`` model.  Each hierarchy's OIDs are split
by *intended use* (person auth ``PE``, non-person / device auth ``NPE``,
content/object signing ``CS``) so that ``providers.py`` can attach the correct
``IntendedUse`` flag to the certificates that assert each policy.

Every OID below is transcribed from a primary certificate-policy document.
The formal names and the person-vs-device classification are taken verbatim
from the OID-registration section (``1.2 Document Name and Identification``)
of each CP, cross-checked against the DoD Cyber Exchange interoperability
"Approved Assurance Levels" reference file.

Primary sources (see ``docs/cp-policy-table.md`` for the per-OID citation
table).  Each was re-read in full on 2026-08-21 and every OID below was
compared against its registration section:

- DoD PKI X.509 Certificate Policy, **v11 (15 Dec 2025)**, Section 1.2.
  https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/pdf/DoD%20CP%20V11%20(20251215).pdf
  (The interoperability reference prints this URL with ``+`` for spaces, which
  404s; re-encode as ``%20``.  Earlier revisions of this module cited v10.7
  because the v11 link appeared unreachable for that reason.)
- X.509 Certificate Policy for the U.S. Federal PKI Common Policy Framework,
  **v2.13**, Sections 1.2 and 1.4.2.
  https://www.idmanagement.gov/docs/fpki-x509-cert-policy-common.pdf
- X.509 Certificate Policy for the Federal Bridge CA (FBCA), **v3.9**,
  Sections 1.2 and 1.4.2.
  https://www.idmanagement.gov/docs/fpki-x509-cert-policy-fbca.pdf
- DoD ECA X.509 Certificate Policy, **v4.8 (3 Jun 2024)**, Sections 1.2,
  1.4.1 and 10.5.6.
  https://dl.dod.cyber.mil/wp-content/uploads/eca/pdf/unclass-eca_cp.pdf
- DoD Approved Assurance Levels from External Partner PKIs, v1.19
  (20 Apr 2026).
  https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/txt/unclass-pki_interop_assurance_levels.txt

REVIEW STATUS: the OID-to-use mappings drive a security boundary (personal
vs. non-person-entity vs. card-presence vs. object-signing).  All four
hierarchies were verified name-by-name against the CP registration sections
above on 2026-08-21 — DoD 20/20, FPKI Common 13/13, FBCA 10/10, ECA 16/16.
The review corrected one omission (ECA ``.7``) and one classification error
(the card-authentication policies, which every governing CP forbids treating
as authenticating the holder).  Re-verify when any CP above is superseded.
"""

# ---------------------------------------------------------------------------
# DoD PKI — arc {joint-iso-ccitt(2) country(16) us(840) organization(1)
# gov(101) dod(2) infosec(1) certificate-policy(11)} = 2.16.840.1.101.2.1.11.x
# Source: DoD X.509 CP v11 (15 Dec 2025) Section 1.2.
#
# DELIBERATELY EXCLUDED: 2.16.840.1.101.2.1.11.31 (id-US-dod-peerInterop).
# It is registered in Section 1.2 and it *does* appear in the DoD Approved
# Assurance Levels interoperability list, so a reviewer cross-checking that
# file will see it as missing — it is not.  CP v11 Section 1.2 states: "The
# stipulations in this CP apply to all policy OIDs except id-dod-peerInterop
# ...  The id-dod-peerInterop OID is only asserted in cross certificates at
# the direction of the DoD PKI Policy Management Authority (PMA)."  It is a
# CA-to-CA policy and never appears in an end-entity certificate, so adding it
# to any provider set here would let a cross-certificate policy match a
# Subscriber credential.
# ---------------------------------------------------------------------------
# Person (PE) policies: Medium, Medium-Hardware and Admin families.  These
# assert on identity, digital-signature (S/MIME) and, historically, PIV-Auth
# certificates issued to human Subscribers.  Intended use: PERSONAL_AUTH.
#   OIDs marked (*) are retained by the CP "for historical purposes" and are
#   no longer authorized in newly issued end-entity certificates, but remain
#   valid on unexpired credentials in the field.  The two PIV-Auth OIDs are a
#   special case: CP v11's revision history records them as "the 'DoD PIV'
#   OIDs which were added, but never used", so no certificate should assert
#   them at all — they are kept only so an unexpected assertion is recognised
#   rather than falling through to UNKNOWN.
DOD_PE_OIDS: set[str] = {
    "2.16.840.1.101.2.1.11.5",  # id-US-dod-medium (*)
    "2.16.840.1.101.2.1.11.9",  # id-US-dod-mediumHardware (*)
    "2.16.840.1.101.2.1.11.10",  # id-US-dod-PIV-Auth (*)
    "2.16.840.1.101.2.1.11.18",  # id-US-dod-medium-2048 (*)
    "2.16.840.1.101.2.1.11.19",  # id-US-dod-mediumHardware-2048 (*)
    "2.16.840.1.101.2.1.11.20",  # id-US-dod-PIV-Auth-2048 (*)
    "2.16.840.1.101.2.1.11.39",  # id-US-dod-medium-112
    "2.16.840.1.101.2.1.11.40",  # id-US-dod-medium-128
    "2.16.840.1.101.2.1.11.41",  # id-US-dod-medium-192
    "2.16.840.1.101.2.1.11.42",  # id-US-dod-mediumHardware-112
    "2.16.840.1.101.2.1.11.43",  # id-US-dod-mediumHardware-128
    "2.16.840.1.101.2.1.11.44",  # id-US-dod-mediumHardware-192
    "2.16.840.1.101.2.1.11.59",  # id-US-dod-admin
}

# Non-Person Entity (NPE / device) policies.  DoD CP v11 Section 1.2:
#   "All NPE certificates shall assert the appropriate Internal NPE or Medium
#    NPE OID.  Medium NPE certificates may also assert any Medium Software or
#    Medium Hardware OID if they meet the corresponding requirements."
#
# The second sentence matters: a device certificate may legitimately assert a
# person OID as well.  Matching on OID intersection alone therefore cannot
# decide person-vs-device — see the dual-assertion handling in providers.py.
# Intended use: NPE_AUTH (never PERSONAL_AUTH).
#   Note the CP itself spells .17 "Id-US-dod-mediumNPE" with a capital I in
#   the deprecated-OID block — a typo in the source document, not a distinct
#   registration.
DOD_NPE_OIDS: set[str] = {
    "2.16.840.1.101.2.1.11.17",  # id-US-dod-mediumNPE (*)
    "2.16.840.1.101.2.1.11.36",  # id-US-dod-mediumNPE-112
    "2.16.840.1.101.2.1.11.37",  # id-US-dod-mediumNPE-128
    "2.16.840.1.101.2.1.11.38",  # id-US-dod-mediumNPE-192
    "2.16.840.1.101.2.1.11.60",  # id-US-dod-internalNPE-112
    "2.16.840.1.101.2.1.11.61",  # id-US-dod-internalNPE-128
    "2.16.840.1.101.2.1.11.62",  # id-US-dod-internalNPE-192
}

# DoD content/object signing does NOT use a DoD-arc OID.  Per DoD CP v11
# Section 1.2, DoD PIV content-signing certificates assert the FPKI Common
# policy id-fpki-common-piv-contentSigning {2.16.840.1.101.3.2.1.3.39} — see
# FPKI_OBJECT_SIGNING_OIDS below.

# ---------------------------------------------------------------------------
# FPKI Common Policy Framework — arc 2.16.840.1.101.3.2.1.3.x (id-fpki-common-*)
# Source: FPKI Common Policy CP v2.13 Sections 1.2 and 1.4.2.
# ---------------------------------------------------------------------------
# Person (PE) policies: used solely for authentication or human digital
# signature.  Intended use: PERSONAL_AUTH.
FPKI_PE_OIDS: set[str] = {
    "2.16.840.1.101.3.2.1.3.6",  # id-fpki-common-policy (software sig/auth)
    "2.16.840.1.101.3.2.1.3.7",  # id-fpki-common-hardware
    "2.16.840.1.101.3.2.1.3.13",  # id-fpki-common-authentication
    "2.16.840.1.101.3.2.1.3.16",  # id-fpki-common-high
    "2.16.840.1.101.3.2.1.3.40",  # id-fpki-common-derived-pivAuth
    "2.16.840.1.101.3.2.1.3.41",  # id-fpki-common-derived-pivAuth-hardware
    "2.16.840.1.101.3.2.1.3.45",  # id-fpki-common-pivi-authentication
}

# Card-authentication policies.  Intended use: CARD_AUTH — NEVER PERSONAL_AUTH.
#
# FPKI Common Policy v2.13 Section 1.4.2, "Prohibited Certificate Uses":
#   "Certificates that assert id-fpki-common-cardAuth or
#    id-fpki-common-pivi-cardAuth must only be used to authenticate the
#    hardware token containing the associated private key and must not be
#    interpreted as authenticating the presenter or holder of the token."
#
# These previously sat in FPKI_PE_OIDS.  The private key needs no activation
# data, and on a real card the card-authentication and personal-authentication
# certificates can share a subject identifier — so a PIN-less read would have
# authenticated as the cardholder.
FPKI_CARD_AUTH_OIDS: set[str] = {
    "2.16.840.1.101.3.2.1.3.17",  # id-fpki-common-cardAuth
    "2.16.840.1.101.3.2.1.3.46",  # id-fpki-common-pivi-cardAuth
}

# Non-Person Entity (device) policies.  FPKI Common CP: "Device Subscriber
# certificates".  Intended use: NPE_AUTH.
FPKI_NPE_OIDS: set[str] = {
    "2.16.840.1.101.3.2.1.3.8",  # id-fpki-common-devices (software)
    "2.16.840.1.101.3.2.1.3.36",  # id-fpki-common-devicesHardware
}

# Content/object signing policies.  Certificates must carry a critical EKU
# (id-PIV-content-signing / id-fpki-pivi-content-signing) and are issued to a
# card-management system, not a person.  Intended use: OBJECT_SIGNING.
FPKI_OBJECT_SIGNING_OIDS: set[str] = {
    "2.16.840.1.101.3.2.1.3.39",  # id-fpki-common-piv-contentSigning
    "2.16.840.1.101.3.2.1.3.47",  # id-fpki-common-pivi-contentSigning
}

# ---------------------------------------------------------------------------
# Federal Bridge CA (FBCA) — SAME numeric arc 2.16.840.1.101.3.2.1.3.x but the
# id-fpki-certpcy-* suffixes are defined by the FBCA CP (disjoint from the
# id-fpki-common-* suffixes above).  Source: FBCA CP v3.9 Section 1.2
#   (verified 2026-08-21).
#
#   Rudimentary (.1) and Basic (.2) assurance are intentionally excluded.  The
#   authority is the preamble of the DoD Approved Assurance Levels reference,
#   which states: "DoD PKI only maps OIDs determined to be equivalent to DoD or
#   Federal Bridge Certification Authority (FBCA) medium hardware assurance
#   level or higher; other OIDs issued by DoD-Approved External PKIs are not
#   acceptable."  That file does not enumerate the excluded levels — an earlier
#   version of this comment implied it did — so the justification is the
#   floor stated above, not an absence from a list.
# ---------------------------------------------------------------------------
FBCA_PE_OIDS: set[str] = {
    "2.16.840.1.101.3.2.1.3.3",  # id-fpki-certpcy-mediumAssurance
    "2.16.840.1.101.3.2.1.3.4",  # id-fpki-certpcy-highAssurance
    "2.16.840.1.101.3.2.1.3.12",  # id-fpki-certpcy-mediumHardware
    "2.16.840.1.101.3.2.1.3.14",  # id-fpki-certpcy-medium-CBP
    "2.16.840.1.101.3.2.1.3.15",  # id-fpki-certpcy-mediumHW-CBP
    "2.16.840.1.101.3.2.1.3.18",  # id-fpki-certpcy-pivi-hardware
}

# FBCA v3.9 Section 1.4.2, "Prohibited Certificate Uses":
#   "Certificates that map to id-fpki-certpcy-pivi-cardAuth must be used only
#    to authenticate the hardware token containing the associated private key
#    and must not be interpreted as authenticating the presenter or holder of
#    the token."
FBCA_CARD_AUTH_OIDS: set[str] = {
    "2.16.840.1.101.3.2.1.3.19",  # id-fpki-certpcy-pivi-cardAuth
}

FBCA_NPE_OIDS: set[str] = {
    "2.16.840.1.101.3.2.1.3.37",  # id-fpki-certpcy-mediumDevice
    "2.16.840.1.101.3.2.1.3.38",  # id-fpki-certpcy-mediumDeviceHardware
}

FBCA_OBJECT_SIGNING_OIDS: set[str] = {
    "2.16.840.1.101.3.2.1.3.20",  # id-fpki-certpcy-pivi-contentSigning
}

# ---------------------------------------------------------------------------
# DoD ECA (External Certification Authority) — arc 2.16.840.1.101.3.2.1.12.x
# Issued to contractors and non-DoD entities accessing DoD systems (IA-8).
# Source: DoD ECA CP v4.8 Sections 1.2, 1.4.1, 10.5.6.  Per Section 1.2: "End-Entity
# certificates issued to devices shall always assert a Medium Device, Medium
# Device Hardware or PIV-I Content Signing policy.  All other policies defined
# in this document are reserved for human subscribers."
# ---------------------------------------------------------------------------
# Person (PE) policies.  Intended use: PERSONAL_AUTH.
#   .1/.2/.3 are "no longer authorized for issuance" but remain valid in the
#   field.
ECA_PE_OIDS: set[str] = {
    "2.16.840.1.101.3.2.1.12.1",  # id-eca-medium
    "2.16.840.1.101.3.2.1.12.2",  # id-eca-medium-hardware
    "2.16.840.1.101.3.2.1.12.3",  # id-eca-medium-token
    "2.16.840.1.101.3.2.1.12.4",  # id-eca-medium-sha256
    "2.16.840.1.101.3.2.1.12.5",  # id-eca-medium-token-sha256
    "2.16.840.1.101.3.2.1.12.6",  # id-eca-medium-hardware-pivi
    "2.16.840.1.101.3.2.1.12.10",  # id-eca-medium-hardware-sha256
    "2.16.840.1.101.3.2.1.12.11",  # id-eca-medium-sha384
    "2.16.840.1.101.3.2.1.12.12",  # id-eca-medium-token-sha384
    "2.16.840.1.101.3.2.1.12.14",  # id-eca-medium-hardware-sha384
}

# Non-Person Entity (device) policies.  Intended use: NPE_AUTH.
#   .9 (id-eca-medium-device-sha256) is the policy observed in the wild on the
#   WidePoint/ORC-issued AtHoc emergency-alert cert (CN=athocalerts.com).  It
#   is a DEVICE policy, not a content-signing policy.
ECA_NPE_OIDS: set[str] = {
    "2.16.840.1.101.3.2.1.12.9",  # id-eca-medium-device-sha256
    "2.16.840.1.101.3.2.1.12.13",  # id-eca-medium-device-sha384
    "2.16.840.1.101.3.2.1.12.15",  # id-eca-medium-device-hardware-sha384
    "2.16.840.1.101.3.2.1.12.16",  # id-eca-medium-device-hardware-sha256
}

# Content/object signing policy.  Intended use: OBJECT_SIGNING.  EKU
# id-fpki-pivi-content-signing {2.16.840.1.101.3.8.7}; signs data objects on a
# PIV-I smart card only (ECA CP v4.8 Section 1.2 / 10.5.11).
ECA_OBJECT_SIGNING_OIDS: set[str] = {
    "2.16.840.1.101.3.2.1.12.8",  # id-eca-contentsigning-pivi
}

# Card-authentication policy.  Intended use: CARD_AUTH — NEVER PERSONAL_AUTH.
#
# ECA CP v4.8 Section 1.2 registers this as
#   id-eca-cardauth-pivi   ID::= {id-eca-policies 7}
# and Section 1.4.1 states: "Because Card Authentication assurance
# certificates do not require activation data to unlock the private key,
# validation of a Card Authentication certificate provides only proof of the
# physical presence of the smart card token.  It provides no proof of the
# identity of the individual in possession of the token."
#
# Section 10.5.6 gives the profile: EKU c=yes id-PIV-cardAuth
# {2.16.840.1.101.3.6.8}, subject sn=<GUID> with no person name.
#
# A previous comment here asserted that .7 was unassigned and omitted it
# entirely, so an ECA PIV-I Card Authentication certificate matched no
# provider at all (verified against CP v4.8, 2026-08-21).
ECA_CARD_AUTH_OIDS: set[str] = {
    "2.16.840.1.101.3.2.1.12.7",  # id-eca-cardauth-pivi
}

# ---------------------------------------------------------------------------
# Aggregate sets by use, spanning hierarchies.  Provider definitions in
# providers.py compose their auth_oids / email_signing_oids from these.
# ---------------------------------------------------------------------------
FEDERAL_PE_OIDS: frozenset[str] = frozenset(FPKI_PE_OIDS | FBCA_PE_OIDS)
FEDERAL_NPE_OIDS: frozenset[str] = frozenset(FPKI_NPE_OIDS | FBCA_NPE_OIDS)
OBJECT_SIGNING_OIDS: frozenset[str] = frozenset(
    FPKI_OBJECT_SIGNING_OIDS | FBCA_OBJECT_SIGNING_OIDS | ECA_OBJECT_SIGNING_OIDS
)
# Card/token-presence policies across all three hierarchies.  Kept out of
# FEDERAL_PE_OIDS deliberately: every CP that defines one of these forbids
# interpreting it as authenticating the holder (FPKI Common v2.13 §1.4.2,
# FBCA v3.9 §1.4.2, ECA v4.8 §1.4.1).
CARD_AUTH_OIDS: frozenset[str] = frozenset(
    FPKI_CARD_AUTH_OIDS | FBCA_CARD_AUTH_OIDS | ECA_CARD_AUTH_OIDS
)
