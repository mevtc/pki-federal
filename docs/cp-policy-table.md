# Certificate Policy OID Reference

Every policy OID recognised by `pki.federal.oids`, with the certificate
policy that defines it and the `IntendedUse` it maps to.

## Sources

All four policies were re-read in full and every OID below compared
against its registration section on **2026-08-23**.

| # | Document | Version | Sections read | URL |
|---|---|---|---|---|
| 1 | DoD PKI X.509 Certificate Policy | **v11**, 15 Dec 2025 | §1.2 | https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/pdf/DoD%20CP%20V11%20(20251215).pdf |
| 2 | FPKI Common Policy Framework | **v2.13** | §1.2, §1.4.2 | https://www.idmanagement.gov/docs/fpki-x509-cert-policy-common.pdf |
| 3 | Federal Bridge CA (FBCA) CP | **v3.9** | §1.2, §1.4.2 | https://www.idmanagement.gov/docs/fpki-x509-cert-policy-fbca.pdf |
| 4 | DoD ECA X.509 Certificate Policy | **v4.8**, 3 Jun 2024 | §1.2, §1.4.1, §10.5.6 | https://dl.dod.cyber.mil/wp-content/uploads/eca/pdf/unclass-eca_cp.pdf |
| 5 | DoD Approved Assurance Levels (interop) | v1.19, 20 Apr 2026 | preamble | https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/txt/unclass-pki_interop_assurance_levels.txt |

> The DoD CP v11 URL is printed in source 5 with `+` for spaces, which 404s.
> Re-encode as `%20`. Earlier revisions of `oids.py` cited v10.7 for that reason.

**Verification result:** DoD 20/20, FPKI Common 13/13, FBCA 10/10, ECA 16/16 —
every label matches its CP registration text. Two corrections came out of the
review; see *Deliberate omissions and corrections* below.

## DoD PKI

Registered in DoD CP v11 §1.2.

| OID | CP name | IntendedUse | Subject |
|---|---|---|---|
| `2.16.840.1.101.2.1.11.5` | id-US-dod-medium *(deprecated)* | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.2.1.11.9` | id-US-dod-mediumHardware *(deprecated)* | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.2.1.11.10` | id-US-dod-PIV-Auth *(deprecated)* | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.2.1.11.17` | id-US-dod-mediumNPE *(deprecated)* | `NPE_AUTH` | Device / service |
| `2.16.840.1.101.2.1.11.18` | id-US-dod-medium-2048 *(deprecated)* | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.2.1.11.19` | id-US-dod-mediumHardware-2048 *(deprecated)* | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.2.1.11.20` | id-US-dod-PIV-Auth-2048 *(deprecated)* | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.2.1.11.36` | id-US-dod-mediumNPE-112 | `NPE_AUTH` | Device / service |
| `2.16.840.1.101.2.1.11.37` | id-US-dod-mediumNPE-128 | `NPE_AUTH` | Device / service |
| `2.16.840.1.101.2.1.11.38` | id-US-dod-mediumNPE-192 | `NPE_AUTH` | Device / service |
| `2.16.840.1.101.2.1.11.39` | id-US-dod-medium-112 | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.2.1.11.40` | id-US-dod-medium-128 | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.2.1.11.41` | id-US-dod-medium-192 | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.2.1.11.42` | id-US-dod-mediumHardware-112 | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.2.1.11.43` | id-US-dod-mediumHardware-128 | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.2.1.11.44` | id-US-dod-mediumHardware-192 | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.2.1.11.59` | id-US-dod-admin | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.2.1.11.60` | id-US-dod-internalNPE-112 | `NPE_AUTH` | Device / service |
| `2.16.840.1.101.2.1.11.61` | id-US-dod-internalNPE-128 | `NPE_AUTH` | Device / service |
| `2.16.840.1.101.2.1.11.62` | id-US-dod-internalNPE-192 | `NPE_AUTH` | Device / service |

## FPKI Common Policy

Registered in Common Policy v2.13 §1.2.

| OID | CP name | IntendedUse | Subject |
|---|---|---|---|
| `2.16.840.1.101.3.2.1.3.6` | id-fpki-common-policy (software sig/auth) | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.3.7` | id-fpki-common-hardware | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.3.8` | id-fpki-common-devices (software) | `NPE_AUTH` | Device / service |
| `2.16.840.1.101.3.2.1.3.13` | id-fpki-common-authentication | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.3.16` | id-fpki-common-high | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.3.17` | id-fpki-common-cardAuth | `CARD_AUTH` | Card / token |
| `2.16.840.1.101.3.2.1.3.36` | id-fpki-common-devicesHardware | `NPE_AUTH` | Device / service |
| `2.16.840.1.101.3.2.1.3.39` | id-fpki-common-piv-contentSigning | `OBJECT_SIGNING` | Card-management system |
| `2.16.840.1.101.3.2.1.3.40` | id-fpki-common-derived-pivAuth | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.3.41` | id-fpki-common-derived-pivAuth-hardware | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.3.45` | id-fpki-common-pivi-authentication | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.3.46` | id-fpki-common-pivi-cardAuth | `CARD_AUTH` | Card / token |
| `2.16.840.1.101.3.2.1.3.47` | id-fpki-common-pivi-contentSigning | `OBJECT_SIGNING` | Card-management system |

## Federal Bridge CA

Registered in FBCA CP v3.9 §1.2.

| OID | CP name | IntendedUse | Subject |
|---|---|---|---|
| `2.16.840.1.101.3.2.1.3.3` | id-fpki-certpcy-mediumAssurance | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.3.4` | id-fpki-certpcy-highAssurance | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.3.12` | id-fpki-certpcy-mediumHardware | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.3.14` | id-fpki-certpcy-medium-CBP | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.3.15` | id-fpki-certpcy-mediumHW-CBP | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.3.18` | id-fpki-certpcy-pivi-hardware | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.3.19` | id-fpki-certpcy-pivi-cardAuth | `CARD_AUTH` | Card / token |
| `2.16.840.1.101.3.2.1.3.20` | id-fpki-certpcy-pivi-contentSigning | `OBJECT_SIGNING` | Card-management system |
| `2.16.840.1.101.3.2.1.3.37` | id-fpki-certpcy-mediumDevice | `NPE_AUTH` | Device / service |
| `2.16.840.1.101.3.2.1.3.38` | id-fpki-certpcy-mediumDeviceHardware | `NPE_AUTH` | Device / service |

## DoD ECA

Registered in ECA CP v4.8 §1.2.

| OID | CP name | IntendedUse | Subject |
|---|---|---|---|
| `2.16.840.1.101.3.2.1.12.1` | id-eca-medium | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.12.2` | id-eca-medium-hardware | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.12.3` | id-eca-medium-token | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.12.4` | id-eca-medium-sha256 | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.12.5` | id-eca-medium-token-sha256 | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.12.6` | id-eca-medium-hardware-pivi | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.12.7` | id-eca-cardauth-pivi | `CARD_AUTH` | Card / token |
| `2.16.840.1.101.3.2.1.12.8` | id-eca-contentsigning-pivi | `OBJECT_SIGNING` | Card-management system |
| `2.16.840.1.101.3.2.1.12.9` | id-eca-medium-device-sha256 | `NPE_AUTH` | Device / service |
| `2.16.840.1.101.3.2.1.12.10` | id-eca-medium-hardware-sha256 | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.12.11` | id-eca-medium-sha384 | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.12.12` | id-eca-medium-token-sha384 | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.12.13` | id-eca-medium-device-sha384 | `NPE_AUTH` | Device / service |
| `2.16.840.1.101.3.2.1.12.14` | id-eca-medium-hardware-sha384 | `PERSONAL_AUTH` | Person |
| `2.16.840.1.101.3.2.1.12.15` | id-eca-medium-device-hardware-sha384 | `NPE_AUTH` | Device / service |
| `2.16.840.1.101.3.2.1.12.16` | id-eca-medium-device-hardware-sha256 | `NPE_AUTH` | Device / service |

## Deliberate omissions and corrections

| OID | Status | Reason |
|---|---|---|
| `2.16.840.1.101.2.1.11.31` | **Excluded** | `id-US-dod-peerInterop`. Registered in CP v11 §1.2 and present in the DoD approved-assurance list, so it looks missing — it is not. v11: *"The id-dod-peerInterop OID is only asserted in cross certificates at the direction of the DoD PKI PMA."* A CA-to-CA policy; adding it would let a cross-certificate policy match a Subscriber credential. |
| `2.16.840.1.101.3.2.1.3.1` | **Excluded** | `id-fpki-certpcy-rudimentaryAssurance`. Below the DoD interop floor: *"DoD PKI only maps OIDs determined to be equivalent to DoD or FBCA medium hardware assurance level or higher."* |
| `2.16.840.1.101.3.2.1.3.2` | **Excluded** | `id-fpki-certpcy-basicAssurance`. Same floor. |
| `2.16.840.1.101.3.2.1.12.7` | **Added 2026-08-23** | `id-eca-cardauth-pivi` was absent, and a comment wrongly asserted it was unassigned. It is registered in ECA CP v4.8 §1.2; an ECA PIV-I card-authentication certificate previously matched no provider. |
| `…3.17`, `…3.46`, `…3.19` | **Reclassified 2026-08-23** | The card-authentication policies were in the person sets. Every governing CP forbids that reading — FPKI Common v2.13 §1.4.2 and FBCA v3.9 §1.4.2: such certificates *"must only be used to authenticate the hardware token … and must not be interpreted as authenticating the presenter or holder of the token."* |

## Notes

- CP v11 spells `.17` as `Id-US-dod-mediumNPE` with a capital I in the
  deprecated-OID block. A typo in the source document, not a separate
  registration — a case-sensitive search for it comes up empty.
- FPKI Common groups `id-fpki-common-cardAuth` under *"PIV Device Subscriber
  Certificates"*, which reads like an argument for `NPE_AUTH`. It is not: that
  heading separates non-person subscribers from person ones, and
  content-signing shares it while mapping to `OBJECT_SIGNING`. §1.4.2 says the
  certificate authenticates *the token* — neither a person nor a service.
- Deprecated OIDs are retained: they are no longer issued but remain valid on
  unexpired credentials in the field.

