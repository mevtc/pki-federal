"""DoD and Federal PKI certificate policy OID registries.

OID definitions are sourced from:

- DoD PKI OIDs: DISA PKI/PKE Reference Materials
  https://public.cyber.mil/pki-pke/interoperability/

- Federal PKI OIDs: X.509 Certificate Policy for the U.S. FPKI Common Policy Framework
  https://www.idmanagement.gov/topics/fpki/

- ECA OIDs: DoD ECA Certificate Policy
  https://public.cyber.mil/eca/

- OID assignments under arc 2.16.840.1.101.2 (DoD) and 2.16.840.1.101.3 (FPKI)
  are registered in the FPKI OID registry maintained by GSA/FICAM:
  https://www.idmanagement.gov/fpki/
"""

# DoD authentication certificate policy OIDs (CAC)
# Source: DoD CIO PKI/PKE SRG, DISA STIG V-259702
DOD_AUTH_OIDS: set[str] = {
    "2.16.840.1.101.2.1.11.5",  # id-fpki-certpcy-dodMediumHardware
    "2.16.840.1.101.2.1.11.9",  # id-fpki-certpcy-dodMedium
    "2.16.840.1.101.2.1.11.19",  # id-fpki-certpcy-dodPIVAuth
    "2.16.840.1.101.2.1.11.42",  # id-fpki-certpcy-dodPIVAuth2
}

# Federal PKI PIV authentication certificate policy OIDs
# Source: X.509 Certificate Policy for the U.S. FPKI Common Policy Framework v2.6+
FPKI_PIV_AUTH_OIDS: set[str] = {
    "2.16.840.1.101.3.2.1.3.13",  # id-fpki-common-authentication
    "2.16.840.1.101.3.2.1.3.16",  # id-fpki-common-derived-pivAuth
}

# DoD email signing certificate policy OIDs (S/MIME)
# Source: DoD CIO PKI/PKE SRG
DOD_EMAIL_SIGNING_OIDS: set[str] = {
    "2.16.840.1.101.2.1.11.10",  # id-fpki-certpcy-dodMediumToken
    "2.16.840.1.101.2.1.11.18",  # id-fpki-certpcy-dodMediumTokenSHA256
    "2.16.840.1.101.2.1.11.36",  # id-fpki-certpcy-dodMediumHardware2048
    "2.16.840.1.101.2.1.11.39",  # id-fpki-certpcy-dodMedium2048
}

# Federal PKI email signing certificate policy OIDs
# Source: X.509 Certificate Policy for the U.S. FPKI Common Policy Framework v2.6+
FPKI_EMAIL_SIGNING_OIDS: set[str] = {
    "2.16.840.1.101.3.2.1.3.12",  # id-fpki-common-policy
    "2.16.840.1.101.3.2.1.3.40",  # id-fpki-common-piv-contentSigning
}

# ECA (External Certification Authority) authentication certificate policy OIDs
# Issued to contractors and non-DoD entities accessing DoD systems (IA-8).
# Source: DoD ECA Certificate Policy v4.4+
# https://public.cyber.mil/eca/
ECA_AUTH_OIDS: set[str] = {
    "2.16.840.1.101.3.2.1.12.1",  # id-eca-medium
    "2.16.840.1.101.3.2.1.12.2",  # id-eca-medium-hardware
    "2.16.840.1.101.3.2.1.12.3",  # id-eca-medium-token
    "2.16.840.1.101.3.2.1.12.4",  # id-eca-medium-sha256
    "2.16.840.1.101.3.2.1.12.5",  # id-eca-medium-token-sha256
    "2.16.840.1.101.3.2.1.12.6",  # id-eca-medium-hardware-pivi
    "2.16.840.1.101.3.2.1.12.10",  # id-eca-medium-hardware-sha256
}
