"""DoD and Federal PKI certificate policy OID registries."""

# DoD authentication certificate policy OIDs (CAC)
DOD_AUTH_OIDS: set[str] = {
    "2.16.840.1.101.2.1.11.5",  # id-fpki-certpcy-dodMediumHardware
    "2.16.840.1.101.2.1.11.9",  # id-fpki-certpcy-dodMedium
    "2.16.840.1.101.2.1.11.19",  # id-fpki-certpcy-dodPIVAuth
    "2.16.840.1.101.2.1.11.42",  # id-fpki-certpcy-dodPIVAuth2
}

# Federal PKI PIV authentication certificate policy OIDs
FPKI_PIV_AUTH_OIDS: set[str] = {
    "2.16.840.1.101.3.2.1.3.13",  # id-fpki-common-authentication
    "2.16.840.1.101.3.2.1.3.16",  # id-fpki-common-derived-pivAuth
}

# DoD email signing certificate policy OIDs (S/MIME)
DOD_EMAIL_SIGNING_OIDS: set[str] = {
    "2.16.840.1.101.2.1.11.10",  # id-fpki-certpcy-dodMediumToken
    "2.16.840.1.101.2.1.11.18",  # id-fpki-certpcy-dodMediumTokenSHA256
    "2.16.840.1.101.2.1.11.36",  # id-fpki-certpcy-dodMediumHardware2048
    "2.16.840.1.101.2.1.11.39",  # id-fpki-certpcy-dodMedium2048
}

# Federal PKI email signing certificate policy OIDs
FPKI_EMAIL_SIGNING_OIDS: set[str] = {
    "2.16.840.1.101.3.2.1.3.12",  # id-fpki-common-policy
    "2.16.840.1.101.3.2.1.3.40",  # id-fpki-common-piv-contentSigning
}
