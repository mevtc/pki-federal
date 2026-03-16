"""DoD and Federal PKI CA trust store management.

Downloads, parses, deduplicates, and merges CA certificate bundles from
DISA (DoD), repo.fpki.gov (Federal PKI), and other provider sources.

Controls: SC-12 (Cryptographic Key Management), IA-5(2) (PKI-Based Auth)
"""

import io
import logging
import os
import zipfile

from cryptography.hazmat.primitives.serialization.pkcs7 import (
    load_der_pkcs7_certificates,
    load_pem_pkcs7_certificates,
)
from cryptography.x509 import load_der_x509_certificate
from pki_core.trust_store import (  # noqa: F401
    MAX_DOWNLOAD_BYTES,
    USER_AGENT,
    build_ca_bundle_for_providers,
    download,
    fetch_trust_store_source,
    merge_and_deduplicate,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Certificate source URLs
# ---------------------------------------------------------------------------

DOD_PKI_ZIP_URL = os.environ.get(
    "DOD_PKI_URL",
    "https://dl.dod.cyber.mil/wp-content/uploads/pki-pke/zip/unclass-certificates_pkcs7_DoD.zip",
)

FCPCA_G2_URL = "https://repo.fpki.gov/fcpca/fcpcag2.crt"
FBCA_G4_ISSUED_TO_URL = "https://repo.fpki.gov/bridge/caCertsIssuedTofbcag4.p7c"
FBCA_G4_ISSUED_BY_URL = "https://repo.fpki.gov/bridge/caCertsIssuedByfbcag4.p7c"


# ---------------------------------------------------------------------------
# Federal-specific source fetchers
# ---------------------------------------------------------------------------


def fetch_dod_certs(url: str | None = None) -> list:
    """Download and parse DoD CA certificates from DISA PKCS7 ZIP.

    Args:
        url: Override the default DoD PKI ZIP URL.

    Returns:
        List of cryptography x509.Certificate objects.
    """
    certs = []
    zip_data = download(url or DOD_PKI_ZIP_URL)

    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        for name in zf.namelist():
            if not (name.endswith(".p7b") or name.endswith(".p7c")):
                continue
            if ".." in name or name.startswith("/"):
                logger.warning("Skipping suspicious ZIP entry: %s", name)
                continue

            p7_data = zf.read(name)
            try:
                parsed = load_pem_pkcs7_certificates(p7_data)
                logger.info("Parsed %d certs from %s (PEM PKCS7)", len(parsed), name)
                certs.extend(parsed)
            except Exception:
                try:
                    parsed = load_der_pkcs7_certificates(p7_data)
                    logger.info("Parsed %d certs from %s (DER PKCS7)", len(parsed), name)
                    certs.extend(parsed)
                except Exception as e:
                    logger.warning("Could not parse %s: %s", name, e)

    logger.info("Total DoD CA certificates: %d", len(certs))
    return certs


def fetch_fpki_certs() -> list:
    """Download and parse Federal PKI CA certificates.

    Returns:
        List of cryptography x509.Certificate objects.
    """
    certs = []

    # Federal Common Policy CA G2 root (DER X.509)
    der_data = download(FCPCA_G2_URL)
    cert = load_der_x509_certificate(der_data)
    certs.append(cert)
    logger.info("Loaded FCPCA G2 root: %s", cert.subject)

    # Federal Bridge CA G4 bundles (PKCS7/DER)
    for url in [FBCA_G4_ISSUED_TO_URL, FBCA_G4_ISSUED_BY_URL]:
        p7c_data = download(url)
        parsed = load_der_pkcs7_certificates(p7c_data)
        logger.info("Parsed %d certs from %s", len(parsed), url)
        certs.extend(parsed)

    logger.info("Total FPKI CA certificates: %d", len(certs))
    return certs


# ---------------------------------------------------------------------------
# Convenience bundle builder
# ---------------------------------------------------------------------------


def build_ca_bundle(
    output_path: str | None = None,
    filter_fn=None,
) -> tuple[str, dict]:
    """Fetch DoD + FPKI certs, merge, deduplicate, and optionally write to file.

    Args:
        output_path: If provided, write the PEM bundle to this path.
        filter_fn: Optional callable(cert) -> bool for filtering.

    Returns:
        Tuple of (pem_bundle_string, stats_dict).
    """
    dod_certs = fetch_dod_certs()
    fpki_certs = fetch_fpki_certs()

    if not dod_certs and not fpki_certs:
        raise RuntimeError("No certificates fetched from either source")

    pem_bundle, stats = merge_and_deduplicate(
        [("DoD", dod_certs), ("FPKI", fpki_certs)],
        filter_fn=filter_fn,
    )

    if output_path:
        from pathlib import Path

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(pem_bundle)
        logger.info("CA bundle written to %s", output_path)

    return pem_bundle, stats
