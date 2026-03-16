"""DoD and Federal PKI CA trust store management.

Downloads, parses, deduplicates, and merges CA certificate bundles from
DISA (DoD), repo.fpki.gov (Federal PKI), and other provider sources.

Controls: SC-12 (Cryptographic Key Management), IA-5(2) (PKI-Based Auth)
"""

import io
import logging
import os
import zipfile

import httpx
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    load_der_pkcs7_certificates,
    load_pem_pkcs7_certificates,
)
from cryptography.x509 import load_der_x509_certificate

from .certificate import cert_fingerprint, cert_to_pem

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

USER_AGENT = "federal-pki/0.1"


# ---------------------------------------------------------------------------
# Download helper
# ---------------------------------------------------------------------------


def _download(url: str, timeout: int = 60) -> bytes:
    """Download a URL and return raw bytes."""
    logger.info("Downloading %s", url)
    resp = httpx.get(
        url,
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    )
    resp.raise_for_status()
    logger.info("Downloaded %d bytes from %s", len(resp.content), url)
    return resp.content


# ---------------------------------------------------------------------------
# Source fetchers
# ---------------------------------------------------------------------------


def fetch_dod_certs(url: str | None = None) -> list:
    """Download and parse DoD CA certificates from DISA PKCS7 ZIP.

    Args:
        url: Override the default DoD PKI ZIP URL.

    Returns:
        List of cryptography x509.Certificate objects.
    """
    certs = []
    zip_data = _download(url or DOD_PKI_ZIP_URL)

    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        for name in zf.namelist():
            if not (name.endswith(".p7b") or name.endswith(".p7c")):
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
    der_data = _download(FCPCA_G2_URL)
    cert = load_der_x509_certificate(der_data)
    certs.append(cert)
    logger.info("Loaded FCPCA G2 root: %s", cert.subject)

    # Federal Bridge CA G4 bundles (PKCS7/DER)
    for url in [FBCA_G4_ISSUED_TO_URL, FBCA_G4_ISSUED_BY_URL]:
        p7c_data = _download(url)
        parsed = load_der_pkcs7_certificates(p7c_data)
        logger.info("Parsed %d certs from %s", len(parsed), url)
        certs.extend(parsed)

    logger.info("Total FPKI CA certificates: %d", len(certs))
    return certs


# ---------------------------------------------------------------------------
# Merge and deduplicate
# ---------------------------------------------------------------------------


def merge_and_deduplicate(
    cert_lists: list[tuple[str, list]],
    filter_fn=None,
) -> tuple[str, dict]:
    """Merge certificate lists, deduplicate by fingerprint, return PEM bundle.

    Args:
        cert_lists: List of (source_label, cert_list) tuples.
        filter_fn: Optional callable(cert) -> bool. If provided, only certs
            where filter_fn returns True are included.

    Returns:
        Tuple of (pem_bundle_string, stats_dict).
    """
    seen: dict[str, str] = {}
    pem_parts = []

    for source, certs in cert_lists:
        for cert in certs:
            fp = cert_fingerprint(cert)
            if fp in seen:
                continue
            if filter_fn and not filter_fn(cert):
                logger.debug("Skipping filtered cert: %s", cert.subject)
                continue
            seen[fp] = source
            pem_parts.append(cert_to_pem(cert))

    sources = set(seen.values())
    stats = {src: sum(1 for s in seen.values() if s == src) for src in sources}
    stats["total"] = len(seen)

    logger.info("Merged bundle: %s = %d unique certificates", stats, stats["total"])
    return "".join(pem_parts), stats


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


# ---------------------------------------------------------------------------
# Provider-aware trust store building (SC-12)
# ---------------------------------------------------------------------------


def fetch_trust_store_source(source) -> list:
    """Download and parse certificates from a single TrustStoreSource.

    Dispatches on source.format: pkcs7_zip, pkcs7_der, der.
    """
    fmt = source.format
    if fmt == "pkcs7_zip":
        return _fetch_pkcs7_zip(source.url)
    elif fmt == "pkcs7_der":
        return _fetch_pkcs7_der(source.url)
    elif fmt == "der":
        return _fetch_der_cert(source.url)
    else:
        logger.warning("Unknown trust store format: %s", fmt)
        return []


def _fetch_pkcs7_zip(url: str) -> list:
    """Download ZIP containing PKCS7 bundles, parse all certs."""
    certs = []
    zip_data = _download(url)
    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        for name in zf.namelist():
            if not (name.endswith(".p7b") or name.endswith(".p7c")):
                continue
            p7_data = zf.read(name)
            try:
                parsed = load_pem_pkcs7_certificates(p7_data)
                certs.extend(parsed)
            except Exception:
                try:
                    parsed = load_der_pkcs7_certificates(p7_data)
                    certs.extend(parsed)
                except Exception as e:
                    logger.warning("Could not parse %s: %s", name, e)
    return certs


def _fetch_pkcs7_der(url: str) -> list:
    """Download a DER-encoded PKCS7 bundle."""
    data = _download(url)
    return list(load_der_pkcs7_certificates(data))


def _fetch_der_cert(url: str) -> list:
    """Download a single DER-encoded X.509 certificate."""
    data = _download(url)
    return [load_der_x509_certificate(data)]


def build_ca_bundle_for_providers(
    registry=None,
    output_path: str | None = None,
    filter_fn=None,
) -> tuple[str, dict]:
    """Fetch CA certificates for all providers in a registry.

    Only loads CAs from enabled providers, enforcing least-privilege on the
    trust chain (SC-12).

    Args:
        registry: ProviderRegistry. Defaults to CAC + PIV.
        output_path: If provided, write the PEM bundle to this path.
        filter_fn: Optional callable(cert) -> bool for filtering.

    Returns:
        Tuple of (pem_bundle_string, stats_dict).
    """
    if registry is None:
        from .providers import default_registry

        registry = default_registry()

    cert_lists = []
    for provider in registry.all():
        for source in provider.trust_store_sources:
            label = source.label or provider.name
            try:
                certs = fetch_trust_store_source(source)
                logger.info(
                    "Fetched %d certs from %s (%s)", len(certs), source.url, label
                )
                cert_lists.append((label, certs))
            except Exception as e:
                logger.error("Failed to fetch %s: %s", source.url, e)

    if not cert_lists or not any(certs for _, certs in cert_lists):
        raise RuntimeError("No certificates fetched from any provider source")

    pem_bundle, stats = merge_and_deduplicate(cert_lists, filter_fn=filter_fn)

    if output_path:
        from pathlib import Path

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(pem_bundle)
        logger.info("CA bundle written to %s", output_path)

    return pem_bundle, stats
