"""CRL fetching and revocation checking with stale-while-revalidate caching."""

import hashlib
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from cryptography import x509
from platformdirs import user_cache_dir

from .certificate import CertificateError

logger = logging.getLogger(__name__)


def _default_cache_dir() -> str:
    """Return the platform-standard cache directory for federal-pki CRLs."""
    return str(Path(user_cache_dir("federal-pki")) / "crls")


@dataclass
class CRLConfig:
    """Configuration for CRL cache behaviour.

    ``cache_dir`` defaults to the platform-standard user cache location
    (e.g. ``~/.cache/federal-pki/crls`` on Linux,
    ``~/Library/Caches/federal-pki/crls`` on macOS).  Pass an explicit
    value to override.
    """

    cache_dir: str = field(default_factory=_default_cache_dir)
    cache_ttl: int = 3600  # seconds
    strict: bool = True
    fetch_timeout: int = 10  # seconds


def get_crl_distribution_points(cert: x509.Certificate) -> list[str]:
    """Extract HTTP(S) CRL distribution point URLs from a certificate."""
    try:
        ext = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    except x509.ExtensionNotFound:
        return []

    urls = []
    for dp in ext.value:
        if dp.full_name is None:
            continue
        for name in dp.full_name:
            if isinstance(name, x509.UniformResourceIdentifier):
                url = name.value
                if url.startswith("http://") or url.startswith("https://"):
                    urls.append(url)
    return urls


def check_revocation(cert: x509.Certificate, config: CRLConfig) -> None:
    """Check certificate revocation against CRL distribution points.

    Uses a stale-while-revalidate cache strategy:
    - Fresh cache  -> used immediately, no network I/O.
    - Stale cache  -> used immediately; background thread refreshes it.
    - No cache     -> blocking fetch (first-ever request only).

    Raises CertificateError if the certificate's serial number appears in any CRL.
    If a CRL cannot be fetched and no cached copy exists, behaviour is controlled
    by config.strict (default True -> raise).
    """
    urls = get_crl_distribution_points(cert)
    if not urls:
        logger.warning(
            "Certificate serial=%s has no CRL distribution points; skipping revocation check",
            format(cert.serial_number, "x"),
        )
        return

    for url in urls:
        try:
            crl = get_crl(url, config)
        except CertificateError:
            raise
        except Exception as e:
            logger.error("CRL unavailable for %s: %s", url, e)
            if config.strict:
                raise CertificateError("Could not verify revocation status; CRL unavailable") from e
            logger.warning("strict=false -- allowing without revocation check for %s", url)
            continue

        if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
            raise CertificateError(
                f"Certificate has been revoked (serial {format(cert.serial_number, 'x')})"
            )


def get_crl(url: str, config: CRLConfig) -> x509.CertificateRevocationList:
    """Return a parsed CRL for the given URL using a file-backed cache.

    Strategy (stale-while-revalidate):
      1. Fresh cache  -> return immediately.
      2. Stale cache  -> return stale copy; spawn background thread to refresh.
      3. No cache     -> fetch synchronously, cache result, return.
    """
    cache_dir = Path(config.cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)

    url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
    cache_file = cache_dir / f"{url_hash}.crl"

    if cache_file.exists():
        age = time.time() - cache_file.stat().st_mtime
        if age < config.cache_ttl:
            return parse_crl_bytes(cache_file.read_bytes())
        else:
            logger.debug(
                "CRL stale (%.0fs old) for %s -- serving cache, refreshing in background",
                age,
                url,
            )
            threading.Thread(
                target=refresh_crl,
                args=(url, cache_file, config.fetch_timeout),
                daemon=True,
            ).start()
            return parse_crl_bytes(cache_file.read_bytes())

    logger.debug("No CRL cache for %s -- fetching synchronously", url)
    return refresh_crl(url, cache_file, config.fetch_timeout)


def refresh_crl(url: str, cache_file: Path, timeout: int = 10) -> x509.CertificateRevocationList:
    """Fetch a CRL from url, write it to cache_file, and return parsed CRL.

    Called directly (blocking) when no cache exists, or from a daemon thread
    when the cache is stale.
    """
    try:
        resp = httpx.get(url, timeout=timeout, follow_redirects=True)
        resp.raise_for_status()
        data = resp.content
        crl = parse_crl_bytes(data)
        tmp = cache_file.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.rename(cache_file)
        logger.debug("CRL cached from %s (%d bytes)", url, len(data))
        return crl
    except CertificateError:
        raise
    except Exception as e:
        logger.error("Failed to fetch/cache CRL from %s: %s", url, e)
        raise


def parse_crl_bytes(data: bytes) -> x509.CertificateRevocationList:
    """Load a CRL from DER bytes (standard for DoD) with PEM fallback."""
    try:
        return x509.load_der_x509_crl(data)
    except Exception:
        pass
    try:
        return x509.load_pem_x509_crl(data)
    except Exception as e:
        raise CertificateError(f"Failed to parse CRL: {e}") from e


def prefetch_crls(cert: x509.Certificate, config: CRLConfig) -> dict[str, str]:
    """Proactively fetch and cache CRLs for a certificate.

    Intended for scheduled invocation (cron / Lambda) to keep the CRL cache
    warm so that real requests never block on a network fetch.

    Returns a dict mapping each CRL URL to "refreshed", "skipped (fresh)",
    or "error: <message>".
    """
    urls = get_crl_distribution_points(cert)
    if not urls:
        return {}

    cache_dir = Path(config.cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, str] = {}

    for url in urls:
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
        cache_file = cache_dir / f"{url_hash}.crl"
        if cache_file.exists():
            age = time.time() - cache_file.stat().st_mtime
            if age < config.cache_ttl:
                results[url] = "skipped (fresh)"
                continue
        try:
            refresh_crl(url, cache_file, config.fetch_timeout)
            results[url] = "refreshed"
        except Exception as e:
            results[url] = f"error: {e}"

    return results


def get_crl_max_age(cert: x509.Certificate, config: CRLConfig) -> float | None:
    """Return the age in seconds of the oldest cached CRL for a certificate.

    Returns None if no CRL distribution points are found.
    Returns float("inf") if any CRL has no cached file yet.
    """
    urls = get_crl_distribution_points(cert)
    if not urls:
        return None

    cache_dir = Path(config.cache_dir)
    max_age: float | None = None

    for url in urls:
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
        cache_file = cache_dir / f"{url_hash}.crl"
        if not cache_file.exists():
            return float("inf")
        age = time.time() - cache_file.stat().st_mtime
        if max_age is None or age > max_age:
            max_age = age

    return max_age
