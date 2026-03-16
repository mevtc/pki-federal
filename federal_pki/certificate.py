"""Backward-compatible re-exports from pki-core."""

from pki_core.certificate import (  # noqa: F401
    CertificateError,
    cert_fingerprint,
    cert_to_pem,
    extract_email,
    extract_san_fascn,
    extract_san_uris,
    extract_san_uuid,
    get_name_attr,
    get_policy_oids,
    is_expired,
    is_not_yet_valid,
    load_certificate,
)
