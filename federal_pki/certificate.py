"""X.509 certificate parsing utilities for DoD and Federal PKI certificates."""

from datetime import datetime, timezone
from hashlib import sha256

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID, NameOID


class CertificateError(Exception):
    """Raised when certificate parsing or validation fails."""


def load_certificate(data: bytes) -> x509.Certificate:
    """Load an x509 certificate from PEM or DER bytes."""
    try:
        return x509.load_pem_x509_certificate(data)
    except Exception:
        pass
    try:
        return x509.load_der_x509_certificate(data)
    except Exception as e:
        raise CertificateError(f"Failed to parse certificate: {e}")


def get_name_attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    """Get first attribute value for an OID from an x509 Name."""
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else None


def get_policy_oids(cert: x509.Certificate) -> list[str]:
    """Extract certificate policy OIDs."""
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.CERTIFICATE_POLICIES
        )
        return [p.policy_identifier.dotted_string for p in ext.value]
    except x509.ExtensionNotFound:
        return []


def extract_email(cert: x509.Certificate) -> str | None:
    """Extract email from SAN (rfc822Name) or subject."""
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        emails = san.value.get_values_for_type(x509.RFC822Name)
        if emails:
            return emails[0]
    except x509.ExtensionNotFound:
        pass

    return get_name_attr(cert.subject, NameOID.EMAIL_ADDRESS)


def extract_san_uris(cert: x509.Certificate) -> list[str]:
    """Extract URI values from Subject Alternative Name."""
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        return list(san.value.get_values_for_type(x509.UniformResourceIdentifier))
    except x509.ExtensionNotFound:
        return []


def extract_san_uuid(cert: x509.Certificate) -> str | None:
    """Extract PIV UUID from SAN URI (urn:uuid:...)."""
    for uri in extract_san_uris(cert):
        if uri.lower().startswith("urn:uuid:"):
            return uri[9:]
    return None


def extract_san_fascn(cert: x509.Certificate) -> str | None:
    """Extract FASC-N from SAN OtherName (OID 2.16.840.1.101.3.6.6)."""
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        for general_name in san.value:
            if isinstance(general_name, x509.OtherName):
                if general_name.type_id.dotted_string == "2.16.840.1.101.3.6.6":
                    return general_name.value.hex()
    except (x509.ExtensionNotFound, Exception):
        pass
    return None


def cert_fingerprint(cert: x509.Certificate) -> str:
    """SHA-256 fingerprint of the DER encoding."""
    return sha256(cert.public_bytes(Encoding.DER)).hexdigest()


def cert_to_pem(cert: x509.Certificate) -> str:
    """Convert an x509 certificate to PEM string."""
    return cert.public_bytes(Encoding.PEM).decode("ascii")


def is_expired(cert: x509.Certificate) -> bool:
    """Return True if the certificate has expired."""
    return cert.not_valid_after_utc < datetime.now(timezone.utc)