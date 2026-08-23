#!/usr/bin/env python3
"""Read every certificate off an inserted smartcard and validate each one.

A manual hardware test — it needs a physical CAC / PIV / ECA card in a
reader, so it cannot run in CI.  Use it to check pki-federal against real
credentials rather than synthetic fixtures.

Each certificate is validated twice: once expecting ``clientAuth`` (the
pki-core default, and what fpki-verify-milter uses) and once expecting
``emailProtection`` (S/MIME).  Certificates whose result differs between
the two are flagged EKU-SENSITIVE — these are the ones an S/MIME caller
must not validate with the authentication default.  See pki-core's
``expected_eku`` and the CHANGELOG entry that introduced it.

Requires OpenSC (``pkcs15-tool``) on PATH or at --pkcs15-tool, and
**pki-core >= 0.5.0** for ``expected_eku``.  pki-federal itself only needs
>= 0.4.0, so an environment valid for the library can still be too old for
this script; it checks at startup rather than failing with a TypeError deep
in the validation call.

Privacy: exported certificates carry the cardholder's name, email and
certificate serials.  They are written to a temporary directory by
default; pass --outdir only if you intend to keep them, and do not commit
them.

Examples::

    ./scripts/validate-card.py
    ./scripts/validate-card.py --label my-cac --outdir /tmp/cac-certs
    ./scripts/validate-card.py --no-revocation      # offline
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from pki.core.certificate import load_certificate
from pki.core.crl import load_ca_certs_from_pem
from pki.core.revocation import CRL, OCSP, RevocationPolicy
from pki.core.trust_store import build_ca_bundle_for_providers
from pki.core.validation import CertificatePolicy, validate_certificate
from pki.federal import SP800_78_ALGORITHM_POLICY
from pki.federal.crl import CRLConfig
from pki.federal.providers import full_registry

EKU_NAMES = {
    ExtendedKeyUsageOID.CLIENT_AUTH: "clientAuth",
    ExtendedKeyUsageOID.EMAIL_PROTECTION: "emailProtection",
    ExtendedKeyUsageOID.SERVER_AUTH: "serverAuth",
    ExtendedKeyUsageOID.CODE_SIGNING: "codeSigning",
    x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.2"): "msSmartcardLogon",
    # id-PIV-cardAuth per ECA CP v4.8 certificate profile ("Extended key usage
    # c=yes; id-PIV-cardAuth {2.16.840.1.101.3.6.8}").  Deliberately no entry
    # for 2.16.840.1.101.3.6.7: content-signing OIDs in this estate are
    # id-fpki-common-piv-contentSigning {2.16.840.1.101.3.2.1.3.39} and
    # id-fpki-pivi-content-signing {2.16.840.1.101.3.8.7} (see oids.py), and an
    # unverified label here would be the same defect 0.5.0 fixed in oids.py.
    x509.ObjectIdentifier("2.16.840.1.101.3.6.8"): "id-PIV-cardAuth",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--label", default="card", help="subdirectory name for exported certs")
    p.add_argument("--outdir", type=Path, help="where to write certs (default: a temp dir)")
    p.add_argument("--bundle", type=Path, help="CA bundle PEM (default: build one, cached)")
    p.add_argument("--crl-cache", type=Path, help="CRL cache directory")
    p.add_argument("--pkcs15-tool", default=shutil.which("pkcs15-tool") or "pkcs15-tool")
    p.add_argument("--no-revocation", action="store_true", help="skip CRL/OCSP (offline)")
    p.add_argument("--timeout", type=int, default=60, help="pkcs15-tool timeout in seconds")
    return p.parse_args()


def describe_extensions(cert: x509.Certificate) -> tuple[str, str]:
    """Return human-readable (key_usage, extended_key_usage) strings."""
    # get_extension_for_class() is generic over the extension type, so the
    # returned .value is precisely typed.  get_extension_for_oid() returns a
    # bare ExtensionType and forces a cast.
    try:
        ekus = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        eku_str = ", ".join(EKU_NAMES.get(o, o.dotted_string) for o in ekus)
    except x509.ExtensionNotFound:
        eku_str = "(none — unrestricted per RFC 5280)"

    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        ku_str = (
            ", ".join(
                name
                for name, present in (
                    ("digitalSignature", ku.digital_signature),
                    ("nonRepudiation", ku.content_commitment),
                    ("keyEncipherment", ku.key_encipherment),
                    ("keyAgreement", ku.key_agreement),
                )
                if present
            )
            or "(none set)"
        )
    except x509.ExtensionNotFound:
        ku_str = "(none)"

    return ku_str, eku_str


def check_pki_core_supports_eku() -> str | None:
    """Return an error message if the installed pki-core predates expected_eku.

    Capability check rather than a version-string comparison: it asks whether
    the field this script actually uses exists, so it stays correct across
    backports and pre-releases.
    """
    if "expected_eku" not in CertificatePolicy.__dataclass_fields__:
        try:
            from importlib.metadata import version

            found = version("pki-core")
        except Exception:
            # Diagnostics only — a missing/odd dist must not mask the real
            # message, which is the absent field rather than the version.
            found = "unknown"
        return (
            f"pki-core {found} has no CertificatePolicy.expected_eku; this "
            "script needs >= 0.5.0. pki-federal itself only requires >= 0.4.0, "
            "so the library can be satisfied while this script is not."
        )
    return None


def main() -> int:
    args = parse_args()

    problem = check_pki_core_supports_eku()
    if problem:
        print(f"error: {problem}", file=sys.stderr)
        return 2

    if not shutil.which(args.pkcs15_tool) and not Path(args.pkcs15_tool).is_file():
        print(
            f"error: pkcs15-tool not found at {args.pkcs15_tool!r} — install OpenSC",
            file=sys.stderr,
        )
        return 2

    outdir = args.outdir or Path(tempfile.mkdtemp(prefix="pki-card-"))
    outdir = outdir / args.label
    outdir.mkdir(parents=True, exist_ok=True)

    registry = full_registry()

    bundle = args.bundle or (outdir.parent / "ca-bundle.pem")
    if not bundle.exists():
        print("Building CA bundle (DoD + FPKI + ECA) ...", flush=True)
        build_ca_bundle_for_providers(registry, output_path=str(bundle))
    ca_certs = load_ca_certs_from_pem(bundle.read_bytes())
    print(f"Trust store: {len(ca_certs)} CA certificates")

    crl_cache = args.crl_cache or (outdir.parent / "crlcache")
    crl_cache.mkdir(parents=True, exist_ok=True)

    def policy_for(eku: x509.ObjectIdentifier) -> CertificatePolicy:
        return CertificatePolicy(
            check_chain=True,
            trust_store=ca_certs,
            algorithm_policy=SP800_78_ALGORITHM_POLICY,
            registry=registry,
            check_validity_period=True,
            expected_eku=eku,
            revocation=None
            if args.no_revocation
            else RevocationPolicy(
                checks=(CRL, OCSP),
                issuer_certs=ca_certs,
                crl_config=CRLConfig(cache_dir=str(crl_cache)),
                strict=True,
            ),
        )

    policies = {
        "clientAuth": policy_for(ExtendedKeyUsageOID.CLIENT_AUTH),
        "emailProtection": policy_for(ExtendedKeyUsageOID.EMAIL_PROTECTION),
    }

    listing = subprocess.run(
        [args.pkcs15_tool, "--list-certificates"],
        capture_output=True,
        text=True,
        timeout=args.timeout,
    )
    if listing.returncode != 0:
        print(f"error: could not read card:\n{listing.stderr.strip()}", file=sys.stderr)
        return 1

    ids = re.findall(r"ID\s+:\s*([0-9a-fA-F]+)", listing.stdout)
    labels = re.findall(r"X\.509 Certificate \[(.*?)\]", listing.stdout)
    if not ids:
        print("error: no certificates found on card", file=sys.stderr)
        return 1

    print(f"Card reports {len(ids)} certificates: {', '.join(ids)}")
    print(f"Exported to: {outdir}\n")

    sensitive = 0
    for cert_id, cert_label in zip(ids, labels + [""] * len(ids), strict=False):
        read = subprocess.run(
            [args.pkcs15_tool, "--read-certificate", cert_id],
            capture_output=True,
            timeout=args.timeout,
        )
        if read.returncode != 0 or not read.stdout.strip():
            print(f"[{cert_id}] {cert_label}\n        could not read\n")
            continue

        (outdir / f"cert-{cert_id}.pem").write_bytes(read.stdout)
        cert = load_certificate(read.stdout)
        ku_str, eku_str = describe_extensions(cert)
        results = {name: validate_certificate(cert, pol) for name, pol in policies.items()}

        print(f"[{cert_id}] {cert_label}")
        print(f"        expires : {cert.not_valid_after_utc:%Y-%m-%d}")
        print(f"        KU      : {ku_str}")
        print(f"        EKU     : {eku_str}")
        for name, res in results.items():
            print(f"        {name:>15} : {res.status.name}")
        identity = next((r.identity for r in results.values() if r.identity), None)
        if identity:
            print(f"        identity: {identity.credential_type} / {identity.primary_id}")

        statuses = {r.status for r in results.values()}
        if len(statuses) > 1:
            sensitive += 1
            print("        *** EKU-SENSITIVE — validating this cert with the clientAuth")
            print("            default would reject it; S/MIME callers must set")
            print("            expected_eku=EMAIL_PROTECTION ***")
        print()

    print(f"{len(ids)} certificates checked, {sensitive} EKU-sensitive.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
