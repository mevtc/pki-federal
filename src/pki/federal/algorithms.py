"""SP 800-78 algorithm policy for Federal PKI certificates.

Defines approved cryptographic algorithms per NIST SP 800-78
(Cryptographic Algorithms and Key Sizes for Personal Identity
Verification).  The defaults match SP 800-78-5 requirements for PIV
authentication certificates.

Applications may override with stricter requirements::

    from pki.core.algorithms import AlgorithmPolicy

    # ECC P-384 only, no RSA
    ecc_only = AlgorithmPolicy(
        min_rsa_bits=0,
        allowed_curves=frozenset({"secp384r1"}),
    )
"""

from pki.core.algorithms import AlgorithmPolicy

# SP 800-78-5 approved algorithms for PIV
# - RSA: 2048, 3072, 4096
# - ECC: P-256 (secp256r1), P-384 (secp384r1)
# - Hash: SHA-256, SHA-384, SHA-512
SP800_78_ALGORITHM_POLICY = AlgorithmPolicy(
    min_rsa_bits=2048,
    allowed_curves=frozenset({"secp256r1", "secp384r1"}),
    allowed_hashes=frozenset({"sha256", "sha384", "sha512"}),
)
