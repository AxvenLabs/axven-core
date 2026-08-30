#!/usr/bin/env python3
"""SEC-185: prove ML-DSA-44 interoperability before production backend migration."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa
from dilithium_py.ml_dsa import ML_DSA_44

import axven


def _expect_invalid(fn):
    try:
        fn()
    except (InvalidSignature, ValueError):
        return
    raise AssertionError("invalid ML-DSA input unexpectedly verified")


def main():
    checks = 0

    # The production-capable pyca/OpenSSL ML-DSA backend must be available in
    # the exact runtime/dependency closure validated by Axven CI.
    pyca_priv = mldsa.MLDSA44PrivateKey.generate()
    pyca_pub = pyca_priv.public_key()
    pyca_pub_raw = pyca_pub.public_bytes_raw()
    pyca_seed = pyca_priv.private_bytes_raw()
    assert len(pyca_pub_raw) == 1312
    assert len(pyca_seed) == 32
    checks += 1
    print("[GREEN] pyca ML-DSA-44 backend available with canonical key sizes")

    message = b"axven-sec185-mldsa-interoperability-v1"

    # Existing Axven/dilithium-py signatures must verify under pyca.  This is
    # the compatibility gate required before changing consensus verification.
    legacy_pub, legacy_secret = ML_DSA_44.keygen()
    legacy_sig = ML_DSA_44.sign(legacy_secret, message)
    assert len(legacy_pub) == 1312
    assert len(legacy_secret) == 2560
    assert len(legacy_sig) == 2420
    mldsa.MLDSA44PublicKey.from_public_bytes(legacy_pub).verify(
        legacy_sig, message
    )
    checks += 1
    print("[GREEN] existing Axven ML-DSA signatures verify under pyca")

    # The reverse direction proves both implementations agree on the FIPS 204
    # pure-ML-DSA wire encoding and empty-context message semantics.
    pyca_sig = pyca_priv.sign(message)
    assert len(pyca_sig) == 2420
    assert ML_DSA_44.verify(pyca_pub_raw, message, pyca_sig)
    checks += 1
    print("[GREEN] pyca ML-DSA signatures verify under legacy implementation")

    # Both backends must fail closed on message tampering.
    _expect_invalid(
        lambda: mldsa.MLDSA44PublicKey.from_public_bytes(legacy_pub).verify(
            legacy_sig, message + b"!"
        )
    )
    assert not ML_DSA_44.verify(pyca_pub_raw, message + b"!", pyca_sig)
    checks += 1
    print("[GREEN] both backends reject message tampering")

    # Both backends must fail closed on signature tampering.
    legacy_bad = bytearray(legacy_sig)
    legacy_bad[len(legacy_bad) // 2] ^= 1
    _expect_invalid(
        lambda: mldsa.MLDSA44PublicKey.from_public_bytes(legacy_pub).verify(
            bytes(legacy_bad), message
        )
    )
    pyca_bad = bytearray(pyca_sig)
    pyca_bad[len(pyca_bad) // 2] ^= 1
    assert not ML_DSA_44.verify(pyca_pub_raw, message, bytes(pyca_bad))
    checks += 1
    print("[GREEN] both backends reject signature tampering")

    # Exercise the exact 32-byte Axven transaction sighash domain as well as
    # empty and non-empty messages to catch accidental API-mode differences.
    for msg in (b"", bytes(range(32)), b"Axven/FIPS-204/ML-DSA-44"):
        old_pk, old_sk = ML_DSA_44.keygen()
        old_sig = ML_DSA_44.sign(old_sk, msg)
        mldsa.MLDSA44PublicKey.from_public_bytes(old_pk).verify(old_sig, msg)

        new_priv = mldsa.MLDSA44PrivateKey.generate()
        new_pk = new_priv.public_key().public_bytes_raw()
        new_sig = new_priv.sign(msg)
        assert ML_DSA_44.verify(new_pk, msg, new_sig)
    checks += 1
    print("[GREEN] cross-backend pure ML-DSA message semantics agree")

    # Axven remains ML-DSA-44 and canonical chain identity is untouched.
    assert axven.CHAIN_CONFIG["pq_scheme"] == "ml-dsa-44"
    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == (
        "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    )
    checks += 1
    print("[GREEN] canonical chain identity and PQ scheme unchanged")

    assert checks == 7
    print("SEC-185 ML-DSA backend interoperability: 7/7 GREEN")


if __name__ == "__main__":
    main()
