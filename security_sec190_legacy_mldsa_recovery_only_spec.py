#!/usr/bin/env python3
"""SEC-190: legacy expanded ML-DSA keys are recovery-only, never signing keys."""

from unittest import mock

from dilithium_py.ml_dsa import ML_DSA_44

import axven
import wallet


def main():
    checks = 0
    message = b"axven-sec190-recovery-only-v1"
    legacy = axven._mldsa()

    public_key, secret_key = ML_DSA_44.keygen()
    assert len(public_key) == axven.ML_DSA_PUBLIC_KEY_BYTES
    assert len(secret_key) == axven.ML_DSA_LEGACY_SECRET_KEY_BYTES
    checks += 1
    print("[GREEN] canonical legacy expanded ML-DSA key material recognized")

    recovered = axven.MLDSAWallet((public_key, secret_key))
    assert recovered.public_key == public_key
    try:
        recovered.sign(message)
    except RuntimeError as exc:
        assert "recovery-only" in str(exc)
    else:
        raise AssertionError("legacy expanded ML-DSA key was allowed to sign")
    checks += 1
    print("[GREEN] legacy expanded ML-DSA signing fails closed")

    with mock.patch.object(
        legacy,
        "sign",
        side_effect=AssertionError("legacy signer invoked during recovery validation"),
    ):
        wallet._validate_mldsa_keypair(public_key, secret_key)
    checks += 1
    print("[GREEN] recovery validation derives public key without legacy signing")

    bad_public = bytearray(public_key)
    bad_public[0] ^= 1
    try:
        axven.MLDSAWallet((bytes(bad_public), secret_key))
    except ValueError:
        pass
    else:
        raise AssertionError("mismatched legacy expanded keypair accepted")
    checks += 1
    print("[GREEN] mismatched legacy expanded keypair rejected")

    try:
        wallet._validate_mldsa_keypair(bytes(bad_public), secret_key)
    except wallet.BackupError:
        pass
    else:
        raise AssertionError("mismatched legacy backup keypair accepted")
    checks += 1
    print("[GREEN] mismatched legacy backup recovery material rejected")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    print(f"SEC-190 legacy ML-DSA recovery-only contract: {checks}/{checks} GREEN")


if __name__ == "__main__":
    main()
