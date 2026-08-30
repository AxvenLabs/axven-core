#!/usr/bin/env python3
"""SEC-187: migrate new ML-DSA wallet keygen/signing to pyca with legacy recovery compatibility."""

import base64
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import mldsa
from dilithium_py.ml_dsa import ML_DSA_44

import axven
import wallet


def main():
    checks = 0
    msg = b"axven-sec187-wallet-signer-v1"

    # New wallet generation must not call the educational legacy key generator.
    legacy = axven._mldsa()
    with mock.patch.object(legacy, "keygen", side_effect=AssertionError("legacy keygen used")):
        fresh = axven.MLDSAWallet()
    assert len(fresh.public_key) == 1312
    assert len(fresh._secret) == 32
    checks += 1
    print("[GREEN] new ML-DSA wallet generation uses pyca seed keys")

    # New signing must remain independent of legacy .sign().
    with mock.patch.object(legacy, "sign", side_effect=AssertionError("legacy sign used")):
        sig = fresh.sign(msg)
    assert len(sig) == 2420
    mldsa.MLDSA44PublicKey.from_public_bytes(fresh.public_key).verify(sig, msg)
    checks += 1
    print("[GREEN] new ML-DSA wallet signing uses pyca/OpenSSL")

    # The 32-byte seed must deterministically bind to the persisted public key.
    loaded_seed = mldsa.MLDSA44PrivateKey.from_seed_bytes(fresh._secret)
    assert loaded_seed.public_key().public_bytes_raw() == fresh.public_key
    reloaded = axven.MLDSAWallet((fresh.public_key, fresh._secret))
    assert axven._verify_mldsa44_signature(fresh.public_key, msg, reloaded.sign(msg))
    checks += 1
    print("[GREEN] pyca seed keypair reload is canonical")

    bad_pub = bytearray(fresh.public_key)
    bad_pub[0] ^= 1
    try:
        axven.MLDSAWallet((bytes(bad_pub), fresh._secret))
    except ValueError:
        pass
    else:
        raise AssertionError("mismatched seed/public keypair accepted")
    checks += 1
    print("[GREEN] mismatched seed/public keypair rejected")

    # Existing 2560-byte expanded wallets may be opened for recovery, but never sign.
    legacy_pub, legacy_sk = ML_DSA_44.keygen()
    assert len(legacy_sk) == 2560
    legacy_wallet = axven.MLDSAWallet((legacy_pub, legacy_sk))
    assert legacy_wallet.public_key == legacy_pub
    try:
        legacy_wallet.sign(msg)
    except RuntimeError as exc:
        assert "recovery-only" in str(exc)
    else:
        raise AssertionError("legacy expanded ML-DSA key was allowed to sign")
    checks += 1
    print("[GREEN] legacy expanded wallet is recovery-only and cannot sign")

    # Newly-created WalletIdentity objects and backups persist the compact seed.
    ident = wallet.WalletIdentity()
    assert len(ident.ml_secret_key) == wallet.ML_DSA_SEED_KEY_BYTES == 32
    backup = wallet.export_backup(ident, "sec187-pass")
    restored = wallet.restore_backup(backup, "sec187-pass")
    assert restored.ml_public_key == ident.ml_public_key
    assert restored.ml_secret_key == ident.ml_secret_key
    assert axven._verify_mldsa44_signature(
        restored.ml_public_key, msg,
        axven.MLDSAWallet((restored.ml_public_key, restored.ml_secret_key)).sign(msg),
    )
    checks += 1
    print("[GREEN] new seed wallet backup roundtrip preserved")

    # Legacy backup material remains recoverable without silently rewriting identity.
    legacy_ident = wallet.WalletIdentity(ml_keypair=(legacy_pub, legacy_sk))
    legacy_backup = wallet.export_backup(legacy_ident, "legacy-pass")
    legacy_restored = wallet.restore_backup(legacy_backup, "legacy-pass")
    assert legacy_restored.ml_public_key == legacy_pub
    assert legacy_restored.ml_secret_key == legacy_sk
    try:
        axven.MLDSAWallet(
            (legacy_restored.ml_public_key, legacy_restored.ml_secret_key)
        ).sign(msg)
    except RuntimeError:
        pass
    else:
        raise AssertionError("restored legacy key regained signing capability")
    checks += 1
    print("[GREEN] legacy expanded backup recovery roundtrip preserved without signing")

    # Backup parser accepts only the two standards-relevant Axven private forms.
    material = {
        "ed_private": base64.b64encode(wallet._raw_ed_private(ident)).decode("ascii"),
        "ml_public": base64.b64encode(ident.ml_public_key).decode("ascii"),
        "ml_secret": base64.b64encode(b"x" * 31).decode("ascii"),
    }
    try:
        wallet._validated_backup_material(material)
    except wallet.BackupError:
        pass
    else:
        raise AssertionError("non-canonical ML-DSA private-key length accepted")
    checks += 1
    print("[GREEN] non-canonical ML-DSA private-key lengths rejected")

    # Seed validation terminates at production signing; legacy validation is recovery-only.
    wallet._validate_mldsa_keypair(ident.ml_public_key, ident.ml_secret_key)
    with mock.patch.object(
        legacy,
        "sign",
        side_effect=AssertionError("legacy sign used during recovery validation"),
    ):
        wallet._validate_mldsa_keypair(legacy_pub, legacy_sk)
    checks += 1
    print("[GREEN] wallet keypair validation keeps legacy material recovery-only")

    assert axven.CHAIN_ID == "axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT == "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    assert axven.CHAIN_CONFIG["pq_scheme"] == "ml-dsa-44"
    assert axven.CHAIN_CONFIG["pq_hybrid_activation_height"] == 2000
    assert axven.CHAIN_CONFIG["pq_pure_activation_height"] == 5000
    checks += 1
    print("[GREEN] chain identity and PQ activation semantics unchanged")

    assert checks == 10
    print("SEC-187 ML-DSA wallet signer migration: 10/10 GREEN")


if __name__ == "__main__":
    main()
