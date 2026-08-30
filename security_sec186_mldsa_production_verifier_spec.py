#!/usr/bin/env python3
"""SEC-186: production ML-DSA consensus verification uses pyca/OpenSSL."""

import base64
import inspect

import axven


class _LegacyVerifyBomb:
    def verify(self, *args, **kwargs):
        raise AssertionError("legacy dilithium-py verify path was invoked")


def _flip_b64(text):
    raw=bytearray(base64.b64decode(text,validate=True))
    raw[len(raw)//2] ^= 1
    return base64.b64encode(bytes(raw)).decode("ascii")


def main():
    checks=0
    message=b"axven-sec186-consensus-sighash!!"[:32]
    assert len(message)==32

    # Sign fixtures with the legacy wallet implementation before disabling its
    # verify method.  SEC-186 intentionally migrates verification only.
    ml_wallet=axven.MLDSAWallet()
    ml_tx=axven.Transaction(
        [axven.TxInput("11"*32,0)],
        [axven.TxOutput(1,ml_wallet.address)],
    )
    ml_input=ml_wallet.sign_input(ml_tx,0)
    ml_hash=ml_tx.sighash()
    ml_utxo={"recipient":ml_wallet.address}

    hybrid_wallet=axven.HybridWallet()
    hybrid_tx=axven.Transaction(
        [axven.TxInput("22"*32,1)],
        [axven.TxOutput(1,hybrid_wallet.address)],
    )
    hybrid_input=hybrid_wallet.sign_input(hybrid_tx,0)
    hybrid_hash=hybrid_tx.sighash()
    hybrid_utxo={"recipient":hybrid_wallet.address}

    original_mldsa=axven._mldsa
    try:
        # Consensus verification must not depend on dilithium-py anymore.
        axven._mldsa=lambda: _LegacyVerifyBomb()
        assert axven.verify_input(ml_input,ml_utxo,ml_hash)
        checks += 1
        print("[GREEN] pure ML-DSA consensus verification uses pyca/OpenSSL")

        assert axven.verify_input(hybrid_input,hybrid_utxo,hybrid_hash)
        checks += 1
        print("[GREEN] hybrid ML-DSA consensus verification uses pyca/OpenSSL")

        bad_ml=dict(ml_input)
        bad_ml["signature"]=_flip_b64(bad_ml["signature"])
        assert not axven.verify_input(bad_ml,ml_utxo,ml_hash)

        bad_hybrid=dict(hybrid_input)
        bad_hybrid["ml_signature"]=_flip_b64(bad_hybrid["ml_signature"])
        assert not axven.verify_input(bad_hybrid,hybrid_utxo,hybrid_hash)
        checks += 1
        print("[GREEN] pyca consensus paths reject ML-DSA signature tampering")
    finally:
        axven._mldsa=original_mldsa

    # Fail closed before backend construction on malformed raw sizes/types.
    assert not axven._verify_mldsa44_signature(b"x"*1311,message,b"y"*2420)
    assert not axven._verify_mldsa44_signature(b"x"*1312,message,b"y"*2419)
    assert not axven._verify_mldsa44_signature(bytearray(1312),message,b"y"*2420)
    assert not axven._verify_mldsa44_signature(b"x"*1312,"not-bytes",b"y"*2420)
    checks += 1
    print("[GREEN] malformed ML-DSA verification inputs fail closed")

    # The legacy implementation remains available only for keygen/sign during
    # this staged migration; verify_input must contain no legacy verify call.
    verify_source=inspect.getsource(axven.verify_input)
    assert "_mldsa().verify" not in verify_source
    assert verify_source.count("_verify_mldsa44_signature") == 2
    checks += 1
    print("[GREEN] consensus verifier source has no legacy ML-DSA verify call")

    # Existing wallet signing behavior remains byte-compatible in this SEC.
    signed=axven.MLDSAWallet().sign(b"z"*32)
    assert type(signed) is bytes and len(signed)==2420
    checks += 1
    print("[GREEN] existing ML-DSA signing behavior preserved")

    # Canonical devnet identity and activation rules remain untouched.
    assert axven.CHAIN_ID=="axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT==(
        "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    )
    assert axven.CHAIN_CONFIG["pq_hybrid_activation_height"]==2000
    assert axven.CHAIN_CONFIG["pq_pure_activation_height"]==5000
    assert axven.CHAIN_CONFIG["pq_scheme"]=="ml-dsa-44"
    checks += 1
    print("[GREEN] canonical chain identity and activation rules unchanged")

    assert checks==7
    print("SEC-186 production ML-DSA verifier migration: 7/7 GREEN")


if __name__=="__main__":
    main()
