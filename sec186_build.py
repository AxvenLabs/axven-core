#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path

AXVEN = Path("axven.py")
SPEC = Path("security_sec186_mldsa_production_verifier_spec.py")
MANIFEST = Path("release_manifest.json")

src = AXVEN.read_text(encoding="utf-8")
old_import = "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey\nfrom cryptography.hazmat.primitives import serialization\n"
new_import = "from cryptography.exceptions import InvalidSignature\nfrom cryptography.hazmat.primitives.asymmetric import mldsa\nfrom cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey\nfrom cryptography.hazmat.primitives import serialization\n"
assert src.count(old_import) == 1
src = src.replace(old_import, new_import, 1)

old_anchor = '''def _mldsa():
    global _ML
    if _ML is not None:return _ML
    try: from dilithium_py.ml_dsa import ML_DSA_44
    except Exception:
        from dilithium_py.ml_dsa.default_parameters import ML_DSA_44
    _ML=ML_DSA_44; return _ML
class MLDSAWallet:
'''
new_anchor = '''def _mldsa():
    global _ML
    if _ML is not None:return _ML
    try: from dilithium_py.ml_dsa import ML_DSA_44
    except Exception:
        from dilithium_py.ml_dsa.default_parameters import ML_DSA_44
    _ML=ML_DSA_44; return _ML

def _verify_mldsa44_signature(public_key, message, signature):
    """Verify pure ML-DSA-44 with the pinned pyca/OpenSSL backend."""
    if type(public_key) is not bytes or len(public_key) != 1312:
        return False
    if type(signature) is not bytes or len(signature) != 2420:
        return False
    if type(message) is not bytes:
        return False
    try:
        verifier=mldsa.MLDSA44PublicKey.from_public_bytes(public_key)
        verifier.verify(signature,message)
        return True
    except (InvalidSignature,ValueError,TypeError):
        return False

class MLDSAWallet:
'''
assert src.count(old_anchor) == 1
src = src.replace(old_anchor, new_anchor, 1)

old_pure = '            return ml_address_from_pubkey(pub)==utxo["recipient"] and bool(_mldsa().verify(pub,sighash,sig))\n'
new_pure = '            return ml_address_from_pubkey(pub)==utxo["recipient"] and _verify_mldsa44_signature(pub,sighash,sig)\n'
assert src.count(old_pure) == 1
src = src.replace(old_pure, new_pure, 1)

old_hybrid = '            Ed25519PublicKey.from_public_bytes(ep).verify(es,sighash); return bool(_mldsa().verify(mp,sighash,ms))\n'
new_hybrid = '            Ed25519PublicKey.from_public_bytes(ep).verify(es,sighash); return _verify_mldsa44_signature(mp,sighash,ms)\n'
assert src.count(old_hybrid) == 1
src = src.replace(old_hybrid, new_hybrid, 1)
AXVEN.write_text(src, encoding="utf-8", newline="\n")

spec = r'''#!/usr/bin/env python3
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
'''
SPEC.write_text(spec, encoding="utf-8", newline="\n")

manifest=json.loads(MANIFEST.read_text(encoding="utf-8"))
# consensus_code_sha256 is the historical canonical activation pin.  This
# implementation migration must not rewrite that activation record.
consensus_pin=manifest["consensus_code_sha256"]
for path in (AXVEN,SPEC):
    raw=path.read_bytes()
    manifest["files"][path.as_posix()]={
        "bytes":len(raw),
        "sha256":hashlib.sha256(raw).hexdigest(),
    }
assert manifest["consensus_code_sha256"]==consensus_pin
MANIFEST.write_text(
    json.dumps(manifest,indent=2,sort_keys=True)+"\n",
    encoding="utf-8",
    newline="\n",
)
