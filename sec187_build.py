#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path

SPEC = Path("security_sec187_mldsa_expanded_key_import_spec.py")
MANIFEST = Path("release_manifest.json")

spec = r'''#!/usr/bin/env python3
"""SEC-187: prove legacy 2560-byte ML-DSA secrets import into pyca/OpenSSL."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa

import axven


ML_DSA_44_OID_DER=bytes.fromhex("0609608648016503040311")


def _der_length(n):
    if n < 0:
        raise ValueError("negative DER length")
    if n < 0x80:
        return bytes([n])
    raw=n.to_bytes((n.bit_length()+7)//8,"big")
    return bytes([0x80|len(raw)])+raw


def _der(tag,content):
    return bytes([tag])+_der_length(len(content))+content


def _expanded_mldsa44_pkcs8(secret):
    if type(secret) is not bytes or len(secret)!=2560:
        raise ValueError("ML-DSA-44 expanded secret must be 2560 bytes")
    version=b"\x02\x01\x00"
    algorithm=_der(0x30,ML_DSA_44_OID_DER)
    expanded_choice=_der(0x04,secret)
    private_key=_der(0x04,expanded_choice)
    return _der(0x30,version+algorithm+private_key)


def main():
    checks=0

    # RFC 9881 C.1.1.2 has this exact outer structure/length for the expanded
    # ML-DSA-44 private-key form.
    probe=_expanded_mldsa44_pkcs8(b"\0"*2560)
    assert probe[:4]==bytes.fromhex("30820a18")
    assert probe[4:7]==bytes.fromhex("020100")
    assert probe[7:20]==bytes.fromhex("300b0609608648016503040311")
    assert probe[20:24]==bytes.fromhex("04820a04")
    assert probe[24:28]==bytes.fromhex("04820a00")
    assert len(probe)==2588
    checks += 1
    print("[GREEN] RFC 9881 expanded ML-DSA-44 PKCS#8 encoding is canonical")

    legacy=axven._mldsa()
    messages=(b"",bytes(range(32)),b"axven-sec187-expanded-key-import")

    for round_index in range(3):
        public_key,expanded_secret=legacy.keygen()
        assert len(public_key)==1312
        assert len(expanded_secret)==2560

        der=_expanded_mldsa44_pkcs8(expanded_secret)
        loaded=serialization.load_der_private_key(der,password=None)
        assert isinstance(loaded,mldsa.MLDSA44PrivateKey)
        loaded_public=loaded.public_key().public_bytes_raw()
        assert loaded_public==public_key

        for message in messages:
            # New backend signs with the exact legacy private key and both
            # verifiers accept the signature.
            pyca_sig=loaded.sign(message)
            assert len(pyca_sig)==2420
            loaded.public_key().verify(pyca_sig,message)
            assert legacy.verify(public_key,message,pyca_sig)
            assert axven._verify_mldsa44_signature(public_key,message,pyca_sig)

            # Existing legacy signatures remain valid against the imported key.
            legacy_sig=legacy.sign(expanded_secret,message)
            loaded.public_key().verify(legacy_sig,message)
            assert axven._verify_mldsa44_signature(public_key,message,legacy_sig)

        print(f"[GREEN] legacy expanded key round {round_index+1} imports and cross-signs")

    checks += 1
    print("[GREEN] existing 2560-byte Axven secrets import without wallet rotation")

    # Exact private-key format boundary: no truncation/extension aliases.
    for bad in (b"",b"x"*2559,b"x"*2561,bytearray(2560)):
        try:
            _expanded_mldsa44_pkcs8(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("non-canonical expanded ML-DSA secret accepted")
    checks += 1
    print("[GREEN] expanded-secret size/type aliases rejected")

    # DER corruption/truncation must fail closed in the production loader.
    public_key,expanded_secret=legacy.keygen()
    der=_expanded_mldsa44_pkcs8(expanded_secret)
    for bad_der in (der[:-1],der+b"\x00",b"\x30\x00"):
        try:
            loaded=serialization.load_der_private_key(bad_der,password=None)
        except (ValueError,TypeError):
            continue
        raise AssertionError(f"malformed expanded-key DER unexpectedly loaded: {loaded!r}")
    checks += 1
    print("[GREEN] malformed expanded-key DER fails closed")

    # Imported public-key identity must bind to the same Axven address.
    loaded=serialization.load_der_private_key(
        _expanded_mldsa44_pkcs8(expanded_secret),password=None
    )
    assert axven.ml_address_from_pubkey(loaded.public_key().public_bytes_raw()) == (
        axven.ml_address_from_pubkey(public_key)
    )
    checks += 1
    print("[GREEN] legacy wallet address identity is preserved")

    assert axven.CHAIN_ID=="axven-devnet-2"
    assert axven.CONFIG_FINGERPRINT==(
        "ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae"
    )
    assert axven.CHAIN_CONFIG["pq_scheme"]=="ml-dsa-44"
    checks += 1
    print("[GREEN] canonical chain identity and PQ scheme unchanged")

    assert checks==6
    print("SEC-187 legacy ML-DSA expanded-key import: 6/6 GREEN")


if __name__=="__main__":
    main()
'''
SPEC.write_text(spec,encoding="utf-8",newline="\n")

manifest=json.loads(MANIFEST.read_text(encoding="utf-8"))
raw=SPEC.read_bytes()
manifest["files"][SPEC.as_posix()]={
    "bytes":len(raw),
    "sha256":hashlib.sha256(raw).hexdigest(),
}
MANIFEST.write_text(
    json.dumps(manifest,indent=2,sort_keys=True)+"\n",
    encoding="utf-8",newline="\n",
)
