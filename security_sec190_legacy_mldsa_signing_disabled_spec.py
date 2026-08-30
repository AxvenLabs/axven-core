#!/usr/bin/env python3
"""SEC-190: legacy expanded ML-DSA keys are recovery-only, never sign."""
from __future__ import annotations

from unittest import mock

import axven
import wallet


class RecoveryOnlyBackend:
    def __init__(self, public_key):
        self.public_key = public_key
        self.pk_calls = 0
        self.sign_calls = 0

    def pk_from_sk(self, secret_key):
        self.pk_calls += 1
        assert len(secret_key) == axven.ML_DSA_LEGACY_SECRET_KEY_BYTES
        return self.public_key

    def sign(self, secret_key, message):
        self.sign_calls += 1
        raise AssertionError("legacy backend signing must never be reachable")


def main():
    checks = []

    def green(name, condition=True):
        assert condition, name
        checks.append(name)
        print(f"[GREEN] {name}")

    legacy_public = b"P" * axven.ML_DSA_PUBLIC_KEY_BYTES
    legacy_secret = b"S" * axven.ML_DSA_LEGACY_SECRET_KEY_BYTES
    backend = RecoveryOnlyBackend(legacy_public)

    with mock.patch.object(axven, "_mldsa", return_value=backend):
        recovered = axven.MLDSAWallet((legacy_public, legacy_secret))
        green("legacy expanded key may be opened for explicit recovery")
        try:
            recovered.sign(b"sec190-live-signing-must-fail")
        except RuntimeError as exc:
            green("legacy expanded key live signing fails closed", "recovery-only" in str(exc))
        else:
            raise AssertionError("legacy expanded key unexpectedly signed")
        green("legacy educational backend sign primitive was never invoked", backend.sign_calls == 0)

        wallet._validate_mldsa_keypair(legacy_public, legacy_secret)
        green("legacy backup keypair validation uses recovery-only public derivation")
        green("backup validation never invokes legacy signer", backend.sign_calls == 0)
        green("legacy recovery public derivation was exercised", backend.pk_calls >= 2)

    fresh = axven.MLDSAWallet()
    msg = b"sec190-pyca-production-signing"
    sig = fresh.sign(msg)
    green("seed-backed production ML-DSA signing remains enabled")
    green("seed-backed production signature verifies", axven._verify_mldsa44_signature(fresh.public_key, msg, sig))

    print(f"SEC-190 legacy ML-DSA signing disabled: {len(checks)}/{len(checks)} GREEN")


if __name__ == "__main__":
    main()
