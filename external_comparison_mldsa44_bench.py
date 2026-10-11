#!/usr/bin/env python3
"""External-comparison ML-DSA-44 diagnostic benchmark.

This is comparison instrumentation, not a consensus rule or SLA benchmark.
It measures the Axven production verification wrapper on one valid ML-DSA-44
signature and a same-length tampered signature, then emits a single JSON object.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import statistics
import sys
import time

import axven


BASELINE_COMMIT = "1917ffe1541f7946699972737056121bd5dbfc9c"
SCHEMA = "axven-external-comparison-mldsa44-v1"


def median_ns(fn, iterations: int, samples: int) -> float:
    fn()  # warmup
    totals = []
    for _ in range(samples):
        start = time.perf_counter_ns()
        for _i in range(iterations):
            fn()
        totals.append(time.perf_counter_ns() - start)
    return statistics.median(totals) / iterations


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=500)
    parser.add_argument("--samples", type=int, default=7)
    args = parser.parse_args()
    if args.iterations < 1 or args.samples < 3:
        raise SystemExit("iterations must be >=1 and samples >=3")

    if axven.CHAIN_CONFIG["pq_scheme"] != "ml-dsa-44":
        raise SystemExit("unexpected Axven PQ scheme")

    message = hashlib.sha256(b"axven-external-comparison-mldsa44-v1").digest()
    wallet = axven.MLDSAWallet()
    public_key = wallet.public_key
    signature = wallet.sign(message)

    if len(public_key) != 1312:
        raise SystemExit(f"unexpected ML-DSA-44 public key size: {len(public_key)}")
    if len(signature) != 2420:
        raise SystemExit(f"unexpected ML-DSA-44 signature size: {len(signature)}")

    tampered = bytearray(signature)
    tampered[len(tampered) // 2] ^= 1
    tampered = bytes(tampered)

    verify_valid = lambda: axven._verify_mldsa44_signature(public_key, message, signature)
    verify_invalid = lambda: axven._verify_mldsa44_signature(public_key, message, tampered)

    if verify_valid() is not True:
        raise SystemExit("valid ML-DSA-44 signature did not verify")
    if verify_invalid() is not False:
        raise SystemExit("tampered ML-DSA-44 signature unexpectedly verified")

    valid_ns = median_ns(verify_valid, args.iterations, args.samples)
    invalid_ns = median_ns(verify_invalid, args.iterations, args.samples)

    payload = {
        "schema": SCHEMA,
        "axven_baseline_commit": BASELINE_COMMIT,
        "chain_id": axven.CHAIN_ID,
        "pq_scheme": axven.CHAIN_CONFIG["pq_scheme"],
        "fips_standard": "FIPS 204",
        "parameter_set": "ML-DSA-44",
        "verification_path": "Axven _verify_mldsa44_signature via pyca/OpenSSL",
        "public_key_bytes": len(public_key),
        "signature_bytes": len(signature),
        "message_bytes": len(message),
        "message_sha256": hashlib.sha256(message).hexdigest(),
        "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
        "signature_hash_role": "comparison instrumentation only; not asserted as a checkpoint protocol field",
        "tampered_signature_sha256": hashlib.sha256(tampered).hexdigest(),
        "valid_verify": True,
        "tampered_verify": False,
        "iterations_per_sample": args.iterations,
        "samples": args.samples,
        "valid_median_ns_per_verify": round(valid_ns, 1),
        "invalid_median_ns_per_reject": round(invalid_ns, 1),
        "valid_median_ms_per_verify": round(valid_ns / 1_000_000.0, 6),
        "invalid_median_ms_per_reject": round(invalid_ns / 1_000_000.0, 6),
        "invalid_to_valid_time_ratio": round(invalid_ns / valid_ns, 6),
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "note": "Diagnostic measurement only; host-dependent and not a consensus/SLA input.",
    }
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
