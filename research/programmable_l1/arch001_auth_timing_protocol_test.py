#!/usr/bin/env python3
"""Focused fail-closed tests for the research-only timing diagnostic."""
import subprocess
import unittest
from unittest.mock import patch

import arch001_auth_cost_compare as cost
import arch001_auth_timing_protocol_evidence as protocol
import arch001_decision_bundle as bundle

VALID = "ARCH-001 authorization sensitivity: 5/5 GREEN\n" + "\n".join(
    f"{scheme} canonical_witness_bytes {size} median_verify_ns 100"
    for scheme, size in zip(protocol.SCHEMES, (279, 5184, 5383))
)


class TimingProtocolTests(unittest.TestCase):
    def test_valid_rows(self):
        self.assertEqual(tuple(protocol.parse_rows(VALID)), protocol.SCHEMES)

    def test_malformed_rows_fail_closed(self):
        variants = [
            VALID + "\ned25519 canonical_witness_bytes 279 median_verify_ns 1",
            VALID.replace("ml-dsa-44", "ed25519"),
            VALID.replace("5/5 GREEN", "4/5 GREEN"),
            VALID.replace("canonical_witness_bytes", "bytes", 1),
            VALID.replace("median_verify_ns 100", "median_verify_ns 0", 1),
            VALID.replace("median_verify_ns 100", "median_verify_ns -1", 1),
            VALID.replace("canonical_witness_bytes 279", "canonical_witness_bytes bad"),
            "\n".join(VALID.splitlines()[:-1]),
            VALID.replace("ed25519", "unknown", 1),
        ]
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                protocol.parse_rows(value)

    def test_process_failure_and_stderr(self):
        for code, stderr in ((1, "failure"), (0, "warning")):
            with patch.object(protocol.subprocess, "run", return_value=subprocess.CompletedProcess([], code, VALID, stderr)):
                with self.assertRaises(ValueError):
                    protocol.run_once()

    def test_timeout_propagates(self):
        with patch.object(protocol.subprocess, "run", side_effect=subprocess.TimeoutExpired([], 60)):
            with self.assertRaises(subprocess.TimeoutExpired):
                protocol.run_once()

    def test_timed_rejection_cannot_be_reported_as_success(self):
        for value in (False, None):
            with self.assertRaises(ValueError):
                cost.median_ns(lambda: value)

    def test_size_drift_fails_closed(self):
        rows = protocol.parse_rows(VALID)
        changed = dict(rows, ed25519=(280, 100))
        with patch.object(protocol, "run_once", side_effect=[rows, changed, rows, rows, rows]):
            with self.assertRaisesRegex(ValueError, "witness sizes changed"):
                protocol.main()

    def test_source_drift_fails_closed(self):
        rows = protocol.parse_rows(VALID)
        with patch.object(protocol, "run_once", return_value=rows), patch.object(
            protocol, "source_provenance", side_effect=[{"fixture": "before"}, {"fixture": "after"}]
        ):
            with self.assertRaisesRegex(ValueError, "source changed"):
                protocol.main()

    def test_diagnostics_excluded_from_canonical_registry(self):
        self.assertNotIn(protocol.FIXTURE.name, bundle.FIXTURES)
        self.assertNotIn("arch001_auth_timing_protocol_evidence.py", bundle.FIXTURES)


if __name__ == "__main__":
    unittest.main()
