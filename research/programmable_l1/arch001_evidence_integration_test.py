#!/usr/bin/env python3
"""Regressions for observed integration failures in canonical research evidence."""
import contextlib
import io
import json
import unittest

import arch001_program_conflict_evidence as conflict
import arch001_native_measurement_evidence as native
import arch001_tradeoff_snapshot_evidence as snapshot
from arch001_migration_reuse_compare import MATRIX
from arch001_model import canonical_bytes


class EvidenceIntegrationTests(unittest.TestCase):
    def test_program_conflict_reproducible_and_fail_closed(self):
        first = conflict.execute_once()
        self.assertEqual(first, conflict.execute_once())
        pre, accepted, errors = first
        self.assertTrue(all(a != b for a, b in zip(pre, accepted)))
        self.assertEqual(errors, ("spent-or-missing-program-outpoint", "stale-program-sequence", "stale-program-object-version"))

    def test_native_measurement_emits_all_candidates_without_mutation(self):
        outputs = []
        for _ in range(2):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                native.main()
            outputs.append(out.getvalue())
        self.assertEqual(*outputs)
        evidence = json.loads(outputs[0].splitlines()[1])
        self.assertEqual(evidence["logical_workload"]["initial_total"], 125)
        self.assertEqual({r["candidate"] for r in evidence["rows"]}, {"utxo", "account-state", "object-resource"})
        self.assertTrue(all(r["replay_rejected"] and r["rejected_state_unchanged"] for r in evidence["rows"]))

    def test_snapshot_counts_match_underlying_matrix(self):
        evidence = snapshot.build_evidence()
        self.assertEqual(canonical_bytes(evidence), canonical_bytes(snapshot.build_evidence()))
        self.assertFalse(evidence["weights_applied"])
        self.assertFalse(evidence["architecture_selected"])
        for row in evidence["rows"]:
            source = MATRIX["account" if row["candidate"] == "account-state" else row["candidate"]]
            for classification in ("preserve", "adapt", "replace", "new"):
                self.assertEqual(row[f"migration_{classification}"], sum(v == classification for v in source.values()))


if __name__ == "__main__":
    unittest.main()
