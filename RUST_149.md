# RUST-149 — TEST-ONLY RUST-146 checkpoint monitor rotation journal

RUST-149 records the reviewed RUST-146 checkpoint-monitor family as an append-only signed journal across M1/M2/M3 -> M2/M3/M4 -> M3/M4/M5.

The journal preserves cumulative revocation `[M1, M2]`, binds the exact RUST-146 monitor bundle plus RUST-147 first rotation/authorization/successor bundle and RUST-148 second rotation/authorization/final bundle, and requires 2-of-3 signatures for both prefix and final checkpoints. All 3/3 valid two-monitor subsets are exercised for both epochs.

The final journal must retain the checkpointed prefix byte-for-byte at the semantic-entry level and link entries by predecessor hashes. Any same-parent final checkpoint substitution is rejected fail-closed. The detached selftest keeps the 35/35 expected cases matrix covering journal rewrites, rollback, revocation omission, quorum downgrade, signature mutation, noncanonical evidence, and signed fork substitution.

CI reconstructs the exact reviewed 316-path RUST-148 manifest and appends four RUST-149 canonical journal/checkpoint paths, yielding a 320-path verifier manifest. The detached consumer contains 120 verifier modules plus the RUST-149 selftest and final-state anchor, yielding a 122-file isolated consumer. Evidence and manifest are read-only; verifier/selftest execute under `env -i` and `/usr/bin/python3 -S`.

This checkpoint is TEST-only and non-publishing. It introduces no production monitor administration, signing authority, key custody, release/deployment authority, network capability, consensus change, or production Rust routing. Production consensus remains Python-authoritative.
