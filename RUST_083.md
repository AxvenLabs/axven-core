# RUST-083 — TEST-ONLY RUST-081 checkpoint monitor-set rotation

RUST-083 composes the exact reviewed RUST-082 checkpoint-monitor verifier and rotates the independent TEST-only monitor set from M1/M2/M3 to M2/M3/M4.

The predecessor and successor sets both use a 2-of-3 threshold. The rotation explicitly revokes M1. Predecessor authorization by M1/M2/M3 must accept all 3/3 valid two-monitor subsets, and successor monitoring by M2/M3/M4 must also accept all 3/3 valid two-monitor subsets.

The signed rotation binds the exact predecessor monitor-set digest, exact successor monitor set, revocation list, exact RUST-082 monitor-bundle SHA-256, all 12 canonical RUST-081 checkpoint target fields, sequence, and `production=false`.

Successor reports bind the new monitor-set epoch and digest plus all 12 canonical checkpoint target fields. Revoked M1 cannot reappear. Old RUST-082 bundle replay, quorum downgrade, duplicate or unsorted monitor identities, unknown monitors, signature mutation, non-canonical evidence, and mutation of any target field are rejected fail-closed.

A valid signed same-parent RUST-081 checkpoint fork can be recognized in predecessor evidence, but successor evidence binding that fork is rejected against the canonical checkpoint.

The detached selftest requires 3/3 predecessor authorization availability, 3/3 successor monitoring availability, and 48/48 expected fail-closed cases. Deterministic private seeds exist only in the TEST-only producer fixture; verifier and selftest code have no signing or network capability.

The workflow pins the exact reviewed RUST-082 verifier and predecessor workflow Git blobs, inherits the predecessor's fixed 134-path evidence manifest, appends exactly three RUST-083 canonical paths, and verifies a 137-path manifest inside a 56-file verifier-only detached consumer under `env -i` with `/usr/bin/python3 -S`.

No production monitor administration, durable publication, network gossip, key custody, HSM/TPM integration, OIDC, release/deployment authority, consensus change, or production Rust routing is introduced.

Production consensus remains Python-authoritative.
