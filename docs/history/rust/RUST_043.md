# RUST-043 — TEST-ONLY monitor-set rotation and revocation continuity

RUST-043 composes the exact reviewed RUST-042 observer-journal checkpoint monitor verifier and rotates the pinned TEST monitor set from `M1/M2/M3` to `M2/M3/M4`.

The transition is authorized by a deterministic 2-of-3 quorum of the predecessor monitor set, explicitly revokes `M1`, binds the exact predecessor RUST-042 monitor bundle SHA-256 and exact canonical RUST-041 final observer-journal checkpoint SHA-256, and carries an activation-source binding with `production=false`.

Successor monitor observations use a new schema/domain and bind monitor-set sequence `1` plus the exact successor monitor-set digest. Old RUST-042 bundle replay at the new epoch is rejected. A valid signed successor report for a distinct checkpoint with the same observer-set sequence and previous-checkpoint parent remains fail-closed even when a canonical successor quorum is otherwise present.

This is TEST-only key-management continuity. It does **not** create independent monitor administration/custody, durable network transport, transparency publication, compromise recovery, HSM/TPM custody, production anti-rollback, production fork-discovery guarantees, or production Rust routing. Production consensus remains Python-authoritative.
