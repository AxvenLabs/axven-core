# RUST-042 — TEST-ONLY observer-journal checkpoint monitoring

RUST-042 composes the exact reviewed RUST-041 append-only observer-set rotation journal verifier and adds a deterministic TEST-only multi-monitor split-view discovery layer.

Three pinned TEST monitor identities (`M1/M2/M3`) sign observations of the exact canonical RUST-041 final observer-journal checkpoint. A normal observation bundle requires at least 2-of-3 distinct valid monitor reports matching the exact checkpoint digest, observer-set epoch, journal/head digests, previous checkpoint, canonical RUST-037 checkpoint-statement digest, and activation source commit.

A valid signed report for a distinct checkpoint with the same observer-set sequence and previous-checkpoint parent is fail-closed as `observed monitor same-parent observer-journal fork`, even when two other monitors report the canonical checkpoint. The selftest also validates that the conflicting checkpoint is itself a valid RUST-041 observer-quorum checkpoint before exercising the split-view rejection.

This is a TEST-only simulation. It does **not** create independent monitor administration, durable network transport, global gossip, transparency publication, real compromise recovery, HSM/TPM custody, production anti-rollback, production fork-discovery guarantees, or production Rust routing. Production consensus remains Python-authoritative.
