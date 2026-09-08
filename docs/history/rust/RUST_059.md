# RUST-059 — TEST-ONLY observer-rotation-journal monitor-set rotation continuity

RUST-059 composes the exact reviewed RUST-058 observer-rotation-journal checkpoint monitor verifier and adds deterministic TEST-only monitor-set rotation/revocation continuity.

The monitor set rotates from `M1/M2/M3 -> M2/M3/M4` at monitor-set sequence 1. M1 is explicitly revoked and deterministic TEST-only M4 is introduced. The transition requires a valid 2-of-3 authorization quorum from the exact predecessor M1/M2/M3 set.

The rotation binds the exact predecessor monitor-set digest, exact RUST-058 predecessor monitor-bundle SHA-256, exact RUST-057 final observer-rotation-journal checkpoint SHA-256 and checkpoint-statement SHA-256, inherited observed/journal-observer/monitor-journal checkpoint bindings, activation source commit, successor set, revocation list, and `production=false`.

Successor monitoring uses distinct v2 schemas/domain and is bound to monitor-set sequence 1 and the exact M2/M3/M4 set digest. All 3/3 valid predecessor two-monitor authorization subsets and all 3/3 valid successor two-monitor reporting subsets are accepted. The old RUST-058 v1 monitor bundle cannot replay as successor evidence.

A valid signed successor report for a distinct checkpoint with the same observer-set sequence and same previous-checkpoint parent is rejected fail-closed as a split view, even if two other successor monitors report the canonical checkpoint.

The detached verifier and selftest contain no private signing or network capability. Deterministic TEST private Ed25519 seeds exist only in the producer fixture and are checked against reviewed public-key pins.

This TEST-only evidence does **not** create global network gossip, production monitor administration, production signing, key custody, HSM/TPM use, OIDC, publication, release/deployment authority, anti-rollback policy, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
