# RUST-060 — TEST-ONLY multi-step observer-rotation-journal monitor rotation continuity

RUST-060 composes the exact reviewed RUST-059 observer-rotation-journal monitor-set rotation verifier and extends that TEST-only administration history with a second authorized rotation.

The reviewed history becomes `M1/M2/M3 -> M2/M3/M4 -> M3/M4/M5`. M1 remains revoked, M2 is newly revoked, and deterministic TEST-only M5 is introduced. The second transition requires a valid 2-of-3 authorization quorum from the exact predecessor M2/M3/M4 set.

The second rotation binds the exact predecessor set digest, exact RUST-059 first-rotation SHA-256, exact RUST-059 rotation-authorization SHA-256, exact RUST-059 successor-bundle SHA-256, cumulative revocation `[M1, M2]`, exact RUST-057 observer-rotation-journal checkpoint SHA-256 and checkpoint-statement SHA-256, inherited observed/journal-observer/monitor-journal checkpoint bindings, activation source commit, final M3/M4/M5 set, and `production=false`.

Final monitoring uses distinct v3 schemas/domain and is bound to monitor-set sequence 2 and the exact M3/M4/M5 set digest. All 3/3 valid predecessor two-monitor authorization subsets and all 3/3 final two-monitor reporting subsets are accepted. The RUST-059 v2 successor bundle cannot replay as final evidence.

A valid signed final report for a distinct checkpoint with the same observer-set sequence and same previous-checkpoint parent is rejected fail-closed as a split view, even when two other final monitors report the canonical checkpoint.

The detached verifier and selftest contain no private signing or network capability. Deterministic TEST private Ed25519 seeds exist only in the producer fixture and are checked against reviewed public-key pins.

This TEST-only evidence does **not** create global network gossip, production monitor administration, production signing, key custody, HSM/TPM use, OIDC, publication, release/deployment authority, anti-rollback policy, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
