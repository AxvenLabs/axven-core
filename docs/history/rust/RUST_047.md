# RUST-047 — TEST-ONLY monitor-journal observer-set rotation continuity

RUST-047 composes the exact reviewed RUST-046 monitor-journal checkpoint observation verifier and adds TEST-only observer-set rotation/revocation continuity.

The journal-observer set rotates from J1/J2/J3 to J2/J3/J4 at observer-set sequence 1. J1 is explicitly revoked and deterministic TEST-only J4 is introduced. The exact transition must be authorized by a valid 2-of-3 quorum from the predecessor J1/J2/J3 set.

The rotation binds the exact predecessor observer-set digest, exact RUST-046 observation-bundle SHA-256, exact canonical RUST-045 final monitor-journal checkpoint SHA-256, exact checkpoint-statement SHA-256, activation source commit, successor set, revocation list, and `production=false`.

Successor observation uses a distinct v2 schema/domain and is bound to the exact J2/J3/J4 set digest and sequence. All 3/3 valid predecessor two-observer authorization subsets and all 3/3 valid successor two-observer reporting subsets are accepted. The old RUST-046 v1 observation bundle cannot replay as successor evidence.

A valid signed successor report for a distinct checkpoint with the same monitor-set sequence and same previous-checkpoint parent is rejected fail-closed as an observed split view, even if two other successor observers report the canonical checkpoint.

The detached verifier and selftest contain no private signing or network capability. Deterministic TEST private Ed25519 seeds exist only in the producer fixture and are checked against reviewed public-key pins.

This TEST-only evidence does **not** create global network gossip, independent production observer administration, durable publication, production signing, key custody, HSM/TPM use, OIDC, release/deployment authority, anti-rollback policy, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
