# RUST-051 — TEST-ONLY journal-monitor set rotation and revocation continuity

RUST-051 composes the exact reviewed RUST-050 journal-observer-journal checkpoint monitor verifier and adds TEST-only journal-monitor set rotation/revocation continuity.

The journal-monitor set rotates from `JM1/JM2/JM3` to `JM2/JM3/JM4` at monitor-set sequence 1. `JM1` is explicitly revoked and deterministic TEST-only `JM4` is introduced. The exact transition must be authorized by a valid 2-of-3 quorum from the predecessor `JM1/JM2/JM3` set.

The rotation binds the exact predecessor monitor-set digest, exact RUST-050 monitor-bundle SHA-256, exact canonical RUST-049 final journal-observer checkpoint SHA-256, the inherited exact RUST-045 monitor-journal checkpoint SHA-256 and checkpoint-statement SHA-256, activation source commit, successor set, revocation list, and `production=false`.

Successor monitoring uses a distinct v2 schema/domain and is bound to the exact `JM2/JM3/JM4` set digest and sequence. All 3/3 valid predecessor two-monitor authorization subsets and all 3/3 valid successor two-monitor reporting subsets are accepted. The old RUST-050 v1 monitor bundle cannot replay as successor evidence.

A valid signed successor report for a distinct journal-observer checkpoint with the same observer-set sequence and same previous-checkpoint parent is rejected fail-closed as an observed split view, even if two other successor monitors report the canonical checkpoint.

The detached verifier and selftest contain no private signing or network capability. Deterministic TEST private Ed25519 seeds exist only in the producer fixture and are checked against reviewed public-key pins.

This TEST-only evidence does **not** create global network gossip, independent production journal-monitor administration, durable publication, production signing, key custody, HSM/TPM use, OIDC, release/deployment authority, anti-rollback policy, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
