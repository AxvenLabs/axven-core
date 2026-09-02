# RUST-055 — TEST-ONLY journal-monitor-journal observer-set rotation continuity

RUST-055 composes the exact reviewed RUST-054 journal-monitor-journal checkpoint observation verifier and adds deterministic TEST-only observer-set rotation/revocation continuity.

The reviewed observer set rotates:

**O1/O2/O3 -> O2/O3/O4**

O1 is explicitly revoked and deterministic TEST-only O4 is introduced. The sequence-1 rotation binds the exact RUST-054 observation-bundle SHA-256, exact final RUST-053 checkpoint SHA-256 and checkpoint-statement SHA-256, the exact predecessor observer-set digest, the exact successor observer set, activation source commit, and `production=false`.

Rotation authorization requires 2-of-3 signatures from the exact predecessor O1/O2/O3 set. All 3/3 valid two-observer authorization subsets are accepted. Successor observation uses a distinct v2 schema/domain, requires 2-of-3 reports from exact O2/O3/O4, and accepts all 3/3 valid two-observer reporting subsets.

The old RUST-054 v1 observation bundle cannot replay as sequence-1 successor evidence. A valid signed distinct final journal-monitor-journal checkpoint with the same monitor-set sequence and same previous-checkpoint parent is rejected fail-closed even when a canonical successor quorum is otherwise present.

The detached verifier and selftest contain no private signing or network capability. Deterministic TEST private Ed25519 seeds remain producer-side only and are checked against reviewed public-key pins.

This remains TEST-only. It does not create independent observer administration, durable global gossip, real compromise recovery, production signing, HSM/TPM custody, production anti-rollback, OIDC, artifact publication, release/deployment authority, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
