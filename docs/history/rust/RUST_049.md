# RUST-049 — TEST-ONLY journal-observer rotation journal continuity

RUST-049 composes the exact reviewed RUST-048 multi-step journal-observer rotation verifier and adds a deterministic TEST-only append-only journal/checkpoint layer over the journal-observer administration history.

The reviewed journal-observer history remains:

`J1/J2/J3 -> J2/J3/J4 -> J3/J4/J5`

The journal has three monotonic entries. Entry 0 binds the exact RUST-046 journal-observer bundle. Entry 1 binds the exact RUST-047 rotation, rotation authorization and successor bundle with J1 revoked. Entry 2 binds the exact RUST-048 second rotation, authorization and final bundle with cumulative revocation `[J1, J2]`. Every non-genesis entry hashes its exact predecessor, so a checkpointed prefix cannot be rewritten.

A prefix checkpoint covers entries 0..1 and is signed by the exact TEST-only `J2/J3/J4` successor journal-observer set. The final checkpoint covers entries 0..2, binds the exact prefix-checkpoint SHA-256, and is signed by the exact TEST-only `J3/J4/J5` final journal-observer set. Both require 2-of-3 signatures. The availability contract accepts all 3/3 valid two-observer subsets for each checkpoint.

The journal and both checkpoint statements bind the exact canonical RUST-045 final monitor-journal checkpoint SHA-256, its checkpoint-statement SHA-256, the activation source commit and `production=false`. A valid signed same-parent final journal-observer-rotation-journal checkpoint fork is rejected fail-closed.

The detached verifier and selftest contain no private signing or network capability. Deterministic TEST private Ed25519 seeds exist only in the producer fixture and are checked against the reviewed public-key pins.

This TEST-only evidence does **not** create independent journal-observer administration, production signing, key custody, HSM/TPM use, durable network publication, OIDC, release/deployment authority, anti-rollback policy, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
