# RUST-081 — TEST-ONLY append-only RUST-077 checkpoint observer rotation journal

RUST-081 composes the exact reviewed RUST-080 multi-step observer rotation and records the complete independent TEST-only checkpoint-observer administration history in an append-only signed journal/checkpoint layer.

## Contract

- Journal entry 0 binds the exact RUST-078 O1/O2/O3 observation bundle.
- Journal entry 1 binds the exact RUST-079 first rotation, first authorization, and O2/O3/O4 successor observation bundle with O1 revoked.
- Journal entry 2 binds the exact RUST-080 second rotation, second authorization, and O3/O4/O5 final observation bundle with cumulative revocation `[O1, O2]`.
- Entries are monotonic (`0 -> 1 -> 2`) and hash-chain each predecessor entry.
- The prefix checkpoint covers entries 0..1 and is signed 2-of-3 by O2/O3/O4; all 3/3 valid two-observer subsets are accepted.
- The final checkpoint covers entries 0..2, binds the exact prefix checkpoint SHA-256 as parent, and is signed 2-of-3 by O3/O4/O5; all 3/3 valid two-observer subsets are accepted.
- Journal/checkpoint statements bind the exact RUST-077 final checkpoint SHA-256 and statement SHA-256, a digest of all 12 canonical target fields, activation source, and `production=false`.
- The final journal cannot rewrite its checkpointed prefix.
- A valid signed same-parent final journal-checkpoint fork is recognized but rejected fail-closed.
- Detached selftest covers 35/35 fail-closed cases spanning journal rewrites/truncation/hash links, revocation omission, checkpoint parent/head/target/source/set/quorum/signature mutation, non-canonical evidence, and valid signed same-parent fork substitution.

## Boundary

The workflow remains read-only and manifest-bounded. Deterministic TEST private seeds are producer-only; detached verifier/selftest contain no signing or network capability. No production observer administration, publication, key custody, consensus change, or production Rust routing is introduced.

Production consensus remains Python-authoritative.
