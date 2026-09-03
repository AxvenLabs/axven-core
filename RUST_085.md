# RUST-085 — TEST-ONLY append-only RUST-081 checkpoint monitor rotation journal

RUST-085 composes the exact reviewed RUST-084 multi-step checkpoint-monitor rotation verifier and records the complete TEST-only RUST-081 checkpoint monitor administration history in an append-only signed journal/checkpoint chain.

The administration sequence is `M1/M2/M3 -> M2/M3/M4 -> M3/M4/M5`. Entry 0 binds the exact RUST-082 predecessor monitor bundle. Entry 1 binds the exact RUST-083 first rotation, authorization and successor bundle while revoking M1. Entry 2 binds the exact RUST-084 second rotation, authorization and final bundle with cumulative revocation `[M1, M2]`. Every non-genesis entry hashes its exact predecessor entry.

A prefix journal/checkpoint freezes entries 0–1 under the M2/M3/M4 monitor set. Its checkpoint requires a 2-of-3 Ed25519 quorum and all 3/3 valid two-monitor subsets are accepted. The final journal must preserve that checkpointed prefix byte-for-byte, appends entry 2, and is checkpointed by the M3/M4/M5 monitor set with the same 2-of-3 / 3-of-3-subset availability contract. The final checkpoint binds the exact SHA-256 of the prefix checkpoint as its parent.

Both prefix and final checkpoints bind the exact canonical RUST-081 final observer-rotation-journal checkpoint, its canonical statement, the digest over every RUST-082 `TARGET_KEYS` field, the activation source commit, journal digest and head-entry digest. A validly signed final checkpoint that shares the canonical parent but changes journal/head evidence is rejected as a same-parent split view.

The detached selftest covers 35/35 fail-closed cases, including genesis/prefix rewrites, rotation and authorization digest substitution, target/source/production mutation, journal truncation, hash-chain rollback, cumulative-revocation omission, quorum/duplicate/signature failure, final-parent/set/head mutation, non-canonical JSON and a validly signed same-parent checkpoint fork.

Deterministic TEST private seeds exist only in the producer fixture. The verifier and selftest have no signing or network capability. CI keeps generated continuity evidence read-only, stages a verifier-only detached consumer, uses a fixed 144-path evidence manifest, and runs verification under a clean `env -i` plus `/usr/bin/python3 -S` environment.

This checkpoint does not introduce global gossip, durable publication, production key custody, production signing, HSM/TPM integration, OIDC, release/deployment authority, consensus changes or production Rust routing. Production consensus remains Python-authoritative.
