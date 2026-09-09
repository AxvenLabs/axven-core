# RUST-077 — TEST-ONLY append-only RUST-074 checkpoint monitor rotation journal

RUST-077 composes the exact reviewed RUST-076 multi-step monitor rotation verifier and records the complete TEST-only checkpoint-monitor administration history in an append-only signed journal/checkpoint layer.

The journal records `M1/M2/M3 -> M2/M3/M4 -> M3/M4/M5` as three monotonic hash-chained entries. Entry 0 binds the exact RUST-074 monitor bundle, entry 1 binds the exact RUST-075 first rotation/authorization/successor evidence with M1 revoked, and entry 2 binds the exact RUST-076 second rotation/authorization/final evidence with cumulative revocation `[M1, M2]`.

The prefix checkpoint covers entries 0..1 and is 2-of-3 signed by M2/M3/M4. The final checkpoint covers entries 0..2, binds the exact prefix checkpoint SHA-256 as its previous checkpoint, and is 2-of-3 signed by M3/M4/M5. Both checkpoint sets accept all 3/3 valid two-monitor subsets.

Journal and checkpoint statements bind the exact RUST-073 final observer-rotation-journal checkpoint SHA-256 and checkpoint-statement SHA-256, plus a digest of every field in the complete inherited RUST-074 canonical checkpoint target, activation source commit, and `production=false`.

The final journal cannot rewrite its checkpointed prefix. A validly signed distinct final checkpoint sharing the same monitor-set sequence and previous-checkpoint parent is recognized as a same-parent split view and rejected fail-closed.

The detached selftest exercises 35/35 fail-closed cases covering prefix/final journal rewriting and truncation, hash-chain substitution, rotation/authorization/bundle digest mutation, cumulative revocation omission, checkpoint parent/head/target/source/set/quorum/signature mutation, non-canonical evidence, and valid signed same-parent fork substitution. Prefix and final checkpoint availability are separately checked across all 3/3 valid two-monitor subsets.

Deterministic TEST private seeds exist only in the producer fixture. The detached verifier and selftest contain no private signing or network capability. Workflow evidence is read-only, manifest-bounded, verifier-only, and executed with `env -i` plus `/usr/bin/python3 -S`.

This TEST-only layer does **not** create global network gossip, production monitor administration/signing, durable publication, key custody, HSM/TPM use, OIDC, release/deployment authority, anti-rollback policy, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
