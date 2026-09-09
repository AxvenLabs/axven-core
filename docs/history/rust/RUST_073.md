# RUST-073 — TEST-ONLY append-only monitor-rotation-journal observer rotation journal

RUST-073 composes the exact reviewed RUST-072 multi-step observer rotation verifier and records the complete TEST-only observer administration history in an append-only hash-chained journal with signed checkpoints.

The journal records three monotonic entries for `O1/O2/O3 -> O2/O3/O4 -> O3/O4/O5`. Entry 0 binds the exact RUST-070 predecessor observation bundle and the initial observer-set digest. Entry 1 binds the exact RUST-071 first rotation, rotation authorization and successor observation bundle with O1 revoked. Entry 2 binds the exact RUST-072 second rotation, authorization and final observation bundle with cumulative revocation `[O1, O2]`. Every non-genesis entry binds the canonical SHA-256 of its predecessor entry so history cannot be silently reordered or rewritten.

The prefix journal covers entries 0..1 and is checkpointed by the exact O2/O3/O4 observer set with a strict 2-of-3 Ed25519 quorum. The final journal covers entries 0..2; its checkpoint is signed by the exact O3/O4/O5 observer set with a strict 2-of-3 quorum and binds the exact prefix-checkpoint SHA-256 as `previous_checkpoint_sha256`. The final journal must preserve the complete checkpointed prefix byte-for-byte at the canonical object level.

Both prefix and final checkpoint contracts accept all 3/3 valid two-observer subsets. This preserves quorum availability while keeping revoked O1/O2 outside the corresponding successor signer sets.

Journal and checkpoint statements bind the exact RUST-069 final monitor-rotation-journal checkpoint SHA-256 and checkpoint-statement SHA-256, a SHA-256 digest over every field in the complete inherited RUST-070 canonical checkpoint target, the activation source commit, exact observer-set epoch/digest, journal length/head/parent continuity, and `production=false`.

A distinct but validly signed final checkpoint with the same observer-set sequence and same previous-checkpoint parent is rejected fail-closed as an observed split view. Split-view safety remains stronger than availability.

The detached selftest exercises 35/35 fail-closed cases covering prefix and final journal rewrites, truncation and sequence rollback, hash-link and rotation/auth/bundle digest substitution, cumulative revocation omission, checkpoint parent/head/target/source/set substitution, quorum downgrade, duplicate signers, signature mutation, non-canonical evidence, and a valid signed same-parent checkpoint fork. Prefix and final availability are independently exercised across all 3/3 valid two-observer subsets.

Deterministic TEST private keys exist only in the producer fixture. The detached verifier and selftest contain no private signing or network capability. Workflow evidence is made read-only, staged into a verifier-only detached consumer, constrained by a fixed manifest, and executed with `env -i` plus `/usr/bin/python3 -S`.

This TEST-only layer does **not** create global network gossip, production observer administration/signing, durable publication, key custody, HSM/TPM use, OIDC, release/deployment authority, anti-rollback policy, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
