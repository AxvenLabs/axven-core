# RUST-037 — TEST-ONLY append-only rotation journal and checkpoint continuity

RUST-037 layers a tamper-evident, TEST-only journal on top of the reviewed RUST-036 `A/B/C -> B/C/D -> C/D/E` witness rotation chain.

- Journal entries are fixed to sequences `0, 1, 2`, exact witness-set digests, exact rotation-record digests, cumulative revocation state, and a predecessor-entry hash chain.
- A sequence-1 prefix checkpoint is signed by the active `B/C/D` TEST quorum. The sequence-2 checkpoint is signed by `C/D/E` and cryptographically binds the exact prefix checkpoint hash.
- The final journal must preserve the already checkpointed prefix byte-for-byte at the semantic entry level; omission, reordering, predecessor-hash rewrites, revocation truncation, sequence rollback, and checkpoint-parent substitution fail closed.
- When two different same-sequence checkpoints with the same parent are both observed, the TEST-only fork detector rejects the ambiguity. It does **not** provide global gossip or guarantee that an unobserved fork will be discovered.
- Private deterministic TEST seeds exist only in the producer harness and do not enter the detached consumer.

This does **not** provide a production transparency log, durable external checkpoint publication, independent witness administration, HSM/TPM custody, or production anti-rollback. Those remain explicit future design/approval gates. Production consensus remains Python-authoritative.
