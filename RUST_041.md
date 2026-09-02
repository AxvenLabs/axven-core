# RUST-041 — TEST-ONLY append-only observer rotation journal/checkpoint continuity

RUST-041 composes the reviewed RUST-040 multi-step observer-set rotation verifier and records the observer-set history `O1/O2/O3 -> O2/O3/O4 -> O3/O4/O5` in a canonical append-only journal.

The three journal entries bind each observer-set epoch to its exact observer-set SHA-256, rotation payload SHA-256, rotation-authorization SHA-256, observation-bundle SHA-256, cumulative revocation list, and predecessor-entry SHA-256. The sequence-1 prefix is checkpointed by `O2/O3/O4`; the sequence-2 final journal must preserve that exact prefix and is checkpointed by `O3/O4/O5` with the previous-checkpoint digest linked explicitly. The final cumulative revoked set remains `[O1, O2]`.

Both checkpoint envelopes require a deterministic 2-of-3 Ed25519 observer quorum. A validly signed same-parent final observer-journal checkpoint fork is fail-closed when both views are observed. The workflow verifies all three valid 2-observer subsets for both the prefix and final checkpoints, mutation/replay resistance, canonical encoding, read-only external evidence, and pristine detached re-verification.

This is still deterministic TEST-only continuity evidence. It does **not** create independent observer administration, durable network gossip or publication, a transparency service, real compromise recovery, HSM/TPM custody, production anti-rollback, or a global fork-discovery guarantee. Production consensus remains Python-authoritative; production Rust routing and irreversible production trust activation remain separate explicit approval gates.
