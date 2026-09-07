# RUST-036 — TEST-ONLY multi-step witness rotation and cumulative revocation

RUST-035 proves one authorized TEST-only witness-set transition from `A/B/C` to `B/C/D` and explicitly revokes `A`. A single successful transition is not enough to prove that trust state can keep evolving without silently forgetting earlier revocations.

RUST-036 composes the exact reviewed RUST-035 verifier and adds a second transition: `B/C/D -> C/D/E`. The second transition is authorized by the current sequence-1 set, advances the witness-set sequence to `2`, and carries a cumulative revoked set `[A, B]`.

The second rotation binds the SHA-256 of the exact first rotation record, not only the predecessor witness-set digest. The final floor quorum uses a new domain and schema, is bound to witness-set sequence `2`, and accepts only pinned `C/D/E` witnesses. Sequence-0/1 quorum formats, predecessor-set digests, and revoked `A` or `B` identities are rejected after the second rotation.

CI proves all `3/3` valid two-witness subsets of the sequence-1 `B/C/D` set can authorize the second rotation and all `3/3` valid two-witness subsets of `C/D/E` can authorize the final floor quorum. The fail-closed contract covers 25 mutation/replay cases, including cumulative-revocation truncation, predecessor-rotation substitution, set-sequence rollback, revoked-key reintroduction, old quorum-format replay, signature/digest mutation, non-canonical evidence, floor rollback, and activation-source substitution.

This remains a TEST-only continuity simulation. Deterministic fixture seeds do not represent independent key custody or a real compromise-response process. Production witness administration, revocation publication, HSM/TPM integration, transparency infrastructure, durable anti-rollback state, production signing, release/deployment and production Rust routing remain explicit future approval gates. Production consensus remains Python-authoritative.
