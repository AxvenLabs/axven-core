# RUST-035 — TEST-ONLY witness-set rotation and revocation continuity

RUST-034 removes the TEST simulation's single-witness dependency by requiring a verifier-pinned 2-of-3 witness quorum. Its witness set is still static, however: there is no tested continuity contract for replacing a compromised or retired witness without silently resetting trust.

RUST-035 adds a narrow **TEST-ONLY witness-set rotation and revocation simulation**. It rotates the reviewed RUST-034 set `A/B/C` to `B/C/D`, explicitly revokes witness `A`, and requires the existing 2-of-3 set to authorize that exact transition before a successor floor quorum is accepted.

## Contract

The detached consumer verifies five externally supplied objects: the existing final trust state, the external monotonic floor, a canonical witness-set rotation record, a predecessor authorization quorum over that rotation, and a successor quorum over the floor.

The transition is fixed to witness-set sequence `0 -> 1`. The predecessor witness-set digest is bound to the exact reviewed RUST-034 pinned set. The successor set is fixed to the retained TEST witnesses `B/C` plus the new TEST witness `D`, threshold `2`, and `production=false`. The revoked list is exactly `[A]`.

The rotation record is domain-separated and must be authorized by any valid two of the old `A/B/C` witnesses. After rotation, the floor is accepted only through a new domain-separated quorum envelope bound to witness-set sequence `1` and the exact successor-set digest. Witness `A` is not a member of that set and cannot satisfy the successor quorum.

The old RUST-034 quorum schema is deliberately not accepted as a successor quorum, so an otherwise valid pre-rotation quorum cannot be replayed across the witness-set epoch boundary.

## Fail-closed coverage

The mutation contract covers 22 cases including predecessor threshold downgrade, duplicate/signature mutation, predecessor-set digest substitution, successor-set substitution, revocation removal, activation-source mismatch, production substitution, successor threshold downgrade, revoked-witness replay, witness-set sequence rollback, old-set digest replay, successor signature/digest mutation, old quorum-format replay, non-canonical rotation/auth/successor evidence, floor downgrade, and global activation-source mismatch.

The test also proves all `3/3` valid two-witness predecessor authorization subsets and all `3/3` valid two-witness successor `B/C/D` subsets are accepted.

## Security boundary

RUST-035 tests trust continuity and revocation semantics only. The TEST witness private seeds remain deterministic CI fixtures and do **not** represent independent operational custody. A real compromised-key response, independent witness administration, durable revocation publication, HSM/TPM integration, transparency infrastructure, or production anti-rollback storage remains a separate explicit design and approval gate.

RUST-035 adds no production signing, OIDC, artifact publication, release/deployment, chain/consensus change, DNS/site change, or production Rust routing. Production consensus remains Python-authoritative.
