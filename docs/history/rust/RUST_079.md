# RUST-079 — TEST-ONLY RUST-077 checkpoint observer-set rotation

RUST-079 composes the exact reviewed RUST-078 observer verifier and rotates the independent TEST-only checkpoint-observer set from O1/O2/O3 to O2/O3/O4 without changing production consensus authority.

## Contract

- The predecessor observer set is O1/O2/O3 with a strict 2-of-3 threshold.
- The successor observer set is O2/O3/O4 with the same strict 2-of-3 threshold.
- O1 is explicitly revoked and cannot reappear in successor evidence.
- The rotation payload binds the predecessor set digest, exact RUST-078 observation-bundle digest, complete RUST-078 canonical checkpoint target, successor set, sequence, revocation list, activation source, and `production=false`.
- Rotation authorization is signed by the predecessor set; all 3/3 valid two-observer authorization subsets are accepted.
- Successor observations are signed by O2/O3/O4; all 3/3 valid two-observer successor subsets are accepted.
- Every successor statement binds all 12 canonical RUST-077 final checkpoint target fields plus successor observer-set sequence/digest.
- A valid signed same-parent RUST-077 checkpoint fork is recognized as evidence but rejected as the canonical successor observation.
- The detached selftest covers 49/49 fail-closed cases including sequence/set/revocation/bundle continuity, all target fields, quorum/signature failures, revoked-observer resurrection, old-bundle replay, non-canonical evidence, and signed same-parent fork substitution.

## Boundary

The workflow is read-only, uses a fixed evidence manifest and a verifier-only detached consumer, and keeps deterministic TEST private seeds in the producer fixture only. No production observer administration, signing, publication, network gossip, key custody, consensus change, or production Rust routing is introduced.

Production consensus remains Python-authoritative.
