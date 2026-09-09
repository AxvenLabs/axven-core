# RUST-080 — TEST-ONLY multi-step RUST-077 checkpoint observer rotation

RUST-080 composes the exact reviewed RUST-079 first observer-set rotation and performs a second independent TEST-only rotation from O2/O3/O4 to O3/O4/O5.

## Contract

- The predecessor observer set is O2/O3/O4 with a strict 2-of-3 threshold.
- The final observer set is O3/O4/O5 with the same strict 2-of-3 threshold.
- O1 remains revoked and O2 is newly revoked; cumulative revocation is `[O1, O2]`.
- The second rotation binds the exact RUST-079 first rotation, first authorization, and first successor observation-bundle SHA-256 digests.
- The second rotation also binds all 12 canonical RUST-077 final checkpoint target fields, predecessor/final set continuity, source, and `production=false`.
- Second-rotation authorization accepts all 3/3 valid two-observer subsets from O2/O3/O4.
- Final O3/O4/O5 observation accepts all 3/3 valid two-observer subsets.
- Neither O1 nor O2 can reappear in final evidence.
- A valid signed same-parent RUST-077 checkpoint fork is recognized but rejected as canonical final evidence.
- The detached selftest covers 51/51 fail-closed cases including sequence/set/cumulative-revocation continuity, predecessor evidence digests, all target fields, authorization quorum/signature, final set/target/signature, revoked-observer resurrection, first-successor replay, non-canonical evidence, and signed same-parent fork substitution.

## Boundary

The workflow remains read-only and manifest-bounded. Deterministic TEST private seeds are producer-only; detached verifier/selftest contain no signing or network capability. No production observer administration, publication, key custody, consensus change, or production Rust routing is introduced.

Production consensus remains Python-authoritative.
