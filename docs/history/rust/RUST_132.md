# RUST-132 — TEST-ONLY second RUST-130 checkpoint monitor-set rotation

RUST-132 composes the exact reviewed RUST-131 first monitor-set rotation and performs the second TEST-only rotation for the RUST-130 checkpoint-monitor family.

## Contract

- Monitor set rotates from M2/M3/M4 to M3/M4/M5 with a 2-of-3 threshold.
- M1 remains revoked from RUST-131 and M2 is newly revoked; cumulative revocation continuity is explicit.
- The second rotation binds the exact RUST-131 rotation, authorization and successor-bundle SHA-256 values plus all 12 inherited RUST-129 checkpoint target fields.
- All 3/3 valid two-monitor predecessor authorization subsets are accepted.
- All 3/3 valid two-monitor final monitoring subsets are accepted.
- A signed same-parent checkpoint fork remains observable evidence but cannot replace the canonical final bundle.
- The fail-closed matrix is fixed at 53/53 expected rejection cases, including sequence rollback, cumulative-revocation omission, predecessor digest mutation, quorum downgrade, duplicate/unsorted signers, signature mutation, every inherited target mutation, revoked-monitor resurrection, first-successor replay and same-parent fork substitution.
- Producer private keys are deterministic TEST fixture material only. The detached verifier/selftest contain no signing or network capability.
- CI keeps generated evidence read-only with chmod 0444, uses a fixed 272-path manifest and an 105-file verifier-only detached consumer under `env -i` and `/usr/bin/python3 -S`.
- The 100+ checkpoint boundary stays explicit through `rust_*.py` / `RUST_*.md` triggers and zero-padded numeric continuity loops.

No production monitor administration/signing, global publication, key custody, HSM/TPM, OIDC, release/deployment authority, consensus change or production Rust routing is introduced.

Production consensus remains Python-authoritative.
