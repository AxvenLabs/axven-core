# RUST-148 — TEST-ONLY second RUST-146 checkpoint monitor-set rotation

RUST-148 composes the exact reviewed RUST-147 first monitor-set rotation and performs the second TEST-only rotation for the RUST-146 checkpoint-monitor family.

## Contract

- Monitor set rotates from M2/M3/M4 to M3/M4/M5 with a 2-of-3 threshold.
- M1 remains revoked from RUST-147 and M2 is newly revoked; cumulative revocation continuity is explicit.
- The second rotation binds the exact RUST-147 rotation, authorization and successor-bundle SHA-256 values plus all 12 inherited RUST-145 checkpoint target fields.
- All 3/3 valid two-monitor predecessor authorization subsets are accepted.
- All 3/3 valid two-monitor final monitoring subsets are accepted.
- A signed same-parent checkpoint fork remains observable evidence but cannot replace the canonical final bundle.
- The fail-closed matrix covers sequence rollback, cumulative-revocation omission, predecessor digest mutation, quorum downgrade, duplicate/unsorted signers, signature mutation, every inherited target mutation, revoked-monitor resurrection, first-successor replay and same-parent fork substitution.
- Producer private keys are deterministic TEST fixture material only. The detached verifier/selftest contain no signing or network capability.
- CI keeps generated evidence read-only, stages a verifier-only detached consumer and executes it under isolated `env -i` + `/usr/bin/python3 -S`.

No production monitor administration/signing, global publication, key custody, HSM/TPM, OIDC, release/deployment authority, consensus change or production Rust routing is introduced.

Production consensus remains Python-authoritative.
