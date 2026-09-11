# RUST-107 — TEST-ONLY RUST-106 checkpoint monitor-set rotation

RUST-107 composes the exact reviewed RUST-106 detached checkpoint-monitor verifier and rotates its three TEST-only monitors from M1/M2/M3 to M2/M3/M4 while preserving a 2-of-3 quorum.

- The old monitor set is the exact pinned RUST-106 monitor set.
- M1 is explicitly revoked; M2 and M3 continue; a new deterministic TEST-only M4 is introduced.
- The rotation object binds the exact predecessor RUST-106 monitor bundle SHA-256 and every one of the 12 inherited RUST-105 checkpoint target fields.
- Rotation authorization is signed by the predecessor set under the existing 2-of-3 threshold; all 3/3 valid two-monitor predecessor subsets are accepted.
- The successor bundle is bound to a new monitor-set epoch and all 3/3 valid two-monitor successor subsets are accepted.
- Revoked-monitor resurrection, threshold downgrade, duplicate or unsorted signers, payload tampering, signature mutation, target-field mutation, non-canonical successor evidence, old RUST-106 bundle replay, and a signed valid same-parent successor fork all fail closed.
- The detached selftest fixes 50/50 expected rejection cases.
- Producer private keys are deterministic TEST fixture material only. The verifier and selftest have no signing or network capability.
- CI keeps all evidence read-only with chmod 0444, reconstructs a fixed 203-path manifest, stages an 80-file verifier-only detached consumer, and runs under isolated `env -i` + `/usr/bin/python3 -S`.
- 100+ checkpoint path handling remains explicit through `rust_*.py` / `RUST_*.md` triggers and zero-padded numeric loops.
- No production monitor administration/signing, publication, key custody, HSM/TPM, OIDC, release/deployment authority, consensus change, or production Rust routing is introduced.

Production consensus remains Python-authoritative.
