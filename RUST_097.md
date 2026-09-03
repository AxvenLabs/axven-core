# RUST-097 — TEST-ONLY RUST-094 checkpoint monitor-rotation journal

RUST-097 composes the exact reviewed RUST-096 second monitor-set rotation and records the RUST-094 checkpoint-monitor lineage in an append-only TEST-only journal.

## Contract

- Journal lineage is M1/M2/M3 -> M2/M3/M4 -> M3/M4/M5.
- Cumulative revocation `[M1, M2]` is retained in the final journal entry.
- Every journal entry binds the exact monitor-set digest, rotation digest, rotation-authorization digest, monitor-bundle digest and predecessor-entry digest.
- The journal is bound to the exact RUST-093 final checkpoint SHA-256, checkpoint-statement SHA-256, inherited 12-field observed target digest and activation source commit.
- Prefix checkpoint at sequence 1 is authorized by the RUST-095 successor set; final checkpoint at sequence 2 is authorized by the RUST-096 final set.
- Both checkpoints use a 2-of-3 threshold and all 3/3 valid two-monitor subsets are accepted.
- The final journal must preserve the exact checkpointed prefix; prefix rewriting, sequence rollback and hash-chain rewriting fail closed.
- A signed same-parent final checkpoint fork is valid evidence but is explicitly rejected as a substitute for the canonical final checkpoint.
- The fail-closed matrix is fixed at 35/35 expected cases.
- Producer private keys are deterministic TEST fixture material only; verifier/selftest have no signing or network capability.
- CI keeps evidence read-only with chmod 0444, a fixed 177-path manifest and a 70-file verifier-only detached consumer under `env -i` and `/usr/bin/python3 -S`.

No production monitor administration/signing, publication, key custody, HSM/TPM, OIDC, release/deployment authority, consensus change or production Rust routing is introduced.

Production consensus remains Python-authoritative.
