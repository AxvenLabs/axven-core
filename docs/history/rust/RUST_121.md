# RUST-121 — TEST-ONLY RUST-118 checkpoint monitor-rotation journal

RUST-121 composes the exact reviewed RUST-120 second monitor-set rotation and records the complete RUST-118 checkpoint-monitor administration lineage in an append-only TEST-only journal.

## Contract

- Journal lineage is M1/M2/M3 -> M2/M3/M4 -> M3/M4/M5.
- The cumulative revocation `[M1, M2]` is retained in the final journal entry.
- Entry 0 binds the exact RUST-118 predecessor monitor bundle.
- Entry 1 binds the exact RUST-119 rotation, authorization and successor bundle with M1 revoked.
- Entry 2 binds the exact RUST-120 second rotation, authorization and final bundle with cumulative revocation.
- Every journal entry binds exact monitor-set, rotation, rotation-authorization, monitor-bundle and predecessor-entry digests.
- The journal is bound to the exact RUST-117 final checkpoint SHA-256, checkpoint-statement SHA-256, inherited 12-field observed target digest and activation source commit.
- Prefix checkpoint at sequence 1 is authorized by the RUST-119 successor set; final checkpoint at sequence 2 is authorized by the RUST-120 final set.
- Both checkpoints use a 2-of-3 threshold and all 3/3 valid two-monitor subsets are accepted.
- The final journal must preserve the exact checkpointed prefix; prefix rewriting, sequence rollback and hash-chain rewriting fail closed.
- A signed same-parent final checkpoint is valid observable evidence but is rejected as a substitute for the canonical final checkpoint.
- The fail-closed matrix is fixed at 35/35 expected cases.
- Producer private keys are deterministic TEST fixture material only; verifier/selftest have no signing or network capability.
- CI keeps evidence read-only with chmod 0444, a fixed 243-path manifest and a 94-file verifier-only detached consumer under `env -i` and `/usr/bin/python3 -S`.
- The 100+ checkpoint boundary stays explicit through `rust_*.py` / `RUST_*.md` triggers and zero-padded numeric continuity loops.

No production monitor administration/signing, publication, key custody, HSM/TPM, OIDC, release/deployment authority, consensus change or production Rust routing is introduced.

Production consensus remains Python-authoritative.
