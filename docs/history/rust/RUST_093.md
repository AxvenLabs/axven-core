# RUST-093 — TEST-ONLY RUST-090 checkpoint monitor rotation journal

RUST-093 composes the exact reviewed RUST-092 multi-step checkpoint-monitor rotation verifier and records the complete RUST-090 monitor administration history in a detached, append-only signed journal.

## Contract

- History is fixed as `M1/M2/M3 -> M2/M3/M4 -> M3/M4/M5` with a 2-of-3 quorum throughout.
- Entry 0 binds the exact RUST-090 predecessor monitor bundle.
- Entry 1 binds the exact RUST-091 first rotation, quorum authorization and successor bundle, with M1 revoked.
- Entry 2 binds the exact RUST-092 second rotation, quorum authorization and final bundle, with cumulative revocation `[M1, M2]`.
- Journal entries form a canonical SHA-256 predecessor hash chain.
- A two-entry prefix journal is checkpointed by M2/M3/M4; all 3/3 valid two-monitor subsets are accepted.
- The final three-entry journal must preserve that prefix byte-for-byte and is checkpointed by M3/M4/M5; all 3/3 valid two-monitor subsets are accepted.
- The final checkpoint binds the exact prefix checkpoint SHA-256 as its parent.
- Journal/checkpoints bind the exact RUST-089 final checkpoint SHA-256, checkpoint-statement SHA-256, activation source and the digest of all 12 RUST-090 target fields.
- A distinct signed same-parent final checkpoint is rejected as a split view.
- Detached mutation testing fixes a 35/35 fail-closed contract.

## CI boundary

RUST-093 remains TEST-only and non-publishing. Producer private keys are deterministic fixture material only. The detached verifier/selftest have no signing or network capability. CI makes evidence read-only, uses a fixed 166-path manifest and a 66-file verifier-only detached consumer under isolated `/usr/bin/python3 -S` execution.

No production monitor administration/signing, publication, key custody, HSM/TPM, OIDC, release/deployment authority, consensus change or production Rust routing is introduced. Production consensus remains Python-authoritative.
