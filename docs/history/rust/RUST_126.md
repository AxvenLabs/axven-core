# RUST-126 — TEST-ONLY RUST-125 journal checkpoint monitoring

RUST-126 composes the exact reviewed RUST-125 append-only monitor-rotation journal verifier and adds an independent detached 2-of-3 monitor quorum over its final signed checkpoint.

## Contract

- Three independent deterministic TEST-only monitors observe the exact RUST-125 final monitor-rotation-journal checkpoint.
- Any 2-of-3 monitor reports are sufficient; all 3/3 valid two-monitor subsets must verify.
- Every report binds the exact RUST-125 final checkpoint SHA-256 and checkpoint-statement SHA-256 plus all ten inherited checkpoint statement fields, for a fixed 12-field target.
- Reports bind monitor-set sequence/digest, journal entry count, journal/head/previous-checkpoint digests, monitored checkpoint/statement digests, observed-target digest and activation source.
- Quorum downgrade, duplicate/unsorted/unknown monitors, signature mutation, target mutation, non-canonical evidence and RUST-125 checkpoint replay are rejected fail-closed.
- A signed distinct same-parent RUST-125 checkpoint can be recognized as observed fork evidence but cannot replace the canonical monitor bundle.
- Detached selftest fixes 3/3 availability and 27/27 fail-closed rejection cases.

## CI boundary

The exact RUST-125 verifier and predecessor workflow blobs are pinned. Producer private keys remain fixture-only. The detached verifier/selftest have no signing or network capability. CI makes evidence read-only, uses a fixed 255-path manifest and a 99-file verifier-only detached consumer under isolated `/usr/bin/python3 -S` execution. The 100+ checkpoint boundary stays explicit through `rust_*.py` / `RUST_*.md` triggers and zero-padded numeric continuity loops.

No production monitor administration/signing, publication, key custody, HSM/TPM, OIDC, release/deployment authority, consensus change or production Rust routing is introduced. Production consensus remains Python-authoritative.
