# RUST-086 — TEST-ONLY RUST-085 monitor-rotation-journal checkpoint monitoring

RUST-086 composes the exact reviewed RUST-085 append-only checkpoint-monitor rotation journal verifier and adds an independent detached TEST-only monitor quorum over its final signed journal checkpoint.

- Three independent TEST-only monitors form a fixed 2-of-3 quorum; all 3/3 valid two-monitor subsets are accepted.
- Every signed report binds the exact RUST-085 final checkpoint SHA-256 and checkpoint-statement SHA-256 plus the complete inherited journal checkpoint target: monitor-set sequence/digest, entry count, journal/head/parent digests, monitored checkpoint/statement digests, observed-target digest, and activation source.
- The canonical target therefore contains 12 fixed fields and `production=false` remains mandatory in every report and bundle.
- A validly signed same-parent RUST-085 final checkpoint fork may be recognized as observed evidence, but cannot substitute for the canonical monitor bundle.
- Quorum downgrade, below-threshold bundles, duplicate/unsorted or unknown monitors, signature mutation, mutation of every target field, non-canonical evidence, RUST-085 checkpoint replay, and signed same-parent fork substitution are rejected fail-closed.
- The detached selftest requires 3/3 availability and 27/27 expected rejection cases.
- Deterministic TEST private seeds exist only in the producer fixture. The verifier and selftest have no signing or network capability.
- The workflow is read-only, hash-locked, evidence is chmod 0444, the detached consumer contains verifier code only, and verification runs under `env -i` with `/usr/bin/python3 -S`.
- The fixed predecessor manifest contains 144 RUST-085 canonical paths and RUST-086 appends only `/tmp/axven-rust086-monitor-bundle.json`, yielding 145 canonical paths. The observed-fork bundle stays outside the canonical manifest and is passed only to the selftest.

No production monitor administration, global gossip, durable publication, key custody, HSM/TPM use, OIDC, release/deployment authority, consensus change, or production Rust routing is introduced.

Production consensus remains Python-authoritative.
