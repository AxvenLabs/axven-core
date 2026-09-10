# RUST-087 — TEST-ONLY RUST-086 checkpoint monitor-set rotation

RUST-087 composes the exact reviewed RUST-086 detached checkpoint-monitor verifier and rotates its TEST-only monitor set from M1/M2/M3 to M2/M3/M4.

- The old and successor sets both use a fixed 2-of-3 threshold; all 3/3 valid two-monitor predecessor authorization subsets and all 3/3 valid two-monitor successor monitoring subsets are accepted.
- M1 is explicitly revoked and cannot reappear in successor evidence.
- The rotation binds the exact RUST-086 predecessor monitor-bundle SHA-256 and all 12 canonical RUST-085 checkpoint target fields inherited through RUST-086.
- Successor monitor-set epoch fields are explicitly namespaced as `successor_monitor_set_sequence` and `successor_monitor_set_sha256`, so they cannot collide with the monitored checkpoint's own `monitor_set_sequence` and `monitor_set_sha256` target fields.
- The successor bundle and each signed statement bind the new M2/M3/M4 set while preserving the complete canonical target and `production=false` boundary.
- Old RUST-086 bundle replay, quorum downgrade, duplicate/unsorted monitors, revoked-monitor resurrection, signature mutation, mutation of every target field, successor epoch mutation, non-canonical evidence, and a valid signed same-parent checkpoint fork substitution are rejected fail-closed.
- Detached selftest requires 3/3 predecessor authorization availability, 3/3 successor monitoring availability, and 50/50 expected rejection cases.
- Deterministic TEST private seeds remain producer-side only. The detached verifier/selftest contain no signing or network capability.
- The workflow is read-only, hash-locked, chmod 0444, verifier-only and non-publishing. The fixed RUST-086 predecessor manifest contains 145 paths and RUST-087 appends exactly three canonical rotation paths for 148 total; fork evidence stays outside the manifest.

No production monitor administration, global gossip, durable publication, key custody, HSM/TPM use, OIDC, release/deployment authority, consensus change, or production Rust routing is introduced.

Production consensus remains Python-authoritative.
