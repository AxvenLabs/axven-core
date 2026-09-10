# RUST-088 — TEST-ONLY second RUST-085 journal checkpoint monitor-set rotation

RUST-088 composes the exact reviewed RUST-087 detached monitor-set rotation and performs a second TEST-only monitor rotation from M2/M3/M4 to M3/M4/M5.

- Both predecessor and final sets use a fixed 2-of-3 threshold; all 3/3 valid two-monitor predecessor authorization subsets and all 3/3 valid two-monitor final monitoring subsets are accepted.
- M1 remains revoked and M2 is newly revoked; cumulative revocation is `[M1, M2]`, and neither can reappear in final evidence.
- The second rotation binds exact SHA-256 digests of the RUST-087 first rotation, first authorization and first successor bundle.
- All 12 canonical RUST-086 checkpoint target fields remain bound through the second rotation and final monitoring.
- Final monitor-set epoch fields are explicitly namespaced as `final_monitor_set_sequence` and `final_monitor_set_sha256`, avoiding collision with the monitored checkpoint's own `monitor_set_sequence` and `monitor_set_sha256` target fields.
- Old RUST-087 successor replay, cumulative-revocation rollback, quorum downgrade, duplicate/unsorted monitors, target mutation, signature mutation, non-canonical evidence, M1/M2 resurrection and a valid signed same-parent checkpoint fork substitution are rejected fail-closed.
- Detached selftest requires 3/3 predecessor authorization availability, 3/3 final monitoring availability and 53/53 expected rejection cases.
- Deterministic TEST private seeds remain producer-side only. The detached verifier/selftest contain no signing or network capability.
- The workflow is read-only, hash-locked, chmod 0444, verifier-only and non-publishing. It inherits the fixed 148-path RUST-087 manifest and appends exactly three canonical RUST-088 paths for 151 total; fork evidence stays outside the manifest.

No production monitor administration, global gossip, durable publication, key custody, HSM/TPM use, OIDC, release/deployment authority, consensus change or production Rust routing is introduced.

Production consensus remains Python-authoritative.
