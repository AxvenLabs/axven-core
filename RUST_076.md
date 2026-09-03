# RUST-076 — TEST-ONLY second monitor rotation for RUST-074 checkpoint monitors

RUST-076 composes the exact reviewed RUST-075 monitor-set rotation verifier and extends the TEST-only monitor administration history with a second authorized rotation over the same canonical RUST-073 observer-rotation-journal checkpoint target.

The sequence is `M1/M2/M3 -> M2/M3/M4 -> M3/M4/M5`. M1 remains revoked, M2 is newly revoked, and deterministic TEST-only M5 is introduced. The predecessor M2/M3/M4 set authorizes the second rotation with a strict 2-of-3 Ed25519 quorum, and all 3/3 valid two-monitor authorization subsets are accepted.

The second rotation binds the exact RUST-075 first rotation SHA-256, rotation-authorization SHA-256, first successor monitor-bundle SHA-256, predecessor/final monitor-set continuity, cumulative revocation `[M1, M2]`, and every field in the complete inherited RUST-074 canonical checkpoint target.

Final v3 M3/M4/M5 reports carry monitor-set sequence/digest plus the complete inherited target, require a strict 2-of-3 quorum, and accept all 3/3 valid two-monitor subsets. Revoked M1 and M2 cannot reappear in final evidence.

Rollback, predecessor digest substitution, cumulative-revocation omission, inherited-target substitution, final-set substitution, quorum downgrade, duplicate/unsorted signers, signature mutation, non-canonical evidence, first-successor replay, and a valid signed same-parent final split view are rejected fail-closed.

The detached selftest exercises 3/3 predecessor authorization availability, 3/3 final monitoring availability, and 51/51 fail-closed cases. Deterministic TEST private monitor seeds remain producer-side only; detached verifier/selftest contain no private signing or network capability.

Workflow evidence remains read-only, manifest-bounded, verifier-only, and executed with `env -i` plus `/usr/bin/python3 -S`.

This TEST-only layer does **not** introduce global network gossip, production monitor administration/signing, durable publication, key custody, HSM/TPM use, OIDC, release/deployment authority, anti-rollback policy, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
