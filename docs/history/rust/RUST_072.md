# RUST-072 — TEST-ONLY multi-step monitor-rotation-journal observer-set rotation

RUST-072 composes the exact reviewed RUST-071 observer-set rotation verifier and extends the TEST-only observer administration history with a second authorized rotation.

The observer set evolves `O1/O2/O3 -> O2/O3/O4 -> O3/O4/O5`. O1 remains revoked, O2 is newly revoked, and deterministic TEST-only O5 is introduced. The second rotation must be authorized by at least 2-of-3 distinct valid predecessor O2/O3/O4 signatures, and all 3/3 valid two-observer authorization subsets are accepted.

The second rotation binds the exact RUST-071 first-rotation SHA-256, exact first-rotation authorization SHA-256, exact RUST-071 successor-observation-bundle SHA-256, predecessor and final observer-set digests, cumulative revocation `[O1, O2]`, and every field in the complete inherited RUST-070 canonical checkpoint target: checkpoint and checkpoint-statement digests, monitor-set sequence and digest, journal entry count, journal and head-entry digests, previous-checkpoint digest, monitored checkpoint and statement digests, inherited observed-target digest, and activation source commit. `production=false` remains mandatory.

Final v3 observation reports are accepted only from O3/O4/O5 and require at least 2-of-3 distinct valid Ed25519 reports. All 3/3 valid two-observer final availability subsets are accepted. Revoked O1 and O2 cannot reappear in final evidence.

A valid signed final report describing a distinct target with the same monitor-set sequence and same previous-checkpoint parent is rejected fail-closed as an observed split view. This keeps split-view safety over availability.

The detached selftest exercises 51/51 fail-closed cases covering sequence rollback, predecessor/final-set substitution, cumulative revocation omission, predecessor rotation/auth/successor digest substitution, every inherited target field in both rotation and final reports, authorization downgrade/duplicate/order/signature mutation, final quorum/set/resurrection/signature mutation, non-canonical evidence, first-successor replay, and valid signed same-parent fork substitution.

Deterministic TEST private keys exist only in the producer fixture. The detached verifier and selftest contain no private signing or network capability. Workflow evidence is read-only and verified through a fixed manifest in an `env -i` / `/usr/bin/python3 -S` detached consumer.

This TEST-only layer does **not** create global network gossip, production observer administration/signing, durable publication, key custody, HSM/TPM use, OIDC, release/deployment authority, anti-rollback policy, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
