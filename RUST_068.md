# RUST-068 — TEST-ONLY multi-step monitor rotation for the RUST-066 checkpoint monitors

RUST-068 composes the exact reviewed RUST-067 monitor-set rotation verifier and extends the TEST-only monitor administration history with a second authorized rotation: `M1/M2/M3 -> M2/M3/M4 -> M3/M4/M5`.

M1 remains revoked and M2 is newly revoked. The second rotation is sequence 2 and binds the exact RUST-067 first rotation SHA-256, first authorization SHA-256, first successor monitor bundle SHA-256, predecessor monitor-set digest, final monitor-set bytes, cumulative revocation `[M1, M2]`, activation source commit, and every field in the complete inherited RUST-066 canonical checkpoint target.

Authorization requires 2-of-3 signatures from the predecessor M2/M3/M4 set and all 3/3 valid two-monitor authorization subsets are accepted. The final v3 monitor bundle is pinned to M3/M4/M5, requires 2-of-3 reports, and accepts all 3/3 valid two-monitor availability subsets. Revoked M1 and M2 cannot appear in the final set or reports.

Valid signed final reports that bind a distinct checkpoint with the same observer-set sequence and previous-checkpoint parent are rejected fail-closed as same-parent split views. Rollback, predecessor digest substitution, cumulative-revocation omission, inherited target substitution, monitor-set substitution, threshold downgrade, duplicate/unsorted signers, signature mutation, non-canonical evidence, predecessor-successor replay, and valid signed same-parent fork substitution are rejected.

The detached verifier and selftest contain no private signing or network capability. Deterministic TEST private Ed25519 seeds exist only in the producer fixture and are checked against pinned public keys. Evidence is made read-only before detached verification.

This TEST-only evidence does **not** create durable global gossip, production monitor administration, production signing, key custody, HSM/TPM use, OIDC, publication, release/deployment authority, anti-rollback policy, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
