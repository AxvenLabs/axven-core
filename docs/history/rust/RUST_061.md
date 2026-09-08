# RUST-061 — TEST-only observer-rotation-journal monitor rotation journal continuity

RUST-061 composes the exact reviewed RUST-060 multi-step observer-rotation-journal monitor rotation verifier and records its monitor-set history in an append-only journal with signed checkpoints.

The TEST-only history is `M1/M2/M3 -> M2/M3/M4 -> M3/M4/M5`. Entry 0 binds the exact RUST-058 monitor bundle, entry 1 binds the exact RUST-059 rotation, authorization, successor bundle and M1 revocation, and entry 2 binds the exact RUST-060 second rotation, authorization, final bundle and cumulative M1/M2 revocation.

The prefix checkpoint commits entries 0–1 under the exact M2/M3/M4 2-of-3 set. The final checkpoint commits all three entries under the exact M3/M4/M5 2-of-3 set and binds the SHA-256 of the prefix checkpoint as its previous checkpoint. The journal also binds the exact RUST-057 observer-rotation-journal checkpoint and statement plus a digest of the complete inherited monitored target.

RUST-061 rejects prefix rewrites, sequence rollback, broken entry hash chains, rotation/auth/bundle digest substitution, revocation omission, threshold downgrade, duplicate signers, invalid signatures, non-canonical evidence, and a distinct otherwise-valid signed same-parent final checkpoint.

This checkpoint is TEST-only and does **not** create independent monitor administration. It adds no OIDC, artifact publication, production signing, HSM/TPM custody, production anti-rollback, durable global gossip, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
