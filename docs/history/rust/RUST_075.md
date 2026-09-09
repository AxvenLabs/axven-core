# RUST-075 — TEST-ONLY monitor-set rotation for RUST-074 checkpoint monitors

RUST-075 composes the exact reviewed RUST-074 checkpoint-monitor verifier and adds deterministic TEST-only monitor-set rotation/revocation continuity over the same canonical RUST-073 observer-rotation-journal checkpoint target.

The monitor set rotates `M1/M2/M3 -> M2/M3/M4`. M1 is explicitly revoked. The predecessor M1/M2/M3 set authorizes the rotation with a strict 2-of-3 Ed25519 quorum, and all 3/3 valid two-monitor authorization subsets are accepted.

The rotation binds the exact predecessor RUST-074 monitor bundle SHA-256, predecessor and successor monitor-set digests, the explicit revocation list, activation source commit, and every field in the complete RUST-074 canonical checkpoint target.

Successor M2/M3/M4 reports use distinct v2 schemas/domain, carry monitor-set sequence/digest plus the complete inherited target, and require a strict 2-of-3 quorum. All 3/3 valid two-monitor successor subsets are accepted. Revoked M1 cannot reappear in successor evidence.

A valid signed same-parent successor split view is rejected fail-closed. The predecessor RUST-074 bundle cannot replay as a RUST-075 successor bundle. Non-canonical evidence, quorum downgrade, duplicate/unsorted signers, unknown signers, signature mutation, target substitution, set substitution, revocation omission, and production-boundary mutations are rejected.

The detached selftest exercises 3/3 predecessor authorization availability, 3/3 successor availability, and 48/48 fail-closed cases covering the complete rotation/successor target, authorization envelope, monitor sets, replay, non-canonical evidence, and valid signed same-parent fork substitution.

Deterministic TEST private monitor seeds remain producer-side only. The detached verifier and selftest contain no private signing or network capability. Workflow evidence remains read-only, manifest-bounded, verifier-only, and runs with `env -i` plus `/usr/bin/python3 -S`.

This TEST-only layer does **not** introduce global network gossip, production monitor administration/signing, durable publication, key custody, HSM/TPM use, OIDC, release/deployment authority, anti-rollback policy, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
