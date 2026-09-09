# RUST-071 — TEST-ONLY monitor-rotation-journal observer-set rotation continuity

RUST-071 composes the exact reviewed RUST-070 monitor-rotation-journal checkpoint observation verifier and adds deterministic TEST-only observer-set rotation/revocation continuity.

The observer administration transition is `O1/O2/O3 -> O2/O3/O4`. O1 is explicitly revoked. The predecessor O1/O2/O3 set must authorize the rotation with at least 2-of-3 distinct valid Ed25519 signatures, and all 3/3 valid two-observer authorization subsets are accepted.

The rotation binds the exact predecessor RUST-070 observation-bundle SHA-256, predecessor/successor observer-set digests, revocation list, and every field in the complete inherited RUST-070 canonical checkpoint target: checkpoint and checkpoint-statement SHA-256, monitor-set sequence/digest, entry count, journal/head/parent digests, monitored checkpoint and monitored-checkpoint-statement digests, observed-target digest, activation source commit, and `production=false`.

Successor observation statements add observer-set sequence/digest and carry that complete canonical target unchanged. Acceptance requires at least 2-of-3 distinct valid O2/O3/O4 reports, and all 3/3 valid two-observer successor subsets are accepted. Revoked O1 cannot reappear.

A valid signed successor report describing a distinct checkpoint with the same monitor-set sequence and same previous-checkpoint parent is rejected fail-closed as a split view, even when other successor observers report the canonical checkpoint. Split-view safety remains preferred over availability.

Deterministic TEST private Ed25519 seeds remain producer-side only. Detached verifier/selftest code has no signing or network capability. The workflow is read-only, manifest-bounded, credentialless after checkout, and non-publishing.

This TEST-only evidence does not create global network gossip, production observer administration/signing, durable publication, key custody, HSM/TPM use, OIDC, release/deployment authority, anti-rollback policy, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
