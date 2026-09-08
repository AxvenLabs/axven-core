# RUST-062 — TEST-ONLY observer-rotation-journal monitor-rotation-journal checkpoint observation

RUST-062 composes the exact reviewed RUST-061 observer-rotation-journal monitor rotation journal verifier and adds a detached TEST-only multi-observer observation layer over its final checkpoint.

Three deterministic TEST-only observer identities independently report the exact RUST-061 final monitor-rotation-journal checkpoint. Acceptance requires at least 2-of-3 distinct valid Ed25519 reports. Every report binds the exact checkpoint SHA-256, checkpoint-statement SHA-256, final monitor-set sequence/digest, entry count, journal digest, head-entry digest, previous-checkpoint digest, exact RUST-057 observer-rotation-journal checkpoint and statement digests, the complete inherited observed-target digest, activation source commit, and `production=false`.

The canonical RUST-061 final checkpoint is first revalidated through the full reviewed RUST-061 verifier chain. Observation does not replace or weaken the underlying 2-of-3 final M3/M4/M5 monitor checkpoint signatures.

A valid signed report for a distinct checkpoint with the same monitor-set sequence and same previous-checkpoint parent is treated as an observed split view and rejected fail-closed, even when two other observers report the canonical checkpoint. This strict rule favors split-view safety over availability.

The availability contract accepts all 3/3 valid two-observer subsets. The detached verifier and selftest contain no private signing or network capability. Deterministic TEST private Ed25519 seeds exist only in the producer fixture and are checked against the reviewed public-key pins.

This TEST-only evidence does **not** create global network gossip, independent observer administration, durable publication, production signing, key custody, HSM/TPM use, OIDC, release/deployment authority, anti-rollback policy, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
