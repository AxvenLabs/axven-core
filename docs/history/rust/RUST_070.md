# RUST-070 — TEST-ONLY monitor-rotation-journal checkpoint observation

RUST-070 composes the exact reviewed RUST-069 append-only checkpoint-monitor rotation journal verifier and adds a detached TEST-only multi-observer observation layer over its final checkpoint.

Three deterministic TEST-only observer identities independently report the exact RUST-069 final monitor-rotation-journal checkpoint. Acceptance requires at least 2-of-3 distinct valid Ed25519 reports. The availability contract accepts all 3/3 valid two-observer subsets.

Every report binds the exact final checkpoint SHA-256 and checkpoint-statement SHA-256, final monitor-set sequence/digest, entry count, journal digest, head-entry digest, previous-checkpoint digest, the exact monitored checkpoint and monitored-checkpoint-statement digests inherited by RUST-069, the complete inherited observed-target digest, activation source commit, and `production=false`.

The canonical RUST-069 final checkpoint is first revalidated through the full reviewed RUST-069 verifier chain. Observation does not replace or weaken the underlying 2-of-3 M3/M4/M5 final checkpoint signatures.

A valid signed report for a distinct checkpoint with the same monitor-set sequence and same previous-checkpoint parent is treated as an observed split view and rejected fail-closed, even when two other observers report the canonical checkpoint. This strict rule favors split-view safety over availability.

The detached verifier and selftest contain no private signing or network capability. Deterministic TEST private Ed25519 seeds exist only in the producer fixture and are checked against reviewed public-key pins.

This TEST-only evidence does **not** create global network gossip, independent observer administration, durable publication, production signing, key custody, HSM/TPM use, OIDC, release/deployment authority, anti-rollback policy, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
