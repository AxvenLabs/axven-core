# RUST-078 — TEST-ONLY observer quorum for the RUST-077 monitor rotation journal checkpoint

RUST-078 composes the exact reviewed RUST-077 append-only checkpoint-monitor rotation journal verifier and adds an independent detached TEST-only observer quorum over its final signed checkpoint.

Three deterministic TEST-only observer identities O1/O2/O3 independently report the exact canonical RUST-077 final monitor-rotation-journal checkpoint. Acceptance requires at least 2-of-3 distinct valid Ed25519 observer reports, and all 3/3 valid two-observer subsets are accepted.

Every observer statement binds the exact RUST-077 final checkpoint SHA-256 and checkpoint-statement SHA-256, final monitor-set sequence and digest, entry count, journal SHA-256, head-entry SHA-256, previous-checkpoint SHA-256, monitored RUST-073 checkpoint and statement digests, inherited observed-target digest, activation source commit, and `production=false`.

The complete reviewed RUST-077 verifier chain is executed first. The underlying M3/M4/M5 2-of-3 final journal-checkpoint signatures are therefore revalidated before observer evidence can be accepted; observation does not replace or weaken the monitor checkpoint quorum.

If a validly signed RUST-077 checkpoint shares the canonical monitor-set sequence and previous-checkpoint parent but has a different target, signed observer evidence for that fork can be recognized as a cross-observer split view. Such a mixed bundle is never accepted as the canonical RUST-078 bundle and is rejected fail-closed.

The detached selftest exercises all 3/3 valid two-observer subsets and 25/25 fail-closed cases covering threshold downgrade, below-threshold evidence, duplicate or unsorted observers, unknown observer, signature mutation, production-boundary violations, schema/algorithm mutation, source/sequence/parent substitution, every canonical checkpoint target digest and count, non-canonical evidence, and valid signed same-parent fork substitution.

Deterministic TEST private observer seeds exist only in the producer fixture. The detached verifier and selftest contain no private signing or network capability. Workflow evidence is read-only, manifest-bounded, verifier-only, and executed with `env -i` plus `/usr/bin/python3 -S`.

This TEST-only layer does **not** create global network gossip, production observer administration/signing, durable publication, key custody, HSM/TPM use, OIDC, release/deployment authority, anti-rollback policy, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
