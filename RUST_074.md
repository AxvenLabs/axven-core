# RUST-074 — TEST-ONLY RUST-073 observer-rotation-journal checkpoint monitoring

RUST-074 composes the exact reviewed RUST-073 append-only observer rotation journal verifier and adds an independent detached TEST-only monitor quorum over its final signed checkpoint.

Three deterministic TEST-only monitor identities M1/M2/M3 independently sign the exact canonical RUST-073 final observer-rotation-journal checkpoint target. Acceptance requires at least 2-of-3 distinct valid Ed25519 monitor reports, and all 3/3 valid two-monitor subsets are accepted.

Each monitor statement binds the exact RUST-073 final checkpoint SHA-256 and checkpoint-statement SHA-256, observer-set sequence and digest, journal entry count, journal SHA-256, head-entry SHA-256, previous-checkpoint SHA-256, exact inherited RUST-069 monitor-rotation-journal checkpoint and statement digests, the complete inherited observed-target digest, activation source commit, and `production=false`.

The complete reviewed RUST-073 verifier chain is executed first. The underlying O3/O4/O5 2-of-3 final checkpoint signatures are therefore revalidated before any monitor bundle can be accepted; monitoring does not replace or weaken the observer checkpoint quorum.

If a validly signed RUST-073 checkpoint shares the canonical observer-set sequence and previous-checkpoint parent but has a different target, signed monitor evidence for that fork can be recognized as observed fork evidence. Such a mixed/split-view monitor bundle is never accepted as the canonical RUST-074 bundle and is rejected fail-closed. Split-view safety remains stronger than availability.

The detached selftest exercises all 3/3 valid two-monitor subsets and 27/27 fail-closed cases covering bundle/report/statement schemas, threshold downgrade, below-threshold evidence, duplicate or unsorted monitors, production boundary violations, unknown monitor and signature mutation, all 12 canonical target fields, non-canonical evidence, RUST-073 checkpoint replay, and a valid signed same-parent fork bundle.

Deterministic TEST private monitor seeds exist only in the producer fixture. The detached verifier and selftest contain no private signing or network capability. Workflow evidence is read-only, manifest-bounded, verifier-only, and executed with `env -i` plus `/usr/bin/python3 -S`.

This TEST-only layer does **not** create global network gossip, production monitor administration/signing, durable publication, key custody, HSM/TPM use, OIDC, release/deployment authority, anti-rollback policy, consensus change, or production Rust routing.

Production consensus remains Python-authoritative.
