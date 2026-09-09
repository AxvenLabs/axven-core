# RUST-082 — TEST-ONLY RUST-081 observer-rotation-journal checkpoint monitoring

RUST-082 composes the exact reviewed RUST-081 append-only observer rotation journal verifier and adds an independent detached TEST-only monitor quorum over its final signed checkpoint.

Three deterministic TEST-only monitors M1/M2/M3 are pinned by public key. The canonical monitor bundle requires 2-of-3 signatures, and all 3/3 valid two-monitor subsets must verify independently.

Each signed monitor statement binds the exact RUST-081 final checkpoint SHA-256, exact checkpoint-statement SHA-256, observer-set sequence and digest, entry count, journal digest, head-entry digest, previous-checkpoint digest, the underlying observed checkpoint and statement digests, observed-target digest, activation source commit, and `production=false`.

A valid signed RUST-081 same-parent checkpoint fork can be recognized as evidence, but substituting that fork evidence into the canonical monitor bundle is rejected fail-closed. RUST-081 checkpoint replay, non-canonical monitor evidence, quorum downgrade, duplicate/unsorted monitor identities, signature mutation, unknown monitors, and mutation of any canonical target field are rejected.

The detached selftest requires 3/3 two-monitor availability and 27/27 expected fail-closed cases. Deterministic private seeds exist only in the TEST-only producer fixture; verifier and selftest code have no signing or network capability.

The workflow uses read-only repository permissions, disables persisted checkout credentials, makes generated evidence read-only, stages a verifier-only detached consumer, fixes the complete evidence path manifest, and verifies under `env -i` with `/usr/bin/python3 -S`.

No production monitor administration, durable publication, network gossip, key custody, HSM/TPM integration, OIDC, release/deployment authority, consensus change, or production Rust routing is introduced.

Production consensus remains Python-authoritative.
