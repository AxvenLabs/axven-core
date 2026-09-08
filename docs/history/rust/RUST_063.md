# RUST-063 — TEST-ONLY monitor-rotation-journal observer-set rotation continuity

RUST-063 extends the reviewed RUST-062 monitor-rotation-journal checkpoint observation layer with deterministic TEST-only observer-set rotation and revocation continuity.

The predecessor observer set is **O1/O2/O3** with threshold 2. The successor transition is **O1/O2/O3 -> O2/O3/O4**. **O1 is revoked** and cannot authorize or appear in the successor set. The rotation payload itself is authorized by at least 2-of-3 members of the exact predecessor set, and all 3/3 valid two-observer authorization subsets are exercised.

The rotation binds the **exact RUST-062 predecessor observation bundle**, the exact RUST-061 final monitor-rotation-journal checkpoint SHA-256, the exact checkpoint-statement SHA-256, and the activation source commit. Successor observation statements additionally carry the complete inherited RUST-062 canonical target: monitor-set sequence and digest, journal entry count, journal/head/parent digests, observer-rotation-journal checkpoint and checkpoint-statement digests, the observed-target digest, and the activation source commit.

Successor observation uses a fresh v2 domain/schema and the O2/O3/O4 observer set at sequence 1. Every 2-of-3 successor availability subset is accepted. Duplicate, unsorted, unknown, revoked, below-threshold, replayed, non-canonical, source-mismatched, inherited-target-mismatched, signature-mutated, production-marked, and same-parent fork evidence is rejected fail-closed. A valid signed same-parent fork is intentionally generated as TEST evidence and rejected by canonical successor validation, preserving **split-view safety over availability**.

The fixture is the only component containing deterministic TEST private seeds. Detached verifier and selftest code contain no private signing or network capability. CI checks out the exact PR head with persisted credentials disabled, installs only the hash-locked producer dependency, makes evidence read-only, stages a detached consumer without the fixture or `.git`, and verifies it with a scrubbed environment and `/usr/bin/python3 -S`.

This layer does not create global network gossip, OIDC, artifact publication, release or deployment behavior, production signing, HSM/TPM custody, production anti-rollback, durable global state, consensus changes, or production Rust routing. `production=false` remains mandatory throughout. **Production consensus remains Python-authoritative.**
