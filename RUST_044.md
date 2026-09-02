# RUST-044 — TEST-only multi-step monitor-set rotation continuity

RUST-044 extends reviewed RUST-043 with a second deterministic TEST-only monitor-key rotation:

**M1/M2/M3 -> M2/M3/M4 -> M3/M4/M5**

The second transition is sequence/epoch 2, uses the exact predecessor M2/M3/M4 set for 2-of-3 authorization, and records cumulative revocation `[M1, M2]`. It binds the exact RUST-043 first rotation SHA-256, first rotation-authorization SHA-256, first successor-monitor-bundle SHA-256, canonical RUST-041 checkpoint SHA-256, activation source commit, final monitor-set digest, and `production=false`.

Final monitoring uses a distinct v3 schema/domain. All 3/3 predecessor two-monitor authorization subsets and all 3/3 final two-monitor report subsets are accepted. RUST-043 v2 successor evidence cannot replay as v3 final evidence, and a valid signed same-parent final monitor split view fail-closes.

This remains TEST-only. It does not create independent monitor administration, durable gossip/transport, transparency publication, real compromise recovery, HSM/TPM custody, production anti-rollback, or production Rust routing. Production consensus remains Python-authoritative.
