# Contributing

Before proposing changes:

1. Do not silently alter canonical `axven-devnet-2` consensus parameters.
2. Consensus-incompatible work requires a separately versioned network/decision.
3. Add executable tests before changing consensus-critical behavior.
4. Keep authorization tests and full pipeline/integration tests distinct.
5. Run `run_full_validation.py` before submitting a release candidate.

Non-consensus UX, documentation, explorer, and tooling changes should still
preserve the pinned chain identity and pass post-activation audits.
