# Root document retention guide

This note records documentation categories that should remain at the repository root by default during repository-layout cleanup.

The goal is to keep historical material organized without weakening discoverability or path stability for current operational and release-facing material.

## Keep at root by default

The following classes are intentionally excluded from automatic archival:

- activation and pre-activation records;
- canonical operations and canonical operation records;
- current audit, security-gate, rehearsal, or release-readiness documents;
- release-manifest-bound documentation and changelogs;
- contributor-facing and repository-entry documentation;
- explorer, deployment, publication, signing, key-custody, and other current operational guidance;
- any document referenced by active workflows, policy verifiers, scripts, manifests, or release tooling unless every path-sensitive reference can be reviewed and updated atomically.

Current examples include `CANONICAL_OPERATIONS.md`, `CANONICAL_OPERATION_RECORD.md`, `CD-003_ACTIVATION.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `DEVNET_REHEARSAL.md`, `EXPLORER.md`, and `FINAL_PRE_ACTIVATION_AUDIT.md`.

This list is illustrative rather than exhaustive. A file not listed here is not automatically safe to move.

## Move rule

Before moving any root document, perform a fresh dependency search on the exact current `main` revision. If an active workflow, verifier, policy, script, manifest, release process, deployment process, or publication process depends on the path, either update all references atomically from complete source content or leave the document in place.

Do not reconstruct or rewrite large path-sensitive files from truncated views.

Repository-layout cleanup must not change production code, consensus/state-transition behavior, chain identity, genesis, monetary rules, P2P behavior, cryptographic acceptance, signing or key custody, deployment, publication privileges, or production routing.

Production consensus remains Python-authoritative unless a separately reviewed and explicitly approved change says otherwise.
