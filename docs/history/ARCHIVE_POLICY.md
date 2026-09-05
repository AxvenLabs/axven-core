# Axven history archive policy

`docs/history/` stores completed historical checkpoint material without changing the behavior or authority of the contracts those checkpoints introduced.

## Safe archive candidates

A document is a candidate for archival only when it is historical, no longer the canonical operational instruction, and all path-sensitive references are known.

Moving a path-sensitive document must be atomic with every workflow, verifier, policy, script, manifest, or documentation reference that depends on its exact path.

## Keep out of the archive by default

Do not move these classes of files without a separate dependency review:

- activation or pre-activation instructions;
- canonical operations or canonical operation records;
- release-manifest-bound material;
- current audit or security-gate documents;
- contribution, changelog, explorer, deployment, publication, or other current operational documentation.

## Safety boundary

Archival work must not change production code, consensus or state-transition rules, chain identity, genesis, monetary rules, P2P behavior, cryptographic acceptance, signing or key-custody policy, deployment, publication privileges, or production routing.

Production consensus remains Python-authoritative unless a separate explicitly approved change says otherwise.
