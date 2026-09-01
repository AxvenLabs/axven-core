# RUST-011 — Keyless identity acceptance policy rehearsal

RUST-011 defines and tests the **identity acceptance policy** that a future keyless native-artifact attestation verifier would apply *after* cryptographic verification of a GitHub Actions OIDC/Sigstore identity.

This checkpoint does **not** request an OIDC token, verify a live JWT, publish an attestation, contact a transparency log, upload an artifact, create a release, or route production consensus through Rust.

## Why this checkpoint exists

RUST-010 locked the canonical offline envelope and fail-closed trust-root separation using an explicitly TEST-ONLY Ed25519 key. Before authorizing a real keyless attestation workflow, Axven needs a separately reviewable answer to a different question: **which GitHub workflow identity would be trusted?**

The future cryptographic mechanism and this authorization policy are intentionally separated. A JSON object that merely contains GitHub-shaped claims is not authentication. RUST-011 only tests policy evaluation over already-authenticated/normalized claims.

## Pinned identity policy

The rehearsal policy requires:

- issuer: `https://token.actions.githubusercontent.com`;
- repository: `AxvenLabs/axven-core`;
- immutable repository id: `1331369066`;
- repository owner: `AxvenLabs`;
- immutable owner id: `257053129`;
- repository visibility: `public`;
- runner environment: `github-hosted`;
- ref: `refs/heads/main`;
- ref type: `branch`;
- event: `workflow_dispatch`;
- subject: `repo:AxvenLabs/axven-core:ref:refs/heads/main`;
- workflow ref: `AxvenLabs/axven-core/.github/workflows/native-keyless-attestation.yml@refs/heads/main`;
- workflow SHA: exactly the 40-hex source commit being authorized.

Extra authenticated claims are allowed because real GitHub OIDC tokens contain additional metadata. Missing required claims, type changes, or any mismatch in the values above fail closed.

The audience is deliberately **not** authorized in RUST-011. The eventual signing/attestation mechanism may select a mechanism-specific audience. Choosing and validating that audience belongs to the later cryptographic activation checkpoint and must be reviewed together with the selected signer/verifier implementation.

## Mutation contract

The self-test accepts one canonical synthetic policy fixture and then must reject changes to:

1. issuer;
2. repository name;
3. repository id;
4. repository owner;
5. repository owner id;
6. repository visibility;
7. runner environment;
8. ref;
9. ref type;
10. event name;
11. subject;
12. workflow ref/path;
13. workflow SHA/source binding;
14. a missing required claim;
15. a claim type substitution.

It also proves that a benign extra authenticated claim does not change acceptance.

## Privilege and publication boundary

The dedicated RUST-011 workflow keeps `permissions: contents: read`. It must not contain `id-token: write`, `attestations: write`, `packages: write`, `contents: write`, artifact upload, attestation publication, package publication, release creation, or deployment steps.

The future activation path `.github/workflows/native-keyless-attestation.yml` is intentionally absent in RUST-011. Creating that workflow and granting OIDC/attestation privileges is a separate explicit checkpoint.

## Consensus boundary

Production `expected_state_root()`, `_transition()`, `_apply_forward()`, block validation, mining, reorg, replay, persistence, RPC, P2P, wallet behavior, ML-DSA, and signature acceptance remain unchanged and Python-authoritative.

No chain identity, genesis, reward/monetary rule, P2P protocol, SMT/PQ activation height, ML-DSA behavior, wallet-key semantics, transaction/block signature-acceptance semantics, release publication, or production Rust routing changes in RUST-011.
