# RUST-017 — Detached Git commit/tree proof for signed build inputs

RUST-017 closes the next explicit limitation in the native release-security rehearsal. RUST-016 proves that the eleven supplied source/build-policy files match the SHA-256 values authenticated by the RUST-014 attestation, but the detached consumer still treated the provenance `source.commit` value as a signed claim rather than independently proving that those exact files are reachable from that Git commit.

This checkpoint adds the minimum Git object material required to prove that relationship offline, without copying `.git` and without invoking Git in the detached verifier.

RUST-017 remains TEST-ONLY hardening. It does not publish artifacts, introduce production signing, request OIDC, or route production consensus to Rust.

## Detached bundle

RUST-017 extends the RUST-016 detached bundle. It contains exactly 25 regular files:

- the RUST-015 detached reproducibility verifier;
- the RUST-016 detached signed build-input verifier;
- `rust_017_offline_git_tree_verify.py`;
- two byte-identical portable wheels;
- canonical reproducibility provenance and TEST-ONLY attestation envelope;
- the exact eleven signed source/build-policy inputs below `source-inputs/`;
- `git-objects/commit.object` containing the raw claimed Git commit payload;
- exactly six raw Git tree objects below `git-objects/trees/`.

The six tree objects are the minimal path closure needed for the signed build-input set:

- the commit root tree;
- `.github`;
- `.github/workflows`;
- `native`;
- `native/axven_native`;
- `native/axven_native/src`.

No `.git` directory is copied. The producer workflow uses the checked-out repository only to export raw objects into the detached bundle. The detached verifier itself has no Git executable dependency.

## Layered proof

RUST-017 first requires the complete RUST-016 verification chain to pass. Therefore the consumer already knows that:

- the RUST-014 provenance and envelope are canonical and signature-valid under the pinned TEST-ONLY Ed25519 trust root;
- the two portable wheels are byte-for-byte reproducible and match the signed artifact evidence;
- wheel ZIP/source-epoch policy is valid;
- `production_consensus` is `python`;
- the exact eleven `build_inputs` claims are present;
- each supplied source/build-policy file has the exact signed SHA-256 digest.

RUST-017 then independently verifies Git object linkage.

## Git object verification

The detached verifier implements the relevant Git object format directly with the Python standard library. It does not execute `git`.

For the supplied raw commit payload it recomputes the historical Git object identifier as:

`SHA-1("commit " || decimal_length || NUL || commit_payload)`

and requires exact equality with the signed provenance `source.commit` claim.

The verifier parses the commit header, obtains its root tree object identifier, and also parses the committer timestamp. The timestamp must equal the signed `source_date_epoch` value used by the reproducible-build policy.

Each supplied raw tree object is independently identified as:

`SHA-1("tree " || decimal_length || NUL || tree_payload)`

and its computed object identifier must equal the object identifier encoded in its filename.

The verifier parses Git's raw binary tree-entry format and walks every one of the eleven signed repository-relative paths from the commit root. Intermediate entries must be tree objects; terminal entries must be regular-file blobs rather than symlinks, submodules, or directories.

For every terminal source input, the verifier computes the historical Git blob identifier:

`SHA-1("blob " || decimal_length || NUL || file_bytes)`

and requires it to equal the blob object identifier referenced by the verified tree path.

All six supplied tree objects must be reached while walking the signed input paths. Missing, unused, malformed, renamed, tampered, or symlinked Git object files are rejected.

## SHA-1 scope

GitHub's repository object identifiers for this repository use Git's historical SHA-1 object format. RUST-017 therefore necessarily recomputes SHA-1 to prove commit/tree/blob graph linkage.

RUST-017 does **not** rely on SHA-1 alone for source-content integrity. The same eleven file byte streams have already been independently recomputed with SHA-256 by RUST-016 and authenticated by the RUST-014 Ed25519-signed provenance. The Git SHA-1 graph proof is an additional repository-membership/linkage proof layered on top of that SHA-256 content binding.

## Fail-closed mutation contract

The detached self-test requires ten rejection classes:

1. raw commit-object byte mutation;
2. commit-object symlink substitution;
3. raw tree-object byte mutation;
4. missing required tree object;
5. extra otherwise-valid tree object;
6. tree-object symlink substitution;
7. signed source-input byte mutation;
8. signed source-input path relocation;
9. signed `source.commit` claim mutation;
10. signed `source_date_epoch` claim mutation.

The original wheels, evidence, source-input tree, and Git-object bundle must remain unchanged and verify again after the mutation suite.

## Producer versus consumer boundary

The CI producer side may use `git cat-file`, `git rev-parse`, and `git hash-object` to export and sanity-check the raw object material from the exact checked-out source SHA. This is producer tooling only.

The detached RUST-017 consumer runs under `env -i` and imports only the earlier detached RUST-015/RUST-016 consumer verifiers. It has no Axven production import, RUST-014 producer import, Git command invocation, subprocess dependency, Docker dependency, GitHub environment dependency, or HTTP/network client.

## Privilege and consensus boundary

The workflow remains `contents: read` only. RUST-017 does not upload an Actions artifact, publish a package, create a GitHub Release, request `id-token: write`, write GitHub attestations, use production signing credentials, push containers, deploy code, or enable production Rust routing.

Production remains Python-authoritative. No production file or chain/genesis/monetary/P2P/SMT/PQ/ML-DSA/wallet/signature acceptance rule is changed by this checkpoint.
