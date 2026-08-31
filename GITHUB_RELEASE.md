# Axven Core v0.9.0 Canonical Devnet

Release tag: `<NEW_UNPUBLISHED_TAG>`

Historical public tag: `v0.9.0-devnet` — **legacy pre-hardening preview; MUST NOT be reused or moved**.

Status: **Canonical devnet preview**

This release is the first GitHub-ready Axven Core package built on the
activated `axven-devnet-2` network identity.

Canonical identity:
- chain_id: `axven-devnet-2`
- fingerprint: `ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae`
- genesis: `a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3`

Validated on the real Windows host:
- full validation: `ALL AXVEN CHECKS GREEN`
- real ML-DSA / M-H path
- wallet integration
- daemon / persistence / RPC / P2P
- two-node fork/reorg/reconnect
- canonical activation audit
- canonical block #1 operation/persistence

## Release tag and commit provenance

The historical `v0.9.0-devnet` tag points to the original August 2026 devnet
preview and predates the current release-authenticity hardening. Preserve it as
history. Do not delete it, force-move it, or reuse the same name for a hardened
package.

For every new public release, first fetch canonical tags, choose a **new** tag
name, and run from the exact clean release commit:

`git fetch origin --tags`

`python release_provenance.py prepare <NEW_UNPUBLISHED_TAG>`

Preparation fails closed if the tag already exists locally or on canonical
origin, if the tracked checkout is dirty, if the repository origin is not
AxvenLabs/axven-core, or if the historical `v0.9.0-devnet` name is supplied.
Record both values printed by the tool:

`release commit SHA: <PASTE FINAL 40-HEX COMMIT SHA HERE>`

`release_manifest.json SHA-256: <PASTE FINAL 64-HEX SHA-256 HERE>`

Create an **annotated** tag at that exact commit and push it without `--force`.
A normal push must fail rather than rewrite an existing release tag:

`git tag -a <NEW_UNPUBLISHED_TAG> <RELEASE_COMMIT_SHA> -m "Axven canonical devnet release"`

`git push origin refs/tags/<NEW_UNPUBLISHED_TAG>`

After the push, verify the local annotated tag object, its commit target, the
manifest stored at the tag, and the remote tag object all agree:

`python release_provenance.py verify <NEW_UNPUBLISHED_TAG> <RELEASE_COMMIT_SHA> <TRUSTED_RELEASE_MANIFEST_SHA256>`

Do not publish the GitHub release until this command reports
`Release provenance: GREEN`.

## Release authenticity trust anchor

Before publishing a public release, compute the SHA-256 of the final
`release_manifest.json` from the exact release commit and paste that digest into
the **GitHub release body**. The published digest is a trust anchor and MUST NOT
be sourced from the downloaded release archive or from another file bundled
inside that archive.

Release body fields:

`release commit SHA: <PASTE FINAL 40-HEX COMMIT SHA HERE>`

`release_manifest.json SHA-256: <PASTE FINAL 64-HEX SHA-256 HERE>`

A downloader must first obtain that 64-hex digest from the canonical AxvenLabs
GitHub release page, independently compare it with the downloaded
`release_manifest.json`, and then run:

`python verify_release.py <TRUSTED_RELEASE_MANIFEST_SHA256>`

On Windows, the independent manifest digest can be computed with:

`(Get-FileHash .\release_manifest.json -Algorithm SHA256).Hash.ToLower()`

On Linux, use `sha256sum release_manifest.json`; on macOS, use
`shasum -a 256 release_manifest.json`.

`verify_release.py` deliberately fails closed when the external trust anchor is
missing, malformed, or different from the downloaded manifest. A digest copied
from inside the same release package is not an authenticity check.

## Release payload inventory

Do **not** publish a repository checkout, GitHub source archive, or an existing
working directory as the verified Axven release asset. From the exact validated
release commit, create a new staging directory with:

`python build_release_package.py <NEW_EMPTY_OUTPUT_DIRECTORY>`

The output directory must not already exist. The builder first verifies every
source file against `release_manifest.json`, then copies only those authenticated
files plus the manifest into a clean staging tree, and finally runs the release
verifier on that tree. The SHA-256 printed by the builder is the manifest digest
to publish in the canonical GitHub release body after independent comparison
with the exact release commit.

A downloader must run release verification **before setup, dependency
installation, validation, or first launch**, from the freshly extracted staged
release asset. The manifest defines the exact file inventory: a **single extra
file**, symlink, or special filesystem entry causes verification to fail. There
is no extension-based or documentation-based exception.

This prevents an archive mirror or transport layer from appending an extra
payload such as `sitecustomize.py`, a prebuilt `.venv`, a launcher, DLL/PYD, or
`axven-data` configuration while leaving every authenticated Axven file and the
external manifest digest unchanged.

Important:
- This is a **devnet preview**, not mainnet.
- No independent third-party security audit has been completed.
- RPC and explorer default to loopback.