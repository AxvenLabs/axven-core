# Axven Core v0.9.0 Canonical Devnet

Planned tag: `v0.9.0-devnet.1`

Status: **Canonical devnet preview**

This release is the next GitHub-ready Axven Core package built on the
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

## Legacy release quarantine

The historical prerelease tag `v0.9.0-devnet` resolves to commit
`2c144be2a1139cc3253ef98bac05d7acef2485b6`. It predates the SEC-205 external
manifest trust anchor and the SEC-207 exact staged-payload inventory. It is a
legacy/superseded release record and MUST NOT be treated as the current hardened
Axven package or used as the tag for a new release.

The legacy tag is historical evidence: **never retarget, delete, or reuse it** to
make newer code appear under the old release identity. Every hardened release
must use a fresh previously-unused tag. The release tag must resolve exactly to
the fully validated source commit before the GitHub release is published, and
the GitHub release must continue to identify that same immutable tag/commit.

For the next preview, `v0.9.0-devnet.1` is reserved by this release plan. Before
creating it, verify that the tag does not already exist and record the exact
validated commit SHA. If the tag already exists, stop and choose a new tag rather
than moving it.

## Release authenticity trust anchor

Before publishing a public release, compute the SHA-256 of the final
`release_manifest.json` from the exact release commit and paste that digest into
the **GitHub release body**. The published digest is a trust anchor and MUST NOT
be sourced from the downloaded release archive or from another file bundled
inside that archive.

Release body field:

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
