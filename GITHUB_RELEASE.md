# Axven Core v0.9.0 Canonical Devnet

Tag: `v0.9.0-devnet`

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

Run release verification **before setup, dependency installation, or first
launch**, from a freshly extracted package. The authenticated manifest is also
the allow-list for active/runtime payload. Verification rejects unmanifested
Python modules, launchers, binaries, runtime/config data, virtual environments,
and filesystem indirection such as symlinks. Inert Markdown documentation and
repository-host metadata may remain outside the manifest.

This prevents an archive mirror or transport layer from appending an extra
active file (for example `sitecustomize.py`, a launcher, a DLL/PYD, or an
`axven-data` configuration) while leaving every authenticated Axven file and the
external manifest digest unchanged.

Important:
- This is a **devnet preview**, not mainnet.
- No independent third-party security audit has been completed.
- RPC and explorer default to loopback.
