# RUST-014 — Reproducibility-bound signed provenance rehearsal

RUST-014 binds the RUST-013 reproducible-build result into a separate canonical, TEST-ONLY signed provenance format. It does not mutate the existing RUST-011 portable provenance schema or the RUST-012 detached-consumer format.

The checkpoint answers one narrow question: after two isolated manylinux builds of the same exact source have produced byte-identical portable wheels, can that reproducibility result itself be represented as strict canonical evidence and cryptographically bound to the source, builder policy, artifact, deterministic epoch, and exact build inputs?

## Producer contract

CI checks out one exact Axven source SHA and derives `SOURCE_DATE_EPOCH` from that commit's recorded Unix timestamp. The existing RUST-013 workflow then creates build A and build B in separate manylinux container invocations, with separate compiled target directories, tool-install directories, and wheel output directories.

RUST-014 runs only after the existing RUST-013 byte-reproducibility contract and both RUST-009 portable-wheel checks have passed.

The producer requires both wheelhouses to contain exactly the canonical portable wheel:

`axven_native-0.1.0-cp313-abi3-manylinux_2_28_x86_64.whl`

Both wheel files must be regular non-symlink files and must have identical SHA-256, byte length, and complete bytes.

## Canonical reproducibility provenance

The new provenance schema is:

`axven-native-reproducible-provenance-v1`

It binds:

- repository `AxvenLabs/axven-core` and the exact checked-out source commit;
- the source-derived `SOURCE_DATE_EPOCH`;
- immutable manylinux builder image digest;
- `manylinux_2_28` / `x86_64`;
- builder CPython `3.13.13`, Rust `1.98.0`, maturin `1.15.0`, and PyO3 `0.29.2`;
- deterministic environment controls used by RUST-013;
- the canonical wheel filename, SHA-256, and byte length;
- build A and build B SHA-256 and byte length;
- explicit `byte_identical: true` and `build_count: 2` claims;
- SHA-256 hashes of the exact native/build/policy inputs used by this checkpoint;
- `production_consensus: python`.

The provenance must be canonical JSON: sorted keys, compact separators, UTF-8, and exactly one trailing newline.

## TEST-ONLY attestation envelope

RUST-014 uses a new, domain-separated TEST-ONLY Ed25519 trust root so the reproducibility statement cannot be confused with the RUST-011 portable-candidate envelope.

- envelope schema: `axven-native-reproducible-attestation-envelope-v1`;
- payload type: `application/vnd.axven.native-reproducible-provenance.v1+json`;
- algorithm: `ed25519`;
- key id: `rust-014-test-only-ed25519-v1`;
- domain: `AXVEN_NATIVE_REPRODUCIBLE_ATTESTATION_V1\0`.

The signature authenticates both the exact canonical policy header and the exact canonical provenance bytes using length-delimited framing.

The private seed is deliberately committed and TEST-ONLY. Passing this checkpoint is therefore evidence-format and binding validation, not production release authentication.

## Fail-closed mutation contract

The self-test requires rejection of mutations to:

1. artifact digest;
2. reproducibility epoch;
3. build-B evidence digest;
4. immutable builder image;
5. signature bytes;
6. key id;
7. embedded attacker-supplied trust root;
8. non-canonical envelope encoding.

The original provenance and envelope must remain byte-identical after the mutation suite and must verify again.

## Publication and privilege boundary

The workflow remains `contents: read` only. RUST-014 does not upload either wheel or either evidence file as an Actions artifact, publish a package, create a GitHub Release, request an OIDC token, write a GitHub attestation, push a container image, deploy code, or write a transparency log.

A protected production signing root, release publication, transparency logging, and production Rust routing remain separate explicit approval gates.

## Consensus boundary

Production remains Python-authoritative. No production file imports or routes to `axven_native`, and no chain identity, genesis, reward/monetary rule, P2P protocol, SMT/PQ activation, ML-DSA behavior, wallet-key semantics, or transaction/block signature-acceptance rule changes in RUST-014.
