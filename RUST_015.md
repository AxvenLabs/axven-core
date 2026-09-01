# RUST-015 — Detached offline reproducibility consumer

RUST-015 moves the RUST-014 reproducibility-bound evidence across a repository boundary.

The producer side has already proven that two isolated manylinux builds of one exact source revision emit byte-identical portable wheels and has bound that result into a canonical TEST-ONLY signed provenance envelope. RUST-015 asks whether a clean consumer can independently validate the supplied two-wheel evidence and the signed policy without a source checkout, Git metadata, GitHub runtime context, Docker, or network access.

## Detached bundle

The consumer bundle contains exactly these evidence objects:

- `rust_015_offline_repro_consumer_verify.py`
- `build-a/axven_native-0.1.0-cp313-abi3-manylinux_2_28_x86_64.whl`
- `build-b/axven_native-0.1.0-cp313-abi3-manylinux_2_28_x86_64.whl`
- `reproducible-provenance.json`
- `reproducible-attestation.json`

The verifier is intentionally self-contained apart from the already hash-locked `cryptography` runtime dependency. It does not import Axven production code, RUST-014 producer code, Git helpers, Docker helpers, HTTP clients, or environment-access modules.

CI copies only those five regular files into a clean temporary tree, asserts that no `.git` directory exists, and invokes the verifier under an `env -i` environment with only the Python executable path and UTF-8 controls preserved.

## Independent policy pins

The detached verifier independently pins the RUST-014 public verification policy:

- provenance schema `axven-native-reproducible-provenance-v1`;
- envelope schema `axven-native-reproducible-attestation-envelope-v1`;
- payload type `application/vnd.axven.native-reproducible-provenance.v1+json`;
- Ed25519 algorithm and key id `rust-014-test-only-ed25519-v1`;
- domain `AXVEN_NATIVE_REPRODUCIBLE_ATTESTATION_V1\0`;
- TEST-ONLY public key;
- repository identity;
- immutable manylinux image and exact builder/toolchain versions;
- deterministic environment controls;
- canonical wheel filename;
- exact build-input claim key set;
- `production_consensus: python`.

The envelope is not allowed to supply or override the trust root.

## Evidence the consumer recomputes

Unlike RUST-012, which consumes one portable wheel, RUST-015 receives both reproducibility candidates. The detached verifier independently recomputes and enforces:

- both inputs are regular, non-symlink files in distinct paths;
- both filenames are the canonical portable filename;
- build A SHA-256 and byte length;
- build B SHA-256 and byte length;
- complete byte-for-byte equality of A and B;
- artifact SHA-256 and byte length against the actual wheels;
- `build_count == 2` and `byte_identical == true`;
- build-A/build-B evidence values against the actual files;
- ZIP member timestamps against the signed `source_date_epoch` policy used by RUST-013;
- canonical provenance bytes;
- canonical envelope bytes;
- payload SHA-256;
- Ed25519 signature over the exact canonical header and exact canonical provenance payload.

The source commit timestamp itself and the contents of the named build-input source files cannot be re-derived without a source checkout. Those values remain authenticated signer claims. This limitation is explicit rather than silently presented as detached source reproducibility.

## Fail-closed mutation contract

The detached self-test requires rejection of:

1. build-B wheel byte mutation;
2. renamed/path-confused build-A wheel;
3. artifact digest mutation;
4. source epoch mutation;
5. `byte_identical` downgrade/substitution;
6. build-input claim-set mutation;
7. immutable builder-image substitution;
8. unexpected provenance field / embedded trust-root attempt;
9. non-canonical provenance;
10. signature mutation;
11. key-id substitution;
12. embedded envelope trust-root substitution;
13. non-canonical envelope.

After all mutations the original two wheels and both evidence files must remain byte-identical and verify again.

## Security and release boundary

RUST-015 is still an offline TEST-ONLY verification rehearsal. It does not publish either wheel or evidence file, upload an Actions artifact, create a release, request OIDC, write a GitHub attestation, use a production signing credential, push a package/container, deploy code, or enable production Rust routing.

A protected production release trust root, artifact publication, transparency logging, cross-provider reproducibility, and production Rust routing remain separate explicit approval gates.

## Consensus boundary

Production remains Python-authoritative. No production file imports or routes to `axven_native`, and no chain identity, genesis, monetary rule, P2P protocol, SMT/PQ activation, ML-DSA behavior, wallet-key semantics, or transaction/block signature-acceptance rule changes in RUST-015.
