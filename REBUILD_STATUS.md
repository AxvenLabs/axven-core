# Axven v0.9 Rebuild — Checkpoint 2

## Consensus restoration completed in this checkpoint

- `CHAIN_CONFIG` restored with `axven-devnet-2` and the preserved PQ/SMT schedule.
- `CONFIG_FINGERPRINT` restored exactly:
  `ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae`
- Canonical genesis hash restored exactly:
  `a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3`
- Target-based PoW and cumulative chainwork restored.
- Retarget math and Median-Time-Past contextual validation restored.
- Merkle transaction commitment restored.
- Transactional undo journal and heavier-chain reorg restored.
- Orphan pool / recursive orphan connection restored.
- 7 MiB serialized-block consensus cap restored.
- Legacy canonical sorted UTXO state-root restored.
- Sparse-Merkle reference root restored and height-gated at 10,000.
- Header `utxo_state_root` is checked after the state transition.
- StateStore replay binds chain id + config fingerprint + canonical genesis.
- Mempool remains intentionally in-memory only.

## Regression evidence

`python consensus_rebuild_test.py` passes 18 checks covering:
- fingerprint/genesis pins
- mined-block PoW
- cumulative chainwork
- legacy state-root/live UTXO equivalence
- full replay
- heavier-chain reorg and exact UTXO convergence
- test-only legacy→SMT boundary
- sparse reference root
- persistence roundtrip
- non-persisted mempool ground truth
- byte-cap rejection

`axven._selftest_consensus_restoration()` also passes an Ed25519-only
mine/spend/mempool/mine/replay/state-root-tamper smoke test.

## W-003 status

The surviving wallet integration contract is still blocked in this sandbox by the
absence of the real `dilithium-py` package. No fake or mock ML-DSA backend is used.
The project expects `dilithium-py==1.4.0`; the upstream API used is
`from dilithium_py.ml_dsa import ML_DSA_44` with keygen/sign/verify.

## Next checkpoint

1. Restore incremental Sparse Merkle live-state integration/proofs/compression.
2. Restore P2P with AXVN magic, config-fingerprint handshake, resource caps and
   malformed-wire hardening.
3. Re-run W-003 with the real ML-DSA dependency in the target environment.

Canonical activation remains NOT EXECUTED.


## Checkpoint 3 — Incremental SMT mirror + proofs

Status: GREEN (consensus activation unchanged).

Added:
- `SparseMerkleTree`: incremental insert/update/delete mirror storing only non-default nodes.
- `smt_verify_proof`: inclusion and non-inclusion proof verification.
- Reference oracle `smt_root_reference()` left unchanged.
- Property regression: every incremental mutation is checked against the full reference recompute.
- Proof tamper tests and deterministic rebuild/order-independence tests.

Verification in this checkpoint:
- `smt_incremental_test.py`: 231/231 GREEN.
- `consensus_rebuild_test.py`: all 18 checks GREEN.
- `axven.py selftest`: GREEN.
- 1,200-entry local benchmark: incremental single update ~0.327 ms vs reference recompute ~314.962 ms (~963.6x). Benchmark is environment-specific and not a consensus invariant.

Important:
- CD-003 activation remains NOT EXECUTED.
- `CHAIN_CONFIG`, `CONFIG_FINGERPRINT`, and canonical genesis identity were not changed.
- Incremental SMT is a parallel implementation; the full reference algorithm remains the correctness oracle.


## Checkpoint 4 — P2P identity + propagation + sync

Status: GREEN (activation unchanged).

Added `p2p.py`:
- length-prefixed bounded JSON transport;
- protocol/chain/config/genesis-bound handshake;
- clean mismatch rejection;
- tx propagation into the real mempool;
- block propagation into `Blockchain.add_block`;
- locator-based active-chain block sync;
- clean hostile-block rejection.

Verification:
- `p2p_spec_test.py`: 20/20 GREEN.
- `smt_incremental_test.py`: 231/231 GREEN.
- `consensus_rebuild_test.py`: all 18 checks GREEN.

Important:
- No `CHAIN_CONFIG` change.
- No genesis/fingerprint change.
- CD-003 activation remains NOT EXECUTED.


## Checkpoint 5 — Real TCP node lifecycle

Status: GREEN (activation unchanged).

Added:
- threaded `NodeServer` TCP listener;
- outbound `connect`/request helpers;
- reconnect-safe multi-round locator sync;
- real TCP tx and block propagation helpers;
- malformed-frame isolation;
- identity-mismatch isolation (bad peer does not poison listener).

Verification:
- `p2p_tcp_lifecycle_test.py`: 14/14 GREEN.
- `p2p_spec_test.py`: 20/20 GREEN.
- `consensus_rebuild_test.py`: 18/18 GREEN.
- `smt_incremental_test.py`: 231/231 GREEN.

No CHAIN_CONFIG/genesis/fingerprint changes. CD-003 remains NOT EXECUTED.


## Checkpoint 6 — Axven Core service + local RPC + CLI skeleton

Status: GREEN for the real Ed25519/N path; activation unchanged.

Added:
- `core.py`: one service object unifying Blockchain, Mempool, Wallet orchestration,
  mining, pending reservations, and P2P sync/server lifecycle.
- `rpc.py`: loopback-only JSON-RPC server (public bind intentionally rejected).
- `axven_core.py`: initial local CLI skeleton.
- Wallet secrets are never returned by RPC methods.

Verification:
- `core_rpc_test.py`: 23/23 GREEN.
- `p2p_tcp_lifecycle_test.py`: 14/14 GREEN.
- `p2p_spec_test.py`: 20/20 GREEN.
- `consensus_rebuild_test.py`: 18/18 GREEN.
- `smt_incremental_test.py`: 231/231 GREEN.

Dependency boundary:
- This sandbox still lacks `dilithium-py`; no fake ML-DSA backend was introduced.
- Core/RPC integration uses the real Ed25519 path and opaque unused ML key material
  only to instantiate the already-defined WalletIdentity address views.
- M/H signing remains dependency-gated and must be re-run with the real ML-DSA package.

No CHAIN_CONFIG/genesis/fingerprint changes. CD-003 remains NOT EXECUTED.


## Checkpoint 7 — Wallet persistence + daemon/client CLI split

Status: GREEN for persistence and real Ed25519/N operation; activation unchanged.

Added:
- encrypted/versioned wallet backup with scrypt + AES-256-GCM;
- wrong-passphrase and tamper rejection;
- persistent `DataDir` for chain + wallet;
- `axven-core run` daemon model;
- separate `axven-cli` JSON-RPC client;
- persistent chain reload across process/service lifecycle;
- one-shot `send` is intentionally not used as a local process command because
  the mempool is in-memory by design; send belongs to the live daemon RPC.

Verification:
- `wallet_persistence_cli_test.py`: 16/16 GREEN.
- `core_rpc_test.py`: 23/23 GREEN.
- `p2p_tcp_lifecycle_test.py`: 14/14 GREEN.
- `p2p_spec_test.py`: 20/20 GREEN.
- `consensus_rebuild_test.py`: 18/18 GREEN.
- `smt_incremental_test.py`: 231/231 GREEN.

Dependency boundary:
- fresh `create-wallet` still requires the real `dilithium-py` ML-DSA dependency.
- No fake PQ implementation was added in this sandbox.
- Backup/persistence was tested with real Ed25519 and opaque unused PQ key material.

No CHAIN_CONFIG/genesis/fingerprint changes. CD-003 remains NOT EXECUTED.


## Checkpoint 8 — Long-running daemon lifecycle / restart hardening

Status: GREEN for the real Ed25519/N operational path; activation unchanged.

Added/verified:
- long-running `axven-core run` process lifecycle;
- RPC and P2P active simultaneously;
- clean SIGTERM shutdown persists the active chain;
- restart resumes exact tip/height and validates replayed state;
- mempool intentionally returns empty after restart;
- mining continues from the restored chain;
- fresh peers reconnect and catch up after restart;
- wrong wallet passphrase fails closed before service startup.

Verification:
- `daemon_lifecycle_test.py`: 23/23 GREEN.
- `wallet_persistence_cli_test.py`: 16/16 GREEN.
- `core_rpc_test.py`: 23/23 GREEN.
- `p2p_tcp_lifecycle_test.py`: 14/14 GREEN.
- `p2p_spec_test.py`: 20/20 GREEN.
- `consensus_rebuild_test.py`: 18/18 GREEN.
- `smt_incremental_test.py`: 231/231 GREEN.

No CHAIN_CONFIG/genesis/fingerprint changes. CD-003 remains NOT EXECUTED.


## Checkpoint 9 — Release packaging / install preflight

Status: GREEN for packaging and the currently runnable Ed25519/N path; activation unchanged.

Added:
- installable `pyproject.toml` with `axven-core`, `axven-cli`, `axven-doctor` entry points;
- `axven-doctor` dependency/config/genesis preflight;
- first-run `RUNBOOK.md`;
- release manifest with SHA-256 hashes, pinned fingerprint and pinned genesis hash;
- explicit fail-closed behavior when the real ML-DSA dependency is unavailable.

Verification:
- release packaging: 41/41 GREEN;
- daemon lifecycle: 23/23 GREEN;
- wallet persistence/CLI: 16/16 GREEN;
- Core/RPC: 23/23 GREEN;
- P2P TCP lifecycle: 14/14 GREEN;
- P2P spec: 20/20 GREEN;
- consensus rebuild: 18/18 GREEN;
- incremental SMT: 231/231 GREEN.

Environment note:
- `dilithium-py==1.4.0` is not installed in this sandbox, and `axven-doctor`
  reports that honestly.  No fake PQ backend is shipped.

No CHAIN_CONFIG/genesis/fingerprint changes. CD-003 remains NOT EXECUTED.


## Checkpoint 10 — Release-candidate audit gate / PQ dependency gate

Status: LOCAL RC STRUCTURE GREEN; CANONICAL PQ RC NOT READY in this sandbox.

Added:
- `release_candidate_audit.py`: aggregates packaging/daemon/wallet/Core/P2P/consensus/SMT suites.
- `pq_dependency_check.py`: real ML-DSA-44 keygen/sign/verify smoke, no fake backend.

Fresh verification in this checkpoint:
- `release_packaging_test.py`: 41/41 GREEN.
- `pq_dependency_check.py`: FAIL-CLOSED because `dilithium_py` is not installed in this sandbox.

Important:
- The long all-suite audit was not claimed as freshly GREEN here because the current execution
  environment enforces a ~60s outer limit and interrupted the aggregate run.
- The immediately preceding checkpoint 9 already recorded all component suites GREEN.
- Canonical PQ release-candidate readiness remains gated on installing `dilithium-py==1.4.0`
  and running the real ML-DSA/W-003 M/H paths.
- No fake PQ implementation was introduced.

No CHAIN_CONFIG/genesis/fingerprint changes. CD-003 remains NOT EXECUTED.


## Checkpoint 11 — Real-machine PQ validation kit

Status: VALIDATION KIT READY; canonical PQ RC still requires execution on a
machine with the real `dilithium-py==1.4.0` dependency.

Added:
- `validate_windows.ps1` and `validate_linux_macos.sh`: isolated venv setup,
  dependency install, doctor, and sequential full validation.
- `pq_real_validation.py`: real ML-DSA-44 keygen/sign/verify, N→M migration,
  M spend, H creation, H two-signature spend, downgrade rejection, H2 boundary.
- `run_full_validation.py`: stop-on-first-failure release validation.
- `doctor.py` now requires exact `dilithium-py==1.4.0`, stable fingerprint,
  stable genesis hash, and production consensus parameters.
- `REAL_PQ_VALIDATION.md`: operator instructions.

Sandbox result:
- package download remains impossible because this environment has no DNS/network;
- no fake PQ backend was introduced;
- therefore real PQ execution remains an external gate.

No CHAIN_CONFIG/genesis/fingerprint changes. CD-003 remains NOT EXECUTED.


## Checkpoint 12 — Cross-platform graceful daemon shutdown

Root cause found on the user's Windows machine:
`Popen.send_signal(SIGTERM)` does not provide the Unix-style graceful lifecycle
expected by the daemon test; the child can exit before its persistence `finally`
block completes.

Implemented:
- loopback RPC `stop` command;
- `AxvenCore.request_shutdown()`;
- daemon loop observes the shutdown request and exits through its normal `finally`;
- chain persistence happens before RPC/P2P teardown;
- `axven-cli stop`;
- daemon lifecycle test uses RPC stop rather than OS SIGTERM;
- dedicated graceful shutdown + persistence test.

Verification in rebuild sandbox:
- `graceful_shutdown_test.py`: 6/6 GREEN.
- The larger daemon test was not claimed GREEN in this sandbox on this run because
  the surrounding execution environment interfered with subprocess Python startup.
  The actual Windows failure path is now directly covered by the dedicated test.

PQ status from the user's real Windows machine before this fix:
- dependency smoke GREEN;
- real ML-DSA M/H end-to-end: 22/22 GREEN;
- W-003 wallet integration: 4/4 GREEN;
- release packaging: 55/55 GREEN.

No CHAIN_CONFIG/genesis/fingerprint changes. CD-003 remains NOT EXECUTED.


## Checkpoint 13 — Packaging version-sync fix

Root cause from the user's real Windows validation:
- real PQ dependency smoke: GREEN;
- real ML-DSA M/H end-to-end: GREEN;
- W-003 integration: GREEN;
- release packaging failed only because the test still expected `checkpoint11`
  while the package manifest had advanced to checkpoint12.

Fix:
- release packaging assertion synchronized with the checkpoint13 manifest;
- release file hashes regenerated;
- no consensus, PQ, wallet, genesis, or CHAIN_CONFIG behavior changed.

CD-003 remains NOT EXECUTED.


## Checkpoint 14 — Axven Core v0.9 RC1

Status: RELEASE CANDIDATE READY / ACTIVATION NOT EXECUTED.

Evidence:
- user's real Windows machine: `ALL AXVEN CHECKS GREEN`;
- real ML-DSA-44 dependency and M/H paths were executed successfully;
- W-003 integration was green;
- packaging and daemon lifecycle were green after Windows-specific fixes.

Added:
- `RELEASE_CANDIDATE.md`;
- `rc_audit.py`;
- release manifest advanced to `axven-core-v0.9.0-rc1`.

No CHAIN_CONFIG/genesis/fingerprint changes.
CD-003 remains NOT EXECUTED.


## Checkpoint 16 — Devnet rehearsal state-root API fix

Real Windows checkpoint15 result:
- independent P2P endpoints: GREEN
- same genesis: GREEN
- Node A mature chain: GREEN
- Node B TCP catch-up: GREEN
- rehearsal then failed on test code calling nonexistent `Blockchain.utxo_root`.

Root cause:
- `utxo_root` is an authoritative module-level consensus function;
- Blockchain intentionally does not duplicate it as a mutable/cache attribute.

Fix:
- rehearsal convergence checks now use
  `axven.expected_state_root(chain.utxo, chain.tip.height)`;
- no Blockchain/consensus/P2P/wallet code changed.

CD-003 remains NOT EXECUTED.


## Checkpoint 18 — CD-003 activation
Status: **EXECUTED** on 2026-08-11.
Canonical: `axven-devnet-2` / `ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae` / `a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3`.
No CHAIN_CONFIG or genesis value changed during execution.


## Checkpoint 19 — Windows UTF-8 post-activation audit fix

Real Windows checkpoint18 result:
- real PQ dependency smoke: GREEN
- ML-DSA M/H end-to-end: GREEN
- W-003: GREEN
- packaging: GREEN
- daemon/wallet/Core/P2P: GREEN
- two-node devnet rehearsal: 21/21 GREEN
- post-activation audit failed only when matching an em-dash-containing UTF-8
  string using Windows' default text encoding.

Fix:
- `CD-003_ACTIVATION.md` is read explicitly as UTF-8;
- audit checks stable semantic markers (`EXECUTED`, `CD-003`,
  `axven-devnet-2 CANONICAL`) rather than locale-sensitive punctuation;
- dedicated UTF-8 regression added.

Activation remains EXECUTED. No consensus/genesis/CHAIN_CONFIG code changed.


## Checkpoint 21 — Real canonical operation verified

Real Windows canonical operation completed:
- Node 1 started at genesis/height 0.
- First canonical block mined: `00654a3a90e5d24735d2baa39143e6f0144826caf4daf83b4fdc47beb6b92580`.
- Node 2 accepted exactly one block over real TCP P2P and converged to height 1.
- Both nodes shut down through graceful RPC.
- Node 1 restarted from disk at height 1 with the same tip and chainwork 512.

Result: `CANONICAL DEVNET OPERATION VERIFIED`.

No consensus, CHAIN_CONFIG, fingerprint, or genesis change.


## Checkpoint 22 — Canonical UX layer

Product/UX-only milestone. `axven.py` consensus source hash is unchanged from
Checkpoint 21.

Added:
- read-only Core/RPC overview;
- friendlier CLI connection errors;
- interactive `axven_console.py`;
- Windows `.cmd` launchers that avoid PowerShell execution-policy friction;
- daily-use guide.

Verification:
- UX spec: 21/21 GREEN;
- canonical operation audit: 7/7 GREEN;
- post-activation audit: 11/11 GREEN.

No consensus/genesis/fingerprint/activation change.


## Checkpoint 23 — Local Explorer / read-only API

Added without consensus changes:
- read-only chain explorer model in Core;
- block lookup by height/hash;
- transaction lookup across active chain and mempool;
- recent-block and mempool views;
- local explorer HTTP/API service;
- minimal browser explorer UI;
- Node 1 explorer port 18445 / Node 2 port 18455;
- Windows explorer launch shortcuts.

Verification:
- Explorer spec: 16/16 GREEN.
- UX spec: 21/21 GREEN.
- Core/RPC: 23/23 GREEN.
- Canonical operation audit: 7/7 GREEN.

Explorer remains loopback-only. No wallet-secret endpoint was added.


## Checkpoint 24 — Explorer polish + public release skeleton

Product/release milestone only. Consensus remains unchanged.

Added:
- polished local explorer UI;
- root `README.md`;
- MIT `LICENSE`;
- `SECURITY.md`;
- `CONTRIBUTING.md`;
- `CHANGELOG.md`;
- `.gitignore`;
- public release checklist.

The project is explicitly described as canonical devnet, not mainnet and not
independently audited.

No consensus/genesis/fingerprint/activation change.


## Checkpoint 25 — Release-candidate repository hardening

Added:
- clean package/wheel build smoke;
- release-manifest integrity verifier;
- repository layout documentation;
- GitHub release-notes draft.

This is repository/release engineering only. Canonical consensus identity is
unchanged. A real third-party clean-machine test remains recommended before a
public tag; the automated smoke verifies the package from a clean build path,
not arbitrary external machines.


## Checkpoint 26 — GitHub-ready release bundle

Checkpoint 25 passed the real Windows full validation gate with:
`ALL AXVEN CHECKS GREEN`.

Checkpoint 26 adds release engineering only:
- VERSION;
- GitHub release text;
- release metadata JSON;
- GitHub Actions validation workflow;
- SHA-256 checksum generation for distribution bundles.

No consensus/genesis/fingerprint/activation behavior changed.
