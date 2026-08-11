# Axven Core v0.9 — Release Candidate Record

Status: **RC1 READY / ACTIVATION NOT EXECUTED**

This record captures the first Axven v0.9 rebuild release candidate after the
lost implementation was reconstructed and validated end-to-end.

## Canonical identity pins

- chain_id: `axven-devnet-2`
- CONFIG_FINGERPRINT:
  `ac56ced3ca38dd449dabc3fc0091a3cc4dce6e05c692dcf836f1e493e7efabae`
- genesis hash:
  `a49413203b4a00f3c5b3a5901e8cd198b09f41f58295f22c927883f7fe4e1ab3`

## Consensus / protocol features present

- Ed25519 legacy N addresses and spends
- ML-DSA-44 M addresses and spends
- Hybrid H addresses with Ed25519 AND ML-DSA authorization
- downgrade-proof UTXO-address-authoritative scheme selection
- H1/H2 output creation gate
- grandfathered spends
- canonical input encoding + total deserialization
- witness-separated transaction IDs
- 7 MiB block byte cap
- PoW + cumulative chainwork fork-choice
- MTP / retarget
- reorg + undo + mempool reevaluation
- legacy UTXO root + Sparse Merkle activation path
- incremental SMT mirror + inclusion/non-inclusion proofs
- config/genesis/P2P identity binding

## Wallet / node features present

- WalletIdentity N/M/H views
- encrypted wallet backup/persistence
- scheme-aware coin selection
- PQ-aware change
- Ed25519 / ML-DSA / Hybrid signing orchestration
- pending reservation tracking
- full wallet <-> node integration
- persistent chain state
- localhost JSON-RPC
- CLI
- real TCP P2P sync / propagation / reconnect
- cross-platform graceful shutdown

## Real Windows validation evidence

The user's real Windows machine executed the checkpoint 13 validation kit and
reported:

`ALL AXVEN CHECKS GREEN`

That full validation includes:
- real `dilithium-py==1.4.0` dependency smoke;
- ML-DSA-44 keygen/sign/verify;
- N -> M migration;
- real M spend;
- H output creation;
- real Ed25519 + ML-DSA AND spend;
- H downgrade rejection;
- W-003 wallet integration;
- release packaging;
- daemon lifecycle;
- wallet persistence / CLI;
- Core / RPC;
- TCP P2P;
- consensus rebuild regression;
- incremental SMT regression.

## Activation boundary

This release candidate is **NOT** canonical activation.

CD-003 remains **DESIGNED / NOT EXECUTED**.

Release-candidate validation, genesis pin matching, and preflight readiness do
not by themselves constitute activation. Canonical activation still requires
the separately defined explicit activation decision/execution step.

## Next stage

Operational devnet rehearsal:
1. start two independent Axven Core nodes;
2. mine and propagate blocks;
3. submit wallet transactions;
4. restart/reconnect both nodes;
5. verify exact tip/UTXO convergence;
6. observe N/M/H operation across a controlled small-height test window;
7. only after this rehearsal, revisit the activation decision.


## Checkpoint 15 rehearsal gate

RC1 passed full real-Windows validation. Checkpoint 15 adds a separate two-node
operational rehearsal. The rehearsal is packaged but is not claimed passed
until executed on the real machine with `dilithium-py==1.4.0`.

CD-003 remains NOT EXECUTED.
