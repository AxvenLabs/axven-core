# Checkpoint 15 — Two-node Devnet Operational Rehearsal

This is an executable operational gate layered on top of Axven Core v0.9 RC1.

It starts two independent node states and two real TCP P2P servers, then checks:

1. independent node endpoints with the same pinned genesis;
2. mining enough blocks for a mature spendable coinbase;
3. TCP catch-up and UTXO-root convergence;
4. wallet transaction creation and TCP transaction propagation;
5. block propagation and recipient-balance convergence;
6. independent persistence and restart/replay;
7. an intentional fork where one node becomes heavier;
8. TCP synchronization and cumulative-chainwork reorg;
9. reverse reconnect stability;
10. exact final tip and UTXO-root convergence.

Run on a machine that already passed the real PQ dependency gate:

    .\.venv\Scripts\python.exe devnet_rehearsal.py

or run the full Windows gate:

    .\validate_windows.ps1

Success ends with a JSON object containing `"ok": true`.

This rehearsal does not execute CD-003 and does not change CHAIN_CONFIG,
fingerprint, or genesis.


### Checkpoint 16 correction
The original rehearsal mistakenly accessed `Blockchain.utxo_root`, which is not
part of the Blockchain API. State convergence now calls the authoritative
consensus helper:

`axven.expected_state_root(chain.utxo, chain.tip.height)`

No consensus implementation was changed.
