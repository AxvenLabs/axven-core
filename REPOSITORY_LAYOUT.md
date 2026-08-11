# Repository Layout

Core:
- `axven.py` — consensus primitives and chain
- `wallet.py` — wallet core
- `core.py` — node/wallet orchestration
- `p2p.py` — TCP P2P
- `rpc.py` — JSON-RPC
- `storage.py` — persistent datadir/wallet storage

User/operator:
- `axven_core.py` — daemon / wallet entry point
- `axven_cli.py` — command-line RPC client
- `axven_console.py` — interactive console
- `explorer.py` + `explorer_index.html` — local read-only explorer
- `*.cmd` — Windows convenience launchers

Validation:
- `run_full_validation.py` — aggregate gate
- `*_test.py` — executable contracts/regressions
- `devnet_rehearsal.py` — two-node integration rehearsal

Records:
- `CD-003_ACTIVATION.md`
- `CANONICAL_OPERATION_RECORD.md`
- `CONSENSUS_DECISIONS.md`
- `WALLET_SPEC.md`
- `REBUILD_STATUS.md`
