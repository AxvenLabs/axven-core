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

Active root records:
- `CD-003_ACTIVATION.md`
- `CANONICAL_OPERATION_RECORD.md`
- `REBUILD_STATUS.md`

Archived / community documentation:
- `docs/history/checkpoints/` — historical checkpoint records archived by repository-layout cleanup
- `docs/history/rebuild/README_REBUILD.md` — historical rebuild checkpoint narrative
- `docs/community/GIVETH.md` — Giveth ownership/provenance record

Path-sensitive files:
- RUST/SEC policy, verifier, fixture, manifest, release, and workflow-bound inputs remain at their established paths.
- Repository-layout cleanup must not weaken validation, CI fan-out, fail-closed policy checks, or Python-authoritative production consensus.
