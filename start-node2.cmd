@echo off
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe call setup.cmd
if not exist canonical-node2\wallet.json (
  echo Creating Node 2 wallet...
  .venv\Scripts\python.exe axven_core.py --datadir canonical-node2 create-wallet
)
.venv\Scripts\python.exe axven_core.py --datadir canonical-node2 run --rpc-port 18453 --p2p-port 18454 --explorer-port 18455
