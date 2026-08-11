@echo off
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe call setup.cmd
if not exist canonical-node1\wallet.json (
  echo Creating Node 1 wallet...
  .venv\Scripts\python.exe axven_core.py --datadir canonical-node1 create-wallet
)
echo.
echo Starting Axven with PUBLIC P2P only.
echo RPC:      127.0.0.1:18443
echo Explorer: 127.0.0.1:18445
echo P2P:      0.0.0.0:18444
echo.
.venv\Scripts\python.exe axven_core.py --datadir canonical-node1 run --rpc-host 127.0.0.1 --rpc-port 18443 --p2p-host 0.0.0.0 --p2p-port 18444 --explorer-host 127.0.0.1 --explorer-port 18445
