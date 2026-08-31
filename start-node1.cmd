@echo off
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -NonInteractive -File "%~dp0ensure_runtime.ps1"
if errorlevel 1 exit /b 1
if not exist canonical-node1\wallet.json (
  echo Creating Node 1 wallet...
  .venv\Scripts\python.exe axven_core.py --datadir canonical-node1 create-wallet
)
.venv\Scripts\python.exe axven_core.py --datadir canonical-node1 run --rpc-port 18443 --p2p-port 18444 --explorer-port 18445
