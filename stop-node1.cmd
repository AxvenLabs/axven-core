@echo off
cd /d "%~dp0"
.venv\Scripts\python.exe axven_cli.py --datadir canonical-node1 --rpc-port 18443 stop
pause
