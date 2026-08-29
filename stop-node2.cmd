@echo off
cd /d "%~dp0"
.venv\Scripts\python.exe axven_cli.py --datadir canonical-node2 --rpc-port 18453 stop
pause
