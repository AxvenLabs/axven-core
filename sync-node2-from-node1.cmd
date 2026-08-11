@echo off
cd /d "%~dp0"
.venv\Scripts\python.exe axven_cli.py --rpc-port 18453 sync-peer 127.0.0.1 18444
pause
