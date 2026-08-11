@echo off
cd /d "%~dp0"
.venv\Scripts\python.exe axven_cli.py --rpc-port 18453 overview
pause
