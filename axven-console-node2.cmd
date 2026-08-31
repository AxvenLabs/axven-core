@echo off
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -NonInteractive -File "%~dp0ensure_runtime.ps1"
if errorlevel 1 exit /b 1
.venv\Scripts\python.exe axven_console.py --datadir canonical-node2 --rpc-port 18453
