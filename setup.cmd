@echo off
setlocal
cd /d "%~dp0"

where powershell.exe >nul 2>&1
if errorlevel 1 (
  echo PowerShell is required to run hardened Axven setup.
  exit /b 1
)

powershell.exe -NoLogo -NoProfile -NonInteractive -File "%~dp0validate_windows.ps1"
if errorlevel 1 exit /b 1

echo.
echo Axven setup and validation complete.
exit /b 0
