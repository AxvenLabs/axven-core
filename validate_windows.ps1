$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path ".venv")) {
    py -3 -m venv .venv
}
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -e .

Write-Host "`n=== AXVEN DOCTOR ===" -ForegroundColor Cyan
& .\.venv\Scripts\python.exe doctor.py
if ($LASTEXITCODE -ne 0) { throw "axven-doctor failed" }

Write-Host "`n=== FULL VALIDATION ===" -ForegroundColor Cyan
& .\.venv\Scripts\python.exe run_full_validation.py
if ($LASTEXITCODE -ne 0) { throw "Axven validation failed" }

Write-Host "`nALL AXVEN CHECKS GREEN" -ForegroundColor Green
