$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$Python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"

function Test-AxvenValidatedRuntime {
    if (-not (Test-Path $Python -PathType Leaf)) {
        return $false
    }

    & $Python runtime_provenance.py check *> $null
    if ($LASTEXITCODE -ne 0) {
        return $false
    }

    & $Python doctor.py *> $null
    if ($LASTEXITCODE -ne 0) {
        return $false
    }

    return $true
}

if (-not (Test-AxvenValidatedRuntime)) {
    Write-Host "Axven runtime is missing, stale, or unvalidated; running hardened validation..." -ForegroundColor Yellow
    & (Join-Path $PSScriptRoot "validate_windows.ps1")
}

if (-not (Test-AxvenValidatedRuntime)) {
    throw "Axven runtime provenance validation failed"
}

Write-Host "Axven runtime provenance: GREEN" -ForegroundColor Green
