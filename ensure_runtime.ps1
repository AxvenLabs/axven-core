$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Assert-AxvenLocalRuntimeDirectory {
    param([switch]$AllowMissing)
    if (-not (Test-Path -LiteralPath ".venv")) {
        if ($AllowMissing) { return }
        throw "Axven validated runtime directory is missing"
    }
    $Item = Get-Item -LiteralPath ".venv" -Force
    if (-not $Item.PSIsContainer) {
        throw "Axven validated runtime path is not a directory; remove .venv and rerun validation"
    }
    if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Axven validated runtime directory must not be a reparse point; remove .venv and rerun validation"
    }
}

Assert-AxvenLocalRuntimeDirectory -AllowMissing

$Python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$PythonDigest = Join-Path $PSScriptRoot ".venv\.axven-python.sha256"
$Verifier = Join-Path $PSScriptRoot "runtime_provenance.py"
$VerifierDigest = Join-Path $PSScriptRoot ".venv\.axven-runtime-provenance.sha256"

function Test-AxvenInterpreterDigest {
    if (-not (Test-Path $Python -PathType Leaf)) { return $false }
    if (-not (Test-Path $PythonDigest -PathType Leaf)) { return $false }
    $Expected = (Get-Content -LiteralPath $PythonDigest -Raw).Trim()
    if ($Expected -notmatch "^[0-9a-f]{64}$") { return $false }
    $Actual = (Get-FileHash -LiteralPath $Python -Algorithm SHA256).Hash.ToLowerInvariant()
    return $Actual -eq $Expected
}

function Test-AxvenVerifierDigest {
    if (-not (Test-Path $Verifier -PathType Leaf)) { return $false }
    if (-not (Test-Path $VerifierDigest -PathType Leaf)) { return $false }
    $Expected = (Get-Content -LiteralPath $VerifierDigest -Raw).Trim()
    if ($Expected -notmatch "^[0-9a-f]{64}$") { return $false }
    $Actual = (Get-FileHash -LiteralPath $Verifier -Algorithm SHA256).Hash.ToLowerInvariant()
    return $Actual -eq $Expected
}

function Test-AxvenValidatedRuntime {
    if (-not (Test-Path $Python -PathType Leaf)) {
        return $false
    }
    if (-not (Test-AxvenInterpreterDigest)) {
        return $false
    }
    if (-not (Test-AxvenVerifierDigest)) {
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

if ((Test-Path $Python -PathType Leaf) -and -not (Test-AxvenInterpreterDigest)) {
    throw "Axven runtime interpreter attestation is missing or mismatched; remove .venv and rerun validate_windows.ps1"
}
if ((Test-Path $Python -PathType Leaf) -and -not (Test-AxvenVerifierDigest)) {
    throw "Axven runtime provenance verifier attestation is missing or mismatched; remove .venv and rerun validate_windows.ps1"
}

if (-not (Test-AxvenValidatedRuntime)) {
    Write-Host "Axven runtime is missing, stale, or unvalidated; running hardened validation..." -ForegroundColor Yellow
    & (Join-Path $PSScriptRoot "validate_windows.ps1")
}

Assert-AxvenLocalRuntimeDirectory

if (-not (Test-AxvenValidatedRuntime)) {
    throw "Axven runtime provenance validation failed"
}

Write-Host "Axven runtime provenance: GREEN" -ForegroundColor Green
