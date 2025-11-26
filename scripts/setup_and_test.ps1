<#
PowerShell helper to create a virtual environment, install deps and run tests.
Usage examples (PowerShell):
    # Run once to setup and test
    .\scripts\setup_and_test.ps1

    # Force recreate venv then run
    .\scripts\setup_and_test.ps1 -Recreate
#>

param(
    [switch]$Recreate
)

# Move to repo root (script lives in ./scripts)
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location -Path $repoRoot

$venvPath = Join-Path $repoRoot '.venv'
$pythonExe = Join-Path $venvPath 'Scripts\python.exe'

if ($Recreate -and (Test-Path $venvPath)) {
    Write-Host "Removing existing virtual environment at '$venvPath'..."
    Remove-Item -Recurse -Force -Path $venvPath
}

if (-not (Test-Path $pythonExe)) {
    Write-Host "Creating virtual environment at $venvPath..."
    python -m venv $venvPath
}

if (-not (Test-Path $pythonExe)) {
    Write-Error "Python executable not found in venv. Ensure 'python' is installed and available on PATH."
    exit 1
}

Write-Host "Using Python: $pythonExe"

Write-Host "Upgrading pip..."
& $pythonExe -m pip install --upgrade pip

if (Test-Path "$repoRoot\requirements.txt") {
    Write-Host "Installing runtime dependencies from requirements.txt..."
    & $pythonExe -m pip install -r requirements.txt
} else {
    Write-Warning "requirements.txt not found. Skipping runtime deps install."
}

if (Test-Path "$repoRoot\requirements-dev.txt") {
    Write-Host "Installing dev/test dependencies from requirements-dev.txt..."
    & $pythonExe -m pip install -r requirements-dev.txt
} else {
    Write-Warning "requirements-dev.txt not found. Skipping dev deps install."
}

Write-Host "Running tests (pytest)..."
& $pythonExe -m pytest -q

$exitCode = $LASTEXITCODE
if ($exitCode -ne 0) {
    Write-Error "Tests failed with exit code $exitCode"
    exit $exitCode
}

Write-Host "All tests passed ✅"
exit 0
