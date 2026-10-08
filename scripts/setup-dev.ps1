<#
.SYNOPSIS
    All-in-one local development setup for Felix on Windows.

.DESCRIPTION
    Sets up a fully functional, locally signed, and trusted Felix development
    installation on Windows without requiring Azure Artifact Signing or external
    paid certificates.

    Workflow:
      1. Generates local Felix Development Code Signing Certificate.
      2. Offers to install development trust locally.
      3. Builds or locates felix.exe.
      4. Signs felix.exe with Authenticode.
      5. Installs felix.exe to %LOCALAPPDATA%\Felix\bin and registers User PATH.
      6. Runs verification diagnostics (version and doctor).

.PARAMETER SkipTrust
    Skips the certificate trust installation step.

.PARAMETER Force
    Runs in non-interactive mode with automatic confirmations.
#>

param(
    [switch]$SkipTrust,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host " FELIX :: Windows Local Development Setup" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This workflow sets up a FREE, secure local development environment for Felix." -ForegroundColor Gray
Write-Host "No Azure subscription or paid code-signing certificates are required." -ForegroundColor Gray
Write-Host ""

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptRoot

# Step 1: Generate dev certificate
Write-Host "--- Step 1: Felix Development Certificate ---" -ForegroundColor Cyan
$certScript = Join-Path $scriptRoot "create-dev-cert.ps1"
& powershell -ExecutionPolicy Bypass -File $certScript

# Step 2: Install trust if requested
if (-not $SkipTrust) {
    Write-Host ""
    Write-Host "--- Step 2: Local Trust Installation ---" -ForegroundColor Cyan
    $trustScript = Join-Path $scriptRoot "install-dev-trust.ps1"
    if ($Force) {
        & powershell -ExecutionPolicy Bypass -File $trustScript -Force
    } else {
        & powershell -ExecutionPolicy Bypass -File $trustScript
    }
}

# Step 3: Locate or build binary
Write-Host ""
Write-Host "--- Step 3: Binary Resolution & Build ---" -ForegroundColor Cyan
$binExe = Join-Path $repoRoot "bin\felix.exe"
if (-not (Test-Path $binExe)) {
    Write-Host "[*] Compiling bin\felix.exe from source..." -ForegroundColor Yellow
    Push-Location $repoRoot
    try {
        $goCmd = Get-Command go -ErrorAction SilentlyContinue
        if (-not $goCmd) {
            $env:PATH = "C:\Program Files\Go\bin;" + $env:PATH
        }
        go build -o bin\felix.exe .\cmd\felix
    } finally {
        Pop-Location
    }
}

if (-not (Test-Path $binExe)) {
    Write-Error "Could not find or compile bin\felix.exe."
    exit 1
}
Write-Host "[OK] Binary ready: $binExe" -ForegroundColor Green

# Step 4: Sign binary with development certificate
Write-Host ""
Write-Host "--- Step 4: Authenticode Signing ---" -ForegroundColor Cyan
$signScript = Join-Path $scriptRoot "sign-dev-binary.ps1"
& powershell -ExecutionPolicy Bypass -File $signScript -BinaryPath $binExe

# Step 5: Install to %LOCALAPPDATA%\Felix\bin
Write-Host ""
Write-Host "--- Step 5: Install to User Environment ---" -ForegroundColor Cyan
$installDir = Join-Path $env:LOCALAPPDATA "Felix\bin"
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}
$targetExe = Join-Path $installDir "felix.exe"
Copy-Item -Path $binExe -Destination $targetExe -Force
Write-Host "[OK] Copied signed binary to: $targetExe" -ForegroundColor Green

# Ensure target is also signed
& powershell -ExecutionPolicy Bypass -File $signScript -BinaryPath $targetExe

# PATH registration
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$paths = $userPath -split ';' | Where-Object { $_ -ne '' }
if ($paths -notcontains $installDir) {
    $newPath = ($paths + $installDir) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Host "[OK] Added $installDir to User PATH." -ForegroundColor Green
} else {
    Write-Host "[i] $installDir is already registered in User PATH." -ForegroundColor Gray
}

# Step 6: Diagnostic verification
Write-Host ""
Write-Host "--- Step 6: Diagnostic Verification ---" -ForegroundColor Cyan
Write-Host "[*] Running felix version:" -ForegroundColor Gray
& $targetExe version

Write-Host ""
Write-Host "[*] Running felix doctor:" -ForegroundColor Gray
& $targetExe doctor

Write-Host ""
Write-Host "===========================================================" -ForegroundColor Green
Write-Host " [OK] Felix Local Development Setup Complete!" -ForegroundColor Green
Write-Host "===========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "You can now run Felix commands in any new terminal:" -ForegroundColor Cyan
Write-Host "  felix version" -ForegroundColor Gray
Write-Host "  felix doctor" -ForegroundColor Gray
Write-Host "  felix scan https://example.com --export report.html --json result.json" -ForegroundColor Gray
Write-Host ""
Write-Host "To remove development trust at any time:" -ForegroundColor DarkGray
Write-Host "  powershell -File .\scripts\uninstall-dev-trust.ps1" -ForegroundColor DarkGray
