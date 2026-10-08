<#
.SYNOPSIS
    Felix Windows User-Level Installer

.DESCRIPTION
    Installs Felix to %LOCALAPPDATA%\Felix\bin, adds the directory to the User PATH environment
    variable idempotently (without administrator privileges), and verifies execution.

.PARAMETER BinaryPath
    Optional local path to felix_windows_amd64.exe or felix.exe. If omitted, downloads from official GitHub release.

.PARAMETER Version
    The release version to install (defaults to 1.0.0).
#>

param(
    [string]$BinaryPath = "",
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"

$InstallDir = Join-Path $env:LOCALAPPDATA "Felix\bin"
$TargetExe = Join-Path $InstallDir "felix.exe"

Write-Host "==========================================================="
Write-Host " FELIX :: Windows Automated Installer (v$Version)"
Write-Host "==========================================================="

# 1. Create installation directory
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Write-Host "[+] Created directory: $InstallDir"
}

# 2. Source binary resolution
if ($BinaryPath -ne "" -and (Test-Path $BinaryPath)) {
    Write-Host "[*] Installing from local binary: $BinaryPath"
    Copy-Item -Path $BinaryPath -Destination $TargetExe -Force
} else {
    $ReleaseURL = "https://github.com/jothish-blip/felix/releases/download/v${Version}/felix_windows_amd64.exe"
    Write-Host "[*] Downloading Felix v$Version from GitHub Releases..."
    Write-Host "    $ReleaseURL"

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        Invoke-WebRequest -Uri $ReleaseURL -OutFile $TargetExe -UseBasicParsing
    } catch {
        Write-Warning "Could not download from online URL: $_"
        $LocalDist = Join-Path (Get-Location) "dist\felix_windows_amd64.exe"
        if (Test-Path $LocalDist) {
            Write-Host "[*] Using existing local build from dist\felix_windows_amd64.exe..."
            Copy-Item -Path $LocalDist -Destination $TargetExe -Force
        } else {
            Write-Error "Failed to acquire Felix binary. Download URL: $ReleaseURL"
            exit 1
        }
    }
}

if (-not (Test-Path $TargetExe)) {
    Write-Error "Failed to install felix.exe to $TargetExe"
    exit 1
}

Write-Host "[OK] Installed binary: $TargetExe"

# 3. Idempotent PATH management (User scope, zero admin required)
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$PathEntries = @()
if ($UserPath) {
    $PathEntries = $UserPath -split ';' | Where-Object { $_ -ne '' }
}

if ($PathEntries -notcontains $InstallDir) {
    $NewPath = $InstallDir
    if ($UserPath) {
        $NewPath = "$UserPath;$InstallDir"
    }
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
    Write-Host "[OK] Added $InstallDir to User PATH."
} else {
    Write-Host "[i] $InstallDir is already present in User PATH."
}

# Update current session PATH so immediate verification works
if ($env:Path -notlike "*$InstallDir*") {
    $env:Path = "$InstallDir;$env:Path"
}

# 4. Installation verification
Write-Host ""
Write-Host "[*] Verifying installation..."
& $TargetExe version

Write-Host ""
Write-Host "==========================================================="
Write-Host " [OK] Installation successful! Felix is ready to use."
Write-Host " Open a new terminal and run: felix doctor"
Write-Host "==========================================================="
