<#
.SYNOPSIS
    Felix Windows User-Level Installer

.DESCRIPTION
    Installs Felix to %LOCALAPPDATA%\Felix\bin, adds the directory to the User PATH environment
    variable idempotently (without administrator privileges), and verifies execution.

.PARAMETER BinaryPath
    Optional local path to felix_windows_amd64.exe or felix.exe. If omitted, downloads from official GitHub release.

.PARAMETER ExpectedSHA256
    Expected 64-character SHA-256 digest from an independently trusted source.
    MANDATORY when downloading from GitHub Releases. Optional for local pre-built binaries.

.PARAMETER Version
    The release version to install (defaults to 2.0.0).
#>

param(
    [string]$BinaryPath = "",
    [string]$Version = "2.0.0",
    [string]$ExpectedSHA256 = "",
    [string]$InstallDir = "",
    [switch]$SkipPathUpdate,
    [switch]$DevSign
)

$ErrorActionPreference = "Stop"

if (-not $InstallDir) {
    if ($env:FELIX_INSTALL_DIR) {
        $InstallDir = $env:FELIX_INSTALL_DIR
    } else {
        $InstallDir = Join-Path $env:LOCALAPPDATA "Felix\bin"
    }
}
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
$TargetTmp = "$TargetExe.tmp"

if ($BinaryPath -ne "" -and (Test-Path $BinaryPath)) {
    Write-Host "[*] Installing from local binary: $BinaryPath"
    if ($ExpectedSHA256 -ne "") {
        if ($ExpectedSHA256 -notmatch '^[a-fA-F0-9]{64}$') {
            Write-Error "Provided ExpectedSHA256 '$ExpectedSHA256' is malformed. Must be exactly 64 hexadecimal characters."
            exit 1
        }
        $localHash = (Get-FileHash -Path $BinaryPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($localHash -ne $ExpectedSHA256.ToLowerInvariant()) {
            Write-Error "Cryptographic integrity verification failed for local binary! Expected: $ExpectedSHA256, Actual: $localHash"
            exit 1
        }
        Write-Host "[+] Local binary SHA-256 verified: $localHash"
    }
    Copy-Item -Path $BinaryPath -Destination $TargetTmp -Force
} else {
    if ([string]::IsNullOrWhiteSpace($ExpectedSHA256)) {
        Write-Error "Downloading Felix binary requires an explicitly pinned ExpectedSHA256 digest from an independently trusted source. Download aborted to prevent execution of unverified binaries."
        exit 1
    }
    if ($ExpectedSHA256 -notmatch '^[a-fA-F0-9]{64}$') {
        Write-Error "Provided ExpectedSHA256 '$ExpectedSHA256' is malformed. Must be exactly 64 hexadecimal characters."
        exit 1
    }

    $ReleaseURL = "https://github.com/jothish-blip/felix/releases/download/v${Version}/felix_windows_amd64.exe"
    Write-Host "[*] Downloading Felix v$Version from GitHub Releases..."
    Write-Host "    $ReleaseURL"

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        Invoke-WebRequest -Uri $ReleaseURL -OutFile $TargetTmp -UseBasicParsing
    } catch {
        Write-Warning "Could not download from online URL: $_"
        $LocalDist = Join-Path (Get-Location) "dist\felix_windows_amd64.exe"
        if (Test-Path $LocalDist) {
            Write-Host "[*] Using existing local build from dist\felix_windows_amd64.exe..."
            Copy-Item -Path $LocalDist -Destination $TargetTmp -Force
        } else {
            if (Test-Path $TargetTmp) { Remove-Item -Path $TargetTmp -Force -ErrorAction SilentlyContinue }
            Write-Error "Failed to acquire Felix binary. Download URL: $ReleaseURL"
            exit 1
        }
    }

    $downloadHash = (Get-FileHash -Path $TargetTmp -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($downloadHash -ne $ExpectedSHA256.ToLowerInvariant()) {
        Remove-Item -Path $TargetTmp -Force -ErrorAction SilentlyContinue
        Write-Error "Cryptographic integrity verification failed! Expected SHA256: $ExpectedSHA256, Actual SHA256: $downloadHash. Binary removed."
        exit 1
    }
    Write-Host "[+] Downloaded binary cryptographic SHA-256 integrity verified: $downloadHash"
}

if (-not (Test-Path $TargetTmp) -or (Get-Item $TargetTmp).Length -eq 0) {
    if (Test-Path $TargetTmp) { Remove-Item -Path $TargetTmp -Force -ErrorAction SilentlyContinue }
    Write-Error "Acquired binary is invalid or 0 bytes."
    exit 1
}

Move-Item -Path $TargetTmp -Destination $TargetExe -Force

if (-not (Test-Path $TargetExe)) {
    Write-Error "Failed to install felix.exe to $TargetExe"
    exit 1
}

Write-Host "[OK] Installed binary: $TargetExe"
if ($DevSign) {
    Write-Host "[*] Applying Felix Development Authenticode signature..." -ForegroundColor Cyan
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $signScript = Join-Path $repoRoot "scripts\sign-dev-binary.ps1"
    if (Test-Path $signScript) {
        & powershell -ExecutionPolicy Bypass -File $signScript -BinaryPath $TargetExe
    } else {
        Write-Warning "sign-dev-binary.ps1 not found at $signScript"
    }
}

# 3. Idempotent PATH management (User scope, zero admin required)
if ($SkipPathUpdate -or $env:FELIX_NO_PATH_UPDATE -eq "true") {
    Write-Host "[i] Skipping User PATH registration (SkipPathUpdate is set)."
} else {
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
