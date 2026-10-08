<#
.SYNOPSIS
    Installs the Felix Development Certificate into the local machine trust store.

.DESCRIPTION
    Establishes trust ONLY for the locally generated Felix Development Certificate.
    This enables Authenticode signature validation for Felix binaries on this
    specific development machine without requiring paid Azure code signing.
    
    The certificate is explicitly labeled for DEVELOPMENT / TESTING ONLY.
    No other certificates or security policies are modified.

.PARAMETER Force
    Suppresses the confirmation prompt and proceeds with trust installation.

.PARAMETER CertFile
    Path to the public certificate (.cer). Defaults to certs\felix-dev.cer.
#>

param(
    [switch]$Force,
    [string]$CertFile = ""
)

$ErrorActionPreference = "Stop"

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host " FELIX :: Install Local Development Certificate Trust" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptRoot

# 1. Locate public certificate (.cer)
if (-not $CertFile) {
    $CertFile = Join-Path $repoRoot "certs\felix-dev.cer"
}

if (-not (Test-Path $CertFile)) {
    Write-Host "[*] Public certificate file not found; generating development certificate..." -ForegroundColor Yellow
    $createScript = Join-Path $scriptRoot "create-dev-cert.ps1"
    & powershell -ExecutionPolicy Bypass -File $createScript
}

if (-not (Test-Path $CertFile)) {
    Write-Error "Certificate file $CertFile does not exist."
    exit 1
}

# 2. Inspect certificate details
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertFile)

Write-Host ""
Write-Host "Certificate to be trusted:" -ForegroundColor Yellow
Write-Host "  Subject:     $($cert.Subject)" -ForegroundColor Gray
Write-Host "  Issuer:      $($cert.Issuer)" -ForegroundColor Gray
Write-Host "  Thumbprint:  $($cert.Thumbprint)" -ForegroundColor Gray
Write-Host "  Valid From:  $($cert.NotBefore)" -ForegroundColor Gray
Write-Host "  Valid To:    $($cert.NotAfter)" -ForegroundColor Gray
Write-Host "  Enhanced KU: $(($cert.EnhancedKeyUsageList.FriendlyName) -join ', ')" -ForegroundColor Gray
Write-Host ""

# Safety check: ensure certificate is actually the Felix development certificate
if ($cert.Subject -notlike "*Felix Development*") {
    Write-Error "Security guard: Certificate subject '$($cert.Subject)' does not match expected Felix Development identifier. Aborting."
    exit 1
}

Write-Host "IMPORTANT NOTICE:" -ForegroundColor Yellow
Write-Host "  - This certificate will be trusted ONLY on this local computer." -ForegroundColor Gray
Write-Host "  - It allows locally built or downloaded Felix dev binaries to run with verified Authenticode signatures." -ForegroundColor Gray
Write-Host "  - It is NOT a publicly trusted root authority or commercial publisher." -ForegroundColor Gray
Write-Host "  - Only the single certificate above will be installed. No other certificates are modified." -ForegroundColor Gray
Write-Host ""

# 3. Explicit user confirmation
if (-not $Force) {
    $confirmation = Read-Host "Do you want to trust this development certificate on this machine? (y/N)"
    if ($confirmation -notmatch "^[yY]([eE][sS])?$") {
        Write-Host "Operation cancelled by user. Trust store was NOT modified." -ForegroundColor Yellow
        exit 0
    }
}

# 4. Determine scope (LocalMachine if running elevated, otherwise CurrentUser)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$targetScope = if ($isAdmin) { "LocalMachine" } else { "CurrentUser" }

Write-Host "[*] Installing to $targetScope trust stores (Trusted Root & Trusted Publisher)..." -ForegroundColor Cyan

# Install to Root store
if ($isAdmin) {
    certutil -addstore -f "Root" $CertFile | Out-Null
    certutil -addstore -f "TrustedPublisher" $CertFile | Out-Null
} else {
    Import-Certificate -FilePath $CertFile -CertStoreLocation "Cert:\CurrentUser\Root" | Out-Null
    Import-Certificate -FilePath $CertFile -CertStoreLocation "Cert:\CurrentUser\TrustedPublisher" | Out-Null
}

# 5. Verify certificate installation in store
$rootFound = Get-ChildItem "Cert:\$targetScope\Root" -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
$pubFound = Get-ChildItem "Cert:\$targetScope\TrustedPublisher" -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }

if (-not $rootFound) {
    # Check CurrentUser as fallback
    $rootFound = Get-ChildItem "Cert:\CurrentUser\Root" -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
}

Write-Host ""
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host " Trust Verification" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

if ($rootFound) {
    Write-Host " [PASS] Trusted Root Store:       Present ($($rootFound.Thumbprint))" -ForegroundColor Green
} else {
    Write-Host " [FAIL] Trusted Root Store:       Not detected" -ForegroundColor Red
}

if ($pubFound) {
    Write-Host " [PASS] Trusted Publisher Store:  Present ($($pubFound.Thumbprint))" -ForegroundColor Green
} else {
    Write-Host " [INFO] Trusted Publisher Store:  Optional, not present" -ForegroundColor Gray
}

# 6. Test binary signature verification if a binary exists
$testBin = Join-Path $repoRoot "bin\felix.exe"
if (Test-Path $testBin) {
    Write-Host ""
    Write-Host "[*] Testing Authenticode signature verification on $testBin..." -ForegroundColor Cyan
    $sig = Get-AuthenticodeSignature -FilePath $testBin
    Write-Host " Authenticode Status: $($sig.Status) ($($sig.StatusMessage))" -ForegroundColor $(if ($sig.Status -eq "Valid") { "Green" } else { "Yellow" })
}

Write-Host ""
Write-Host "[OK] Felix Local Development Trust installation complete!" -ForegroundColor Green
Write-Host "To remove this certificate at any time, run:" -ForegroundColor Gray
Write-Host "  powershell -File .\scripts\uninstall-dev-trust.ps1" -ForegroundColor Cyan
