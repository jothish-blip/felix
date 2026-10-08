<#
.SYNOPSIS
    Generates a dedicated local development code-signing certificate for Felix.

.DESCRIPTION
    Creates a self-signed code-signing certificate in the CurrentUser certificate store
    and exports the public certificate (.cer) to the certs/ directory.
    The certificate is explicitly identified as DEVELOPMENT / TESTING ONLY.

.PARAMETER Force
    Overwrites any existing development certificate with the same subject.

.PARAMETER CertDir
    Directory to store the exported public certificate (.cer). Defaults to .\certs.
#>

param(
    [switch]$Force,
    [string]$CertDir = ""
)

$ErrorActionPreference = "Stop"

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host " FELIX :: Generate Local Development Certificate" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

# 1. Determine certificate directory
if (-not $CertDir) {
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    $repoRoot = Split-Path -Parent $scriptRoot
    $CertDir = Join-Path $repoRoot "certs"
}

if (-not (Test-Path $CertDir)) {
    New-Item -ItemType Directory -Path $CertDir -Force | Out-Null
    Write-Host "[+] Created directory: $CertDir" -ForegroundColor Green
}

$certSubject = "CN=Felix Development Code Signing, O=Felix Development, OU=Development Testing Only"
$cerPath = Join-Path $CertDir "felix-dev.cer"

# 2. Check for existing certificate in CurrentUser\My
$existing = Get-ChildItem "Cert:\CurrentUser\My" -ErrorAction SilentlyContinue | Where-Object { $_.Subject -eq $certSubject }

if ($existing -and (-not $Force)) {
    Write-Host "[i] Existing development certificate found in Cert:\CurrentUser\My:" -ForegroundColor Yellow
    Write-Host "    Subject:    $($existing[0].Subject)" -ForegroundColor Gray
    Write-Host "    Thumbprint: $($existing[0].Thumbprint)" -ForegroundColor Gray
    Write-Host "    Valid To:   $($existing[0].NotAfter)" -ForegroundColor Gray

    # Ensure .cer file exists on disk
    if (-not (Test-Path $cerPath)) {
        Export-Certificate -Cert $existing[0] -FilePath $cerPath -Force | Out-Null
        Write-Host "[+] Exported public certificate to: $cerPath" -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "[OK] Using existing development certificate. Use -Force to regenerate." -ForegroundColor Green
    return
}

# 3. Clean up older matching certificates if regenerating with -Force
if ($existing -and $Force) {
    Write-Host "[*] Removing previous development certificate ($($existing[0].Thumbprint))..." -ForegroundColor Yellow
    foreach ($c in $existing) {
        Remove-Item "Cert:\CurrentUser\My\$($c.Thumbprint)" -Force -ErrorAction SilentlyContinue
    }
}

# 4. Generate new self-signed code signing certificate
Write-Host "[*] Generating dedicated Felix Development Code Signing Certificate..." -ForegroundColor Cyan
$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $certSubject `
    -FriendlyName "Felix Development Code Signing (Local Testing Only)" `
    -KeyUsage DigitalSignature `
    -KeySpec Signature `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddYears(2)

# 5. Export public key (.cer)
Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null

Write-Host ""
Write-Host "[OK] Certificate generated and exported successfully:" -ForegroundColor Green
Write-Host "    Subject:    $($cert.Subject)" -ForegroundColor Gray
Write-Host "    Thumbprint: $($cert.Thumbprint)" -ForegroundColor Gray
Write-Host "    Purpose:    $($cert.EnhancedKeyUsageList.FriendlyName -join ', ')" -ForegroundColor Gray
Write-Host "    Valid From: $($cert.NotBefore)" -ForegroundColor Gray
Write-Host "    Valid To:   $($cert.NotAfter)" -ForegroundColor Gray
Write-Host "    Public File: $cerPath" -ForegroundColor Gray
Write-Host ""
Write-Host "Notice: This certificate is explicitly labeled for DEVELOPMENT / TESTING ONLY." -ForegroundColor Yellow
Write-Host "        It is NOT a commercial production identity." -ForegroundColor Yellow
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Sign binary:  powershell -File .\scripts\sign-dev-binary.ps1" -ForegroundColor Gray
Write-Host "  2. Install trust: powershell -File .\scripts\install-dev-trust.ps1" -ForegroundColor Gray
