<#
.SYNOPSIS
    Signs a Felix Windows binary using the local development certificate.

.DESCRIPTION
    Applies standard Windows Authenticode signing to a target binary using
    the dedicated Felix Development Code Signing certificate.
    Verifies and displays the resulting signature details.

.PARAMETER BinaryPath
    Path to the Windows executable to sign (e.g. bin\felix.exe).
    Defaults to bin\felix.exe or dist\felix_windows_amd64.exe.

.PARAMETER TimestampServer
    Optional RFC 3161 timestamp server URL. If omitted or unreachable,
    signing succeeds without a timestamp.
#>

param(
    [string]$BinaryPath = "",
    [string]$TimestampServer = ""
)

$ErrorActionPreference = "Stop"

Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host " FELIX :: Sign Binary (Local Development Certificate)" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptRoot

# 1. Resolve target binary path
if (-not $BinaryPath) {
    $candidates = @(
        (Join-Path $repoRoot "bin\felix.exe"),
        (Join-Path $repoRoot "dist\felix_windows_amd64.exe"),
        (Join-Path $env:LOCALAPPDATA "Felix\bin\felix.exe")
    )
    foreach ($cand in $candidates) {
        if (Test-Path $cand) {
            $BinaryPath = $cand
            break
        }
    }
}

if (-not $BinaryPath -or (-not (Test-Path $BinaryPath))) {
    Write-Error "Target binary not found. Please specify -BinaryPath or build bin\felix.exe first."
    exit 1
}

Write-Host "[*] Target Binary: $BinaryPath" -ForegroundColor Gray

# 2. Locate or create development certificate
$certSubject = "CN=Felix Development Code Signing, O=Felix Development, OU=Development Testing Only"
$cert = Get-ChildItem "Cert:\CurrentUser\My" -ErrorAction SilentlyContinue | Where-Object { $_.Subject -eq $certSubject } | Select-Object -First 1

if (-not $cert) {
    Write-Host "[*] Development certificate not found in store; generating now..." -ForegroundColor Yellow
    $createScript = Join-Path $scriptRoot "create-dev-cert.ps1"
    & powershell -ExecutionPolicy Bypass -File $createScript
    $cert = Get-ChildItem "Cert:\CurrentUser\My" -ErrorAction SilentlyContinue | Where-Object { $_.Subject -eq $certSubject } | Select-Object -First 1
}

if (-not $cert) {
    Write-Error "Failed to acquire Felix Development Certificate."
    exit 1
}

Write-Host "[*] Signing Certificate:" -ForegroundColor Gray
Write-Host "    Subject:    $($cert.Subject)" -ForegroundColor Gray
Write-Host "    Thumbprint: $($cert.Thumbprint)" -ForegroundColor Gray

# 3. Apply Authenticode signature
Write-Host "[*] Applying Authenticode signature..." -ForegroundColor Cyan

$sigResult = $null
if ($TimestampServer) {
    try {
        $sigResult = Set-AuthenticodeSignature -FilePath $BinaryPath -Certificate $cert -TimestampServer $TimestampServer
    } catch {
        Write-Warning "Timestamp server failed; signing without timestamp."
        $sigResult = Set-AuthenticodeSignature -FilePath $BinaryPath -Certificate $cert
    }
} else {
    $sigResult = Set-AuthenticodeSignature -FilePath $BinaryPath -Certificate $cert
}

# 4. Verify signature
$verification = Get-AuthenticodeSignature -FilePath $BinaryPath

Write-Host ""
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host " Signature Verification Result" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host " Status:         $($verification.Status)" -ForegroundColor $(if ($verification.Status -eq "Valid") { "Green" } else { "Yellow" })
Write-Host " Status Message: $($verification.StatusMessage)" -ForegroundColor Gray
Write-Host " Target Path:    $($verification.Path)" -ForegroundColor Gray

if ($verification.SignerCertificate) {
    Write-Host " Signer Subject: $($verification.SignerCertificate.Subject)" -ForegroundColor Gray
    Write-Host " Signer Thumb:   $($verification.SignerCertificate.Thumbprint)" -ForegroundColor Gray
    Write-Host " EKU:            $(($verification.SignerCertificate.EnhancedKeyUsageList.FriendlyName) -join ', ')" -ForegroundColor Gray
}

Write-Host ""
if ($verification.Status -eq "Valid") {
    Write-Host "[OK] Executable is signed and locally trusted!" -ForegroundColor Green
} elseif ($verification.Status -eq "UnknownError") {
    Write-Host "[i] Executable is signed with the Felix Development Certificate." -ForegroundColor Yellow
    Write-Host "    To trust this signature on this machine, run:" -ForegroundColor Yellow
    Write-Host "    powershell -File .\scripts\install-dev-trust.ps1" -ForegroundColor Cyan
} else {
    Write-Host "[!] Signature status: $($verification.Status)" -ForegroundColor Yellow
}
