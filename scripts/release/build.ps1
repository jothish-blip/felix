<#
.SYNOPSIS
    Felix Multi-Platform Release Build Script
.DESCRIPTION
    Cross-compiles Felix for all supported target platforms, builds Debian packages,
    APT repository metadata, Homebrew formula, and computes SHA-256 checksums.
#>

param(
    [string]$Version = "2.0.0"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")

Write-Host "==========================================================="
Write-Host " Building Felix Release v$Version via Packaging Pipeline"
Write-Host "==========================================================="

Push-Location $RepoRoot
try {
    go run ./scripts/packaging $Version
} finally {
    Pop-Location
}
