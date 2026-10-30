$destBase = "C:\SecurityLabs"

$candidates = @(
    @{ Name = "threat-dragon"; Url = "https://github.com/OWASP/threat-dragon.git"; Type = "Web/SPA" },
    @{ Name = "seraphimdroid"; Url = "https://github.com/OWASP/Seraphimdroid.git"; Type = "Android" },
    @{ Name = "owasp-wstg"; Url = "https://github.com/OWASP/wstg.git"; Type = "Web/Benchmark" },
    @{ Name = "owasp-api-security"; Url = "https://github.com/OWASP/API-Security.git"; Type = "API/Security" },
    @{ Name = "owasp-cheatsheets"; Url = "https://github.com/OWASP/CheatSheetSeries.git"; Type = "Defensive/Baseline" },
    @{ Name = "owasp-top10"; Url = "https://github.com/OWASP/Top10.git"; Type = "Web/Benchmark" },
    @{ Name = "owasp-asvs"; Url = "https://github.com/OWASP/ASVS.git"; Type = "Verification/Standard" },
    @{ Name = "owasp-cornucopia"; Url = "https://github.com/OWASP/cornucopia.git"; Type = "Threat/Modeling" },
    @{ Name = "csrf-protector-php"; Url = "https://github.com/owasp/csrf-protector-php.git"; Type = "Web/PHP-Defense" },
    @{ Name = "owasp-blt"; Url = "https://github.com/OWASP/BLT.git"; Type = "Web/Python-Django" },
    @{ Name = "webgoat-legacy"; Url = "https://github.com/WebGoat/WebGoat-Legacy.git"; Type = "Web/Java" },
    @{ Name = "coreruleset"; Url = "https://github.com/coreruleset/coreruleset.git"; Type = "Defensive/WAF" },
    @{ Name = "nettacker"; Url = "https://github.com/OWASP/Nettacker.git"; Type = "Scanner/Testbed" },
    @{ Name = "payloads-all-the-things"; Url = "https://github.com/swisskyrepo/PayloadsAllTheThings.git"; Type = "Test-Cases/PayLoad" },
    @{ Name = "badstore"; Url = "https://github.com/kavishgr/badstore.git"; Type = "Web/Perl-CGI" }
)

$currentCount = (Get-ChildItem $destBase -Directory).Count
Write-Host "Current directory count: $currentCount" -ForegroundColor Cyan

foreach ($c in $candidates) {
    if ((Get-ChildItem $destBase -Directory).Count -ge 50) {
        Write-Host "Target count of 50 reached!" -ForegroundColor Green
        break
    }

    $target = Join-Path $destBase $c.Name
    if (-not (Test-Path $target)) {
        Write-Host "[*] Cloning $($c.Name) ($($c.Type))..." -ForegroundColor Green
        & git clone --depth 1 --quiet $c.Url $target 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] Successfully cloned $($c.Name)" -ForegroundColor Green
        } else {
            Write-Host "[!] Failed to clone $($c.Name)" -ForegroundColor Red
        }
    } else {
        Write-Host "[-] Already exists: $($c.Name)" -ForegroundColor Yellow
    }
}

$finalCount = (Get-ChildItem $destBase -Directory).Count
Write-Host "`nFinal total directories in $destBase : $finalCount" -ForegroundColor Cyan
