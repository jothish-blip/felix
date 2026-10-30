$destBase = "C:\SecurityLabs"

if (!(Test-Path $destBase)) {
    New-Item -ItemType Directory -Path $destBase -Force | Out-Null
}

$repos = @(
    # Web & API Applications
    @{ Name = "dvga"; Url = "https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application.git"; Type = "Web/GraphQL" },
    @{ Name = "dvwa"; Url = "https://github.com/digininja/DVWA.git"; Type = "Web/PHP" },
    @{ Name = "nodegoat"; Url = "https://github.com/OWASP/NodeGoat.git"; Type = "Web/NodeJS" },
    @{ Name = "mutillidae"; Url = "https://github.com/webpwnized/mutillidae.git"; Type = "Web/PHP" },
    @{ Name = "crapi"; Url = "https://github.com/OWASP/crAPI.git"; Type = "API/Microservices" },
    @{ Name = "wrongsecrets"; Url = "https://github.com/OWASP/wrongsecrets.git"; Type = "Cloud/Secrets" },
    @{ Name = "pygoat"; Url = "https://github.com/adeyosemanputra/pygoat.git"; Type = "Web/Python-Django" },
    @{ Name = "vulnerable-flask-app"; Url = "https://github.com/we45/Vulnerable-Flask-App.git"; Type = "Web/Python-Flask" },
    @{ Name = "railsgoat"; Url = "https://github.com/OWASP/railsgoat.git"; Type = "Web/Ruby" },
    @{ Name = "vulnerable-node"; Url = "https://github.com/cr0hn/vulnerable-node.git"; Type = "Web/NodeJS" },
    @{ Name = "pixi"; Url = "https://github.com/OWASP/DevSlop-Pixi.git"; Type = "Web/MEAN" },
    @{ Name = "serverless-goat"; Url = "https://github.com/OWASP/Serverless-Goat.git"; Type = "Cloud/Serverless" },
    @{ Name = "dvna"; Url = "https://github.com/appsecco/dvna.git"; Type = "Web/NodeJS" },
    @{ Name = "bWAPP"; Url = "https://github.com/raesene/bWAPP.git"; Type = "Web/PHP" },
    @{ Name = "dvws-node"; Url = "https://github.com/snoopysecurity/dvws-node.git"; Type = "API/NodeJS" },
    @{ Name = "skf-labs"; Url = "https://github.com/blabla1337/skf-labs.git"; Type = "Web/Multi-Language" },

    # Android Applications
    @{ Name = "android-androgoat"; Url = "https://github.com/satishpatnayak/AndroGoat.git"; Type = "Android" },
    @{ Name = "android-injuredandroid"; Url = "https://github.com/B3nac/InjuredAndroid.git"; Type = "Android" },
    @{ Name = "android-diva"; Url = "https://github.com/payatu/diva-android.git"; Type = "Android" },
    @{ Name = "android-allsafe"; Url = "https://github.com/t0thkr1s/allsafe.git"; Type = "Android" },
    @{ Name = "android-mastg"; Url = "https://github.com/OWASP/owasp-mastg.git"; Type = "Android" },
    @{ Name = "android-security-testing"; Url = "https://github.com/as0ler/Android-Security-Testing.git"; Type = "Android" }
)

Write-Host "Starting batch clone into $destBase..." -ForegroundColor Cyan

$successCount = 0
$skipCount = 0
$failCount = 0

foreach ($repo in $repos) {
    $targetPath = Join-Path $destBase $repo.Name
    if (Test-Path $targetPath) {
        Write-Host "[-] Skipping $($repo.Name) (Already exists at $targetPath)" -ForegroundColor Yellow
        $skipCount++
        continue
    }

    Write-Host "[*] Cloning $($repo.Name) ($($repo.Type))..." -ForegroundColor Green
    & git clone --depth 1 --quiet $repo.Url $targetPath 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Successfully cloned $($repo.Name)" -ForegroundColor Green
        $successCount++
    } else {
        Write-Host "[!] Failed to clone $($repo.Name) from $($repo.Url)" -ForegroundColor Red
        $failCount++
    }
}

Write-Host "`n=== Cloning Summary ===" -ForegroundColor Cyan
Write-Host "Newly Cloned: $successCount"
Write-Host "Skipped (Existing): $skipCount"
Write-Host "Failed: $failCount"
