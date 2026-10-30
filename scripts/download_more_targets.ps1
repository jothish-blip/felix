$destBase = "C:\SecurityLabs"
$apkDir = "C:\SecurityLabs\compiled-apks"

if (!(Test-Path $destBase)) {
    New-Item -ItemType Directory -Path $destBase -Force | Out-Null
}
if (!(Test-Path $apkDir)) {
    New-Item -ItemType Directory -Path $apkDir -Force | Out-Null
}

$moreRepos = @(
    @{ Name = "security-shepherd"; Url = "https://github.com/OWASP/SecurityShepherd.git"; Type = "Web/OWASP" },
    @{ Name = "vulnerable-graphql-api"; Url = "https://github.com/carve-systems/vulnerable-graphql-api.git"; Type = "API/GraphQL" },
    @{ Name = "xvwa"; Url = "https://github.com/s4n7h0/xvwa.git"; Type = "Web/PHP" },
    @{ Name = "owasp-bricks"; Url = "https://github.com/securisec/bricks.git"; Type = "Web/PHP" },
    @{ Name = "secure-coding-dojo"; Url = "https://github.com/OWASP/SecureCodingDojo.git"; Type = "Web/Training" },
    @{ Name = "vwa"; Url = "https://github.com/OWASP/Vulnerable-Web-Application.git"; Type = "Web/OWASP" },
    @{ Name = "cloudgoat"; Url = "https://github.com/RhinoSecurityLabs/cloudgoat.git"; Type = "Cloud/AWS-GCP" },
    @{ Name = "terragoat"; Url = "https://github.com/bridgecrewio/terragoat.git"; Type = "Cloud/Terraform" },
    @{ Name = "dvws-php"; Url = "https://github.com/snoopysecurity/dvws.git"; Type = "API/PHP-WebServices" },
    @{ Name = "mstg-hacking-playground"; Url = "https://github.com/OWASP/mstg-hacking-playground.git"; Type = "Android/Security" },
    @{ Name = "poc-graphql"; Url = "https://github.com/righettod/poc-graphql.git"; Type = "API/GraphQL" },
    @{ Name = "dvsa"; Url = "https://github.com/appsecco/dvsa.git"; Type = "Cloud/Serverless" },
    @{ Name = "wackopicko"; Url = "https://github.com/adamdoupe/WackoPicko.git"; Type = "Web/PHP" }
)

Write-Host "=== Cloning Additional Repositories ===" -ForegroundColor Cyan
foreach ($repo in $moreRepos) {
    $targetPath = Join-Path $destBase $repo.Name
    if (Test-Path $targetPath) {
        Write-Host "[-] Skipping $($repo.Name) (Already exists)" -ForegroundColor Yellow
        continue
    }

    Write-Host "[*] Cloning $($repo.Name) ($($repo.Type))..." -ForegroundColor Green
    & git clone --depth 1 --quiet $repo.Url $targetPath 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Successfully cloned $($repo.Name)" -ForegroundColor Green
    } else {
        Write-Host "[!] Failed to clone $($repo.Name) from $($repo.Url)" -ForegroundColor Red
    }
}

$apkDownloads = @(
    @{ Name = "diva-beta.apk"; Url = "https://raw.githubusercontent.com/payatu/diva-android/master/app/diva-beta.apk" },
    @{ Name = "InjuredAndroid-1.0.12.apk"; Url = "https://github.com/B3nac/InjuredAndroid/releases/download/v1.0.12/InjuredAndroid-1.0.12.apk" },
    @{ Name = "AndroGoat.apk"; Url = "https://raw.githubusercontent.com/satishpatnayak/AndroGoat/master/AndroGoat.apk" },
    @{ Name = "allsafe-v1.1.0.apk"; Url = "https://github.com/t0thkr1s/allsafe/releases/download/v1.1.0/allsafe-v1.1.0.apk" }
)

Write-Host "`n=== Downloading Standalone Production APKs ===" -ForegroundColor Cyan
foreach ($apk in $apkDownloads) {
    $outPath = Join-Path $apkDir $apk.Name
    if (Test-Path $outPath) {
        Write-Host "[-] Skipping $($apk.Name) (Already exists)" -ForegroundColor Yellow
        continue
    }

    Write-Host "[*] Downloading $($apk.Name)..." -ForegroundColor Green
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($apk.Url, $outPath)
        $len = (Get-Item $outPath).Length
        Write-Host "[+] Downloaded $($apk.Name) ($([math]::Round($len/1MB, 2)) MB)" -ForegroundColor Green
    } catch {
        Write-Host "[!] Error downloading $($apk.Name): $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n=== Additional Downloads Finished ===" -ForegroundColor Cyan
