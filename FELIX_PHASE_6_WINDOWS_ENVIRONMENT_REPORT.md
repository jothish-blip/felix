# FELIX — PHASE 6: WINDOWS ENVIRONMENT AUDIT & BASELINE REPORT

**Repository:** `C:\Jothish\felix` (`jothish-blip/felix`, branch `main`)  
**Execution Date:** `2026-11-12` (Asia/Calcutta `+05:30`)  
**Execution Policy:** Windows-Only Execution Campaign (no macOS migration; no new repo clones)

---

## 1. Host Operating System, Hardware & Toolchain Audit

All measurements were captured directly on the existing Windows development laptop before starting Phase 6 live application targets.

| Component | Observed Value | Notes / Constraints |
|---|---|---|
| Operating System | `Microsoft Windows 11 Home` `Version=10.0.26300` `Build=26300` `Arch=64-bit` (`X64`) | Native Windows host execution |
| CPU / Memory | `16,555,320 KB` (`15.79 GB`) total RAM; `6.33–6.40 GB` (`6,708,756 KB`) free pre-campaign | Shared across Go builds, target apps, and VirtualBox VM (4 GB allocated to Kali VM when active) |
| Disk (`C:`) | `87.44 GB` free / `387.15 GB` used (`474.59 GB` total) | Sufficient for local logs, reports, and VirtualBox VM |
| PowerShell | `5.1.26100.9818` | `npm.ps1` execution blocked by PowerShell ExecutionPolicy (`cmd /c npm` works; Juice Shop started directly via `node build/app`) |
| Go Toolchain | `go version go1.27.0 windows/amd64` | `CGO_ENABLED=0`, `CC=gcc`, `GOOS=windows`, `GOARCH=amd64` |
| C/C++ Compilers | `gcc: NOT_FOUND`, `clang: NOT_FOUND` | Race detector (`-race`) cannot compile CGO binaries on this host |
| Git | `git version 2.51.0.windows.1` | Preserved intact |
| Node.js / npm | `v24.20.0` / `12.2.1` (via `cmd /c npm --version`) | Used to execute OWASP Juice Shop natively on Windows |
| Python | `Python 3.11.9` (`pip 24.0`) + `C:\SecurityLabs\vampi\venv\Scripts\python.exe` | Prebuilt VAmPI virtualenv (Flask `2.2.2`, connexion `2.14.2`, PyJWT `2.6.0`, SQLAlchemy `2.0.2`) |
| Java / SQLite | `jdk-25.0.5.21-hotspot`, `Android\Sdk\platform-tools\sqlite3.exe` | Installed on host |
| Browsers / Playwright | Google Chrome `157.0.8103.50` (`C:\Program Files\Google\Chrome\Application\chrome.exe`), Microsoft Edge, Playwright (`chromium-1248`, `chromium_headless_shell-1248`, `ffmpeg-1013`, `winldd-1007` in `$env:LOCALAPPDATA\ms-playwright`) | Available for headless/browser verification |
| Host Container / WSL | `docker: NOT_FOUND`, `docker-compose: NOT_FOUND`, `podman: NOT_FOUND`, `wsl: C:\WINDOWS\system32\wsl.exe` (`wsl --status`: `The Windows Subsystem for Linux is not installed.`) | Host-native Docker is unavailable; **existing** VirtualBox Kali VM hosts Docker |
| VirtualBox | `7.2.16r174877` (`C:\Program Files\Oracle\VirtualBox\VBoxManage.exe`) | Pre-configured VMs: `kali-linux-2026.2-virtualbox-amd64`, `DC01`, `CLIENT01` |
| `FELIX_*` Env Vars | None configured (`0` variables matching `Env:FELIX*`) | Clean default environment |

---

## 2. Network & Listening Port Audit (Pre-Campaign)

Listening TCP sockets on the Windows host prior to starting any Phase 6 target:

| Local Address | Port | Owning PID | Impact on Phase 6 |
|---|---:|---:|---|
| `::` | `80` | `4` (`System` / HTTP.sys) | Port `80` unavailable; targets must NOT bind host port `80` |
| `::` | `445` | `4` (`System`) | Windows SMB service |
| `127.0.0.1` | `5354` | `4820` | Loopback local service |
| `0.0.0.0` | `15672` | `6480` | RabbitMQ / unrelated local service |
| `139`, `4369`, `5672`, `49664–49671` | — | various | Standard Windows / Erlang ports |

Target ports selected for Phase 6 (verified **FREE** prior to launch):
- **OWASP Juice Shop (`v20.2.0`):** `127.0.0.1:3000` (Native Windows Node.js process)
- **OWASP crAPI (`v1.1.5`):** `127.0.0.1:8888` (gateway) & `127.0.0.1:8025` (MailHog), strictly bound to `127.0.0.1` via VirtualBox NAT port forwarding to `kali-linux-2026.2-virtualbox-amd64`
- **VAmPI (`f16052d` + local patch):** `127.0.0.1:5000` (Native Windows Python/Flask process)

---

## 3. Repository State & Mandatory Baseline Regression

Executed inside `C:\Jothish\felix` before any live application campaign:

1. **Git State (`git log -1 --oneline` / `git status --short`):**
   - `HEAD`: `4fc8c8e feat: consolidate FELIX phases 1-5 for Mac migration` (`4fc8c8e1ed3c9d28da71e23e450549ca575cfcc9`)  
     *(Note: The Phase 6 prompt header cited pre-consolidation commit `744914a9f922d602df223d759c9dd592517e09dd`; the actual consolidated repository `HEAD` containing Phase 1–5 work is `4fc8c8e`.)*
   - Tracked modifications present prior to Phase 6 (`8` proof/lab JSON files, untouched by Phase 6):
     - `M test/evidence/phase4/4.4_oast_callback_correlation_proof.json`
     - `M test/evidence/phase4/4.5_cve_updater_atomic_sync_proof.json`
     - `M test/evidence/phase6/6.2_dex_secret_extraction_proof.json`
     - `M test/evidence/phase6/6.3_frida_dynamic_instrumentation_proof.json`
     - `M test/evidence/phase6/6.4_mobile_api_correlation_proof.json`
     - `M test/evidence/phase7/7.4_executive_dossier_proof.json`
     - `M test/evidence/phase8/8.1_swarm_fault_tolerance_proof.json`
     - `M test/lab/lab_results.json`
   - Untracked files before Phase 6: `0`.

2. **Baseline Go Verification:**
   - `go build ./...` -> Exit Code **`0`**
   - `go vet ./...` -> Exit Code **`0`**
   - `go test -p 1 -count=1 ./...` -> Exit Code **`0`** (`48` testable packages `ok`, `2` `[no test files]`: `felix/scratch`, `felix/test/lab/cmd/multiclass`).
   - Isolated binary compiled from exact `HEAD` `4fc8c8e`: `go build -o "$env:TEMP\felix_phase6.exe" ./cmd/felix` -> Exit Code **`0`**.

---

## 4. Target Deployment Architecture (Windows-Isolated)

| Target | Location / Infrastructure | Version / Commit | Bind / Port | Notes |
|---|---|---|---|---|
| **Target A — OWASP Juice Shop** | `C:\SecurityLabs\juice-shop-package\juice-shop_20.2.0` (Node `v24.20.0`, `build\app.js`) | `20.2.0` (`package.json`) | `127.0.0.1:3000` | Packaged distribution with compiled Angular SPA & backend |
| **Target B — OWASP crAPI** | Existing VirtualBox VM `kali-linux-2026.2-virtualbox-amd64` (`/home/kali/labs/crapi`, Docker `28.5.2+dfsg4`, Docker Compose `2.40.3-3`, 10 pre-pulled crAPI images) | `1.1.5` (`VERSION`, commit `b5fc307`) | `127.0.0.1:8888` (`80` in `crapi-web`), `127.0.0.1:8025` (MailHog) via `127.0.0.1`-only VirtualBox NAT forwarding | Isolated NAT network; no host Docker installation required |
| **Target C — VAmPI** | `C:\SecurityLabs\vampi` (`venv\Scripts\python.exe`) | `f16052d` + local patch (`api_views/users.py`, `app.py`) | `127.0.0.1:5000` | Pre-existing local modification hardens `GET /users/v1/{username}` (`401`/`403`) & binds `127.0.0.1:5000` (`alive=86400`, `debug=False`). Original `database/database.db` backed up (`SHA256=4599BBD4AF03491CDA7CA941B2AA28CD42836858BC6CB3478276C1ECC6DB02BD`) prior to testing |

All raw FELIX Phase 6 output directories are written strictly outside tracked git paths (to the conversation scratch workspace), preserving the repository working tree cleanly except for the 10 required Phase 6 Markdown reports.
