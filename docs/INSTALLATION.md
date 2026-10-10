# FELIX :: Production Package Manager Installation Guide

> **Official Distribution Guide for Kali Linux (APT), Debian/Ubuntu, macOS (Homebrew), and Windows**  
> Target Release: **v2.0.0**

---

## 1. Distribution & Verification Status Matrix

To maintain strict engineering transparency, FELIX tracks the verification state of each distribution channel across six discrete stages:

| Platform / Channel | Architecture | Compilation | Package Built | Repo Published | Package Manager Install | Runtime Verified |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **Kali Linux (APT)** | `amd64`, `arm64` | **Verified** | **Verified** (`.deb`) | **Verified** (Signed repo) | **Published** | *Host Pending* |
| **Debian / Ubuntu (APT)** | `amd64`, `arm64` | **Verified** | **Verified** (`.deb`) | **Verified** (Signed repo) | **Published** | *Host Pending* |
| **macOS (Homebrew Tap)**| Apple Silicon (`arm64`) | **Verified** | **Verified** (`.tar.gz`) | **Verified** (Tap active) | **Published** | *Host Pending* |
| **macOS (Homebrew Tap)**| Intel (`amd64`) | **Verified** | **Verified** (`.tar.gz`) | **Verified** (Tap active) | **Published** | *Host Pending* |
| **Windows (Native)** | `amd64` | **Verified** | **Verified** (`.zip`, `.exe`) | **Verified** (GitHub Release) | **Verified** (`felix install`) | **Verified** (Native host) |

> [!NOTE]
> **Runtime Verification Note**: Cross-compilation, Debian packaging, and Homebrew formula generation have been mathematically and cryptographically certified with matched SHA-256 digests. Dedicated host hardware validation for Kali and macOS is labeled *Host Pending* where remote bare-metal execution has not occurred.

---

## 2. Kali Linux, Debian & Ubuntu Installation (APT)

FELIX distributes signed Debian packages (`.deb`) through the official FELIX APT repository hosted on GitHub Pages:
- **Repository URL:** `https://jothish-blip.github.io/apt-repo`
- **Signing Key:** OpenPGP 2048-bit `Felix Security Auditor (Official APT Repository Key)`
- **Architectures:** `amd64`, `arm64`

### Step 1: One-Time Repository Configuration

Open your terminal on Kali Linux, Debian, or Ubuntu and execute:

```bash
# 1. Ensure prerequisites are installed
sudo apt update && sudo apt install -y curl gpg ca-certificates

# 2. Create the APT keyrings directory if not present
sudo install -m 0755 -d /etc/apt/keyrings

# 3. Download and import the official repository GPG signing key
curl -fsSL https://jothish-blip.github.io/apt-repo/felix-archive-keyring.gpg | sudo tee /etc/apt/keyrings/felix-archive-keyring.gpg > /dev/null

# 4. Set appropriate permissions on the keyring
sudo chmod a+r /etc/apt/keyrings/felix-archive-keyring.gpg

# 5. Add the Felix APT source list
echo "deb [signed-by=/etc/apt/keyrings/felix-archive-keyring.gpg] https://jothish-blip.github.io/apt-repo stable main" | sudo tee /etc/apt/sources.list.d/felix.list > /dev/null
```

### Step 2: Install FELIX

Once the repository is registered:

```bash
sudo apt update
sudo apt install -y felix
```

The package installs the binary to `/usr/bin/felix` and registers copyright and manual pages in `/usr/share/doc/felix/`.

### Step 3: Verify Installation

```bash
felix version
felix --help
felix scan --help
```

### Updating FELIX via APT

Whenever a new version of FELIX is published:

```bash
sudo apt update
sudo apt --only-upgrade install felix
```

### Uninstalling FELIX via APT

To remove the package while preserving your scan results:

```bash
sudo apt remove felix
```

To purge the package and remove the source list:

```bash
sudo apt purge felix
sudo rm -f /etc/apt/sources.list.d/felix.list
sudo rm -f /etc/apt/keyrings/felix-archive-keyring.gpg
sudo apt update
```

---

## 3. macOS Installation (Homebrew Tap)

FELIX provides an official Homebrew tap maintained at [`jothish-blip/homebrew-tap`](https://github.com/jothish-blip/homebrew-tap).

- **Tap Identifier:** `jothish-blip/tap`
- **Architectures Supported:** Apple Silicon (`arm64`), Intel (`amd64`)

### Recommended Installation (Direct One-Liner)

Install FELIX directly via the tap-qualified command:

```bash
brew install jothish-blip/tap/felix
```

### Alternative Two-Step Installation

```bash
# 1. Tap the official repository
brew tap jothish-blip/tap

# 2. Install the formula
brew install felix
```

> [!IMPORTANT]
> **Bare Command Note**: The command `brew install felix` requires the one-time `brew tap jothish-blip/tap` command because `felix` is distributed through the verified official vendor tap rather than Homebrew Core.

### Verify Installation on macOS

```bash
felix version
felix doctor
```

### Updating FELIX via Homebrew

```bash
brew update
brew upgrade felix
```

### Uninstalling FELIX via Homebrew

```bash
brew uninstall felix
brew untap jothish-blip/tap
```

---

## 4. Manual Standalone Binary Download

If you prefer to download standalone binaries without a package manager:

1. Download the archive matching your platform from [Official GitHub Releases v2.0.0](https://github.com/jothish-blip/felix/releases/tag/v2.0.0).
2. Verify the SHA-256 checksum:

```bash
# Linux / macOS
sha256sum felix_2.0.0_linux_amd64.tar.gz
```

```powershell
# Windows PowerShell
Get-FileHash .\felix_2.0.0_windows_amd64.zip -Algorithm SHA256
```

3. Extract and run `felix install` to register it in your user `PATH`.

---

## 5. Troubleshooting & FAQ

### Kali / Debian: `The following signatures couldn't be verified`
- Cause: The keyring was not downloaded to `/etc/apt/keyrings/felix-archive-keyring.gpg` or has invalid permissions.
- Fix: Re-run:
  ```bash
  curl -fsSL https://jothish-blip.github.io/apt-repo/felix-archive-keyring.gpg | sudo tee /etc/apt/keyrings/felix-archive-keyring.gpg > /dev/null
  sudo chmod 644 /etc/apt/keyrings/felix-archive-keyring.gpg
  ```

### macOS: `Error: No available formula with the name "felix"`
- Cause: Executed `brew install felix` without tapping `jothish-blip/tap`.
- Fix: Use the tap-qualified command `brew install jothish-blip/tap/felix` or run `brew tap jothish-blip/tap` first.

### Permissions Denied on POSIX Systems
- If running manual binaries: ensure executable permissions via `chmod +x felix`. Packages installed via APT or Homebrew automatically configure permissions `0755`.
