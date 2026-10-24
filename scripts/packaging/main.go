package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

func main() {
	version := "2.0.0"
	linuxAmd64Only := false
	recomputeManifestOnly := false
	for _, a := range os.Args[1:] {
		if a == "--linux-amd64-only" || a == "--linux-only" {
			linuxAmd64Only = true
		} else if a == "--recompute-manifest" || a == "--update-manifest" {
			recomputeManifestOnly = true
		} else if !strings.HasPrefix(a, "-") && a != "" {
			version = a
		}
	}

	repoRoot, err := findRepoRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error locating repo root: %v\n", err)
		os.Exit(1)
	}

	distDir := filepath.Join(repoRoot, "dist")
	isProductionRelease := os.Getenv("FELIX_REQUIRE_PRODUCTION_SIGNING") == "true" || os.Getenv("GITHUB_ACTIONS") == "true"

	if recomputeManifestOnly {
		fmt.Println("===========================================================")
		fmt.Printf(" Recomputing Release Manifests & Signatures v%s\n", version)
		fmt.Println("===========================================================")
		signer, err := resolveSigner(repoRoot, isProductionRelease)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to resolve signer: %v\n", err)
			os.Exit(1)
		}
		if err := generateManifestsAndSignatures(repoRoot, distDir, version, signer, isProductionRelease, linuxAmd64Only); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to recompute manifests: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("\n===========================================================")
		fmt.Printf(" [SUCCESS] Release manifests recomputed and resigned v%s!\n", version)
		fmt.Println("===========================================================")
		return
	}

	if err := os.RemoveAll(distDir); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Cleaning dist: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(distDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Creating dist: %v\n", err)
		os.Exit(1)
	}

	commit := getGitCommit(repoRoot)
	buildTime := time.Now().UTC().Format(time.RFC3339)
	ldflags := fmt.Sprintf("-s -w -X main.Version=%s -X main.GitCommit=%s -X main.BuildTime=%s -X main.Release=Production", version, commit, buildTime)

	fmt.Println("===========================================================")
	if linuxAmd64Only {
		fmt.Printf(" Building Felix Linux amd64 Target v%s (%s)\n", version, commit)
	} else {
		fmt.Printf(" Building Felix Production Release v%s (%s)\n", version, commit)
	}
	fmt.Println("===========================================================")

	type target struct {
		GOOS       string
		GOARCH     string
		BinName    string
		SingleName string
		Archive    string
		IsZip      bool
	}

	var targets []target
	if linuxAmd64Only {
		targets = []target{
			{"linux", "amd64", "felix", "felix_linux_amd64", fmt.Sprintf("felix_%s_linux_amd64.tar.gz", version), false},
		}
	} else {
		targets = []target{
			{"windows", "amd64", "felix.exe", "felix_windows_amd64.exe", fmt.Sprintf("felix_%s_windows_amd64.zip", version), true},
			{"linux", "amd64", "felix", "felix_linux_amd64", fmt.Sprintf("felix_%s_linux_amd64.tar.gz", version), false},
			{"linux", "arm64", "felix", "felix_linux_arm64", fmt.Sprintf("felix_%s_linux_arm64.tar.gz", version), false},
			{"darwin", "amd64", "felix", "felix_darwin_amd64", fmt.Sprintf("felix_%s_darwin_amd64.tar.gz", version), false},
			{"darwin", "arm64", "felix", "felix_darwin_arm64", fmt.Sprintf("felix_%s_darwin_arm64.tar.gz", version), false},
		}
	}

	for _, t := range targets {
		fmt.Printf("[*] Compiling %s/%s...\n", t.GOOS, t.GOARCH)
		binOut := filepath.Join(distDir, t.SingleName)
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags", ldflags, "-o", binOut, "./cmd/felix")
		cmd.Dir = repoRoot
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+t.GOOS, "GOARCH="+t.GOARCH)
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to compile %s/%s: %v\nOutput: %s\n", t.GOOS, t.GOARCH, err, string(out))
			os.Exit(1)
		}

		// Package archive
		stageDir := filepath.Join(distDir, fmt.Sprintf("stage_%s_%s", t.GOOS, t.GOARCH))
		_ = os.MkdirAll(stageDir, 0755)
		stageBin := filepath.Join(stageDir, t.BinName)
		if err := copyFile(binOut, stageBin); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error copying staged binary: %v\n", err)
			os.Exit(1)
		}
		// Copy docs
		for _, doc := range []string{"README.md", "USAGE.md", "SECURITY.md", "LICENSE"} {
			src := filepath.Join(repoRoot, doc)
			if fileExists(src) {
				_ = copyFile(src, filepath.Join(stageDir, doc))
			}
		}

		archivePath := filepath.Join(distDir, t.Archive)
		if t.IsZip {
			if err := createZip(stageDir, archivePath); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to create zip %s: %v\n", t.Archive, err)
				os.Exit(1)
			}
		} else {
			if err := createTarGz(stageDir, archivePath); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to create tar.gz %s: %v\n", t.Archive, err)
				os.Exit(1)
			}
		}
		_ = os.RemoveAll(stageDir)
	}

	// 2. Build Debian .deb packages
	fmt.Println("\n[*] Generating Debian (.deb) packages for Kali / Debian / Ubuntu...")
	debAmd64 := filepath.Join(distDir, fmt.Sprintf("felix_%s_amd64.deb", version))
	debArm64 := filepath.Join(distDir, fmt.Sprintf("felix_%s_arm64.deb", version))

	licensePath := filepath.Join(repoRoot, "LICENSE")

	cfgAmd64 := DebConfig{
		Package:      "felix",
		Version:      version,
		Architecture: "amd64",
		Maintainer:   "Jothish <jothishgandham2@gmail.com>",
		Homepage:     "https://github.com/jothish-blip/felix",
		Section:      "utils",
		Priority:     "optional",
		Description:  "Deterministic web security auditing platform",
		LongDesc:     "Felix is an evidence-first, non-destructive web security auditing platform written in Go.\nAudits web assets, JavaScript bundles, APIs, and cloud backends without invasive exploits.",
		BinaryPath:   filepath.Join(distDir, "felix_linux_amd64"),
		LicensePath:  licensePath,
		OutputPath:   debAmd64,
	}
	if err := BuildDeb(cfgAmd64); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to build amd64 .deb: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[✓] Created Debian package: %s\n", debAmd64)

	debList := []string{debAmd64}

	if !linuxAmd64Only {
		cfgArm64 := DebConfig{
			Package:      "felix",
			Version:      version,
			Architecture: "arm64",
			Maintainer:   "Jothish <jothishgandham2@gmail.com>",
			Homepage:     "https://github.com/jothish-blip/felix",
			Section:      "utils",
			Priority:     "optional",
			Description:  "Deterministic web security auditing platform",
			LongDesc:     "Felix is an evidence-first, non-destructive web security auditing platform written in Go.\nAudits web assets, JavaScript bundles, APIs, and cloud backends without invasive exploits.",
			BinaryPath:   filepath.Join(distDir, "felix_linux_arm64"),
			LicensePath:  licensePath,
			OutputPath:   debArm64,
		}
		if err := BuildDeb(cfgArm64); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to build arm64 .deb: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[✓] Created Debian package: %s\n", debArm64)
		debList = append(debList, debArm64)
	}

	// 3. Build APT Repository
	fmt.Println("\n[*] Building APT Repository & Cryptographic Signatures...")
	aptRepoDir := filepath.Join(distDir, "apt")
	_ = os.MkdirAll(aptRepoDir, 0755)

	signer, err := resolveSigner(repoRoot, isProductionRelease)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] FATAL: %v\n", err)
		os.Exit(1)
	}

	if err := BuildAptRepo(aptRepoDir, debList, signer); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to build APT repository: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[✓] APT repository generated in: %s\n", aptRepoDir)

	if err := generateManifestsAndSignatures(repoRoot, distDir, version, signer, isProductionRelease, linuxAmd64Only); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to generate release manifests: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n===========================================================")
	fmt.Printf(" [SUCCESS] Release build v%s complete!\n", version)
	fmt.Printf(" Artifacts directory: %s\n", distDir)
	fmt.Println("===========================================================")
}

func resolveSigner(repoRoot string, isProductionRelease bool) (*openpgp.Entity, error) {
	keysDir := filepath.Join(repoRoot, "scripts", "packaging", "keys")
	if isProductionRelease {
		signer, err := LoadProductionGpgSigner()
		if err != nil {
			return nil, fmt.Errorf("FELIX_APT_SIGNING_KEY is required for production release packaging (fail closed): %w", err)
		}
		fmt.Printf("[✓] Using protected production GPG signing identity: %X\n", signer.PrimaryKey.Fingerprint)
		return signer, nil
	} else if strings.TrimSpace(os.Getenv("FELIX_APT_SIGNING_KEY")) != "" {
		signer, err := LoadProductionGpgSigner()
		if err != nil {
			return nil, err
		}
		fmt.Printf("[✓] Using GPG signing identity from FELIX_APT_SIGNING_KEY: %X\n", signer.PrimaryKey.Fingerprint)
		return signer, nil
	}

	fmt.Println("[!] SECURITY NOTICE: FELIX_APT_SIGNING_KEY secret is not set in environment.")
	fmt.Println("    Using repository development fixture key for test repository structure validation.")
	fmt.Println("    Production release distribution requires a protected external secret.")
	signer, err := LoadTestFixtureGpgSigner(keysDir, "Felix Security Auditor", "Test Fixture Key", "test-fixture@felix.local")
	if err != nil {
		return nil, fmt.Errorf("failed to load test fixture GPG signer: %w", err)
	}
	if IsCompromisedKey(signer) {
		return nil, fmt.Errorf("security violation: loaded signer matches known permanently compromised key fingerprint (%s)", CompromisedAptKeyFingerprint)
	}
	fmt.Printf("[*] Repository GPG Key (Fixture): %X (RFC 4880 compliant)\n", signer.PrimaryKey.Fingerprint)
	return signer, nil
}

func generateManifestsAndSignatures(repoRoot, distDir, version string, signer *openpgp.Entity, isProductionRelease, linuxAmd64Only bool) error {
	// Compute SHA256SUMS and generate detached cryptographic signature
	fmt.Println("\n[*] Computing SHA256 Checksums for Release Manifest...")
	hashes := make(map[string]string)
	entries, _ := os.ReadDir(distDir)
	var sumLines []string
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "SHA256SUMS" || entry.Name() == "SHA256SUMS.asc" || entry.Name() == "update.json" {
			continue
		}
		path := filepath.Join(distDir, entry.Name())
		h, err := sha256File(path)
		if err != nil {
			continue
		}
		hashes[entry.Name()] = h
		sumLines = append(sumLines, fmt.Sprintf("%s  %s", h, entry.Name()))
	}
	sumsBytes := []byte(strings.Join(sumLines, "\n") + "\n")
	if err := os.WriteFile(filepath.Join(distDir, "SHA256SUMS"), sumsBytes, 0644); err != nil {
		return fmt.Errorf("failed to write SHA256SUMS: %w", err)
	}
	fmt.Printf("[✓] SHA256SUMS created with %d artifacts.\n", len(sumLines))

	if signer != nil {
		var sigBuf bytes.Buffer
		if err := openpgp.ArmoredDetachSignText(&sigBuf, signer, bytes.NewReader(sumsBytes), nil); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to cryptographically sign SHA256SUMS: %v\n", err)
			if isProductionRelease {
				return fmt.Errorf("signing SHA256SUMS: %w", err)
			}
		} else {
			sigPath := filepath.Join(distDir, "SHA256SUMS.asc")
			if err := os.WriteFile(sigPath, sigBuf.Bytes(), 0644); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to write SHA256SUMS.asc: %v\n", err)
				if isProductionRelease {
					return fmt.Errorf("writing SHA256SUMS.asc: %w", err)
				}
			} else {
				fmt.Printf("[✓] Cryptographically signed release manifest: %s\n", sigPath)
			}
		}
	}

	linuxAmd64Hash := hashes[fmt.Sprintf("felix_%s_linux_amd64.tar.gz", version)]

	if !linuxAmd64Only {
		// Generate Homebrew Formula
		fmt.Println("\n[*] Generating Homebrew Formula (Formula/felix.rb)...")
		darwinArm64Hash := hashes[fmt.Sprintf("felix_%s_darwin_arm64.tar.gz", version)]
		darwinAmd64Hash := hashes[fmt.Sprintf("felix_%s_darwin_amd64.tar.gz", version)]
		linuxArm64Hash := hashes[fmt.Sprintf("felix_%s_linux_arm64.tar.gz", version)]

		brewFormula := fmt.Sprintf(`class Felix < Formula
  desc "Deterministic, non-destructive web security auditing platform"
  homepage "https://github.com/jothish-blip/felix"
  version "%s"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/jothish-blip/felix/releases/download/v%s/felix_%s_darwin_arm64.tar.gz"
      sha256 "%s"
    else
      url "https://github.com/jothish-blip/felix/releases/download/v%s/felix_%s_darwin_amd64.tar.gz"
      sha256 "%s"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/jothish-blip/felix/releases/download/v%s/felix_%s_linux_arm64.tar.gz"
      sha256 "%s"
    else
      url "https://github.com/jothish-blip/felix/releases/download/v%s/felix_%s_linux_amd64.tar.gz"
      sha256 "%s"
    end
  end

  def install
    bin.install "felix"
  end

  test do
    assert_match "Felix Security Auditor", shell_output("#{bin}/felix version")
    assert_match "%s", shell_output("#{bin}/felix version")
    assert_match "Usage:", shell_output("#{bin}/felix --help")
  end
end
`, version, version, version, darwinArm64Hash, version, version, darwinAmd64Hash, version, version, linuxArm64Hash, version, version, linuxAmd64Hash, version)

		formulaDir := filepath.Join(distDir, "Formula")
		_ = os.MkdirAll(formulaDir, 0755)
		formulaPath := filepath.Join(formulaDir, "felix.rb")
		_ = os.WriteFile(formulaPath, []byte(brewFormula), 0644)
		fmt.Printf("[✓] Homebrew formula generated: %s\n", formulaPath)

		// Check if windows was previously marked signed
		var windowsSigned bool
		if existingData, err := os.ReadFile(filepath.Join(distDir, "update.json")); err == nil {
			var existingMap map[string]any
			if json.Unmarshal(existingData, &existingMap) == nil {
				if assets, ok := existingMap["assets"].(map[string]any); ok {
					if win, ok := assets["windows-amd64"].(map[string]any); ok {
						if s, ok := win["signed"].(bool); ok && s {
							windowsSigned = true
						}
					}
				}
			}
		}

		// Also generate update.json
		updateJSON := map[string]any{
			"product": "felix",
			"channel": "stable",
			"version": version,
			"release": fmt.Sprintf("https://github.com/jothish-blip/felix/releases/tag/v%s", version),
			"assets": map[string]any{
				"windows-amd64": map[string]any{
					"archive": fmt.Sprintf("felix_%s_windows_amd64.zip", version),
					"sha256":  hashes[fmt.Sprintf("felix_%s_windows_amd64.zip", version)],
					"signed":  windowsSigned,
				},
				"linux-amd64": map[string]any{
					"archive": fmt.Sprintf("felix_%s_linux_amd64.tar.gz", version),
					"sha256":  linuxAmd64Hash,
				},
				"linux-arm64": map[string]any{
					"archive": fmt.Sprintf("felix_%s_linux_arm64.tar.gz", version),
					"sha256":  linuxArm64Hash,
				},
				"darwin-amd64": map[string]any{
					"archive":   fmt.Sprintf("felix_%s_darwin_amd64.tar.gz", version),
					"sha256":    darwinAmd64Hash,
					"signed":    false,
					"notarized": false,
				},
				"darwin-arm64": map[string]any{
					"archive":   fmt.Sprintf("felix_%s_darwin_arm64.tar.gz", version),
					"sha256":    darwinArm64Hash,
					"signed":    false,
					"notarized": false,
				},
			},
		}
		updateData, _ := json.MarshalIndent(updateJSON, "", "  ")
		_ = os.WriteFile(filepath.Join(distDir, "update.json"), updateData, 0644)
	}

	return nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func findRepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := wd
	for {
		if fileExists(filepath.Join(dir, "go.mod")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return wd, nil
}

func getGitCommit(dir string) string {
	cmd := exec.Command("git", "rev-parse", "--short", "HEAD")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "prod"
	}
	return strings.TrimSpace(string(out))
}
