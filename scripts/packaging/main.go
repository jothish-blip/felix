package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	version := "2.0.0"
	if len(os.Args) > 1 && os.Args[1] != "" {
		version = os.Args[1]
	}

	repoRoot, err := findRepoRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error locating repo root: %v\n", err)
		os.Exit(1)
	}

	distDir := filepath.Join(repoRoot, "dist")
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
	fmt.Printf(" Building Felix Production Release v%s (%s)\n", version, commit)
	fmt.Println("===========================================================")

	targets := []struct {
		GOOS       string
		GOARCH     string
		BinName    string
		SingleName string
		Archive    string
		IsZip      bool
	}{
		{"windows", "amd64", "felix.exe", "felix_windows_amd64.exe", fmt.Sprintf("felix_%s_windows_amd64.zip", version), true},
		{"linux", "amd64", "felix", "felix_linux_amd64", fmt.Sprintf("felix_%s_linux_amd64.tar.gz", version), false},
		{"linux", "arm64", "felix", "felix_linux_arm64", fmt.Sprintf("felix_%s_linux_arm64.tar.gz", version), false},
		{"darwin", "amd64", "felix", "felix_darwin_amd64", fmt.Sprintf("felix_%s_darwin_amd64.tar.gz", version), false},
		{"darwin", "arm64", "felix", "felix_darwin_arm64", fmt.Sprintf("felix_%s_darwin_arm64.tar.gz", version), false},
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

	// 3. Build APT Repository
	fmt.Println("\n[*] Building APT Repository & Cryptographic Signatures...")
	aptRepoDir := filepath.Join(distDir, "apt")
	_ = os.MkdirAll(aptRepoDir, 0755)

	signer, err := GenerateGpgSigner("Felix Security Auditor", "Official APT Repository Key", "jothishgandham2@gmail.com")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to generate GPG signing entity: %v\n", err)
		os.Exit(1)
	}

	if err := BuildAptRepo(aptRepoDir, []string{debAmd64, debArm64}, signer); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to build APT repository: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[✓] APT repository generated in: %s\n", aptRepoDir)

	// 4. Compute SHA256SUMS
	fmt.Println("\n[*] Computing SHA256 Checksums for Release Manifest...")
	hashes := make(map[string]string)
	entries, _ := os.ReadDir(distDir)
	var sumLines []string
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == "SHA256SUMS" || entry.Name() == "update.json" {
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
	_ = os.WriteFile(filepath.Join(distDir, "SHA256SUMS"), []byte(strings.Join(sumLines, "\n")+"\n"), 0644)
	fmt.Printf("[✓] SHA256SUMS created with %d artifacts.\n", len(sumLines))

	// 5. Generate Homebrew Formula
	fmt.Println("\n[*] Generating Homebrew Formula (Formula/felix.rb)...")
	darwinArm64Hash := hashes[fmt.Sprintf("felix_%s_darwin_arm64.tar.gz", version)]
	darwinAmd64Hash := hashes[fmt.Sprintf("felix_%s_darwin_amd64.tar.gz", version)]
	linuxArm64Hash := hashes[fmt.Sprintf("felix_%s_linux_arm64.tar.gz", version)]
	linuxAmd64Hash := hashes[fmt.Sprintf("felix_%s_linux_amd64.tar.gz", version)]

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
				"signed":  false,
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

	fmt.Println("\n===========================================================")
	fmt.Printf(" [SUCCESS] Release build v%s complete!\n", version)
	fmt.Printf(" Artifacts directory: %s\n", distDir)
	fmt.Println("===========================================================")
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
