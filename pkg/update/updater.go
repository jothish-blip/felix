package update

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// UpdateOptions configures the update execution.
type UpdateOptions struct {
	TargetVersion          string
	Force                  bool
	DryRun                 bool
	RequireSignature       bool
	TrustedKeyRing         openpgp.KeyRing
	ExpectedKeyFingerprint string
	Progress               func(step, details string)
}

// UpdateResult summarizes the completed update operation.
type UpdateResult struct {
	PreviousVersion   string
	UpdatedVersion    string
	TargetPlatform    string
	ExecutablePath    string
	ArchiveFile       string
	DownloadedBytes   int64
	RollbackOccurred  bool
	SignerFingerprint string
}

// Updater orchestrates the complete secure update pipeline.
type Updater struct {
	Repository             string
	Checker                *Checker
	Downloader             *Downloader
	CurrentVer             string
	RequireSignature       bool
	TrustedKeyRing         openpgp.KeyRing
	ExpectedKeyFingerprint string
}

// NewUpdater creates a new Updater configured for the repository and current version.
func NewUpdater(repo, currentVersion string) *Updater {
	if repo == "" {
		repo = DefaultGitHubRepo
	}
	return &Updater{
		Repository: repo,
		Checker:    NewChecker(repo),
		Downloader: NewDownloader(repo),
		CurrentVer: currentVersion,
	}
}

// Update executes the update workflow end-to-end.
func (u *Updater) Update(ctx context.Context, opts UpdateOptions) (*UpdateResult, error) {
	notify := func(step, details string) {
		if opts.Progress != nil {
			opts.Progress(step, details)
		}
	}

	cleanCurrent := CleanVersion(u.CurrentVer)

	// Step 1: Check available releases
	notify("CHECK", "Querying official release channels...")
	checkRes, err := u.Checker.CheckLatest(ctx, cleanCurrent)
	if err != nil {
		return nil, fmt.Errorf("failed to query update source: %w", err)
	}

	targetVersion := checkRes.LatestVersion
	if opts.TargetVersion != "" {
		targetVersion = CleanVersion(opts.TargetVersion)
	}

	// Step 2: Version comparison rules (Section 19: newer=allowed, same=no update, older=reject unless force)
	cmp, err := Compare(targetVersion, cleanCurrent)
	if err != nil {
		return nil, fmt.Errorf("version comparison error (%s vs %s): %w", targetVersion, cleanCurrent, err)
	}

	if cmp == 0 && !opts.Force {
		return &UpdateResult{
			PreviousVersion: cleanCurrent,
			UpdatedVersion:  cleanCurrent,
			TargetPlatform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		}, nil
	}

	if cmp < 0 && !opts.Force {
		return nil, fmt.Errorf("target version %s is older than current version %s (downgrades are rejected without --force)", targetVersion, cleanCurrent)
	}

	// Step 3: Platform asset mapping
	notify("RESOLVE", fmt.Sprintf("Resolving platform distribution for %s/%s...", runtime.GOOS, runtime.GOARCH))
	expectedArchive, err := ArchiveName(targetVersion, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return nil, err
	}

	var archiveAsset *GitHubAsset
	var checksumAsset *GitHubAsset
	var signatureAsset *GitHubAsset

	for i := range checkRes.Assets {
		asset := &checkRes.Assets[i]
		if strings.EqualFold(asset.Name, expectedArchive) {
			archiveAsset = asset
		}
		if strings.EqualFold(asset.Name, "SHA256SUMS") {
			checksumAsset = asset
		}
		if strings.EqualFold(asset.Name, "SHA256SUMS.asc") || strings.EqualFold(asset.Name, "SHA256SUMS.sig") {
			signatureAsset = asset
		}
	}

	if archiveAsset == nil {
		return nil, fmt.Errorf("no release artifact found matching %q in release %s", expectedArchive, targetVersion)
	}

	// Step 4: Prepare temporary staging workspace
	tempDir, err := os.MkdirTemp("", "felix-update-*")
	if err != nil {
		return nil, fmt.Errorf("failed creating temporary workspace: %w", err)
	}
	defer os.RemoveAll(tempDir)

	archivePath := filepath.Join(tempDir, expectedArchive)

	// Step 5: Download and verify checksum manifest and detached signature
	if checksumAsset == nil {
		return nil, fmt.Errorf("cryptographic verification failed: SHA256SUMS manifest missing from release %s assets", targetVersion)
	}

	requireSig := opts.RequireSignature || u.RequireSignature || os.Getenv("FELIX_UPDATE_REQUIRE_SIGNATURE") == "true"
	if requireSig && signatureAsset == nil {
		return nil, fmt.Errorf("cryptographic signature verification failed: detached signature manifest SHA256SUMS.asc is missing from release %s assets", targetVersion)
	}

	notify("CHECKSUM", "Downloading SHA256SUMS verification manifest...")
	sumsPath := filepath.Join(tempDir, "SHA256SUMS")
	if _, err := u.Downloader.DownloadFile(ctx, checksumAsset.BrowserDownloadURL, sumsPath); err != nil {
		return nil, fmt.Errorf("failed downloading SHA256SUMS manifest: %w", err)
	}

	manifestBytes, err := os.ReadFile(sumsPath)
	if err != nil {
		return nil, fmt.Errorf("failed reading SHA256SUMS manifest: %w", err)
	}

	sumsMap, err := ParseChecksums(bytes.NewReader(manifestBytes))
	if err != nil {
		return nil, fmt.Errorf("failed parsing SHA256SUMS manifest: %w", err)
	}

	if len(sumsMap) == 0 {
		return nil, fmt.Errorf("cryptographic verification failed: SHA256SUMS manifest contains no valid checksum entries")
	}

	expectedSHA256, found := sumsMap[expectedArchive]
	if !found || expectedSHA256 == "" {
		return nil, fmt.Errorf("cryptographic verification failed: target archive %q not found in SHA256SUMS manifest", expectedArchive)
	}

	if len(expectedSHA256) != 64 || !isHex(expectedSHA256) {
		return nil, fmt.Errorf("cryptographic verification failed: malformed SHA256 digest %q for %q in manifest", expectedSHA256, expectedArchive)
	}

	var verifiedSigner *openpgp.Entity
	if signatureAsset != nil {
		notify("SIGNATURE", fmt.Sprintf("Downloading detached signature %s...", signatureAsset.Name))
		sigPath := filepath.Join(tempDir, signatureAsset.Name)
		if _, err := u.Downloader.DownloadFile(ctx, signatureAsset.BrowserDownloadURL, sigPath); err != nil {
			return nil, fmt.Errorf("failed downloading signature manifest %s: %w", signatureAsset.Name, err)
		}

		sigBytes, err := os.ReadFile(sigPath)
		if err != nil {
			return nil, fmt.Errorf("failed reading signature file: %w", err)
		}

		keyring := opts.TrustedKeyRing
		if keyring == nil {
			keyring = u.TrustedKeyRing
		}
		if keyring == nil {
			if envPath := strings.TrimSpace(os.Getenv("FELIX_UPDATE_KEYRING")); envPath != "" {
				loaded, err := LoadKeyringFile(envPath)
				if err != nil {
					return nil, fmt.Errorf("failed loading trusted keyring from %s (FELIX_UPDATE_KEYRING): %w", envPath, err)
				}
				keyring = loaded
			}
		}
		expectedFP := opts.ExpectedKeyFingerprint
		if expectedFP == "" {
			expectedFP = u.ExpectedKeyFingerprint
		}
		if expectedFP == "" {
			expectedFP = strings.TrimSpace(os.Getenv("FELIX_UPDATE_EXPECTED_KEY"))
		}

		if requireSig || keyring != nil || expectedFP != "" {
			notify("SIGNATURE", "Verifying detached cryptographic signature of SHA256SUMS...")
			signer, err := VerifyManifestSignature(manifestBytes, sigBytes, keyring, expectedFP)
			if err != nil {
				return nil, fmt.Errorf("cryptographic signature verification failed: %w", err)
			}
			verifiedSigner = signer
			notify("SIGNATURE", fmt.Sprintf("Signature verified successfully (Signer: %X)", signer.PrimaryKey.Fingerprint))
		}
	}

	// Step 6: Download release archive
	notify("DOWNLOAD", fmt.Sprintf("Downloading %s (%s)...", expectedArchive, formatBytes(archiveAsset.Size)))
	computedHash, err := u.Downloader.DownloadFile(ctx, archiveAsset.BrowserDownloadURL, archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed downloading release artifact: %w", err)
	}

	// Step 7: Cryptographic integrity check
	notify("VERIFY", "Verifying SHA256 cryptographic digest...")
	if !strings.EqualFold(computedHash, expectedSHA256) {
		return nil, fmt.Errorf("CRITICAL: SHA256 mismatch for %s (expected %s, got %s)", expectedArchive, expectedSHA256, computedHash)
	}

	if opts.DryRun {
		notify("DRY-RUN", "Verification successful. Dry run complete; no files modified.")
		var signerFP string
		if verifiedSigner != nil {
			signerFP = fmt.Sprintf("%X", verifiedSigner.PrimaryKey.Fingerprint)
		}
		return &UpdateResult{
			PreviousVersion:   cleanCurrent,
			UpdatedVersion:    targetVersion,
			TargetPlatform:    fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
			ArchiveFile:       expectedArchive,
			DownloadedBytes:   archiveAsset.Size,
			SignerFingerprint: signerFP,
		}, nil
	}

	// Step 8: Safe archive extraction (ZipSlip-protected)
	notify("EXTRACT", "Extracting verified release package...")
	extractDir := filepath.Join(tempDir, "extracted")
	if err := ExtractArchive(archivePath, extractDir); err != nil {
		return nil, fmt.Errorf("failed extracting archive: %w", err)
	}

	// Step 9: Locate and verify extracted executable
	newBinPath, err := LocateExecutable(extractDir, runtime.GOOS)
	if err != nil {
		return nil, err
	}

	notify("STAGE", "Validating extracted binary integrity...")
	if err := VerifyBinary(ctx, newBinPath, targetVersion, runtime.GOOS); err != nil {
		return nil, fmt.Errorf("extracted binary verification failed: %w", err)
	}

	// Step 10: Safe self-replacement with atomic rollback
	notify("INSTALL", "Applying atomic self-replacement...")
	repRes, err := SelfReplace(ctx, newBinPath, targetVersion)
	if err != nil {
		return nil, err
	}

	notify("DONE", fmt.Sprintf("Successfully updated Felix to v%s", targetVersion))

	var signerFP string
	if verifiedSigner != nil {
		signerFP = fmt.Sprintf("%X", verifiedSigner.PrimaryKey.Fingerprint)
	}

	return &UpdateResult{
		PreviousVersion:   cleanCurrent,
		UpdatedVersion:    targetVersion,
		TargetPlatform:    fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		ExecutablePath:    repRes.TargetExecutable,
		ArchiveFile:       expectedArchive,
		DownloadedBytes:   archiveAsset.Size,
		RollbackOccurred:  repRes.RollbackExecuted,
		SignerFingerprint: signerFP,
	}, nil
}

func formatBytes(b int64) string {
	if b >= 1024*1024 {
		return fmt.Sprintf("%.2f MB", float64(b)/(1024*1024))
	}
	if b >= 1024 {
		return fmt.Sprintf("%.2f KB", float64(b)/1024)
	}
	return fmt.Sprintf("%d B", b)
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
