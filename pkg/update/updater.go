package update

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// UpdateOptions configures the update execution.
type UpdateOptions struct {
	TargetVersion string
	Force         bool
	DryRun        bool
	Progress      func(step, details string)
}

// UpdateResult summarizes the completed update operation.
type UpdateResult struct {
	PreviousVersion string
	UpdatedVersion  string
	TargetPlatform  string
	ExecutablePath  string
	ArchiveFile     string
	DownloadedBytes int64
	RollbackOccurred bool
}

// Updater orchestrates the complete secure update pipeline.
type Updater struct {
	Repository string
	Checker    *Checker
	Downloader *Downloader
	CurrentVer string
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

	for i := range checkRes.Assets {
		asset := &checkRes.Assets[i]
		if strings.EqualFold(asset.Name, expectedArchive) {
			archiveAsset = asset
		}
		if strings.EqualFold(asset.Name, "SHA256SUMS") {
			checksumAsset = asset
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

	// Step 5: Download and verify checksum manifest
	var expectedSHA256 string
	if checksumAsset != nil {
		notify("CHECKSUM", "Downloading SHA256SUMS verification manifest...")
		sumsPath := filepath.Join(tempDir, "SHA256SUMS")
		_, err := u.Downloader.DownloadFile(ctx, checksumAsset.BrowserDownloadURL, sumsPath)
		if err == nil {
			f, err := os.Open(sumsPath)
			if err == nil {
				sumsMap, err := ParseChecksums(f)
				f.Close()
				if err == nil {
					expectedSHA256 = sumsMap[expectedArchive]
				}
			}
		}
	}

	// Step 6: Download release archive
	notify("DOWNLOAD", fmt.Sprintf("Downloading %s (%s)...", expectedArchive, formatBytes(archiveAsset.Size)))
	computedHash, err := u.Downloader.DownloadFile(ctx, archiveAsset.BrowserDownloadURL, archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed downloading release artifact: %w", err)
	}

	// Step 7: Cryptographic integrity check
	if expectedSHA256 != "" {
		notify("VERIFY", "Verifying SHA256 cryptographic digest...")
		if !strings.EqualFold(computedHash, expectedSHA256) {
			return nil, fmt.Errorf("CRITICAL: SHA256 mismatch for %s (expected %s, got %s)", expectedArchive, expectedSHA256, computedHash)
		}
	}

	if opts.DryRun {
		notify("DRY-RUN", "Verification successful. Dry run complete; no files modified.")
		return &UpdateResult{
			PreviousVersion: cleanCurrent,
			UpdatedVersion:  targetVersion,
			TargetPlatform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
			ArchiveFile:     expectedArchive,
			DownloadedBytes: archiveAsset.Size,
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

	return &UpdateResult{
		PreviousVersion:  cleanCurrent,
		UpdatedVersion:   targetVersion,
		TargetPlatform:   fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		ExecutablePath:   repRes.TargetExecutable,
		ArchiveFile:      expectedArchive,
		DownloadedBytes:  archiveAsset.Size,
		RollbackOccurred: repRes.RollbackExecuted,
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
