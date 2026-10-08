package update

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// SupportedPlatforms lists the 5 official production release target keys.
var SupportedPlatforms = []string{
	"windows-amd64",
	"linux-amd64",
	"linux-arm64",
	"darwin-amd64",
	"darwin-arm64",
}

// ReleaseMetadata matches Section 14 update metadata schema.
type ReleaseMetadata struct {
	Product string                   `json:"product"`
	Channel string                   `json:"channel"`
	Version string                   `json:"version"`
	Release string                   `json:"release"`
	Assets  map[string]AssetMetadata `json:"assets"`
}

// AssetMetadata defines distribution attributes for a platform archive.
type AssetMetadata struct {
	Archive   string `json:"archive"`
	SHA256    string `json:"sha256"`
	Signed    bool   `json:"signed,omitempty"`
	Notarized bool   `json:"notarized,omitempty"`
}

// TargetKey returns the standard metadata key for the given GOOS and GOARCH.
func TargetKey(goos, goarch string) (string, error) {
	key := fmt.Sprintf("%s-%s", goos, goarch)
	for _, p := range SupportedPlatforms {
		if p == key {
			return key, nil
		}
	}
	return "", fmt.Errorf("unsupported platform: %s/%s (supported: windows/amd64, linux/amd64, linux/arm64, darwin/amd64, darwin/arm64)", goos, goarch)
}

// CurrentTargetKey returns the target key for the running binary platform.
func CurrentTargetKey() (string, error) {
	return TargetKey(runtime.GOOS, runtime.GOARCH)
}

// ArchiveName returns the canonical distribution archive filename for version, goos, and goarch.
func ArchiveName(version, goos, goarch string) (string, error) {
	v := CleanVersion(version)
	switch {
	case goos == "windows" && goarch == "amd64":
		return fmt.Sprintf("felix_%s_windows_amd64.zip", v), nil
	case goos == "linux" && goarch == "amd64":
		return fmt.Sprintf("felix_%s_linux_amd64.tar.gz", v), nil
	case goos == "linux" && goarch == "arm64":
		return fmt.Sprintf("felix_%s_linux_arm64.tar.gz", v), nil
	case goos == "darwin" && goarch == "amd64":
		return fmt.Sprintf("felix_%s_darwin_amd64.tar.gz", v), nil
	case goos == "darwin" && goarch == "arm64":
		return fmt.Sprintf("felix_%s_darwin_arm64.tar.gz", v), nil
	default:
		return "", fmt.Errorf("unsupported target: %s/%s", goos, goarch)
	}
}

// ExecutableName returns the canonical binary name inside the archive.
func ExecutableName(goos string) string {
	if goos == "windows" {
		return "felix.exe"
	}
	return "felix"
}

// StandaloneBinaryName returns the raw release binary filename in dist/.
func StandaloneBinaryName(goos, goarch string) (string, error) {
	switch {
	case goos == "windows" && goarch == "amd64":
		return "felix_windows_amd64.exe", nil
	case goos == "linux" && goarch == "amd64":
		return "felix_linux_amd64", nil
	case goos == "linux" && goarch == "arm64":
		return "felix_linux_arm64", nil
	case goos == "darwin" && goarch == "amd64":
		return "felix_darwin_amd64", nil
	case goos == "darwin" && goarch == "arm64":
		return "felix_darwin_arm64", nil
	default:
		return "", fmt.Errorf("unsupported target: %s/%s", goos, goarch)
	}
}

// GenerateMetadata builds the ReleaseMetadata struct by inspecting files in distDir.
func GenerateMetadata(version, distDir, releaseURL string, windowsSigned, darwinNotarized bool) (*ReleaseMetadata, error) {
	v := CleanVersion(version)
	if releaseURL == "" {
		releaseURL = fmt.Sprintf("https://github.com/jothish-blip/felix/releases/tag/v%s", v)
	}

	meta := &ReleaseMetadata{
		Product: "felix",
		Channel: "stable",
		Version: v,
		Release: releaseURL,
		Assets:  make(map[string]AssetMetadata),
	}

	targets := []struct {
		goos, goarch string
	}{
		{"windows", "amd64"},
		{"linux", "amd64"},
		{"linux", "arm64"},
		{"darwin", "amd64"},
		{"darwin", "arm64"},
	}

	for _, t := range targets {
		key, _ := TargetKey(t.goos, t.goarch)
		archName, err := ArchiveName(v, t.goos, t.goarch)
		if err != nil {
			return nil, err
		}

		filePath := filepath.Join(distDir, archName)
		hash, err := FileSHA256(filePath)
		if err != nil {
			// If archive is not present, use empty hash or return error
			return nil, fmt.Errorf("failed to hash archive %s: %w", filePath, err)
		}

		asset := AssetMetadata{
			Archive: archName,
			SHA256:  hash,
		}
		if t.goos == "windows" {
			asset.Signed = windowsSigned
		}
		if t.goos == "darwin" {
			asset.Signed = darwinNotarized
			asset.Notarized = darwinNotarized
		}

		meta.Assets[key] = asset
	}

	return meta, nil
}

// FileSHA256 computes the SHA256 hex digest of a file.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// WriteMetadataJSON serializes ReleaseMetadata to a JSON file (update.json).
func WriteMetadataJSON(meta *ReleaseMetadata, destPath string) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(destPath, append(data, '\n'), 0644)
}
