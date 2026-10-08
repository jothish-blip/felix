package update

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	MaxArchiveBytes = 64 * 1024 * 1024 // 64 MB max archive size
	DownloadTimeout = 60 * time.Second
)

// Downloader manages secure artifact retrieval.
type Downloader struct {
	AllowedRepo string
	HTTPClient  *http.Client
	UserAgent   string
}

// NewDownloader creates a Downloader with strict security validation.
func NewDownloader(repo string) *Downloader {
	if repo == "" {
		repo = DefaultGitHubRepo
	}
	return &Downloader{
		AllowedRepo: repo,
		HTTPClient: &http.Client{
			Timeout: DownloadTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects during artifact download")
				}
				// Verify redirect destination is HTTPS
				if req.URL.Scheme != "https" {
					return fmt.Errorf("insecure redirect to non-HTTPS URL: %s", req.URL.String())
				}
				// Verify redirect destination belongs to GitHub download infrastructure
				host := strings.ToLower(req.URL.Hostname())
				if host != "github.com" &&
					host != "objects.githubusercontent.com" &&
					host != "github-releases.githubusercontent.com" &&
					!strings.HasSuffix(host, ".githubusercontent.com") {
					return fmt.Errorf("redirect to untrusted domain: %s", host)
				}
				return nil
			},
		},
		UserAgent: fmt.Sprintf("Felix-Auditor (+https://github.com/%s)", repo),
	}
}

// ValidateDownloadURL verifies that a download URL matches official GitHub release domains.
func (d *Downloader) ValidateDownloadURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid download URL: %w", err)
	}

	if u.Scheme != "https" {
		return fmt.Errorf("download URL must use HTTPS: %s", rawURL)
	}

	host := strings.ToLower(u.Hostname())
	if host != "github.com" &&
		host != "objects.githubusercontent.com" &&
		host != "github-releases.githubusercontent.com" &&
		!strings.HasSuffix(host, ".githubusercontent.com") {
		return fmt.Errorf("download URL domain not allowed: %s", host)
	}

	// For github.com, path must point to our official repository releases
	if host == "github.com" {
		expectedPrefix := fmt.Sprintf("/%s/releases/download/", d.AllowedRepo)
		if !strings.HasPrefix(u.Path, expectedPrefix) {
			return fmt.Errorf("download URL path does not match expected repository %s: %s", d.AllowedRepo, u.Path)
		}
	}

	return nil
}

// DownloadFile downloads a file from URL to destPath with size bounds and computes its SHA256 digest.
func (d *Downloader) DownloadFile(ctx context.Context, downloadURL, destPath string) (string, error) {
	if err := d.ValidateDownloadURL(downloadURL); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create download request: %w", err)
	}
	req.Header.Set("User-Agent", d.UserAgent)

	resp, err := d.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to download release artifact: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned HTTP %d for %s", resp.StatusCode, downloadURL)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return "", fmt.Errorf("failed to create destination file %s: %w", destPath, err)
	}
	defer out.Close()

	hasher := sha256.New()
	multiWriter := io.MultiWriter(out, hasher)

	// Bounded copy preventing unbounded download exhaustion
	limitedReader := io.LimitReader(resp.Body, MaxArchiveBytes)
	n, err := io.Copy(multiWriter, limitedReader)
	if err != nil {
		return "", fmt.Errorf("failed during artifact download: %w", err)
	}

	if n >= MaxArchiveBytes {
		return "", fmt.Errorf("download exceeded maximum allowed size of %d bytes", MaxArchiveBytes)
	}

	computedHash := hex.EncodeToString(hasher.Sum(nil))
	return computedHash, nil
}

// ParseChecksums parses a SHA256SUMS file into a map of filename -> sha256 hex string.
func ParseChecksums(r io.Reader) (map[string]string, error) {
	sums := make(map[string]string)
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 2 {
			hash := strings.ToLower(fields[0])
			fileName := strings.TrimPrefix(fields[1], "*")
			sums[fileName] = hash
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to parse checksums: %w", err)
	}

	return sums, nil
}
