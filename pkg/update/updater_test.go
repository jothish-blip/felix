package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func setupMockUpdater(t *testing.T, targetVer string, releaseAssets []GitHubAsset, handler func(url string) (*http.Response, error)) *Updater {
	t.Helper()
	u := NewUpdater("jothish-blip/felix", "1.0.0")

	// Mock Checker response
	cleanVer := CleanVersion(targetVer)
	rel := GitHubRelease{
		TagName: "v" + cleanVer,
		Name:    "Release " + cleanVer,
		HTMLURL: "https://github.com/jothish-blip/felix/releases/tag/v" + cleanVer,
		Assets:  releaseAssets,
	}
	relBytes, _ := json.Marshal(rel)

	checkerTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(relBytes)),
			Header:     make(http.Header),
		}, nil
	})
	u.Checker.HTTPClient = &http.Client{Transport: checkerTransport}

	downloaderTransport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return handler(req.URL.String())
	})
	u.Downloader.HTTPClient = &http.Client{Transport: downloaderTransport}

	return u
}

func TestUpdater_MissingChecksumManifestFailsClosed(t *testing.T) {
	archiveName, err := ArchiveName("2.0.0", runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("failed to get archive name: %v", err)
	}

	assets := []GitHubAsset{
		{
			ID:                 1,
			Name:               archiveName,
			Size:               1024,
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/" + archiveName,
		},
		// Missing SHA256SUMS asset entirely
	}

	u := setupMockUpdater(t, "2.0.0", assets, func(url string) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("dummy-data")),
			Header:     make(http.Header),
		}, nil
	})

	_, err = u.Update(context.Background(), UpdateOptions{TargetVersion: "2.0.0", DryRun: true})
	if err == nil {
		t.Fatalf("expected error when SHA256SUMS asset is missing from release, got nil")
	}
	if !strings.Contains(err.Error(), "SHA256SUMS manifest missing") {
		t.Errorf("expected error message about missing SHA256SUMS manifest, got: %v", err)
	}
}

func TestUpdater_ChecksumDownloadFailureFailsClosed(t *testing.T) {
	archiveName, err := ArchiveName("2.0.0", runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("failed to get archive name: %v", err)
	}

	assets := []GitHubAsset{
		{
			ID:                 1,
			Name:               archiveName,
			Size:               1024,
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/" + archiveName,
		},
		{
			ID:                 2,
			Name:               "SHA256SUMS",
			Size:               256,
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS",
		},
	}

	u := setupMockUpdater(t, "2.0.0", assets, func(url string) (*http.Response, error) {
		if strings.HasSuffix(url, "SHA256SUMS") {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(strings.NewReader("Server error")),
				Header:     make(http.Header),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("dummy-data")),
			Header:     make(http.Header),
		}, nil
	})

	_, err = u.Update(context.Background(), UpdateOptions{TargetVersion: "2.0.0", DryRun: true})
	if err == nil {
		t.Fatalf("expected error when SHA256SUMS download fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed downloading SHA256SUMS manifest") {
		t.Errorf("expected download failure error, got: %v", err)
	}
}

func TestUpdater_UnparseableChecksumManifestFailsClosed(t *testing.T) {
	archiveName, err := ArchiveName("2.0.0", runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("failed to get archive name: %v", err)
	}

	assets := []GitHubAsset{
		{
			ID:                 1,
			Name:               archiveName,
			Size:               1024,
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/" + archiveName,
		},
		{
			ID:                 2,
			Name:               "SHA256SUMS",
			Size:               256,
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS",
		},
	}

	u := setupMockUpdater(t, "2.0.0", assets, func(url string) (*http.Response, error) {
		if strings.HasSuffix(url, "SHA256SUMS") {
			// Empty / comment only manifest
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("# Only comments\n\n")),
				Header:     make(http.Header),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("dummy-data")),
			Header:     make(http.Header),
		}, nil
	})

	_, err = u.Update(context.Background(), UpdateOptions{TargetVersion: "2.0.0", DryRun: true})
	if err == nil {
		t.Fatalf("expected error when SHA256SUMS manifest has no entries, got nil")
	}
	if !strings.Contains(err.Error(), "contains no valid checksum entries") {
		t.Errorf("expected no valid entries error, got: %v", err)
	}
}

func TestUpdater_MissingTargetArchiveInManifestFailsClosed(t *testing.T) {
	archiveName, err := ArchiveName("2.0.0", runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("failed to get archive name: %v", err)
	}

	assets := []GitHubAsset{
		{
			ID:                 1,
			Name:               archiveName,
			Size:               1024,
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/" + archiveName,
		},
		{
			ID:                 2,
			Name:               "SHA256SUMS",
			Size:               256,
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS",
		},
	}

	u := setupMockUpdater(t, "2.0.0", assets, func(url string) (*http.Response, error) {
		if strings.HasSuffix(url, "SHA256SUMS") {
			// Manifest with unrelated file
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("da30a272f4343fe82ffa718e898abe6967b8d2c13ff2584d46e4b68706295608  some_other_file.tar.gz\n")),
				Header:     make(http.Header),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("dummy-data")),
			Header:     make(http.Header),
		}, nil
	})

	_, err = u.Update(context.Background(), UpdateOptions{TargetVersion: "2.0.0", DryRun: true})
	if err == nil {
		t.Fatalf("expected error when target archive is missing from SHA256SUMS, got nil")
	}
	if !strings.Contains(err.Error(), "not found in SHA256SUMS manifest") {
		t.Errorf("expected target archive not found error, got: %v", err)
	}
}

func TestUpdater_MalformedDigestInManifestFailsClosed(t *testing.T) {
	archiveName, err := ArchiveName("2.0.0", runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("failed to get archive name: %v", err)
	}

	assets := []GitHubAsset{
		{
			ID:                 1,
			Name:               archiveName,
			Size:               1024,
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/" + archiveName,
		},
		{
			ID:                 2,
			Name:               "SHA256SUMS",
			Size:               256,
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS",
		},
	}

	u := setupMockUpdater(t, "2.0.0", assets, func(url string) (*http.Response, error) {
		if strings.HasSuffix(url, "SHA256SUMS") {
			// Manifest with invalid 32-char or non-hex digest
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("not-a-valid-sha256-hash  %s\n", archiveName))),
				Header:     make(http.Header),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("dummy-data")),
			Header:     make(http.Header),
		}, nil
	})

	_, err = u.Update(context.Background(), UpdateOptions{TargetVersion: "2.0.0", DryRun: true})
	if err == nil {
		t.Fatalf("expected error when digest is malformed, got nil")
	}
	if !strings.Contains(err.Error(), "malformed SHA256 digest") {
		t.Errorf("expected malformed digest error, got: %v", err)
	}
}

func TestUpdater_ChecksumMismatchFailsClosed(t *testing.T) {
	archiveName, err := ArchiveName("2.0.0", runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("failed to get archive name: %v", err)
	}

	assets := []GitHubAsset{
		{
			ID:                 1,
			Name:               archiveName,
			Size:               1024,
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/" + archiveName,
		},
		{
			ID:                 2,
			Name:               "SHA256SUMS",
			Size:               256,
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS",
		},
	}

	manifestHash := "1111111111111111111111111111111111111111111111111111111111111111"
	dummyArchiveData := "real-downloaded-archive-content"

	u := setupMockUpdater(t, "2.0.0", assets, func(url string) (*http.Response, error) {
		if strings.HasSuffix(url, "SHA256SUMS") {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("%s  %s\n", manifestHash, archiveName))),
				Header:     make(http.Header),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(dummyArchiveData)),
			Header:     make(http.Header),
		}, nil
	})

	_, err = u.Update(context.Background(), UpdateOptions{TargetVersion: "2.0.0", DryRun: true})
	if err == nil {
		t.Fatalf("expected error on SHA256 mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "CRITICAL: SHA256 mismatch") {
		t.Errorf("expected critical SHA256 mismatch error, got: %v", err)
	}
}

func TestUpdater_ValidChecksumSucceedsInDryRun(t *testing.T) {
	archiveName, err := ArchiveName("2.0.0", runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("failed to get archive name: %v", err)
	}

	archiveContent := "valid-archive-test-content-for-hash"
	h := sha256.Sum256([]byte(archiveContent))
	expectedHash := hex.EncodeToString(h[:])

	assets := []GitHubAsset{
		{
			ID:                 1,
			Name:               archiveName,
			Size:               int64(len(archiveContent)),
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/" + archiveName,
		},
		{
			ID:                 2,
			Name:               "SHA256SUMS",
			Size:               256,
			BrowserDownloadURL: "https://github.com/jothish-blip/felix/releases/download/v2.0.0/SHA256SUMS",
		},
	}

	u := setupMockUpdater(t, "2.0.0", assets, func(url string) (*http.Response, error) {
		if strings.HasSuffix(url, "SHA256SUMS") {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(fmt.Sprintf("%s  %s\n", expectedHash, archiveName))),
				Header:     make(http.Header),
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(archiveContent)),
			Header:     make(http.Header),
		}, nil
	})

	res, err := u.Update(context.Background(), UpdateOptions{TargetVersion: "2.0.0", DryRun: true})
	if err != nil {
		t.Fatalf("expected dry-run update to succeed with valid hash, got: %v", err)
	}
	if res.UpdatedVersion != "2.0.0" {
		t.Errorf("expected UpdatedVersion 2.0.0, got: %s", res.UpdatedVersion)
	}
	if res.ArchiveFile != archiveName {
		t.Errorf("expected ArchiveFile %s, got: %s", archiveName, res.ArchiveFile)
	}
}
