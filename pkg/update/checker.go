package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	DefaultGitHubRepo = "jothish-blip/felix"
	DefaultTimeout    = 15 * time.Second
)

// GitHubRelease represents a release object returned by the GitHub API.
type GitHubRelease struct {
	TagName     string        `json:"tag_name"`
	Name        string        `json:"name"`
	HTMLURL     string        `json:"html_url"`
	Draft       bool          `json:"draft"`
	Prerelease  bool          `json:"prerelease"`
	PublishedAt time.Time     `json:"published_at"`
	Body        string        `json:"body"`
	Assets      []GitHubAsset `json:"assets"`
}

// GitHubAsset represents a downloadable file attached to a GitHub release.
type GitHubAsset struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// CheckResult contains information about version status and availability.
type CheckResult struct {
	CurrentVersion  string
	LatestVersion   string
	UpdateAvailable bool
	ReleaseURL      string
	ReleaseName     string
	PublishedAt     time.Time
	ReleaseNotes    string
	Assets          []GitHubAsset
}

// Checker queries official release channels for updates.
type Checker struct {
	Repository string
	APIBaseURL string
	HTTPClient *http.Client
	UserAgent  string
}

// NewChecker returns a Checker configured with official GitHub defaults.
func NewChecker(repo string) *Checker {
	if repo == "" {
		repo = DefaultGitHubRepo
	}
	return &Checker{
		Repository: repo,
		APIBaseURL: "https://api.github.com",
		HTTPClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		UserAgent: fmt.Sprintf("Felix-Auditor (+https://github.com/%s)", repo),
	}
}

// CheckLatest queries the latest release and checks if a newer version exists.
func (c *Checker) CheckLatest(ctx context.Context, currentVersion string) (*CheckResult, error) {
	apiURL := fmt.Sprintf("%s/repos/%s/releases/latest", c.APIBaseURL, c.Repository)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create update check request: %w", err)
	}

	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to reach update service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no published releases found for repository %s", c.Repository)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("update check returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var rel GitHubRelease
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&rel); err != nil {
		return nil, fmt.Errorf("failed to parse release metadata: %w", err)
	}

	cleanLatest := CleanVersion(rel.TagName)
	cleanCurrent := CleanVersion(currentVersion)

	isNewer := false
	if cleanLatest != "" && cleanCurrent != "" {
		isNewer = IsNewer(cleanLatest, cleanCurrent)
	}

	return &CheckResult{
		CurrentVersion:  cleanCurrent,
		LatestVersion:   cleanLatest,
		UpdateAvailable: isNewer,
		ReleaseURL:      rel.HTMLURL,
		ReleaseName:     rel.Name,
		PublishedAt:     rel.PublishedAt,
		ReleaseNotes:    rel.Body,
		Assets:          rel.Assets,
	}, nil
}
