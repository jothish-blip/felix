package ci

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"felix/pkg/secrets"
)

const (
	DefaultGitHubAPIBaseURL = "https://api.github.com"
	DefaultCommentTag       = "<!-- felix-security-pr-comment -->"
)

// IssueComment represents a comment on a GitHub issue or pull request.
type IssueComment struct {
	ID        int64     `json:"id"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	User      struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"user"`
}

// PRReviewComment represents an inline code comment within a pull request review.
type PRReviewComment struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Side string `json:"side,omitempty"`
	Body string `json:"body"`
}

// PRReviewRequest defines the payload for creating a pull request review.
type PRReviewRequest struct {
	CommitID string            `json:"commit_id,omitempty"`
	Body     string            `json:"body"`
	Event    string            `json:"event"` // e.g. "COMMENT"
	Comments []PRReviewComment `json:"comments,omitempty"`
}

// PRReviewResponse represents the response from creating a pull request review.
type PRReviewResponse struct {
	ID       int64  `json:"id"`
	State    string `json:"state"`
	HTMLURL  string `json:"html_url"`
	CommitID string `json:"commit_id"`
	Body     string `json:"body"`
}

// GitHubClient handles interaction with the GitHub REST API for pull-request feedback.
type GitHubClient struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
	UserAgent  string
}

// NewGitHubClient creates a configured GitHubClient.
func NewGitHubClient(baseURL, token string) *GitHubClient {
	cleanBase := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if cleanBase == "" {
		cleanBase = DefaultGitHubAPIBaseURL
	}
	return &GitHubClient{
		BaseURL:    cleanBase,
		Token:      strings.TrimSpace(token),
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
		UserAgent:  "felix-security-ci/1.0",
	}
}

// executeRequest performs an authenticated HTTP request and decodes the JSON response.
func (c *GitHubClient) executeRequest(ctx context.Context, method, path string, reqBody, respTarget any) error {
	url := fmt.Sprintf("%s%s", c.BaseURL, path)

	var bodyReader io.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("failed marshaling request payload: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("failed creating HTTP request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", c.UserAgent)
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		// Ensure token does not leak in error message
		errMsg := err.Error()
		if c.Token != "" {
			errMsg = strings.ReplaceAll(errMsg, c.Token, "[REDACTED_TOKEN]")
		}
		return fmt.Errorf("GitHub API network request to %s failed: %s", path, secrets.RedactText(errMsg))
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed reading GitHub API response from %s: %w", path, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		rawBody := string(respBytes)
		if c.Token != "" {
			rawBody = strings.ReplaceAll(rawBody, c.Token, "[REDACTED_TOKEN]")
		}
		redactedBody := secrets.RedactText(rawBody)
		return fmt.Errorf("GitHub API error (%s %s returned HTTP %d): %s", method, path, resp.StatusCode, redactedBody)
	}

	if respTarget != nil && len(respBytes) > 0 {
		if err := json.Unmarshal(respBytes, respTarget); err != nil {
			return fmt.Errorf("failed parsing GitHub API response JSON from %s: %w", path, err)
		}
	}

	return nil
}

// ListIssueComments retrieves comments on a given PR/issue with pagination support.
func (c *GitHubClient) ListIssueComments(ctx context.Context, owner, repo string, issueNumber int) ([]IssueComment, error) {
	var allComments []IssueComment
	page := 1
	const perPage = 100
	const maxPages = 10 // Safe cap at 1000 comments to prevent unbounded API loops

	for page <= maxPages {
		path := fmt.Sprintf("/repos/%s/%s/issues/%d/comments?per_page=%d&page=%d", owner, repo, issueNumber, perPage, page)
		var pageComments []IssueComment
		if err := c.executeRequest(ctx, http.MethodGet, path, nil, &pageComments); err != nil {
			return nil, err
		}
		allComments = append(allComments, pageComments...)
		if len(pageComments) < perPage {
			break
		}
		page++
	}
	return allComments, nil
}

// GetPRDiff retrieves the unified diff of a pull request.
func (c *GitHubClient) GetPRDiff(ctx context.Context, owner, repo string, prNumber int) (string, error) {
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d", owner, repo, prNumber)
	url := fmt.Sprintf("%s%s", c.BaseURL, path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed creating diff request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.diff")
	req.Header.Set("User-Agent", c.UserAgent)
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		errMsg := err.Error()
		if c.Token != "" {
			errMsg = strings.ReplaceAll(errMsg, c.Token, "[REDACTED_TOKEN]")
		}
		return "", fmt.Errorf("failed fetching PR diff: %s", secrets.RedactText(errMsg))
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("GitHub diff request returned HTTP %d", resp.StatusCode)
	}

	diffBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed reading PR diff: %w", err)
	}

	return string(diffBytes), nil
}

// CreateIssueComment creates a new comment on a PR/issue.
func (c *GitHubClient) CreateIssueComment(ctx context.Context, owner, repo string, issueNumber int, body string) (*IssueComment, error) {
	path := fmt.Sprintf("/repos/%s/%s/issues/%d/comments", owner, repo, issueNumber)
	payload := map[string]string{
		"body": secrets.RedactText(body),
	}
	var comment IssueComment
	if err := c.executeRequest(ctx, http.MethodPost, path, payload, &comment); err != nil {
		return nil, err
	}
	return &comment, nil
}

// UpdateIssueComment updates an existing comment by its ID.
func (c *GitHubClient) UpdateIssueComment(ctx context.Context, owner, repo string, commentID int64, body string) (*IssueComment, error) {
	path := fmt.Sprintf("/repos/%s/%s/issues/comments/%d", owner, repo, commentID)
	payload := map[string]string{
		"body": secrets.RedactText(body),
	}
	var comment IssueComment
	if err := c.executeRequest(ctx, http.MethodPatch, path, payload, &comment); err != nil {
		return nil, err
	}
	return &comment, nil
}

// CreatePRReview creates an inline code review on a pull request.
func (c *GitHubClient) CreatePRReview(ctx context.Context, owner, repo string, prNumber int, req PRReviewRequest) (*PRReviewResponse, error) {
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d/reviews", owner, repo, prNumber)
	// Sanitize comments
	sanitizedReq := req
	sanitizedReq.Body = secrets.RedactText(req.Body)
	for i := range sanitizedReq.Comments {
		sanitizedReq.Comments[i].Body = secrets.RedactText(sanitizedReq.Comments[i].Body)
	}

	var resp PRReviewResponse
	if err := c.executeRequest(ctx, http.MethodPost, path, sanitizedReq, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ListPRReviews retrieves existing pull request reviews.
func (c *GitHubClient) ListPRReviews(ctx context.Context, owner, repo string, prNumber int) ([]PRReviewResponse, error) {
	path := fmt.Sprintf("/repos/%s/%s/pulls/%d/reviews?per_page=100", owner, repo, prNumber)
	var reviews []PRReviewResponse
	if err := c.executeRequest(ctx, http.MethodGet, path, nil, &reviews); err != nil {
		return nil, err
	}
	return reviews, nil
}

// DetectPullRequestContext parses the GitHub event payload to determine PR number, commit SHA, and repository slug.
func DetectPullRequestContext(eventPath string) (prNumber int, headSHA, repoSlug string, err error) {
	if strings.TrimSpace(eventPath) == "" {
		eventPath = os.Getenv("GITHUB_EVENT_PATH")
	}
	if strings.TrimSpace(eventPath) == "" {
		return 0, "", "", fmt.Errorf("GITHUB_EVENT_PATH is not configured")
	}

	data, err := os.ReadFile(eventPath)
	if err != nil {
		return 0, "", "", fmt.Errorf("failed reading event file %s: %w", eventPath, err)
	}

	var eventPayload struct {
		Number      int `json:"number"`
		PullRequest struct {
			Number int `json:"number"`
			Head   struct {
				SHA string `json:"sha"`
			} `json:"head"`
		} `json:"pull_request"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	}

	if err := json.Unmarshal(data, &eventPayload); err != nil {
		return 0, "", "", fmt.Errorf("failed parsing event JSON: %w", err)
	}

	if eventPayload.PullRequest.Number > 0 {
		prNumber = eventPayload.PullRequest.Number
	} else if eventPayload.Number > 0 {
		prNumber = eventPayload.Number
	}

	headSHA = eventPayload.PullRequest.Head.SHA
	repoSlug = eventPayload.Repository.FullName

	return prNumber, headSHA, repoSlug, nil
}
