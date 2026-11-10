package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"felix/pkg/secrets"
)

// GitHubIssuesProvider implements TrackerProvider for GitHub Issues REST API.
type GitHubIssuesProvider struct {
	cfg     TrackerConfig
	client  *http.Client
	baseURL *url.URL
	owner   string
	repo    string
}

// NewGitHubIssuesProvider constructs a new GitHubIssuesProvider instance.
func NewGitHubIssuesProvider(cfg TrackerConfig) (*GitHubIssuesProvider, error) {
	rawURL := strings.TrimSpace(cfg.BaseURL)
	if rawURL == "" {
		rawURL = "https://api.github.com"
	}

	parts := strings.Split(strings.TrimSpace(cfg.ProjectOrRepo), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, errors.New("GitHub repository must be formatted as 'owner/repo'")
	}

	parsedURL, err := ValidateEndpoint(rawURL, cfg.SSRF)
	if err != nil {
		return nil, fmt.Errorf("invalid GitHub BaseURL: %w", err)
	}

	client := cfg.HTTPClient
	if client == nil {
		client = BuildSafeHTTPClient(cfg.Timeout)
	}

	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 100 * time.Millisecond
	}

	return &GitHubIssuesProvider{
		cfg:     cfg,
		client:  client,
		baseURL: parsedURL,
		owner:   parts[0],
		repo:    parts[1],
	}, nil
}

func (p *GitHubIssuesProvider) Name() string {
	return "github"
}

func (p *GitHubIssuesProvider) Platform() TrackerPlatform {
	return PlatformGitHub
}

func (p *GitHubIssuesProvider) ValidateConfig() error {
	if p.baseURL == nil {
		return errors.New("GitHub BaseURL not configured")
	}
	if p.owner == "" || p.repo == "" {
		return errors.New("GitHub repository owner/repo cannot be empty")
	}
	if _, err := ValidateEndpoint(p.baseURL.String(), p.cfg.SSRF); err != nil {
		return fmt.Errorf("SSRF policy violation: %w", err)
	}
	return nil
}

func (p *GitHubIssuesProvider) setHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "FELIX-DefectTracker/3.0")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	token := strings.TrimSpace(p.cfg.APIToken)
	if token == "" {
		token = strings.TrimSpace(p.cfg.Password)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

// executeWithRetry executes an HTTP request against GitHub with bounded backoff and rate limit handling.
func (p *GitHubIssuesProvider) executeWithRetry(ctx context.Context, method, endpoint string, body []byte) (*http.Response, []byte, error) {
	fullURL := strings.TrimRight(p.baseURL.String(), "/") + endpoint

	var lastErr error
	backoff := p.cfg.BackoffBase

	for attempt := 0; attempt <= p.cfg.MaxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

		var bodyReader io.Reader
		if body != nil {
			bodyReader = bytes.NewReader(body)
		}

		httpReq, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed creating GitHub HTTP request: %w", err)
		}
		p.setHeaders(httpReq)

		resp, err := p.client.Do(httpReq)
		if err != nil {
			lastErr = err
			if attempt < p.cfg.MaxRetries {
				select {
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				case <-time.After(backoff):
					backoff *= 2
					continue
				}
			}
			break
		}

		respBody, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("failed reading GitHub response body: %w", readErr)
			if attempt < p.cfg.MaxRetries {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			break
		}

		// Handle HTTP 429 Rate Limiting or primary GitHub rate limit headers
		if resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode == http.StatusForbidden && strings.Contains(strings.ToLower(string(respBody)), "rate limit")) {
			retryAfter := ParseRetryAfter(resp.Header.Get("Retry-After"))
			if retryAfter <= 0 {
				resetHeader := resp.Header.Get("x-ratelimit-reset")
				if resetHeader != "" {
					if resetEpoch, err := strconv.ParseInt(resetHeader, 10, 64); err == nil {
						diff := time.Until(time.Unix(resetEpoch, 0))
						if diff > 0 && diff < 30*time.Second {
							retryAfter = diff
						}
					}
				}
			}
			if retryAfter <= 0 {
				retryAfter = backoff
			}

			if attempt < p.cfg.MaxRetries {
				select {
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				case <-time.After(retryAfter):
					backoff *= 2
					continue
				}
			}
			return resp, respBody, fmt.Errorf("github rate limit exceeded (HTTP %d)", resp.StatusCode)
		}

		// Handle transient 5xx server errors
		if resp.StatusCode >= 500 && resp.StatusCode <= 504 {
			lastErr = fmt.Errorf("github server error HTTP %d: %s", resp.StatusCode, secrets.RedactText(string(respBody)))
			if attempt < p.cfg.MaxRetries {
				select {
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				case <-time.After(backoff):
					backoff *= 2
					continue
				}
			}
			return resp, respBody, lastErr
		}

		return resp, respBody, nil
	}

	if lastErr != nil {
		return nil, nil, fmt.Errorf("github request failed after %d retries: %s", p.cfg.MaxRetries, secrets.RedactText(lastErr.Error()))
	}
	return nil, nil, errors.New("github request failed: max retries reached")
}

// MapGitHubState normalizes GitHub state strings to TrackerIssueState.
func MapGitHubState(state, stateReason string) TrackerIssueState {
	s := strings.ToLower(strings.TrimSpace(state))
	if s == "closed" {
		return TrackerStateClosed
	}
	return TrackerStateOpen
}

// CreateIssue creates a GitHub Issue.
func (p *GitHubIssuesProvider) CreateIssue(ctx context.Context, req CreateIssueRequest) (*ExternalIssue, error) {
	labels := req.Labels
	if len(labels) == 0 {
		labels = []string{"security", "felix", fmt.Sprintf("felix-finding-%s", req.FindingID)}
	}

	payload := map[string]any{
		"title":  req.Title,
		"body":   req.Description,
		"labels": labels,
	}

	for k, v := range req.CustomFields {
		payload[k] = v
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling GitHub issue payload: %w", err)
	}

	endpoint := fmt.Sprintf("/repos/%s/%s/issues", url.PathEscape(p.owner), url.PathEscape(p.repo))
	resp, respBytes, err := p.executeWithRetry(ctx, http.MethodPost, endpoint, bodyBytes)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github create issue returned HTTP %d: %s", resp.StatusCode, secrets.RedactText(string(respBytes)))
	}

	var parsed struct {
		ID        int64    `json:"id"`
		Number    int64    `json:"number"`
		HTMLURL   string   `json:"html_url"`
		Title     string   `json:"title"`
		State     string   `json:"state"`
		CreatedAt string   `json:"created_at"`
		Labels    []struct {
			Name string `json:"name"`
		} `json:"labels"`
	}

	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return nil, fmt.Errorf("failed parsing GitHub issue response JSON: %w", err)
	}

	issueKey := fmt.Sprintf("#%d", parsed.Number)
	issueID := strconv.FormatInt(parsed.Number, 10)

	labelNames := make([]string, 0, len(parsed.Labels))
	for _, l := range parsed.Labels {
		labelNames = append(labelNames, l.Name)
	}

	createdAt, _ := time.Parse(time.RFC3339, parsed.CreatedAt)
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	return &ExternalIssue{
		ID:        issueID,
		Key:       issueKey,
		URL:       parsed.HTMLURL,
		Title:     parsed.Title,
		Severity:  req.Severity,
		State:     TrackerStateOpen,
		Status:    parsed.State,
		Labels:    labelNames,
		CreatedAt: createdAt,
		UpdatedAt: createdAt,
		Platform:  PlatformGitHub,
	}, nil
}

// UpdateIssue updates an existing GitHub Issue.
func (p *GitHubIssuesProvider) UpdateIssue(ctx context.Context, issueID string, req UpdateIssueRequest) (*ExternalIssue, error) {
	cleanID := strings.TrimSpace(issueID)
	if cleanID == "" {
		return nil, errors.New("issueID cannot be empty")
	}

	payload := make(map[string]any)
	if req.Title != "" {
		payload["title"] = req.Title
	}
	if req.Description != "" {
		payload["body"] = req.Description
	}
	if len(req.Labels) > 0 {
		payload["labels"] = req.Labels
	}
	for k, v := range req.CustomFields {
		payload[k] = v
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling GitHub update payload: %w", err)
	}

	endpoint := fmt.Sprintf("/repos/%s/%s/issues/%s", url.PathEscape(p.owner), url.PathEscape(p.repo), url.PathEscape(cleanID))
	resp, respBytes, err := p.executeWithRetry(ctx, http.MethodPatch, endpoint, bodyBytes)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github update issue returned HTTP %d: %s", resp.StatusCode, secrets.RedactText(string(respBytes)))
	}

	// Post update comment if provided
	if req.UpdateComment != "" {
		commentPayload := map[string]string{"body": req.UpdateComment}
		cBytes, _ := json.Marshal(commentPayload)
		commentEndpoint := fmt.Sprintf("/repos/%s/%s/issues/%s/comments", url.PathEscape(p.owner), url.PathEscape(p.repo), url.PathEscape(cleanID))
		_, _, _ = p.executeWithRetry(ctx, http.MethodPost, commentEndpoint, cBytes)
	}

	return p.GetIssue(ctx, cleanID)
}

// GetIssue retrieves a GitHub Issue by issue number.
func (p *GitHubIssuesProvider) GetIssue(ctx context.Context, issueID string) (*ExternalIssue, error) {
	cleanID := strings.TrimSpace(issueID)
	if cleanID == "" {
		return nil, errors.New("issueID cannot be empty")
	}

	endpoint := fmt.Sprintf("/repos/%s/%s/issues/%s", url.PathEscape(p.owner), url.PathEscape(p.repo), url.PathEscape(cleanID))
	resp, respBytes, err := p.executeWithRetry(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("github issue %s not found (HTTP 404)", cleanID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github get issue returned HTTP %d: %s", resp.StatusCode, secrets.RedactText(string(respBytes)))
	}

	var parsed struct {
		ID          int64   `json:"id"`
		Number      int64   `json:"number"`
		HTMLURL     string  `json:"html_url"`
		Title       string  `json:"title"`
		Body        string  `json:"body"`
		State       string  `json:"state"`
		StateReason *string `json:"state_reason"`
		Assignee    *struct {
			Login string `json:"login"`
		} `json:"assignee"`
		Labels []struct {
			Name string `json:"name"`
		} `json:"labels"`
		CreatedAt string  `json:"created_at"`
		UpdatedAt string  `json:"updated_at"`
		ClosedAt  *string `json:"closed_at"`
	}

	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return nil, fmt.Errorf("failed parsing GitHub issue JSON: %w", err)
	}

	var stateReason string
	if parsed.StateReason != nil {
		stateReason = *parsed.StateReason
	}
	state := MapGitHubState(parsed.State, stateReason)

	var assignee string
	if parsed.Assignee != nil {
		assignee = parsed.Assignee.Login
	}

	labelNames := make([]string, 0, len(parsed.Labels))
	var sev string
	for _, l := range parsed.Labels {
		labelNames = append(labelNames, l.Name)
		if strings.HasPrefix(l.Name, "severity:") || strings.HasPrefix(l.Name, "severity-") {
			sev = strings.TrimPrefix(strings.TrimPrefix(l.Name, "severity:"), "severity-")
		}
	}

	createdAt, _ := time.Parse(time.RFC3339, parsed.CreatedAt)
	updatedAt, _ := time.Parse(time.RFC3339, parsed.UpdatedAt)

	var closedAt *time.Time
	if parsed.ClosedAt != nil && *parsed.ClosedAt != "" {
		if t, err := time.Parse(time.RFC3339, *parsed.ClosedAt); err == nil {
			closedAt = &t
		}
	}

	return &ExternalIssue{
		ID:          strconv.FormatInt(parsed.Number, 10),
		Key:         fmt.Sprintf("#%d", parsed.Number),
		URL:         parsed.HTMLURL,
		Title:       parsed.Title,
		Description: parsed.Body,
		Severity:    sev,
		State:       state,
		Status:      parsed.State,
		Assignee:    assignee,
		Resolution:  stateReason,
		Labels:      labelNames,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
		ClosedAt:    closedAt,
		Platform:    PlatformGitHub,
	}, nil
}

// TransitionIssue opens or closes a GitHub Issue.
func (p *GitHubIssuesProvider) TransitionIssue(ctx context.Context, issueID string, targetState TrackerIssueState, comment string) (*ExternalIssue, error) {
	cleanID := strings.TrimSpace(issueID)
	if cleanID == "" {
		return nil, errors.New("issueID cannot be empty")
	}

	payload := make(map[string]any)
	if targetState.IsClosedOrResolved() {
		payload["state"] = "closed"
		payload["state_reason"] = "completed"
	} else {
		payload["state"] = "open"
		payload["state_reason"] = "reopened"
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling transition payload: %w", err)
	}

	endpoint := fmt.Sprintf("/repos/%s/%s/issues/%s", url.PathEscape(p.owner), url.PathEscape(p.repo), url.PathEscape(cleanID))
	resp, respBytes, err := p.executeWithRetry(ctx, http.MethodPatch, endpoint, bodyBytes)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github transition issue returned HTTP %d: %s", resp.StatusCode, secrets.RedactText(string(respBytes)))
	}

	if comment != "" {
		cPayload := map[string]string{"body": comment}
		cBytes, _ := json.Marshal(cPayload)
		commentEndpoint := fmt.Sprintf("/repos/%s/%s/issues/%s/comments", url.PathEscape(p.owner), url.PathEscape(p.repo), url.PathEscape(cleanID))
		_, _, _ = p.executeWithRetry(ctx, http.MethodPost, commentEndpoint, cBytes)
	}

	return p.GetIssue(ctx, cleanID)
}

// SearchIssues queries GitHub for issues labeled with the finding ID.
func (p *GitHubIssuesProvider) SearchIssues(ctx context.Context, query IssueSearchQuery) ([]ExternalIssue, error) {
	findingLabel := fmt.Sprintf("felix-finding-%s", query.FindingID)
	labels := []string{findingLabel}
	labels = append(labels, query.Labels...)

	endpoint := fmt.Sprintf("/repos/%s/%s/issues?labels=%s&state=all&per_page=10",
		url.PathEscape(p.owner),
		url.PathEscape(p.repo),
		url.QueryEscape(strings.Join(labels, ",")),
	)

	resp, respBytes, err := p.executeWithRetry(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github search issues returned HTTP %d: %s", resp.StatusCode, secrets.RedactText(string(respBytes)))
	}

	var parsedList []struct {
		Number  int64  `json:"number"`
		HTMLURL string `json:"html_url"`
		Title   string `json:"title"`
		State   string `json:"state"`
		Labels  []struct {
			Name string `json:"name"`
		} `json:"labels"`
	}

	if err := json.Unmarshal(respBytes, &parsedList); err != nil {
		return nil, fmt.Errorf("failed parsing GitHub search JSON: %w", err)
	}

	results := make([]ExternalIssue, 0, len(parsedList))
	for _, item := range parsedList {
		labelNames := make([]string, 0, len(item.Labels))
		for _, l := range item.Labels {
			labelNames = append(labelNames, l.Name)
		}
		results = append(results, ExternalIssue{
			ID:       strconv.FormatInt(item.Number, 10),
			Key:      fmt.Sprintf("#%d", item.Number),
			URL:      item.HTMLURL,
			Title:    item.Title,
			Status:   item.State,
			State:    MapGitHubState(item.State, ""),
			Labels:   labelNames,
			Platform: PlatformGitHub,
		})
	}

	return results, nil
}
