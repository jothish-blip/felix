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
	"strings"
	"time"

	"felix/pkg/report"
	"felix/pkg/secrets"
)

// JiraProvider implements TrackerProvider for Jira Cloud and Jira Data Center / Server REST API.
type JiraProvider struct {
	cfg        TrackerConfig
	client     *http.Client
	baseURL    *url.URL
	projectKey string
	issueType  string
}

// NewJiraProvider constructs a new JiraProvider instance.
func NewJiraProvider(cfg TrackerConfig) (*JiraProvider, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, errors.New("Jira BaseURL cannot be empty")
	}
	if strings.TrimSpace(cfg.ProjectOrRepo) == "" {
		return nil, errors.New("Jira ProjectKey (ProjectOrRepo) cannot be empty")
	}

	parsedURL, err := ValidateEndpoint(cfg.BaseURL, cfg.SSRF)
	if err != nil {
		return nil, fmt.Errorf("invalid Jira BaseURL: %w", err)
	}

	issueType := strings.TrimSpace(cfg.IssueType)
	if issueType == "" {
		issueType = "Bug"
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

	return &JiraProvider{
		cfg:        cfg,
		client:     client,
		baseURL:    parsedURL,
		projectKey: strings.ToUpper(strings.TrimSpace(cfg.ProjectOrRepo)),
		issueType:  issueType,
	}, nil
}

func (p *JiraProvider) Name() string {
	return "jira"
}

func (p *JiraProvider) Platform() TrackerPlatform {
	return PlatformJira
}

func (p *JiraProvider) ValidateConfig() error {
	if p.baseURL == nil {
		return errors.New("Jira BaseURL not configured")
	}
	if p.projectKey == "" {
		return errors.New("Jira ProjectKey cannot be empty")
	}
	// Re-verify endpoint against SSRF policies
	if _, err := ValidateEndpoint(p.cfg.BaseURL, p.cfg.SSRF); err != nil {
		return fmt.Errorf("SSRF policy violation: %w", err)
	}
	return nil
}

// MapSeverityToJiraPriority maps FELIX canonical severities to standard Jira priorities.
func MapSeverityToJiraPriority(sev string) string {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case report.SeverityCritical:
		return "Highest"
	case report.SeverityHigh:
		return "High"
	case report.SeverityMedium:
		return "Medium"
	case report.SeverityLow:
		return "Low"
	case report.SeverityInfo:
		return "Lowest"
	default:
		return "Medium"
	}
}

// MapJiraStatusToState normalizes Jira status categories/names to TrackerIssueState.
func MapJiraStatusToState(statusName string) TrackerIssueState {
	s := strings.ToLower(strings.TrimSpace(statusName))
	switch s {
	case "closed", "resolved", "done", "fixed", "completed", "verified":
		return TrackerStateClosed
	case "in progress", "in review", "in development", "investigating":
		return TrackerStateInProgress
	case "open", "to do", "reopened", "new", "backlog":
		return TrackerStateOpen
	default:
		if strings.Contains(s, "done") || strings.Contains(s, "close") || strings.Contains(s, "resolve") {
			return TrackerStateClosed
		}
		return TrackerStateOpen
	}
}

func (p *JiraProvider) setAuthHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "FELIX-DefectTracker/3.0")

	if p.cfg.AuthType == "bearer" || p.cfg.Username == "" {
		if p.cfg.APIToken != "" {
			req.Header.Set("Authorization", "Bearer "+p.cfg.APIToken)
		}
	} else if p.cfg.Username != "" && (p.cfg.APIToken != "" || p.cfg.Password != "") {
		secret := p.cfg.APIToken
		if secret == "" {
			secret = p.cfg.Password
		}
		req.SetBasicAuth(p.cfg.Username, secret)
	}
}

// executeWithRetry executes an HTTP request with bounded exponential backoff and rate-limit handling.
func (p *JiraProvider) executeWithRetry(ctx context.Context, method, endpoint string, body []byte) (*http.Response, []byte, error) {
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
			return nil, nil, fmt.Errorf("failed creating Jira HTTP request: %w", err)
		}
		p.setAuthHeaders(httpReq)

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
			lastErr = fmt.Errorf("failed reading Jira response body: %w", readErr)
			if attempt < p.cfg.MaxRetries {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			break
		}

		// Handle HTTP 429 Rate Limiting
		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfter := ParseRetryAfter(resp.Header.Get("Retry-After"))
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
			return resp, respBody, fmt.Errorf("jira rate limit exceeded (HTTP 429)")
		}

		// Handle transient server errors (500, 502, 503, 504)
		if resp.StatusCode >= 500 && resp.StatusCode <= 504 {
			lastErr = fmt.Errorf("jira server error HTTP %d: %s", resp.StatusCode, secrets.RedactText(string(respBody)))
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
		return nil, nil, fmt.Errorf("jira request failed after %d retries: %s", p.cfg.MaxRetries, secrets.RedactText(lastErr.Error()))
	}
	return nil, nil, errors.New("jira request failed: max retries reached")
}

// CreateIssue creates a Jira ticket.
func (p *JiraProvider) CreateIssue(ctx context.Context, req CreateIssueRequest) (*ExternalIssue, error) {
	fields := map[string]any{
		"project": map[string]string{
			"key": p.projectKey,
		},
		"summary":     req.Title,
		"description": req.Description,
		"issuetype": map[string]string{
			"name": p.issueType,
		},
		"labels": req.Labels,
		"priority": map[string]string{
			"name": MapSeverityToJiraPriority(req.Severity),
		},
	}

	for k, v := range req.CustomFields {
		fields[k] = v
	}

	payload := map[string]any{
		"fields": fields,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling Jira issue payload: %w", err)
	}

	resp, respBytes, err := p.executeWithRetry(ctx, http.MethodPost, "/rest/api/2/issue", bodyBytes)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jira create issue returned HTTP %d: %s", resp.StatusCode, secrets.RedactText(string(respBytes)))
	}

	var parsed struct {
		ID   string `json:"id"`
		Key  string `json:"key"`
		Self string `json:"self"`
	}
	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return nil, fmt.Errorf("failed parsing Jira response: %w", err)
	}

	ticketURL := fmt.Sprintf("%s/browse/%s", strings.TrimRight(p.baseURL.String(), "/"), parsed.Key)

	return &ExternalIssue{
		ID:        parsed.ID,
		Key:       parsed.Key,
		URL:       ticketURL,
		Title:     req.Title,
		Severity:  req.Severity,
		State:     TrackerStateOpen,
		Status:    "Open",
		Labels:    req.Labels,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		Platform:  PlatformJira,
	}, nil
}

// UpdateIssue updates fields on an existing Jira issue.
func (p *JiraProvider) UpdateIssue(ctx context.Context, issueID string, req UpdateIssueRequest) (*ExternalIssue, error) {
	cleanID := strings.TrimSpace(issueID)
	if cleanID == "" {
		return nil, errors.New("issueID cannot be empty")
	}

	fields := make(map[string]any)
	if req.Title != "" {
		fields["summary"] = req.Title
	}
	if req.Description != "" {
		fields["description"] = req.Description
	}
	if req.Severity != "" {
		fields["priority"] = map[string]string{
			"name": MapSeverityToJiraPriority(req.Severity),
		}
	}
	if len(req.Labels) > 0 {
		fields["labels"] = req.Labels
	}
	for k, v := range req.CustomFields {
		fields[k] = v
	}

	payload := map[string]any{
		"fields": fields,
	}

	if req.UpdateComment != "" {
		payload["update"] = map[string]any{
			"comment": []map[string]any{
				{
					"add": map[string]string{
						"body": req.UpdateComment,
					},
				},
			},
		}
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling Jira update payload: %w", err)
	}

	endpoint := fmt.Sprintf("/rest/api/2/issue/%s", url.PathEscape(cleanID))
	resp, respBytes, err := p.executeWithRetry(ctx, http.MethodPut, endpoint, bodyBytes)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return nil, fmt.Errorf("jira update issue returned HTTP %d: %s", resp.StatusCode, secrets.RedactText(string(respBytes)))
	}

	return p.GetIssue(ctx, cleanID)
}

// GetIssue fetches issue details from Jira.
func (p *JiraProvider) GetIssue(ctx context.Context, issueID string) (*ExternalIssue, error) {
	cleanID := strings.TrimSpace(issueID)
	if cleanID == "" {
		return nil, errors.New("issueID cannot be empty")
	}

	endpoint := fmt.Sprintf("/rest/api/2/issue/%s", url.PathEscape(cleanID))
	resp, respBytes, err := p.executeWithRetry(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("jira issue %s not found (HTTP 404)", cleanID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jira get issue returned HTTP %d: %s", resp.StatusCode, secrets.RedactText(string(respBytes)))
	}

	var parsed struct {
		ID     string `json:"id"`
		Key    string `json:"key"`
		Fields struct {
			Summary     string `json:"summary"`
			Description string `json:"description"`
			Status      struct {
				Name string `json:"name"`
			} `json:"status"`
			Assignee *struct {
				DisplayName  string `json:"displayName"`
				EmailAddress string `json:"emailAddress"`
			} `json:"assignee"`
			Resolution *struct {
				Name string `json:"name"`
			} `json:"resolution"`
			Priority *struct {
				Name string `json:"name"`
			} `json:"priority"`
			Labels  []string `json:"labels"`
			Created string   `json:"created"`
			Updated string   `json:"updated"`
		} `json:"fields"`
	}

	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return nil, fmt.Errorf("failed parsing Jira issue JSON: %w", err)
	}

	statusName := parsed.Fields.Status.Name
	state := MapJiraStatusToState(statusName)

	var assignee string
	if parsed.Fields.Assignee != nil {
		assignee = parsed.Fields.Assignee.DisplayName
		if assignee == "" {
			assignee = parsed.Fields.Assignee.EmailAddress
		}
	}

	var resolution string
	if parsed.Fields.Resolution != nil {
		resolution = parsed.Fields.Resolution.Name
	}

	var sev string
	if parsed.Fields.Priority != nil {
		sev = parsed.Fields.Priority.Name
	}

	createdAt, _ := time.Parse(time.RFC3339, parsed.Fields.Created)
	updatedAt, _ := time.Parse(time.RFC3339, parsed.Fields.Updated)

	ticketURL := fmt.Sprintf("%s/browse/%s", strings.TrimRight(p.baseURL.String(), "/"), parsed.Key)

	var closedAt *time.Time
	if state.IsClosedOrResolved() {
		closedAt = &updatedAt
	}

	return &ExternalIssue{
		ID:          parsed.ID,
		Key:         parsed.Key,
		URL:         ticketURL,
		Title:       parsed.Fields.Summary,
		Description: parsed.Fields.Description,
		Severity:    sev,
		State:       state,
		Status:      statusName,
		Assignee:    assignee,
		Resolution:  resolution,
		Labels:      parsed.Fields.Labels,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
		ClosedAt:    closedAt,
		Platform:    PlatformJira,
	}, nil
}

// TransitionIssue transitions a Jira issue to a target state.
func (p *JiraProvider) TransitionIssue(ctx context.Context, issueID string, targetState TrackerIssueState, comment string) (*ExternalIssue, error) {
	cleanID := strings.TrimSpace(issueID)
	if cleanID == "" {
		return nil, errors.New("issueID cannot be empty")
	}

	// 1. Fetch available transitions
	endpoint := fmt.Sprintf("/rest/api/2/issue/%s/transitions", url.PathEscape(cleanID))
	resp, respBytes, err := p.executeWithRetry(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed fetching Jira transitions: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed fetching transitions (HTTP %d): %s", resp.StatusCode, secrets.RedactText(string(respBytes)))
	}

	var transResp struct {
		Transitions []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			To   struct {
				Name string `json:"name"`
			} `json:"to"`
		} `json:"transitions"`
	}
	if err := json.Unmarshal(respBytes, &transResp); err != nil {
		return nil, fmt.Errorf("failed parsing transitions JSON: %w", err)
	}

	// 2. Find best transition matching targetState
	var selectedID string
	for _, t := range transResp.Transitions {
		destState := MapJiraStatusToState(t.To.Name)
		if destState == targetState {
			selectedID = t.ID
			break
		}
		// Also match on transition name
		if MapJiraStatusToState(t.Name) == targetState {
			selectedID = t.ID
			break
		}
	}

	if selectedID == "" && len(transResp.Transitions) > 0 {
		// Fallback: pick transition containing keyword
		targetKeyword := "close"
		if targetState == TrackerStateOpen {
			targetKeyword = "reopen"
		} else if targetState == TrackerStateInProgress {
			targetKeyword = "progress"
		}
		for _, t := range transResp.Transitions {
			if strings.Contains(strings.ToLower(t.Name), targetKeyword) || strings.Contains(strings.ToLower(t.To.Name), targetKeyword) {
				selectedID = t.ID
				break
			}
		}
	}

	if selectedID == "" {
		// If no specific transition found, pick first available if closing/reopening, or return error
		if len(transResp.Transitions) > 0 {
			selectedID = transResp.Transitions[0].ID
		} else {
			return nil, fmt.Errorf("no valid transitions found to reach state %s for issue %s", targetState, cleanID)
		}
	}

	// 3. Post transition
	payload := map[string]any{
		"transition": map[string]string{
			"id": selectedID,
		},
	}
	if comment != "" {
		payload["update"] = map[string]any{
			"comment": []map[string]any{
				{
					"add": map[string]string{
						"body": comment,
					},
				},
			},
		}
	}

	bodyBytes, _ := json.Marshal(payload)
	postResp, postBytes, err := p.executeWithRetry(ctx, http.MethodPost, endpoint, bodyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed executing Jira transition: %w", err)
	}
	if postResp.StatusCode != http.StatusNoContent && postResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jira transition returned HTTP %d: %s", postResp.StatusCode, secrets.RedactText(string(postBytes)))
	}

	return p.GetIssue(ctx, cleanID)
}

// SearchIssues queries Jira for issues labeled with the finding ID.
func (p *JiraProvider) SearchIssues(ctx context.Context, query IssueSearchQuery) ([]ExternalIssue, error) {
	jqlClauses := []string{
		fmt.Sprintf("project = %q", p.projectKey),
	}
	if query.FindingID != "" {
		jqlClauses = append(jqlClauses, fmt.Sprintf("labels = %q", fmt.Sprintf("felix-finding-%s", query.FindingID)))
	}
	for _, l := range query.Labels {
		jqlClauses = append(jqlClauses, fmt.Sprintf("labels = %q", l))
	}

	jql := strings.Join(jqlClauses, " AND ")
	limit := query.Limit
	if limit <= 0 {
		limit = 10
	}

	endpoint := fmt.Sprintf("/rest/api/2/search?jql=%s&maxResults=%d", url.QueryEscape(jql), limit)
	resp, respBytes, err := p.executeWithRetry(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jira search returned HTTP %d: %s", resp.StatusCode, secrets.RedactText(string(respBytes)))
	}

	var searchResult struct {
		Issues []struct {
			ID     string `json:"id"`
			Key    string `json:"key"`
			Fields struct {
				Summary string `json:"summary"`
				Status  struct {
					Name string `json:"name"`
				} `json:"status"`
				Assignee *struct {
					DisplayName string `json:"displayName"`
				} `json:"assignee"`
				Labels []string `json:"labels"`
			} `json:"fields"`
		} `json:"issues"`
	}

	if err := json.Unmarshal(respBytes, &searchResult); err != nil {
		return nil, fmt.Errorf("failed parsing Jira search JSON: %w", err)
	}

	results := make([]ExternalIssue, 0, len(searchResult.Issues))
	for _, issue := range searchResult.Issues {
		var assignee string
		if issue.Fields.Assignee != nil {
			assignee = issue.Fields.Assignee.DisplayName
		}
		statusName := issue.Fields.Status.Name
		results = append(results, ExternalIssue{
			ID:       issue.ID,
			Key:      issue.Key,
			URL:      fmt.Sprintf("%s/browse/%s", strings.TrimRight(p.baseURL.String(), "/"), issue.Key),
			Title:    issue.Fields.Summary,
			Status:   statusName,
			State:    MapJiraStatusToState(statusName),
			Assignee: assignee,
			Labels:   issue.Fields.Labels,
			Platform: PlatformJira,
		})
	}

	return results, nil
}
