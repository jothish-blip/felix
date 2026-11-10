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

// ServiceNowProvider implements TrackerProvider for ServiceNow SecOps / Table API.
type ServiceNowProvider struct {
	cfg     TrackerConfig
	client  *http.Client
	baseURL *url.URL
	table   string
}

// NewServiceNowProvider constructs a new ServiceNowProvider.
func NewServiceNowProvider(cfg TrackerConfig) (*ServiceNowProvider, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, errors.New("ServiceNow BaseURL cannot be empty")
	}

	table := strings.TrimSpace(cfg.ProjectOrRepo)
	if table == "" {
		table = strings.TrimSpace(cfg.IssueType)
	}
	if table == "" {
		table = "sn_vul_vulnerable_item" // Standard SecOps Vulnerability Response table
	}

	parsedURL, err := ValidateEndpoint(cfg.BaseURL, cfg.SSRF)
	if err != nil {
		return nil, fmt.Errorf("invalid ServiceNow BaseURL: %w", err)
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

	return &ServiceNowProvider{
		cfg:     cfg,
		client:  client,
		baseURL: parsedURL,
		table:   table,
	}, nil
}

func (p *ServiceNowProvider) Name() string {
	return "servicenow"
}

func (p *ServiceNowProvider) Platform() TrackerPlatform {
	return PlatformServiceNow
}

func (p *ServiceNowProvider) ValidateConfig() error {
	if p.baseURL == nil {
		return errors.New("ServiceNow BaseURL not configured")
	}
	if p.table == "" {
		return errors.New("ServiceNow table cannot be empty")
	}
	if _, err := ValidateEndpoint(p.baseURL.String(), p.cfg.SSRF); err != nil {
		return fmt.Errorf("SSRF policy violation: %w", err)
	}
	return nil
}

// MapSeverityToServiceNowRisk maps canonical severities to standard ServiceNow risk rating (1=Critical, 2=High, 3=Medium, 4=Low, 5=Planning).
func MapSeverityToServiceNowRisk(sev string) string {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case report.SeverityCritical:
		return "1"
	case report.SeverityHigh:
		return "2"
	case report.SeverityMedium:
		return "3"
	case report.SeverityLow:
		return "4"
	case report.SeverityInfo:
		return "5"
	default:
		return "3"
	}
}

// MapServiceNowState normalizes ServiceNow integer or string states to TrackerIssueState.
// Common SecOps / Incident state mappings:
// 1 = New / Open
// 2 = In Progress / Work in progress
// 3 = Awaiting Implementation / On Hold
// 6 = Resolved
// 7 = Closed
// 8 = Canceled
func MapServiceNowState(state string) TrackerIssueState {
	s := strings.TrimSpace(state)
	switch s {
	case "1", "open", "new":
		return TrackerStateOpen
	case "2", "3", "in_progress", "under_investigation", "work_in_progress":
		return TrackerStateInProgress
	case "6", "resolved":
		return TrackerStateResolved
	case "7", "8", "closed", "canceled", "closed_complete":
		return TrackerStateClosed
	default:
		return TrackerStateOpen
	}
}

func (p *ServiceNowProvider) setHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "FELIX-DefectTracker/3.0")

	if p.cfg.AuthType == "bearer" || p.cfg.Username == "" {
		token := p.cfg.APIToken
		if token == "" {
			token = p.cfg.Password
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	} else if p.cfg.Username != "" && (p.cfg.Password != "" || p.cfg.APIToken != "") {
		secret := p.cfg.Password
		if secret == "" {
			secret = p.cfg.APIToken
		}
		req.SetBasicAuth(p.cfg.Username, secret)
	}
}

// executeWithRetry executes an HTTP request against ServiceNow with backoff and rate-limit handling.
func (p *ServiceNowProvider) executeWithRetry(ctx context.Context, method, endpoint string, body []byte) (*http.Response, []byte, error) {
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
			return nil, nil, fmt.Errorf("failed creating ServiceNow HTTP request: %w", err)
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
			lastErr = fmt.Errorf("failed reading ServiceNow response body: %w", readErr)
			if attempt < p.cfg.MaxRetries {
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			break
		}

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
			return resp, respBody, fmt.Errorf("servicenow rate limit exceeded (HTTP 429)")
		}

		if resp.StatusCode >= 500 && resp.StatusCode <= 504 {
			lastErr = fmt.Errorf("servicenow server error HTTP %d: %s", resp.StatusCode, secrets.RedactText(string(respBody)))
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
		return nil, nil, fmt.Errorf("servicenow request failed after %d retries: %s", p.cfg.MaxRetries, secrets.RedactText(lastErr.Error()))
	}
	return nil, nil, errors.New("servicenow request failed: max retries reached")
}

// CreateIssue creates a record in ServiceNow Table API.
func (p *ServiceNowProvider) CreateIssue(ctx context.Context, req CreateIssueRequest) (*ExternalIssue, error) {
	payload := map[string]any{
		"short_description": req.Title,
		"description":       req.Description,
		"risk_rating":       MapSeverityToServiceNowRisk(req.Severity),
		"state":             "1", // 1 = Open
		"correlation_id":    req.FindingID,
	}

	for k, v := range req.CustomFields {
		payload[k] = v
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling ServiceNow payload: %w", err)
	}

	endpoint := fmt.Sprintf("/api/now/table/%s", url.PathEscape(p.table))
	resp, respBytes, err := p.executeWithRetry(ctx, http.MethodPost, endpoint, bodyBytes)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("servicenow create issue returned HTTP %d: %s", resp.StatusCode, secrets.RedactText(string(respBytes)))
	}

	var parsed struct {
		Result struct {
			SysID            string `json:"sys_id"`
			Number           string `json:"number"`
			ShortDescription string `json:"short_description"`
			State            string `json:"state"`
			SysCreatedOn     string `json:"sys_created_on"`
		} `json:"result"`
	}

	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return nil, fmt.Errorf("failed parsing ServiceNow response JSON: %w", err)
	}

	key := parsed.Result.Number
	if key == "" {
		key = parsed.Result.SysID
	}

	recordURL := fmt.Sprintf("%s/nav_to.do?uri=%s.do?sys_id=%s",
		strings.TrimRight(p.baseURL.String(), "/"), p.table, parsed.Result.SysID)

	createdAt, _ := time.Parse("2006-01-02 15:04:05", parsed.Result.SysCreatedOn)
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	return &ExternalIssue{
		ID:        parsed.Result.SysID,
		Key:       key,
		URL:       recordURL,
		Title:     parsed.Result.ShortDescription,
		Severity:  req.Severity,
		State:     TrackerStateOpen,
		Status:    parsed.Result.State,
		Labels:    req.Labels,
		CreatedAt: createdAt,
		UpdatedAt: createdAt,
		Platform:  PlatformServiceNow,
	}, nil
}

// UpdateIssue updates an existing record in ServiceNow.
func (p *ServiceNowProvider) UpdateIssue(ctx context.Context, issueID string, req UpdateIssueRequest) (*ExternalIssue, error) {
	cleanID := strings.TrimSpace(issueID)
	if cleanID == "" {
		return nil, errors.New("issueID (sys_id) cannot be empty")
	}

	payload := make(map[string]any)
	if req.Title != "" {
		payload["short_description"] = req.Title
	}
	if req.Description != "" {
		payload["description"] = req.Description
	}
	if req.Severity != "" {
		payload["risk_rating"] = MapSeverityToServiceNowRisk(req.Severity)
	}
	if req.UpdateComment != "" {
		payload["work_notes"] = req.UpdateComment
	}
	for k, v := range req.CustomFields {
		payload[k] = v
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling ServiceNow update payload: %w", err)
	}

	endpoint := fmt.Sprintf("/api/now/table/%s/%s", url.PathEscape(p.table), url.PathEscape(cleanID))
	resp, respBytes, err := p.executeWithRetry(ctx, http.MethodPatch, endpoint, bodyBytes)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("servicenow update issue returned HTTP %d: %s", resp.StatusCode, secrets.RedactText(string(respBytes)))
	}

	return p.GetIssue(ctx, cleanID)
}

// GetIssue retrieves a record from ServiceNow.
func (p *ServiceNowProvider) GetIssue(ctx context.Context, issueID string) (*ExternalIssue, error) {
	cleanID := strings.TrimSpace(issueID)
	if cleanID == "" {
		return nil, errors.New("issueID (sys_id) cannot be empty")
	}

	endpoint := fmt.Sprintf("/api/now/table/%s/%s", url.PathEscape(p.table), url.PathEscape(cleanID))
	resp, respBytes, err := p.executeWithRetry(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("servicenow record %s not found (HTTP 404)", cleanID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("servicenow get issue returned HTTP %d: %s", resp.StatusCode, secrets.RedactText(string(respBytes)))
	}

	var parsed struct {
		Result struct {
			SysID            string `json:"sys_id"`
			Number           string `json:"number"`
			ShortDescription string `json:"short_description"`
			Description      string `json:"description"`
			State            string `json:"state"`
			AssignedTo       any    `json:"assigned_to"`
			CloseNotes       string `json:"close_notes"`
			RiskRating       string `json:"risk_rating"`
			SysCreatedOn     string `json:"sys_created_on"`
			SysUpdatedOn     string `json:"sys_updated_on"`
		} `json:"result"`
	}

	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return nil, fmt.Errorf("failed parsing ServiceNow response JSON: %w", err)
	}

	state := MapServiceNowState(parsed.Result.State)

	var assignee string
	if m, ok := parsed.Result.AssignedTo.(map[string]any); ok {
		if val, exists := m["display_value"]; exists {
			assignee = fmt.Sprintf("%v", val)
		}
	} else if s, ok := parsed.Result.AssignedTo.(string); ok {
		assignee = s
	}

	createdAt, _ := time.Parse("2006-01-02 15:04:05", parsed.Result.SysCreatedOn)
	updatedAt, _ := time.Parse("2006-01-02 15:04:05", parsed.Result.SysUpdatedOn)

	var closedAt *time.Time
	if state.IsClosedOrResolved() {
		closedAt = &updatedAt
	}

	key := parsed.Result.Number
	if key == "" {
		key = parsed.Result.SysID
	}

	recordURL := fmt.Sprintf("%s/nav_to.do?uri=%s.do?sys_id=%s",
		strings.TrimRight(p.baseURL.String(), "/"), p.table, parsed.Result.SysID)

	return &ExternalIssue{
		ID:          parsed.Result.SysID,
		Key:         key,
		URL:         recordURL,
		Title:       parsed.Result.ShortDescription,
		Description: parsed.Result.Description,
		State:       state,
		Status:      parsed.Result.State,
		Assignee:    assignee,
		Resolution:  parsed.Result.CloseNotes,
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
		ClosedAt:    closedAt,
		Platform:    PlatformServiceNow,
	}, nil
}

// TransitionIssue updates ServiceNow record state (e.g. resolve=6, close=7, reopen=1).
func (p *ServiceNowProvider) TransitionIssue(ctx context.Context, issueID string, targetState TrackerIssueState, comment string) (*ExternalIssue, error) {
	cleanID := strings.TrimSpace(issueID)
	if cleanID == "" {
		return nil, errors.New("issueID cannot be empty")
	}

	payload := make(map[string]any)
	if targetState.IsClosedOrResolved() {
		payload["state"] = "7" // 7 = Closed
		if comment != "" {
			payload["close_notes"] = comment
		}
	} else {
		payload["state"] = "1" // 1 = Open
		if comment != "" {
			payload["work_notes"] = comment
		}
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling transition payload: %w", err)
	}

	endpoint := fmt.Sprintf("/api/now/table/%s/%s", url.PathEscape(p.table), url.PathEscape(cleanID))
	resp, respBytes, err := p.executeWithRetry(ctx, http.MethodPatch, endpoint, bodyBytes)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("servicenow transition issue returned HTTP %d: %s", resp.StatusCode, secrets.RedactText(string(respBytes)))
	}

	return p.GetIssue(ctx, cleanID)
}

// SearchIssues queries ServiceNow records by correlation_id (Finding ID).
func (p *ServiceNowProvider) SearchIssues(ctx context.Context, query IssueSearchQuery) ([]ExternalIssue, error) {
	sysparmQuery := fmt.Sprintf("correlation_id=%s", query.FindingID)

	endpoint := fmt.Sprintf("/api/now/table/%s?sysparm_query=%s&sysparm_limit=10",
		url.PathEscape(p.table), url.QueryEscape(sysparmQuery))

	resp, respBytes, err := p.executeWithRetry(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("servicenow search returned HTTP %d: %s", resp.StatusCode, secrets.RedactText(string(respBytes)))
	}

	var parsed struct {
		Result []struct {
			SysID            string `json:"sys_id"`
			Number           string `json:"number"`
			ShortDescription string `json:"short_description"`
			State            string `json:"state"`
		} `json:"result"`
	}

	if err := json.Unmarshal(respBytes, &parsed); err != nil {
		return nil, fmt.Errorf("failed parsing ServiceNow search JSON: %w", err)
	}

	results := make([]ExternalIssue, 0, len(parsed.Result))
	for _, item := range parsed.Result {
		key := item.Number
		if key == "" {
			key = item.SysID
		}
		recordURL := fmt.Sprintf("%s/nav_to.do?uri=%s.do?sys_id=%s",
			strings.TrimRight(p.baseURL.String(), "/"), p.table, item.SysID)

		results = append(results, ExternalIssue{
			ID:       item.SysID,
			Key:      key,
			URL:      recordURL,
			Title:    item.ShortDescription,
			Status:   item.State,
			State:    MapServiceNowState(item.State),
			Platform: PlatformServiceNow,
		})
	}

	return results, nil
}
