package notify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"felix/pkg/report"
	"felix/pkg/secrets"
)

// TrackerPlatform identifies the external defect tracker platform.
type TrackerPlatform string

const (
	PlatformJira       TrackerPlatform = "jira"
	PlatformGitHub     TrackerPlatform = "github"
	PlatformServiceNow TrackerPlatform = "servicenow"
)

// TrackerIssueState represents the normalized lifecycle state of an issue in a defect tracker.
type TrackerIssueState string

const (
	TrackerStateOpen       TrackerIssueState = "OPEN"
	TrackerStateInProgress TrackerIssueState = "IN_PROGRESS"
	TrackerStateResolved   TrackerIssueState = "RESOLVED"
	TrackerStateClosed     TrackerIssueState = "CLOSED"
	TrackerStateUnknown    TrackerIssueState = "UNKNOWN"
)

// IsClosedOrResolved returns true if the issue state indicates external completion.
func (s TrackerIssueState) IsClosedOrResolved() bool {
	return s == TrackerStateResolved || s == TrackerStateClosed
}

// ExternalIssue represents a defect ticket in an external tracker.
type ExternalIssue struct {
	ID          string            `json:"id"`                     // Unique platform identifier (e.g. "10001" or "sys_123")
	Key         string            `json:"key"`                    // Human-readable key (e.g. "SEC-101", "#42", "VUL001001")
	URL         string            `json:"url"`                    // Web URL for viewing the ticket
	Title       string            `json:"title"`                  // Summary / Title
	Description string            `json:"description,omitempty"`  // Full issue description
	Severity    string            `json:"severity,omitempty"`     // External priority / severity
	State       TrackerIssueState `json:"state"`                  // Normalized state
	Status      string            `json:"status"`                 // Raw platform status string (e.g. "Done", "closed", "Resolved")
	Assignee    string            `json:"assignee,omitempty"`     // Assigned engineer / team
	Resolution  string            `json:"resolution,omitempty"`   // Resolution reason (e.g. "Fixed", "Won't Fix", "completed")
	Labels      []string          `json:"labels,omitempty"`       // Associated labels / tags
	CreatedAt   time.Time         `json:"created_at"`             // Creation timestamp
	UpdatedAt   time.Time         `json:"updated_at"`             // Last update timestamp
	ClosedAt    *time.Time        `json:"closed_at,omitempty"`    // Closure timestamp if resolved/closed
	Platform    TrackerPlatform   `json:"platform"`               // Originating tracker platform
	RawFields   map[string]any    `json:"raw_fields,omitempty"`   // Additional platform-specific attributes
}

// CreateIssueRequest encapsulates all data required to instantiate a ticket from a security finding.
type CreateIssueRequest struct {
	FindingID                string              `json:"finding_id"`
	RuleID                   string              `json:"rule_id,omitempty"`
	Title                    string              `json:"title"`
	Description              string              `json:"description"`
	Severity                 string              `json:"severity"`
	CVSS                     float64             `json:"cvss,omitempty"`
	CVSSVector               string              `json:"cvss_vector,omitempty"`
	Target                   string              `json:"target"`
	Endpoint                 string              `json:"endpoint,omitempty"`
	PrimaryAssetID           string              `json:"primary_asset_id,omitempty"`
	CWE                      string              `json:"cwe,omitempty"`
	CVE                      string              `json:"cve,omitempty"`
	ReproductionSteps        []string            `json:"reproduction_steps,omitempty"`
	SafeCurlCommand          string              `json:"safe_curl_command,omitempty"`
	EvidenceDigest           string              `json:"evidence_digest,omitempty"`
	EvidenceLocation         string              `json:"evidence_location,omitempty"`
	Remediation              string              `json:"remediation,omitempty"`
	AssessmentID             string              `json:"assessment_id,omitempty"`
	FindingStatus            report.FindingStatus `json:"finding_status"`
	AnalysisMethod           string              `json:"analysis_method,omitempty"`
	VerificationStatus       string              `json:"verification_status,omitempty"`
	VerificationResult       string              `json:"verification_result,omitempty"`
	SourceEngine             string              `json:"source_engine,omitempty"`
	SyntheticFixture         bool                `json:"synthetic_fixture,omitempty"`
	Labels                   []string            `json:"labels,omitempty"`
	CustomFields             map[string]any      `json:"custom_fields,omitempty"`
}

// UpdateIssueRequest encapsulates updates for an existing tracker ticket.
type UpdateIssueRequest struct {
	Title             string         `json:"title,omitempty"`
	Description       string         `json:"description,omitempty"`
	Severity          string         `json:"severity,omitempty"`
	CVSS              float64        `json:"cvss,omitempty"`
	CVSSVector        string         `json:"cvss_vector,omitempty"`
	Remediation       string         `json:"remediation,omitempty"`
	Labels            []string       `json:"labels,omitempty"`
	CustomFields      map[string]any `json:"custom_fields,omitempty"`
	UpdateComment     string         `json:"update_comment,omitempty"`
}

// IssueSearchQuery defines search parameters to query tickets by finding identity.
type IssueSearchQuery struct {
	FindingID  string            `json:"finding_id"`
	Labels     []string          `json:"labels,omitempty"`
	State      TrackerIssueState `json:"state,omitempty"`
	Limit      int               `json:"limit,omitempty"`
}

// TrackerProvider defines the pluggable adapter interface for defect trackers.
type TrackerProvider interface {
	// Name returns the descriptive name of the provider.
	Name() string

	// Platform returns the canonical TrackerPlatform.
	Platform() TrackerPlatform

	// ValidateConfig validates provider settings, endpoints, and credentials without making live mutations.
	ValidateConfig() error

	// CreateIssue creates a new issue in the tracker.
	CreateIssue(ctx context.Context, req CreateIssueRequest) (*ExternalIssue, error)

	// UpdateIssue updates an existing issue with new finding details.
	UpdateIssue(ctx context.Context, issueID string, req UpdateIssueRequest) (*ExternalIssue, error)

	// GetIssue retrieves the current status and fields of an existing issue.
	GetIssue(ctx context.Context, issueID string) (*ExternalIssue, error)

	// TransitionIssue updates the issue workflow state (e.g. resolve, close, reopen).
	TransitionIssue(ctx context.Context, issueID string, targetState TrackerIssueState, comment string) (*ExternalIssue, error)

	// SearchIssues queries for existing issues matching the search criteria (e.g. for duplicate prevention).
	SearchIssues(ctx context.Context, query IssueSearchQuery) ([]ExternalIssue, error)
}

// TrackerConfig holds common configuration for tracker adapters.
type TrackerConfig struct {
	BaseURL           string        `json:"base_url"`
	ProjectOrRepo     string        `json:"project_or_repo"` // Jira project key, GitHub "owner/repo", or ServiceNow table
	Username          string        `json:"username,omitempty"`
	APIToken          string        `json:"-"` // Redacted from serialization
	Password          string        `json:"-"` // Redacted from serialization
	AuthType          string        `json:"auth_type,omitempty"` // "basic", "bearer", "token"
	IssueType         string        `json:"issue_type,omitempty"` // Default "Bug" or "sn_vul_vulnerable_item"
	SSRF              SSRFConfig    `json:"ssrf_config"`
	Timeout           time.Duration `json:"timeout"`
	MaxRetries        int           `json:"max_retries"`
	BackoffBase       time.Duration `json:"backoff_base"`
	HTTPClient        *http.Client  `json:"-"`
}

// DefaultTrackerConfig provides safe default settings.
func DefaultTrackerConfig() TrackerConfig {
	return TrackerConfig{
		SSRF:        DefaultSSRFConfig(),
		Timeout:     15 * time.Second,
		MaxRetries:  3,
		BackoffBase: 100 * time.Millisecond,
	}
}

// SyncAction classifies the outcome of an individual finding synchronization operation.
type SyncAction string

const (
	SyncActionCreated    SyncAction = "CREATED"
	SyncActionUpdated    SyncAction = "UPDATED"
	SyncActionReconciled SyncAction = "RECONCILED"
	SyncActionClosed     SyncAction = "CLOSED"
	SyncActionReopened   SyncAction = "REOPENED"
	SyncActionSkipped    SyncAction = "SKIPPED"
	SyncActionConflict   SyncAction = "CONFLICT"
	SyncActionFailed     SyncAction = "FAILED"
)

// SyncItemResult captures the synchronization outcome for a single finding.
type SyncItemResult struct {
	FindingID               string             `json:"finding_id"`
	Platform                TrackerPlatform    `json:"platform"`
	Action                  SyncAction         `json:"action"`
	ExternalIssueID         string             `json:"external_issue_id,omitempty"`
	ExternalIssueKey        string             `json:"external_issue_key,omitempty"`
	ExternalURL             string             `json:"external_url,omitempty"`
	ExternalState           TrackerIssueState  `json:"external_state,omitempty"`
	ExternalStatus          string             `json:"external_status,omitempty"`
	ExternalAssignee        string             `json:"external_assignee,omitempty"`
	FindingStatus           report.FindingStatus `json:"finding_status"`
	VulnerabilityRemediated bool               `json:"vulnerability_remediated"`
	Message                 string             `json:"message"`
	Error                   string             `json:"error,omitempty"`
}

// SyncResult aggregates the outcomes of a batch synchronization.
type SyncResult struct {
	Platform       TrackerPlatform  `json:"platform"`
	TotalProcessed int              `json:"total_processed"`
	Created        int              `json:"created"`
	Updated        int              `json:"updated"`
	Reconciled     int              `json:"reconciled"`
	Closed         int              `json:"closed"`
	Reopened       int              `json:"reopened"`
	Skipped        int              `json:"skipped"`
	Conflicts      int              `json:"conflicts"`
	Errors         int              `json:"errors"`
	ItemResults    []SyncItemResult `json:"item_results"`
	Duration       time.Duration    `json:"duration"`
	ExecutedAt     time.Time        `json:"executed_at"`
}

// -----------------------------------------------------------------------------
// Formatters and Finding Extraction Helpers
// -----------------------------------------------------------------------------

// FormatTicketTitle constructs a standard, clean ticket summary.
func FormatTicketTitle(f report.Finding) string {
	sev := strings.ToUpper(strings.TrimSpace(f.Severity))
	if sev == "" {
		sev = report.SeverityUnknown
	}
	id := strings.TrimSpace(f.ID)
	title := strings.TrimSpace(f.Title)
	if id != "" {
		return fmt.Sprintf("[FELIX-%s] %s: %s", sev, id, title)
	}
	return fmt.Sprintf("[FELIX-%s] %s", sev, title)
}

// ExtractCVSSScoreAndVector extracts CVSS score and vector string from finding details.
func ExtractCVSSScoreAndVector(f report.Finding) (float64, string) {
	var score float64
	var vector string

	if f.EvidenceDetails.Details != nil {
		for _, key := range []string{"cvss", "cvss_score", "cvss-score", "cvss_v3", "cvssScore"} {
			if val, ok := f.EvidenceDetails.Details[key]; ok {
				var s float64
				if n, err := fmt.Sscanf(strings.TrimSpace(val), "%f", &s); err == nil && n == 1 {
					score = s
					break
				}
			}
		}
		for _, key := range []string{"cvss_vector", "cvssVector", "vector_string", "vectorString"} {
			if val, ok := f.EvidenceDetails.Details[key]; ok {
				vector = strings.TrimSpace(val)
				break
			}
		}
	}

	if score == 0 && f.ScoreExplanation != nil && f.ScoreExplanation.BaseScore != 0 {
		score = f.ScoreExplanation.BaseScore
	}

	return score, vector
}

// ExtractCWEAndCVE retrieves CWE and CVE references from RuleID and Details.
func ExtractCWEAndCVE(f report.Finding) (string, string) {
	var cwe, cve string

	// Check RuleID
	rule := strings.ToUpper(strings.TrimSpace(f.RuleID))
	if strings.HasPrefix(rule, "CWE-") {
		cwe = rule
	} else if strings.HasPrefix(rule, "CVE-") {
		cve = rule
	}

	// Check Details
	if f.EvidenceDetails.Details != nil {
		if val, ok := f.EvidenceDetails.Details["cwe"]; ok && cwe == "" {
			cwe = strings.TrimSpace(val)
		}
		if val, ok := f.EvidenceDetails.Details["cve"]; ok && cve == "" {
			cve = strings.TrimSpace(val)
		}
	}

	return cwe, cve
}

// FormatTicketDescription renders a structured Markdown description for tracker tickets.
// It rigorously distinguishes live verification from synthetic fixtures and preserves provenance.
func FormatTicketDescription(f report.Finding, assessmentID string) string {
	var b strings.Builder

	cvssScore, cvssVector := ExtractCVSSScoreAndVector(f)
	cwe, cve := ExtractCWEAndCVE(f)

	b.WriteString("# [FELIX Security Finding] " + f.Title + "\n\n")

	// Overview Table
	b.WriteString("### Finding Metadata\n")
	b.WriteString(fmt.Sprintf("- **Finding ID:** `%s`\n", f.ID))
	if f.RuleID != "" {
		b.WriteString(fmt.Sprintf("- **Rule / Check ID:** `%s`\n", f.RuleID))
	}
	b.WriteString(fmt.Sprintf("- **Severity:** **%s**\n", f.Severity))
	if cvssScore > 0 {
		if cvssVector != "" {
			b.WriteString(fmt.Sprintf("- **CVSS Score:** %.1f (`%s`)\n", cvssScore, cvssVector))
		} else {
			b.WriteString(fmt.Sprintf("- **CVSS Score:** %.1f\n", cvssScore))
		}
	}
	if cwe != "" {
		b.WriteString(fmt.Sprintf("- **CWE Reference:** %s\n", cwe))
	}
	if cve != "" {
		b.WriteString(fmt.Sprintf("- **CVE Reference:** %s\n", cve))
	}
	if f.Target != "" {
		b.WriteString(fmt.Sprintf("- **Affected Target:** `%s`\n", f.Target))
	}
	if f.Endpoint != "" {
		b.WriteString(fmt.Sprintf("- **Endpoint:** `%s`\n", f.Endpoint))
	}
	if f.PrimaryAssetID != "" {
		b.WriteString(fmt.Sprintf("- **Asset ID:** `%s`\n", f.PrimaryAssetID))
	}
	if assessmentID != "" {
		b.WriteString(fmt.Sprintf("- **Assessment ID:** `%s`\n", assessmentID))
	}
	b.WriteString("\n---\n")

	// Description
	b.WriteString("### Description\n")
	desc := strings.TrimSpace(f.Description)
	if desc == "" {
		desc = "No extended narrative provided."
	}
	b.WriteString(desc + "\n\n")

	// Empirical Verification & Provenance
	b.WriteString("### Empirical Verification & Evidence Lineage\n")
	b.WriteString(fmt.Sprintf("- **Evaluation Status:** `%s`\n", f.Status))
	analysisMethod := string(f.AnalysisMethod)
	if analysisMethod == "" {
		analysisMethod = string(f.Verification.AnalysisMethod)
	}
	if analysisMethod == "" {
		analysisMethod = string(report.AnalysisMethodStatic)
	}
	b.WriteString(fmt.Sprintf("- **Analysis Method:** `%s`\n", analysisMethod))

	verStatus := string(f.Verification.Status)
	if verStatus == "" {
		verStatus = string(report.VerificationNotVerified)
	}
	b.WriteString(fmt.Sprintf("- **Verification Status:** `%s`\n", verStatus))

	if strings.TrimSpace(f.Verification.Result) != "" {
		b.WriteString(fmt.Sprintf("- **Verification Result:** %s\n", f.Verification.Result))
	}

	// Provenance Details
	prov := f.Provenance
	if prov == nil {
		prov = f.EvidenceDetails.Provenance
	}
	if prov != nil {
		if prov.SourceEngine != "" {
			b.WriteString(fmt.Sprintf("- **Source Engine:** `%s`\n", prov.SourceEngine))
		}
		if prov.ContentDigest != "" {
			b.WriteString(fmt.Sprintf("- **Evidence Digest:** `%s`\n", prov.ContentDigest))
		}
		if prov.Location != "" {
			b.WriteString(fmt.Sprintf("- **Evidence Location:** `%s`\n", prov.Location))
		}
	}

	// Synthetic Fixture Caveat (Crucial for honest provenance!)
	if f.Verification.SyntheticFixture || strings.Contains(f.Evidence, "[SYNTHETIC FIXTURE]") {
		b.WriteString("\n> **CAUTION — SYNTHETIC EVIDENCE:** This finding was observed or generated from a synthetic " +
			"test fixture or offline benchmark. It has NOT been empirically confirmed against a live production endpoint.\n")
	}
	b.WriteString("\n---\n")

	// Reproduction Proof
	hasRepro := len(f.Verification.ReproductionSteps) > 0 || strings.TrimSpace(f.Verification.SafeCurlCommand) != ""
	if hasRepro {
		b.WriteString("### Reproduction Proof\n")
		if len(f.Verification.ReproductionSteps) > 0 {
			b.WriteString("**Reproduction Steps:**\n")
			for i, step := range f.Verification.ReproductionSteps {
				b.WriteString(fmt.Sprintf("%d. %s\n", i+1, step))
			}
			b.WriteString("\n")
		}
		if strings.TrimSpace(f.Verification.SafeCurlCommand) != "" {
			b.WriteString("**Safe Reproduction Command:**\n```bash\n")
			b.WriteString(f.Verification.SafeCurlCommand + "\n```\n\n")
		}
		b.WriteString("---\n")
	}

	// Remediation Guidance
	b.WriteString("### Remediation Guidance\n")
	rem := strings.TrimSpace(f.Remediation)
	if rem != "" {
		b.WriteString(rem + "\n")
	}
	if f.RemediationAdvice != nil {
		if strings.TrimSpace(f.RemediationAdvice.Summary) != "" && strings.TrimSpace(f.RemediationAdvice.Summary) != rem {
			b.WriteString(fmt.Sprintf("**Advice Summary:** %s\n", f.RemediationAdvice.Summary))
		}
		if len(f.RemediationAdvice.Steps) > 0 {
			b.WriteString("\n**Mitigation Steps:**\n")
			for i, s := range f.RemediationAdvice.Steps {
				b.WriteString(fmt.Sprintf("- %s\n", s))
				_ = i
			}
		}
	} else if rem == "" {
		b.WriteString("Consult engineering security policies for remediation standards.\n")
	}
	b.WriteString("\n---\n")

	b.WriteString("*Synchronized by FELIX v3.0 Enterprise Defect Management Gateway*\n")
	return b.String()
}

// ComputeFindingFingerprint calculates a deterministic SHA-256 digest of finding fields.
// Used for change detection, idempotency, and conflict analysis.
func ComputeFindingFingerprint(f report.Finding) string {
	cvss, _ := ExtractCVSSScoreAndVector(f)
	repro := strings.Join(f.Verification.ReproductionSteps, "|")
	raw := fmt.Sprintf("%s|%s|%s|%s|%.1f|%s|%s|%s|%s|%s|%s",
		f.ID,
		f.Title,
		f.Severity,
		f.Description,
		cvss,
		f.Target,
		f.Endpoint,
		f.Remediation,
		string(f.Status),
		string(f.Verification.Status),
		repro,
	)
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

// BuildCreateIssueRequest converts a report.Finding into a CreateIssueRequest.
func BuildCreateIssueRequest(f report.Finding, assessmentID string) CreateIssueRequest {
	cvssScore, cvssVector := ExtractCVSSScoreAndVector(f)
	cwe, cve := ExtractCWEAndCVE(f)

	prov := f.Provenance
	if prov == nil {
		prov = f.EvidenceDetails.Provenance
	}
	var sourceEngine, digest, evLoc string
	if prov != nil {
		sourceEngine = prov.SourceEngine
		digest = prov.ContentDigest
		evLoc = prov.Location
	}

	labels := []string{
		"security",
		"felix",
		fmt.Sprintf("felix-finding-%s", f.ID),
		fmt.Sprintf("severity-%s", strings.ToLower(f.Severity)),
	}
	if cwe != "" {
		labels = append(labels, strings.ToLower(cwe))
	}

	return CreateIssueRequest{
		FindingID:          f.ID,
		RuleID:             f.RuleID,
		Title:              FormatTicketTitle(f),
		Description:        FormatTicketDescription(f, assessmentID),
		Severity:           f.Severity,
		CVSS:               cvssScore,
		CVSSVector:         cvssVector,
		Target:             f.Target,
		Endpoint:           f.Endpoint,
		PrimaryAssetID:     f.PrimaryAssetID,
		CWE:                cwe,
		CVE:                cve,
		ReproductionSteps:  f.Verification.ReproductionSteps,
		SafeCurlCommand:    f.Verification.SafeCurlCommand,
		EvidenceDigest:     digest,
		EvidenceLocation:   evLoc,
		Remediation:        f.Remediation,
		AssessmentID:       assessmentID,
		FindingStatus:      f.Status,
		AnalysisMethod:     string(f.AnalysisMethod),
		VerificationStatus: string(f.Verification.Status),
		VerificationResult: f.Verification.Result,
		SourceEngine:       sourceEngine,
		SyntheticFixture:   f.Verification.SyntheticFixture,
		Labels:             labels,
	}
}

// -----------------------------------------------------------------------------
// TrackerSyncEngine (Bidirectional Sync Orchestrator)
// -----------------------------------------------------------------------------

// TrackerSyncEngine coordinates bidirectional synchronization between FELIX findings
// and defect tracking platforms, managing idempotency, duplicate prevention, and state persistence.
type TrackerSyncEngine struct {
	provider TrackerProvider
	store    TrackerSyncStore
}

// NewTrackerSyncEngine constructs a new synchronization engine.
func NewTrackerSyncEngine(provider TrackerProvider, store TrackerSyncStore) (*TrackerSyncEngine, error) {
	if provider == nil {
		return nil, errors.New("tracker provider cannot be nil")
	}
	if store == nil {
		return nil, errors.New("tracker sync store cannot be nil")
	}
	if err := provider.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("provider configuration invalid: %w", err)
	}
	return &TrackerSyncEngine{
		provider: provider,
		store:    store,
	}, nil
}

// SyncFindingToTracker pushes a finding to the external defect tracker (FELIX -> Tracker).
// It prevents duplicates by inspecting the persistent store and querying the tracker by finding ID.
// If the issue already exists and details have changed, it updates the issue.
func (e *TrackerSyncEngine) SyncFindingToTracker(ctx context.Context, f report.Finding, assessmentID string) (SyncItemResult, error) {
	now := time.Now().UTC()
	platform := e.provider.Platform()
	res := SyncItemResult{
		FindingID:     f.ID,
		Platform:      platform,
		FindingStatus: f.Status,
	}

	fingerprint := ComputeFindingFingerprint(f)

	// 1. Check local persistent mapping store
	rec, found := e.store.Get(f.ID, platform)
	if !found {
		// 2. Query external platform to prevent duplicate creation if created out-of-band
		existing, err := e.provider.SearchIssues(ctx, IssueSearchQuery{
			FindingID: f.ID,
			Limit:     1,
		})
		if err == nil && len(existing) > 0 {
			// Link to existing external ticket
			ext := existing[0]
			rec = &SyncRecord{
				FindingID:               f.ID,
				Platform:                platform,
				ExternalIssueID:         ext.ID,
				ExternalIssueKey:        ext.Key,
				ExternalURL:             ext.URL,
				LastSyncedAt:            now,
				FindingFingerprint:      fingerprint,
				ExternalStatus:          ext.Status,
				ExternalState:           ext.State,
				ExternalAssignee:        ext.Assignee,
				VulnerabilityRemediated: false, // Invariant: external ticket status never marks vulnerability remediated
				AuditTrail: []SyncAuditEntry{
					{
						Timestamp: now,
						Action:    "LINKED_EXISTING",
						Details:   fmt.Sprintf("Discovered and linked existing external issue %s (%s)", ext.Key, ext.ID),
					},
				},
			}
			_ = e.store.Put(rec)
			found = true
		}
	}

	if !found {
		// 3. Create new issue
		req := BuildCreateIssueRequest(f, assessmentID)
		issue, err := e.provider.CreateIssue(ctx, req)
		if err != nil {
			res.Action = SyncActionFailed
			res.Error = secrets.RedactText(err.Error())
			res.Message = "Failed creating external ticket"
			return res, err
		}

		newRec := &SyncRecord{
			FindingID:               f.ID,
			Platform:                platform,
			ExternalIssueID:         issue.ID,
			ExternalIssueKey:        issue.Key,
			ExternalURL:             issue.URL,
			LastSyncedAt:            now,
			FindingFingerprint:      fingerprint,
			ExternalStatus:          issue.Status,
			ExternalState:           issue.State,
			ExternalAssignee:        issue.Assignee,
			VulnerabilityRemediated: false,
			AuditTrail: []SyncAuditEntry{
				{
					Timestamp: now,
					Action:    "CREATED",
					Details:   fmt.Sprintf("Created new external issue %s (%s)", issue.Key, issue.ID),
				},
			},
		}
		if err := e.store.Put(newRec); err != nil {
			// Log store warning but preserve successful external issue result
			newRec.AuditTrail = append(newRec.AuditTrail, SyncAuditEntry{
				Timestamp: now,
				Action:    "STORE_ERROR",
				Details:   fmt.Sprintf("Store error: %v", err),
			})
		}

		res.Action = SyncActionCreated
		res.ExternalIssueID = issue.ID
		res.ExternalIssueKey = issue.Key
		res.ExternalURL = issue.URL
		res.ExternalState = issue.State
		res.ExternalStatus = issue.Status
		res.ExternalAssignee = issue.Assignee
		res.Message = fmt.Sprintf("Created external ticket %s", issue.Key)
		return res, nil
	}

	// 4. Issue exists -> Check for change or update
	res.ExternalIssueID = rec.ExternalIssueID
	res.ExternalIssueKey = rec.ExternalIssueKey
	res.ExternalURL = rec.ExternalURL
	res.ExternalState = rec.ExternalState
	res.ExternalStatus = rec.ExternalStatus
	res.ExternalAssignee = rec.ExternalAssignee

	if rec.FindingFingerprint == fingerprint {
		res.Action = SyncActionSkipped
		res.Message = fmt.Sprintf("Finding unchanged since last sync (%s); update skipped", rec.ExternalIssueKey)
		return res, nil
	}

	// Finding details changed -> push update
	cvssScore, cvssVector := ExtractCVSSScoreAndVector(f)
	upReq := UpdateIssueRequest{
		Title:         FormatTicketTitle(f),
		Description:   FormatTicketDescription(f, assessmentID),
		Severity:      f.Severity,
		CVSS:          cvssScore,
		CVSSVector:    cvssVector,
		Remediation:   f.Remediation,
		UpdateComment: fmt.Sprintf("[FELIX] Finding details updated at %s (Severity: %s, CVSS: %.1f)", now.Format(time.RFC3339), f.Severity, cvssScore),
	}

	updatedIssue, err := e.provider.UpdateIssue(ctx, rec.ExternalIssueID, upReq)
	if err != nil {
		res.Action = SyncActionFailed
		res.Error = secrets.RedactText(err.Error())
		res.Message = fmt.Sprintf("Failed updating external ticket %s", rec.ExternalIssueKey)
		return res, err
	}

	rec.FindingFingerprint = fingerprint
	rec.LastSyncedAt = now
	rec.ExternalStatus = updatedIssue.Status
	rec.ExternalState = updatedIssue.State
	rec.ExternalAssignee = updatedIssue.Assignee
	rec.AuditTrail = append(rec.AuditTrail, SyncAuditEntry{
		Timestamp: now,
		Action:    "UPDATED",
		Details:   fmt.Sprintf("Updated finding fields in external issue %s", rec.ExternalIssueKey),
	})
	_ = e.store.Put(rec)

	res.Action = SyncActionUpdated
	res.ExternalState = updatedIssue.State
	res.ExternalStatus = updatedIssue.Status
	res.ExternalAssignee = updatedIssue.Assignee
	res.Message = fmt.Sprintf("Updated external ticket %s", updatedIssue.Key)
	return res, nil
}

// SyncTrackerToFELIX synchronizes external issue status changes into local state (Tracker -> FELIX).
//
// CRITICAL SEMANTIC INVARIANT:
// Closing or resolving an external ticket in Jira, GitHub, or ServiceNow does NOT mark the vulnerability
// as fixed or remediated in FELIX. Local vulnerability remediation is an empirical condition that can
// only be established via verification retesting (Phase 9.2). External closure is recorded solely as
// an external workflow state change with an explicit "UNVERIFIED" status audit note.
func (e *TrackerSyncEngine) SyncTrackerToFELIX(ctx context.Context, findingID string) (SyncItemResult, error) {
	now := time.Now().UTC()
	platform := e.provider.Platform()
	res := SyncItemResult{
		FindingID: findingID,
		Platform:  platform,
	}

	rec, found := e.store.Get(findingID, platform)
	if !found {
		res.Action = SyncActionFailed
		res.Error = fmt.Sprintf("no external ticket mapping found for finding %s on platform %s", findingID, platform)
		res.Message = "Finding not tracked"
		return res, fmt.Errorf("finding %s not mapped", findingID)
	}

	res.ExternalIssueID = rec.ExternalIssueID
	res.ExternalIssueKey = rec.ExternalIssueKey
	res.ExternalURL = rec.ExternalURL

	extIssue, err := e.provider.GetIssue(ctx, rec.ExternalIssueID)
	if err != nil {
		res.Action = SyncActionFailed
		res.Error = secrets.RedactText(err.Error())
		res.Message = fmt.Sprintf("Failed fetching external issue %s", rec.ExternalIssueKey)
		return res, err
	}

	res.ExternalState = extIssue.State
	res.ExternalStatus = extIssue.Status
	res.ExternalAssignee = extIssue.Assignee

	oldState := rec.ExternalState
	newState := extIssue.State

	rec.ExternalStatus = extIssue.Status
	rec.ExternalState = extIssue.State
	rec.ExternalAssignee = extIssue.Assignee
	rec.LastSyncedAt = now

	// Detect workflow transition
	if oldState != newState {
		if newState.IsClosedOrResolved() {
			// External ticket was CLOSED or RESOLVED:
			// Invariant: VulnerabilityRemediated remains FALSE.
			rec.VulnerabilityRemediated = false
			rec.AuditTrail = append(rec.AuditTrail, SyncAuditEntry{
				Timestamp: now,
				Action:    "EXTERNAL_CLOSURE_DETECTED",
				Details: fmt.Sprintf("External issue %s transitioned to %s (%s). NOTE: Independent vulnerability "+
					"remediation remains UNVERIFIED pending empirical retest.", rec.ExternalIssueKey, newState, extIssue.Status),
			})
			_ = e.store.Put(rec)

			res.Action = SyncActionClosed
			res.VulnerabilityRemediated = false
			res.Message = fmt.Sprintf("External ticket %s closed in %s; vulnerability remediation remains UNVERIFIED",
				rec.ExternalIssueKey, platform)
			return res, nil
		}

		if oldState.IsClosedOrResolved() && !newState.IsClosedOrResolved() {
			// External ticket was REOPENED:
			rec.VulnerabilityRemediated = false
			rec.AuditTrail = append(rec.AuditTrail, SyncAuditEntry{
				Timestamp: now,
				Action:    "EXTERNAL_REOPEN_DETECTED",
				Details: fmt.Sprintf("External issue %s reopened (now %s / %s).",
					rec.ExternalIssueKey, newState, extIssue.Status),
			})
			_ = e.store.Put(rec)

			res.Action = SyncActionReopened
			res.VulnerabilityRemediated = false
			res.Message = fmt.Sprintf("External ticket %s reopened in %s", rec.ExternalIssueKey, platform)
			return res, nil
		}
	}

	// State reconciled without transition
	rec.AuditTrail = append(rec.AuditTrail, SyncAuditEntry{
		Timestamp: now,
		Action:    "RECONCILED",
		Details:   fmt.Sprintf("Status confirmed as %s (%s)", extIssue.State, extIssue.Status),
	})
	_ = e.store.Put(rec)

	res.Action = SyncActionReconciled
	res.Message = fmt.Sprintf("External ticket %s state reconciled (%s)", rec.ExternalIssueKey, extIssue.Status)
	return res, nil
}

// SyncAll executes bidirectional synchronization across a slice of findings.
func (e *TrackerSyncEngine) SyncAll(ctx context.Context, findings []report.Finding, assessmentID string) SyncResult {
	start := time.Now()
	res := SyncResult{
		Platform:       e.provider.Platform(),
		TotalProcessed: len(findings),
		ExecutedAt:     start.UTC(),
		ItemResults:    make([]SyncItemResult, 0, len(findings)),
	}

	for _, f := range findings {
		// 1. Sync finding to tracker
		itemRes, err := e.SyncFindingToTracker(ctx, f, assessmentID)
		if err != nil {
			res.Errors++
		} else {
			switch itemRes.Action {
			case SyncActionCreated:
				res.Created++
			case SyncActionUpdated:
				res.Updated++
			case SyncActionSkipped:
				res.Skipped++
			case SyncActionConflict:
				res.Conflicts++
			}
		}

		// 2. Sync tracker status back to FELIX state
		statusRes, err := e.SyncTrackerToFELIX(ctx, f.ID)
		if err == nil {
			switch statusRes.Action {
			case SyncActionClosed:
				res.Closed++
			case SyncActionReopened:
				res.Reopened++
			case SyncActionReconciled:
				res.Reconciled++
			}
		}

		res.ItemResults = append(res.ItemResults, itemRes)
	}

	res.Duration = time.Since(start)
	return res
}

// ParseRetryAfter attempts to extract sleep duration from a Retry-After header value.
func ParseRetryAfter(headerVal string) time.Duration {
	clean := strings.TrimSpace(headerVal)
	if clean == "" {
		return 0
	}
	// Try parsing as integer seconds
	var sec int
	if n, err := fmt.Sscanf(clean, "%d", &sec); err == nil && n == 1 && sec > 0 {
		return time.Duration(sec) * time.Second
	}
	// Try parsing as HTTP-date
	if t, err := http.ParseTime(clean); err == nil {
		diff := time.Until(t)
		if diff > 0 {
			return diff
		}
	}
	return 0
}

// BuildSafeHTTPClient constructs an http.Client with validated timeouts and transport.
func BuildSafeHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return ErrTooManyRedirects
			}
			return nil
		},
	}
}

// ValidateTrackerURL validates the tracker destination URL against SSRF and scheme restrictions.
func ValidateTrackerURL(rawURL string, cfg SSRFConfig) (*url.URL, error) {
	return ValidateEndpoint(rawURL, cfg)
}
