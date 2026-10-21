package assessment

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"felix/pkg/correlation"
	"felix/pkg/provenance"
	"felix/pkg/report"
)

// AssessmentStatus represents the lifecycle state of an assessment.
type AssessmentStatus string

const (
	StatusDraft               AssessmentStatus = "DRAFT"
	StatusReady               AssessmentStatus = "READY"
	StatusRunning             AssessmentStatus = "RUNNING"
	StatusCompleted           AssessmentStatus = "COMPLETED"
	StatusCompletedWithErrors AssessmentStatus = "COMPLETED_WITH_ERRORS"
	StatusFailed              AssessmentStatus = "FAILED"
	StatusCancelled           AssessmentStatus = "CANCELLED"
	StatusQueued              AssessmentStatus = "QUEUED"
	StatusSkipped             AssessmentStatus = "SKIPPED"
	StatusInterrupted         AssessmentStatus = "INTERRUPTED"
)

// IsValidTransition returns true if moving from fromStatus to toStatus is permitted.
func IsValidTransition(from, to AssessmentStatus) bool {
	switch from {
	case StatusDraft:
		return to == StatusReady || to == StatusCancelled
	case StatusReady:
		return to == StatusRunning || to == StatusDraft || to == StatusCancelled
	case StatusRunning:
		return to == StatusCompleted || to == StatusCompletedWithErrors || to == StatusFailed || to == StatusCancelled
	case StatusCompleted, StatusCompletedWithErrors, StatusFailed, StatusCancelled:
		// Terminal states: a new scan must create a new execution run rather than directly mutating the terminal assessment
		return to == StatusReady || to == StatusRunning
	default:
		return false
	}
}

// IsValidExecutionTransition enforces explicit, valid transitions for execution records.
func IsValidExecutionTransition(from, to AssessmentStatus) bool {
	if from == to {
		// Idempotent finalization
		return true
	}
	switch from {
	case StatusQueued:
		return to == StatusRunning || to == StatusCancelled || to == StatusSkipped || to == StatusFailed
	case StatusRunning:
		return to == StatusCompleted || to == StatusCompletedWithErrors || to == StatusFailed || to == StatusCancelled || to == StatusInterrupted
	case StatusCompleted, StatusCompletedWithErrors, StatusFailed, StatusCancelled, StatusSkipped, StatusInterrupted:
		// Terminal execution outcome cannot be overwritten
		return false
	default:
		// Initial unrecorded state permits entering QUEUED, RUNNING, SKIPPED, or FAILED
		return to == StatusQueued || to == StatusRunning || to == StatusSkipped || to == StatusFailed
	}
}

// IsTerminalExecutionStatus returns true if status represents a terminal execution outcome.
func IsTerminalExecutionStatus(status AssessmentStatus) bool {
	switch status {
	case StatusCompleted, StatusCompletedWithErrors, StatusFailed, StatusCancelled, StatusSkipped, StatusInterrupted:
		return true
	default:
		return false
	}
}

// AuthorizationStatus defines the state of client authorization.
type AuthorizationStatus string

const (
	AuthNotRecorded AuthorizationStatus = "NOT_RECORDED"
	AuthPending     AuthorizationStatus = "PENDING"
	AuthApproved    AuthorizationStatus = "APPROVED"
	AuthExpired     AuthorizationStatus = "EXPIRED"
	AuthRevoked     AuthorizationStatus = "REVOKED"
)

// TargetType defines the nature of an assessment target.
type TargetType string

const (
	TargetWebsite    TargetType = "WEBSITE"
	TargetAPIBaseURL TargetType = "API_BASE_URL"
	TargetSubdomain  TargetType = "SUBDOMAIN"
	TargetAsset      TargetType = "ASSET"
)

// Client represents a security assessment client/organization.
type Client struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Organization string    `json:"organization,omitempty"`
	ContactName  string    `json:"contact_name,omitempty"`
	ContactEmail string    `json:"contact_email,omitempty"`
	Notes        string    `json:"notes,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Archived     bool      `json:"archived"`
}

// Assessment represents a client-authorized security auditing project.
type Assessment struct {
	ID                 string                `json:"id"`
	Ref                string                `json:"ref"` // Human-readable reference, e.g. ASM-2026-0001
	ClientID           string                `json:"client_id"`
	Name               string                `json:"name"`
	Description        string                `json:"description,omitempty"`
	AssessmentType     string                `json:"assessment_type"` // e.g. BLACK_BOX_WEB, API_AUDIT, HYBRID
	Status             AssessmentStatus      `json:"status"`
	CreatedAt          time.Time             `json:"created_at"`
	UpdatedAt          time.Time             `json:"updated_at"`
	StartedAt          *time.Time            `json:"started_at,omitempty"`
	CompletedAt        *time.Time            `json:"completed_at,omitempty"`
	ScopeMode          string                `json:"scope_mode"` // same-origin, subdomains, explicit
	ConfigSnapshotJSON string                `json:"config_snapshot_json,omitempty"`
	FindingCount       int                   `json:"finding_count"`
	Targets            []AssessmentTarget    `json:"targets,omitempty"`
	Authorization      *AuthorizationRecord  `json:"authorization,omitempty"`
	Exclusions         []Exclusion           `json:"exclusions,omitempty"`
	ScopeRules         []ScopeRule           `json:"scope_rules,omitempty"`
	Executions         []AssessmentExecution `json:"executions,omitempty"`
}

// AssessmentTarget represents an approved web asset or endpoint within an assessment.
type AssessmentTarget struct {
	ID           string     `json:"id"`
	AssessmentID string     `json:"assessment_id"`
	TargetURL    string     `json:"target_url"`
	TargetType   TargetType `json:"target_type"`
	ScopeStatus  string     `json:"scope_status"` // APPROVED, EXCLUDED, PENDING
	Label        string     `json:"label,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// AuthorizationRecord captures the explicit permission granted to audit targets.
type AuthorizationRecord struct {
	ID                  string              `json:"id"`
	AssessmentID        string              `json:"assessment_id"`
	AuthorizingParty    string              `json:"authorizing_party"`
	AuthorizationMethod string              `json:"authorization_method"` // WRITTEN_CONTRACT, EMAIL, TICKET, STATEMENT_OF_WORK
	DateReceived        time.Time           `json:"date_received"`
	ValidFrom           *time.Time          `json:"valid_from,omitempty"`
	ValidUntil          *time.Time          `json:"valid_until,omitempty"`
	ScopeDocRef         string              `json:"scope_doc_ref,omitempty"` // Local path or document ID
	InternalNotes       string              `json:"internal_notes,omitempty"`
	Status              AuthorizationStatus `json:"status"`
	CreatedAt           time.Time           `json:"created_at"`
	UpdatedAt           time.Time           `json:"updated_at"`
}

// IsCurrentlyValid verifies if the authorization is APPROVED and within its validity window.
func (a *AuthorizationRecord) IsCurrentlyValid(now time.Time) (bool, string) {
	if a == nil {
		return false, "no authorization record exists"
	}
	if a.Status != AuthApproved {
		return false, fmt.Sprintf("authorization status is %s (must be APPROVED)", a.Status)
	}
	if a.ValidFrom != nil && now.Before(*a.ValidFrom) {
		return false, fmt.Sprintf("authorization not yet active (valid from %s)", a.ValidFrom.Format(time.RFC3339))
	}
	if a.ValidUntil != nil && now.After(*a.ValidUntil) {
		return false, fmt.Sprintf("authorization expired on %s", a.ValidUntil.Format(time.RFC3339))
	}
	return true, ""
}

// ScopeRule defines an approved origin, hostname, or path rule.
type ScopeRule struct {
	ID           string    `json:"id"`
	AssessmentID string    `json:"assessment_id"`
	RuleType     string    `json:"rule_type"` // EXACT_ORIGIN, HOSTNAME, PATH_PREFIX
	Pattern      string    `json:"pattern"`
	CreatedAt    time.Time `json:"created_at"`
}

// Exclusion types
const (
	ExclusionHostname   = "HOSTNAME"
	ExclusionPathPrefix = "PATH_PREFIX"
	ExclusionExactURL   = "EXACT_URL"
	ExclusionRegex      = "REGEX"
)

// Exclusion defines an explicit target, host, or path forbidden from being scanned.
type Exclusion struct {
	ID            string    `json:"id"`
	AssessmentID  string    `json:"assessment_id"`
	ExclusionType string    `json:"exclusion_type"` // HOSTNAME, PATH_PREFIX, REGEX, EXACT_URL
	Pattern       string    `json:"pattern"`
	Reason        string    `json:"reason,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// ScanConfigSnapshot stores the exact scanner parameters applied during an execution.
type ScanConfigSnapshot struct {
	TimeoutSeconds int    `json:"timeout_seconds"`
	Concurrency    int    `json:"concurrency"`
	ScopeMode      string `json:"scope_mode"`
	MaxAssets      int    `json:"max_assets"`
	MaxSizeBytes   int64  `json:"max_size_bytes"`
	UserAgent      string `json:"user_agent"`
	FelixVersion   string                           `json:"felix_version"`
	BuildID        string                           `json:"build_id,omitempty"`
	Provenance     *provenance.AssessmentProvenance `json:"provenance,omitempty"`
}

// AssessmentExecution records a single execution run of an assessment.
type AssessmentExecution struct {
	ID               string              `json:"id"`
	AssessmentID     string              `json:"assessment_id"`
	ScheduleID       string              `json:"schedule_id,omitempty"`
	ScheduledFor     *time.Time          `json:"scheduled_for,omitempty"`
	ClientID         string              `json:"client_id,omitempty"`
	TenantID         string              `json:"tenant_id,omitempty"`
	AccountID        string              `json:"account_id,omitempty"`
	InitiationSource string              `json:"initiation_source,omitempty"` // "manual", "scheduled", "api"
	AssessmentType   string              `json:"assessment_type,omitempty"`
	Status           AssessmentStatus    `json:"status"` // QUEUED, RUNNING, COMPLETED, COMPLETED_WITH_ERRORS, FAILED, CANCELLED, SKIPPED, INTERRUPTED
	StartedAt        time.Time           `json:"started_at"`
	CompletedAt      *time.Time          `json:"completed_at,omitempty"`
	DurationMs       int64               `json:"duration_ms,omitempty"`
	RequestCount     int                 `json:"request_count,omitempty"`
	FindingCount     int                 `json:"finding_count"`
	TargetCount      int                 `json:"target_count,omitempty"`
	SnapshotID       string              `json:"snapshot_id,omitempty"`
	ErrorMessage     string              `json:"error_message,omitempty"`
	ConfigSnapshot   ScanConfigSnapshot  `json:"config_snapshot"`
	WorkerID         string              `json:"worker_id,omitempty"`
	HeartbeatAt      *time.Time          `json:"heartbeat_at,omitempty"`
	LeaseExpiresAt   *time.Time          `json:"lease_expires_at,omitempty"`
	RecoveryAttempts int                 `json:"recovery_attempts,omitempty"`
	LastRecoveryAt   *time.Time          `json:"last_recovery_at,omitempty"`
	RecoveryReason   string              `json:"recovery_reason,omitempty"`
	CheckpointJSON   string              `json:"checkpoint_json,omitempty"`
	IdempotencyKey   string              `json:"idempotency_key,omitempty"`
	CreatedAt        time.Time           `json:"created_at,omitempty"`
	UpdatedAt        time.Time                        `json:"updated_at,omitempty"`
	Findings         []AssessmentFinding              `json:"findings,omitempty"`
	Reports          []ReportRecord                   `json:"reports,omitempty"`
	Provenance       *provenance.AssessmentProvenance `json:"provenance,omitempty"`
}

// GetProvenance returns the assessment provenance associated with this execution.
func (e *AssessmentExecution) GetProvenance() *provenance.AssessmentProvenance {
	if e == nil {
		return nil
	}
	if e.Provenance != nil {
		return e.Provenance
	}
	return e.ConfigSnapshot.Provenance
}

// ExecutionListOptions provides tenant-scoped filtering and pagination for listing execution history.
type ExecutionListOptions struct {
	Auth             TenantAuthContext
	AssessmentID     string
	ScheduleID       string
	ClientID         string
	TenantID         string
	AccountID        string
	Status           AssessmentStatus
	InitiationSource string
	Since            *time.Time
	Until            *time.Time
	Limit            int
	Offset           int
}

var (
	// ErrExecutionNotFound indicates the requested execution record does not exist.
	ErrExecutionNotFound = errors.New("execution record not found")

	// ErrExecutionUnauthorized indicates the caller lacks authorization to view or access the execution.
	ErrExecutionUnauthorized = errors.New("unauthorized access to execution record")

	// ErrExecutionTerminal indicates a terminal execution outcome cannot be modified.
	ErrExecutionTerminal = errors.New("cannot modify terminal execution outcome")

	// ErrInvalidStateTransition indicates an invalid lifecycle state transition.
	ErrInvalidStateTransition = errors.New("invalid execution state transition")

	// ErrLeaseLost indicates the worker's execution lease was revoked, expired, or claimed by another worker.
	ErrLeaseLost = errors.New("execution lease lost: worker no longer holds active ownership")

	// ErrExecutionOverlap indicates an active execution is already in progress for this assessment.
	ErrExecutionOverlap = errors.New("overlapping execution: assessment already has an active execution in progress")

	// ErrIdempotencyConflict indicates an execution with the specified idempotency key already exists.
	ErrIdempotencyConflict = errors.New("idempotency conflict: an execution with this idempotency key already exists")

	// ErrNoEligibleBaseline indicates no eligible baseline execution was found for comparison.
	ErrNoEligibleBaseline = errors.New("no eligible baseline execution found for assessment")

	// ErrIneligibleBaseline indicates the specified baseline is ineligible (e.g. failed, cancelled, or inconclusive).
	ErrIneligibleBaseline = errors.New("ineligible baseline execution outcome")

	// ErrIncompatibleAssessmentScope indicates the executions being compared have incompatible target scopes.
	ErrIncompatibleAssessmentScope = errors.New("incompatible assessment scopes for comparison")
)

// GenerateDeterministicIdempotencyKey generates a stable idempotency key for an operation.
func GenerateDeterministicIdempotencyKey(scope, identifier string, seed ...string) string {
	h := sha256.New()
	h.Write([]byte(scope))
	h.Write([]byte(":"))
	h.Write([]byte(identifier))
	for _, s := range seed {
		h.Write([]byte(":"))
		h.Write([]byte(s))
	}
	return "idemp-" + hex.EncodeToString(h.Sum(nil))[:24]
}

// AssessmentFinding links an existing Felix finding directly to its assessment, run, and target.
type AssessmentFinding struct {
	ID                 string                    `json:"id"`
	AssessmentID       string                    `json:"assessment_id"`
	ExecutionID        string                    `json:"execution_id"`
	TargetID           string                    `json:"target_id"`
	OriginalFindingID  string                    `json:"original_finding_id"` // report.Finding.ID
	RuleID             string                    `json:"rule_id,omitempty"`
	Status             report.FindingStatus      `json:"status,omitempty"`
	AnalysisMethod     report.AnalysisMethod     `json:"analysis_method,omitempty"`
	PrimaryAssetID     string                    `json:"primary_asset_id,omitempty"`
	AffectedAssetIDs   []string                  `json:"affected_asset_ids,omitempty"`
	Title              string                    `json:"title"`
	Category           string                    `json:"category"`
	Severity           string                    `json:"severity"`
	Confidence         string                    `json:"confidence"`
	VerificationStatus report.VerificationStatus `json:"verification_status"`
	TargetURL          string                    `json:"target_url"`
	Endpoint           string                    `json:"endpoint"`
	Method             string                    `json:"method"`
	Fingerprint        string                    `json:"fingerprint"`
	Score              int                       `json:"score"`
	ScoreExplanation   *report.FindingScoreExplanation `json:"score_explanation,omitempty"`
	EvidenceDetails    report.EvidenceDetails    `json:"evidence"`
	VerificationRecord report.VerificationRecord `json:"verification"`
	Remediation        string                    `json:"remediation,omitempty"`
	RemediationAdvice  *report.RemediationAdvice `json:"remediation_advice,omitempty"`
	Provenance         *report.EvidenceProvenance `json:"provenance,omitempty"`
	LifecycleStatus    string                    `json:"lifecycle_status,omitempty"`
	CreatedAt          time.Time                 `json:"created_at"`
}

// ComputeAssessmentFindingID generates a deterministic finding ID for persistence in an assessment run.
func ComputeAssessmentFindingID(assessmentID, findingID string) string {
	h := sha256.New()
	cleanAsm := strings.TrimSpace(assessmentID)
	cleanFnd := strings.TrimSpace(findingID)
	h.Write([]byte(fmt.Sprintf("%s:%s", cleanAsm, cleanFnd)))
	sum := h.Sum(nil)
	return fmt.Sprintf("fnd_%s", hex.EncodeToString(sum[:12])) // 24 hex characters
}

// ReportRecord indexes a generated HTML or JSON assessment report.
type ReportRecord struct {
	ID           string    `json:"id"`
	AssessmentID string    `json:"assessment_id"`
	ExecutionID  string    `json:"execution_id"`
	Format       string    `json:"format"` // HTML, JSON
	FilePath     string    `json:"file_path"`
	FelixVersion string    `json:"felix_version"`
	Status       string    `json:"status"` // GENERATED, FAILED
	CreatedAt    time.Time `json:"created_at"`
}

// GenerateAssessmentRef produces a human-readable assessment reference formatted as ASM-YYYY-XXXX.
func GenerateAssessmentRef() string {
	now := time.Now().UTC()
	b := make([]byte, 2)
	_, _ = rand.Read(b)
	return fmt.Sprintf("ASM-%d-%04X", now.Year(), binary.BigEndian.Uint16(b))
}

// ToReportFinding maps an AssessmentFinding back to a complete report.Finding,
// ensuring no status, classification, provenance, remediation advice, or evidence metadata is lost.
func ToReportFinding(f AssessmentFinding) report.Finding {
	rf := report.Finding{
		ID:                f.OriginalFindingID,
		RuleID:            f.RuleID,
		Status:            f.Status,
		AnalysisMethod:    f.AnalysisMethod,
		PrimaryAssetID:    f.PrimaryAssetID,
		AffectedAssetIDs:  f.AffectedAssetIDs,
		Title:             f.Title,
		Category:          f.Category,
		Severity:          f.Severity,
		Confidence:        f.Confidence,
		Target:            f.TargetURL,
		Endpoint:          f.Endpoint,
		Method:            f.Method,
		Fingerprint:       f.Fingerprint,
		Score:             f.Score,
		ScoreExplanation:  f.ScoreExplanation,
		Evidence:          f.EvidenceDetails.Observation,
		EvidenceDetails:   f.EvidenceDetails,
		Verification:      f.VerificationRecord,
		Remediation:       f.Remediation,
		RemediationAdvice: f.RemediationAdvice,
		Provenance:        f.Provenance,
		LifecycleStatus:   f.LifecycleStatus,
		Timestamp:         f.CreatedAt,
	}
	if rf.ID == "" {
		rf.ID = f.ID
	}
	if rf.Status == "" {
		rf.Status = report.FindingStatusFromVerification(f.VerificationStatus)
	}
	if rf.Verification.Status == "" && f.VerificationStatus != "" {
		rf.Verification.Status = f.VerificationStatus
	}
	if rf.Fingerprint == "" {
		rf.Fingerprint = f.Fingerprint
	}
	if rf.EvidenceDetails.Details == nil {
		rf.EvidenceDetails.Details = make(map[string]string)
	}
	if f.TargetID != "" && rf.EvidenceDetails.Details["associated_target_ids"] == "" {
		rf.EvidenceDetails.Details["associated_target_ids"] = f.TargetID
		rf.EvidenceDetails.Details["target_id_count"] = "1"
	}
	if f.TargetURL != "" && rf.EvidenceDetails.Details["associated_targets"] == "" {
		rf.EvidenceDetails.Details["associated_targets"] = f.TargetURL
	}
	if rf.Fingerprint == "" || !correlation.IsValidFingerprint(rf, rf.Fingerprint) {
		rf.Fingerprint = correlation.ComputeStableFingerprint(rf)
	}
	if rf.ScoreExplanation == nil {
		expl := report.ExplainFindingScore(rf)
		rf.ScoreExplanation = &expl
	}
	return rf
}

// CompareAssessmentFindings compares two sets of AssessmentFindings across assessments or runs using default options.
func CompareAssessmentFindings(baseline, current []AssessmentFinding) correlation.AssessmentComparison {
	return CompareAssessmentFindingsWithOptions(baseline, current, correlation.DefaultComparisonOptions())
}

// CompareAssessmentFindingsWithOptions compares two sets of AssessmentFindings with execution lifecycle and scope constraints.
func CompareAssessmentFindingsWithOptions(baseline, current []AssessmentFinding, opts correlation.ComparisonOptions) correlation.AssessmentComparison {
	baselineReport := make([]report.Finding, len(baseline))
	for i, bf := range baseline {
		baselineReport[i] = ToReportFinding(bf)
	}
	currentReport := make([]report.Finding, len(current))
	for i, cf := range current {
		currentReport[i] = ToReportFinding(cf)
	}
	return correlation.CompareFindingsWithOptions(baselineReport, currentReport, opts)
}

// DeduplicateAssessmentFindings consolidates duplicate AssessmentFindings within an execution using canonical stable fingerprints.
func DeduplicateAssessmentFindings(findings []AssessmentFinding) []AssessmentFinding {
	if len(findings) <= 1 {
		return findings
	}

	reportFindings := make([]report.Finding, len(findings))
	findingMeta := make(map[string]AssessmentFinding, len(findings))
	for i, f := range findings {
		rf := ToReportFinding(f)
		reportFindings[i] = rf
		findingMeta[rf.ID] = f
	}

	dedupRes := correlation.NewDeduplicator(nil).Deduplicate(reportFindings)
	result := make([]AssessmentFinding, len(dedupRes.CanonicalFindings))
	for i, crf := range dedupRes.CanonicalFindings {
		orig := findingMeta[crf.ID]

		// Multi-target preservation: collect all target IDs and URLs across the consolidated duplicate group
		targetIDSet := make(map[string]struct{})
		if orig.TargetID != "" {
			targetIDSet[orig.TargetID] = struct{}{}
		}

		targetURLSet := make(map[string]struct{})
		if orig.TargetURL != "" {
			targetURLSet[orig.TargetURL] = struct{}{}
		}
		if crf.Target != "" {
			targetURLSet[crf.Target] = struct{}{}
		}

		if crf.EvidenceDetails.Details != nil {
			dupIDs := crf.EvidenceDetails.Details["duplicate_finding_ids"]
			if dupIDs != "" {
				for _, id := range strings.Split(dupIDs, ",") {
					id = strings.TrimSpace(id)
					if id != "" {
						if dupAF, ok := findingMeta[id]; ok {
							if dupAF.TargetID != "" {
								targetIDSet[dupAF.TargetID] = struct{}{}
							}
							if dupAF.TargetURL != "" {
								targetURLSet[dupAF.TargetURL] = struct{}{}
							}
						}
					}
				}
			}
			if existingTargets := crf.EvidenceDetails.Details["associated_targets"]; existingTargets != "" {
				for _, u := range strings.Split(existingTargets, ",") {
					if u = strings.TrimSpace(u); u != "" {
						targetURLSet[u] = struct{}{}
					}
				}
			}
		}

		var targetIDs []string
		for tid := range targetIDSet {
			targetIDs = append(targetIDs, tid)
		}
		sort.Strings(targetIDs)

		var targetURLs []string
		for u := range targetURLSet {
			targetURLs = append(targetURLs, u)
		}
		sort.Strings(targetURLs)

		if crf.EvidenceDetails.Details == nil {
			crf.EvidenceDetails.Details = make(map[string]string)
		}
		crf.EvidenceDetails.Details["associated_target_ids"] = strings.Join(targetIDs, ",")
		crf.EvidenceDetails.Details["target_id_count"] = strconv.Itoa(len(targetIDs))
		if len(targetURLs) > 1 {
			crf.EvidenceDetails.Details["associated_targets"] = strings.Join(targetURLs, ", ")
		}

		af := ToAssessmentFinding(orig.AssessmentID, orig.ExecutionID, orig.TargetID, crf)
		if orig.ID != "" {
			af.ID = orig.ID
		}
		af.VerificationStatus = crf.Verification.Status
		af.Confidence = crf.Confidence
		af.Score = crf.Score
		af.VerificationRecord = crf.Verification
		af.Status = crf.Status
		af.AnalysisMethod = crf.AnalysisMethod
		af.LifecycleStatus = crf.LifecycleStatus
		result[i] = af
	}
	return result
}

// -----------------------------------------------------------------------------
// Phase 6.5: Assessment History & Persistent Snapshots
// -----------------------------------------------------------------------------

var (
	ErrSnapshotNotFound     = errors.New("assessment snapshot not found")
	ErrSnapshotUnauthorized = errors.New("unauthorized: access denied to assessment snapshot")
	ErrSnapshotImmutable    = errors.New("assessment snapshot is immutable and cannot be modified")
	ErrEvidenceNotFound     = errors.New("historical evidence record not found")
)

// AssessmentSnapshot represents an immutable point-in-time record of an assessment execution.
type AssessmentSnapshot struct {
	ID             string             `json:"id"`
	SnapshotRef    string             `json:"snapshot_ref"` // e.g. SNP-2026-0001
	AssessmentID   string             `json:"assessment_id"`
	AssessmentRef  string             `json:"assessment_ref"`
	ExecutionID    string             `json:"execution_id"`
	ClientID       string             `json:"client_id"`
	TenantID       string             `json:"tenant_id,omitempty"`
	AccountID      string             `json:"account_id,omitempty"`
	Name           string             `json:"name"`
	AssessmentType string             `json:"assessment_type"`
	Status         AssessmentStatus   `json:"status"` // COMPLETED, COMPLETED_WITH_ERRORS, FAILED, CANCELLED
	IsComplete     bool               `json:"is_complete"` // false for failed, cancelled, or partial executions
	StartedAt      time.Time          `json:"started_at"`
	CompletedAt    *time.Time         `json:"completed_at,omitempty"`
	DurationMs     int64              `json:"duration_ms"`
	RequestCount   int                `json:"request_count"`
	TargetCount    int                `json:"target_count"`
	FindingCount   int                `json:"finding_count"`
	ScopeMode      string             `json:"scope_mode"`
	ScopedTargets  []string           `json:"scoped_targets,omitempty"`
	ConfigSnapshot ScanConfigSnapshot `json:"config_snapshot"`
	ScopeJSON      string             `json:"scope_json,omitempty"`
	Metadata       map[string]string  `json:"metadata,omitempty"`
	CreatedAt      time.Time          `json:"created_at"`
}

// HistoricalEvidenceRecord captures a discrete piece of security evidence tied to a specific snapshot and finding.
type HistoricalEvidenceRecord struct {
	ID                 string                    `json:"id"`
	SnapshotID         string                    `json:"snapshot_id"`
	AssessmentID       string                    `json:"assessment_id"`
	ExecutionID        string                    `json:"execution_id"`
	FindingID          string                    `json:"finding_id"` // AssessmentFinding.ID or Canonical ID
	FindingFingerprint string                    `json:"finding_fingerprint"`
	TargetID           string                    `json:"target_id"`
	TargetURL          string                    `json:"target_url"`
	EvidenceID         string                    `json:"evidence_id"` // Provenance.EvidenceID
	EvidenceType       string                    `json:"evidence_type"` // http_response, header, token, etc.
	SourceEngine       string                    `json:"source_engine"` // crawler, apisec, webvuln, etc.
	DetectionMethod    string                    `json:"detection_method,omitempty"`
	Observation        string                    `json:"observation"`
	HTTPStatus         int                       `json:"http_status,omitempty"`
	HTTPMethod         string                    `json:"http_method,omitempty"`
	ContentType        string                    `json:"content_type,omitempty"`
	Payload            string                    `json:"payload,omitempty"`
	SafeCurlCommand    string                    `json:"safe_curl_command,omitempty"`
	VerificationStatus report.VerificationStatus `json:"verification_status"`
	VerificationResult string                    `json:"verification_result,omitempty"`
	TenantID           string                    `json:"tenant_id,omitempty"`
	AccountID          string                    `json:"account_id,omitempty"`
	DetailsJSON        string                    `json:"details_json,omitempty"`
	CreatedAt          time.Time                 `json:"created_at"`
}

// TenantAuthContext defines the caller's tenant and account authorization boundaries.
type TenantAuthContext struct {
	ClientID  string
	TenantID  string
	AccountID string
	isAdmin   bool
}

// IsAdmin returns true if the context has verified administrative privileges.
func (c TenantAuthContext) IsAdmin() bool {
	return c.isAdmin
}

// NewTenantAuthContext creates a scoped authorization context for a tenant and account.
func NewTenantAuthContext(clientID, tenantID, accountID string) TenantAuthContext {
	return TenantAuthContext{
		ClientID:  strings.TrimSpace(clientID),
		TenantID:  strings.TrimSpace(tenantID),
		AccountID: strings.TrimSpace(accountID),
		isAdmin:   false,
	}
}

// NewClientAuthContext creates a client-level authorization context.
func NewClientAuthContext(clientID string) TenantAuthContext {
	return TenantAuthContext{
		ClientID: strings.TrimSpace(clientID),
		isAdmin:  false,
	}
}

// NewAdminAuthContext creates a privileged authorization context for trusted administration.
// This constructor must only be invoked by verified server-side middleware after validating administrative credentials.
func NewAdminAuthContext() TenantAuthContext {
	return TenantAuthContext{
		isAdmin: true,
	}
}

// ResolveAuthContext establishes an authorized TenantAuthContext from verified server-side identity and role.
// An administrative context is issued ONLY if the caller's verified role matches an authorized administrative role.
// Any untrusted or non-admin role requires a valid clientID and is strictly restricted to its tenant boundary.
func ResolveAuthContext(verifiedRole, clientID, tenantID, accountID string) (TenantAuthContext, error) {
	role := strings.ToLower(strings.TrimSpace(verifiedRole))
	if role == "admin" || role == "system_admin" || role == "operator_admin" {
		return NewAdminAuthContext(), nil
	}
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return TenantAuthContext{}, errors.New("unauthorized: non-admin context requires valid client_id")
	}
	return NewTenantAuthContext(clientID, tenantID, accountID), nil
}

// AuthorizeAdminContext validates trusted administrative role before issuing an admin context.
func AuthorizeAdminContext(verifiedRole string) (TenantAuthContext, error) {
	role := strings.ToLower(strings.TrimSpace(verifiedRole))
	if role != "admin" && role != "system_admin" && role != "operator_admin" {
		return TenantAuthContext{}, fmt.Errorf("forbidden: role %q lacks administrative authority", verifiedRole)
	}
	return NewAdminAuthContext(), nil
}

// Authorizes returns true if the context is permitted to access a resource with the given client, tenant, and account IDs.
// It strictly fails closed on missing, unauthenticated, or mismatched authorization boundaries.
func (c TenantAuthContext) Authorizes(clientID, tenantID, accountID string) bool {
	if c.isAdmin {
		return true
	}
	// Missing or unauthenticated context fails closed. A non-admin caller MUST have a valid ClientID.
	if c.ClientID == "" {
		return false
	}
	// If context specifies a client, clientID must match
	if clientID == "" || c.ClientID != clientID {
		return false
	}
	// If context specifies a tenant, resource must match if tenant-scoped
	if c.TenantID != "" && tenantID != "" && c.TenantID != tenantID {
		return false
	}
	// If context specifies an account, resource must match if account-scoped
	if c.AccountID != "" && accountID != "" && c.AccountID != accountID {
		return false
	}
	return true
}

// UnmarshalJSON strictly prevents setting isAdmin from untrusted JSON payloads.
// External deserialization cannot elevate privileges to admin.
func (c *TenantAuthContext) UnmarshalJSON(data []byte) error {
	type rawContext struct {
		ClientID      string `json:"client_id"`
		TenantID      string `json:"tenant_id"`
		AccountID     string `json:"account_id"`
		IsAdminSnake  *bool  `json:"is_admin,omitempty"`
		IsAdminCamel  *bool  `json:"isAdmin,omitempty"`
		IsAdminPascal *bool  `json:"IsAdmin,omitempty"`
	}
	var raw rawContext
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if (raw.IsAdminSnake != nil && *raw.IsAdminSnake) ||
		(raw.IsAdminCamel != nil && *raw.IsAdminCamel) ||
		(raw.IsAdminPascal != nil && *raw.IsAdminPascal) {
		return errors.New("unauthorized: is_admin cannot be set by untrusted request payloads")
	}
	c.ClientID = strings.TrimSpace(raw.ClientID)
	c.TenantID = strings.TrimSpace(raw.TenantID)
	c.AccountID = strings.TrimSpace(raw.AccountID)
	c.isAdmin = false
	return nil
}

// MarshalJSON serializes the authorization context.
func (c TenantAuthContext) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"client_id":  c.ClientID,
		"tenant_id":  c.TenantID,
		"account_id": c.AccountID,
		"is_admin":   c.isAdmin,
	})
}

// SnapshotListOptions provides filtering and pagination for listing historical assessment snapshots.
type SnapshotListOptions struct {
	Auth         *TenantAuthContext
	ClientID     string
	TenantID     string
	AccountID    string
	AssessmentID string
	Status       AssessmentStatus
	Limit        int
	Offset       int
}

// GenerateSnapshotRef produces a human-readable snapshot reference formatted as SNP-YYYY-XXXX.
func GenerateSnapshotRef() string {
	now := time.Now().UTC()
	b := make([]byte, 2)
	_, _ = rand.Read(b)
	return fmt.Sprintf("SNP-%d-%04X", now.Year(), binary.BigEndian.Uint16(b))
}

// BuildAssessmentSnapshot builds an AssessmentSnapshot from an execution run and its findings.
func BuildAssessmentSnapshot(asm *Assessment, execRecord *AssessmentExecution, targetURLs []string, findings []AssessmentFinding, isComplete bool) *AssessmentSnapshot {
	var scopedTargets []string
	for _, u := range targetURLs {
		u = strings.TrimSpace(u)
		if u != "" {
			scopedTargets = append(scopedTargets, u)
		}
	}
	sort.Strings(scopedTargets)

	tenantID := ""
	accountID := ""
	for _, f := range findings {
		if f.EvidenceDetails.Details != nil {
			if t, ok := f.EvidenceDetails.Details["tenant_id"]; ok && t != "" && tenantID == "" {
				tenantID = t
			}
			if a, ok := f.EvidenceDetails.Details["account_id"]; ok && a != "" && accountID == "" {
				accountID = a
			}
		}
		if tenantID != "" && accountID != "" {
			break
		}
	}
	if tenantID == "" && asm != nil {
		tenantID = asm.ClientID
	}

	snapRef := GenerateSnapshotRef()
	snapID := "snp_" + execRecord.ID
	if strings.HasPrefix(execRecord.ID, "exec-") || strings.HasPrefix(execRecord.ID, "exec_") {
		snapID = "snp_" + execRecord.ID[5:]
	}

	asmID := ""
	asmRef := ""
	clientID := ""
	name := ""
	asmType := ""
	scopeMode := "same-origin"
	if asm != nil {
		asmID = asm.ID
		asmRef = asm.Ref
		clientID = asm.ClientID
		name = asm.Name
		asmType = asm.AssessmentType
		scopeMode = asm.ScopeMode
	} else {
		asmID = execRecord.AssessmentID
	}

	meta := make(map[string]string)
	if execRecord.ErrorMessage != "" {
		meta["error_message"] = execRecord.ErrorMessage
	}
	if !isComplete || (execRecord.Status != StatusCompleted && execRecord.Status != StatusCompletedWithErrors) {
		meta["inconclusive"] = "true"
	}
	if execRecord.Status == StatusCancelled {
		meta["cancelled"] = "true"
	}
	if strings.Contains(strings.ToLower(execRecord.ErrorMessage), "timeout") || strings.Contains(strings.ToLower(execRecord.ErrorMessage), "deadline exceeded") {
		meta["timeout"] = "true"
	}

	return &AssessmentSnapshot{
		ID:             snapID,
		SnapshotRef:    snapRef,
		AssessmentID:   asmID,
		AssessmentRef:  asmRef,
		ExecutionID:    execRecord.ID,
		ClientID:       clientID,
		TenantID:       tenantID,
		AccountID:      accountID,
		Name:           name,
		AssessmentType: asmType,
		Status:         execRecord.Status,
		IsComplete:     isComplete,
		StartedAt:      execRecord.StartedAt,
		CompletedAt:    execRecord.CompletedAt,
		DurationMs:     execRecord.DurationMs,
		RequestCount:   execRecord.RequestCount,
		TargetCount:    len(scopedTargets),
		FindingCount:   len(findings),
		ScopeMode:      scopeMode,
		ScopedTargets:  scopedTargets,
		ConfigSnapshot: execRecord.ConfigSnapshot,
		Metadata:       meta,
		CreatedAt:      time.Now().UTC(),
	}
}

// -----------------------------------------------------------------------------
// Phase 6.7: Incomplete Assessment Handling & Coverage Modeling
// -----------------------------------------------------------------------------

// AssessmentCoverage captures the multi-dimensional coverage achieved by an assessment.
type AssessmentCoverage struct {
	OverallOutcome    AssessmentStatus `json:"overall_outcome"`
	IsComplete        bool             `json:"is_complete"`
	IsInconclusive    bool             `json:"is_inconclusive"`
	ScopedTargets     []string         `json:"scoped_targets,omitempty"`
	AssessedTargets   []string         `json:"assessed_targets,omitempty"`
	FailedTargets     []string         `json:"failed_targets,omitempty"`
	SkippedTargets    []string         `json:"skipped_targets,omitempty"`
	CoveredCategories []string         `json:"covered_categories,omitempty"`
	FailedCategories  []string         `json:"failed_categories,omitempty"`
	SkippedCategories []string         `json:"skipped_categories,omitempty"`
}

// CanResolveFinding evaluates whether a candidate absent finding has sufficient qualifying coverage
// across execution outcome, target scope, and detector/category coverage to safely transition to RESOLVED.
// If any requirement is missing or violated, it returns false and an explanatory safety refusal reason.
func (c *AssessmentCoverage) CanResolveFinding(primaryTarget string, associatedTargets []string, category string) (bool, string) {
	// 1. Execution Outcome Checks
	if !c.IsComplete {
		return false, "assessment execution is marked incomplete"
	}
	if c.OverallOutcome != StatusCompleted && c.OverallOutcome != StatusCompletedWithErrors {
		return false, fmt.Sprintf("assessment completion status is %s (must be COMPLETED)", c.OverallOutcome)
	}
	if c.IsInconclusive {
		return false, "assessment outcome is inconclusive or invalidated by errors"
	}

	// 2. Build complete list of affected targets
	targetMap := make(map[string]struct{})
	if pt := strings.TrimSpace(primaryTarget); pt != "" {
		targetMap[pt] = struct{}{}
	}
	for _, at := range associatedTargets {
		if at = strings.TrimSpace(at); at != "" {
			targetMap[at] = struct{}{}
		}
	}
	if len(targetMap) == 0 {
		return false, "finding has no associated target information"
	}

	var findingTargets []string
	for t := range targetMap {
		findingTargets = append(findingTargets, t)
	}
	sort.Strings(findingTargets)

	// 3. Target Scope Verification
	if len(c.ScopedTargets) == 0 {
		return false, "assessment has zero scoped targets"
	}
	for _, t := range findingTargets {
		if !correlation.IsSingleTargetInScope(t, c.ScopedTargets) {
			return false, fmt.Sprintf("target %q is not in authorized assessment scope", t)
		}
	}

	// 4. Target Failure & Omission Checks
	if len(c.FailedTargets) > 0 {
		for _, t := range findingTargets {
			if correlation.IsSingleTargetInScope(t, c.FailedTargets) {
				return false, fmt.Sprintf("target %q encountered execution failure, transport error, or timeout", t)
			}
		}
	}
	if len(c.SkippedTargets) > 0 {
		for _, t := range findingTargets {
			if correlation.IsSingleTargetInScope(t, c.SkippedTargets) {
				return false, fmt.Sprintf("target %q was skipped, omitted, or unassessed", t)
			}
		}
	}

	// 5. Successful Assessment Verification (if assessed targets tracked)
	if len(c.AssessedTargets) > 0 {
		for _, t := range findingTargets {
			if !correlation.IsSingleTargetInScope(t, c.AssessedTargets) {
				return false, fmt.Sprintf("target %q was not successfully assessed", t)
			}
		}
	}

	// 6. Detector & Category Coverage Checks
	normCat := strings.ToLower(report.NormalizeCategory(category))
	if len(c.FailedCategories) > 0 {
		for _, fc := range c.FailedCategories {
			if strings.EqualFold(normCat, strings.ToLower(report.NormalizeCategory(fc))) {
				return false, fmt.Sprintf("check category %q failed during assessment execution", category)
			}
		}
	}
	if len(c.SkippedCategories) > 0 {
		for _, sc := range c.SkippedCategories {
			if strings.EqualFold(normCat, strings.ToLower(report.NormalizeCategory(sc))) {
				return false, fmt.Sprintf("check category %q was skipped or disabled", category)
			}
		}
	}
	if len(c.CoveredCategories) > 0 {
		covered := false
		for _, cc := range c.CoveredCategories {
			cleanCC := strings.ToLower(report.NormalizeCategory(cc))
			if strings.EqualFold(normCat, cleanCC) || cleanCC == "all" || cleanCC == "*" {
				covered = true
				break
			}
		}
		if !covered {
			return false, fmt.Sprintf("check category %q was not executed in assessment scope", category)
		}
	}

	return true, ""
}

// Coverage extracts the AssessmentCoverage representation from an AssessmentSnapshot.
func (s *AssessmentSnapshot) Coverage() AssessmentCoverage {
	return AssessmentCoverage{
		OverallOutcome:    s.Status,
		IsComplete:        s.IsComplete,
		IsInconclusive:    s.IsInconclusive(),
		ScopedTargets:     s.ScopedTargets,
		AssessedTargets:   s.GetAssessedTargets(),
		FailedTargets:     s.GetFailedTargets(),
		SkippedTargets:    s.GetSkippedTargets(),
		CoveredCategories: s.GetCoveredCategories(),
		FailedCategories:  s.GetFailedCategories(),
		SkippedCategories: s.GetSkippedCategories(),
	}
}

// IsInconclusive returns true if the snapshot was marked inconclusive or represents an incomplete execution.
func (s *AssessmentSnapshot) IsInconclusive() bool {
	if !s.IsComplete {
		return true
	}
	if s.Status != StatusCompleted && s.Status != StatusCompletedWithErrors {
		return true
	}
	if s.CompletedAt == nil || s.CompletedAt.IsZero() {
		return true
	}
	if s.Metadata != nil {
		if s.Metadata["inconclusive"] == "true" ||
			s.Metadata["coverage_inconclusive"] == "true" ||
			s.Metadata["timeout"] == "true" ||
			s.Metadata["cancelled"] == "true" ||
			s.Metadata["missing_required_evidence"] == "true" ||
			s.Metadata["unsupported_coverage"] == "true" {
			return true
		}
		if s.Metadata["error_message"] != "" && s.Status != StatusCompleted && s.Status != StatusCompletedWithErrors {
			return true
		}
	}
	return false
}

func parseMetadataCommaList(meta map[string]string, key string) []string {
	if meta == nil {
		return nil
	}
	raw := meta[key]
	if raw == "" {
		return nil
	}
	var res []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			res = append(res, p)
		}
	}
	return res
}

func setMetadataCommaList(meta map[string]string, key string, items []string) map[string]string {
	if meta == nil {
		meta = make(map[string]string)
	}
	var clean []string
	for _, it := range items {
		if it = strings.TrimSpace(it); it != "" {
			clean = append(clean, it)
		}
	}
	if len(clean) > 0 {
		meta[key] = strings.Join(clean, ",")
	} else {
		delete(meta, key)
	}
	return meta
}

// GetAssessedTargets returns targets that completed scan without failure.
func (s *AssessmentSnapshot) GetAssessedTargets() []string {
	return parseMetadataCommaList(s.Metadata, "assessed_targets")
}

// SetAssessedTargets sets targets that completed scan without failure.
func (s *AssessmentSnapshot) SetAssessedTargets(targets []string) {
	s.Metadata = setMetadataCommaList(s.Metadata, "assessed_targets", targets)
}

// GetFailedTargets returns targets that encountered connection failures, timeouts, or transport errors.
func (s *AssessmentSnapshot) GetFailedTargets() []string {
	return parseMetadataCommaList(s.Metadata, "failed_targets")
}

// SetFailedTargets records targets that encountered connection failures, timeouts, or transport errors.
func (s *AssessmentSnapshot) SetFailedTargets(targets []string) {
	s.Metadata = setMetadataCommaList(s.Metadata, "failed_targets", targets)
}

// GetSkippedTargets returns targets omitted or skipped during execution.
func (s *AssessmentSnapshot) GetSkippedTargets() []string {
	return parseMetadataCommaList(s.Metadata, "skipped_targets")
}

// SetSkippedTargets records targets omitted or skipped during execution.
func (s *AssessmentSnapshot) SetSkippedTargets(targets []string) {
	s.Metadata = setMetadataCommaList(s.Metadata, "skipped_targets", targets)
}

// GetCoveredCategories returns the categories/checks evaluated during the assessment.
func (s *AssessmentSnapshot) GetCoveredCategories() []string {
	cats := parseMetadataCommaList(s.Metadata, "covered_categories")
	if len(cats) == 0 {
		cats = parseMetadataCommaList(s.Metadata, "scoped_categories")
	}
	return cats
}

// SetCoveredCategories records the categories/checks evaluated during the assessment.
func (s *AssessmentSnapshot) SetCoveredCategories(categories []string) {
	s.Metadata = setMetadataCommaList(s.Metadata, "covered_categories", categories)
}

// GetFailedCategories returns categories/checks that encountered errors during execution.
func (s *AssessmentSnapshot) GetFailedCategories() []string {
	return parseMetadataCommaList(s.Metadata, "failed_categories")
}

// SetFailedCategories records categories/checks that encountered errors during execution.
func (s *AssessmentSnapshot) SetFailedCategories(categories []string) {
	s.Metadata = setMetadataCommaList(s.Metadata, "failed_categories", categories)
}

// GetSkippedCategories returns categories/checks that were disabled or skipped.
func (s *AssessmentSnapshot) GetSkippedCategories() []string {
	cats := parseMetadataCommaList(s.Metadata, "skipped_categories")
	if len(cats) == 0 {
		cats = parseMetadataCommaList(s.Metadata, "disabled_categories")
	}
	return cats
}

// SetSkippedCategories records categories/checks that were disabled or skipped.
func (s *AssessmentSnapshot) SetSkippedCategories(categories []string) {
	s.Metadata = setMetadataCommaList(s.Metadata, "skipped_categories", categories)
}

// MarkInconclusive marks the snapshot as inconclusive with a reason.
func (s *AssessmentSnapshot) MarkInconclusive(reason string) {
	if s.Metadata == nil {
		s.Metadata = make(map[string]string)
	}
	s.Metadata["inconclusive"] = "true"
	if reason != "" {
		s.Metadata["inconclusive_reason"] = reason
	}
}

// ExtractHistoricalEvidence extracts distinct historical evidence records from assessment findings.
func ExtractHistoricalEvidence(snapshotID string, findings []AssessmentFinding) []HistoricalEvidenceRecord {
	var records []HistoricalEvidenceRecord
	seenEvidence := make(map[string]struct{})

	for _, f := range findings {
		tenantID := ""
		accountID := ""
		if f.EvidenceDetails.Details != nil {
			tenantID = f.EvidenceDetails.Details["tenant_id"]
			accountID = f.EvidenceDetails.Details["account_id"]
		}

		primaryEvID := ""
		if f.Provenance != nil && f.Provenance.EvidenceID != "" {
			primaryEvID = f.Provenance.EvidenceID
		} else if f.EvidenceDetails.Details != nil && f.EvidenceDetails.Details["evidence_id"] != "" {
			primaryEvID = f.EvidenceDetails.Details["evidence_id"]
		}
		if primaryEvID == "" {
			primaryEvID = fmt.Sprintf("ev_%s_primary", f.ID)
		}

		sourceEngine := f.RuleID
		if f.Provenance != nil && f.Provenance.SourceEngine != "" {
			sourceEngine = f.Provenance.SourceEngine
		}
		evType := "http_response"
		if f.Provenance != nil && f.Provenance.EvidenceType != "" {
			evType = f.Provenance.EvidenceType
		}

		payload := ""
		if f.EvidenceDetails.Details != nil {
			payload = f.EvidenceDetails.Details["payload"]
		}

		key := snapshotID + ":" + f.ID + ":" + primaryEvID
		if _, exists := seenEvidence[key]; !exists {
			seenEvidence[key] = struct{}{}
			rec := HistoricalEvidenceRecord{
				ID:                 fmt.Sprintf("ev_hist_%x", sha256.Sum256([]byte(key)))[:24],
				SnapshotID:         snapshotID,
				AssessmentID:       f.AssessmentID,
				ExecutionID:        f.ExecutionID,
				FindingID:          f.ID,
				FindingFingerprint: f.Fingerprint,
				TargetID:           f.TargetID,
				TargetURL:          f.TargetURL,
				EvidenceID:         primaryEvID,
				EvidenceType:       evType,
				SourceEngine:       sourceEngine,
				DetectionMethod:    f.EvidenceDetails.DetectionMethod,
				Observation:        f.EvidenceDetails.Observation,
				HTTPStatus:         f.EvidenceDetails.HTTPStatus,
				HTTPMethod:         f.EvidenceDetails.HTTPMethod,
				ContentType:        f.EvidenceDetails.ContentType,
				Payload:            payload,
				SafeCurlCommand:    f.VerificationRecord.SafeCurlCommand,
				VerificationStatus: f.VerificationStatus,
				VerificationResult: f.VerificationRecord.Result,
				TenantID:           tenantID,
				AccountID:          accountID,
				CreatedAt:          f.CreatedAt,
			}
			records = append(records, rec)
		}

		// Secondary consolidated evidence IDs from Phase 6.4 deduplication
		if f.EvidenceDetails.Details != nil {
			if mergedEvs := f.EvidenceDetails.Details["merged_evidence_ids"]; mergedEvs != "" {
				for _, mID := range strings.Split(mergedEvs, ",") {
					mID = strings.TrimSpace(mID)
					if mID == "" || mID == primaryEvID {
						continue
					}
					mKey := snapshotID + ":" + f.ID + ":" + mID
					if _, exists := seenEvidence[mKey]; !exists {
						seenEvidence[mKey] = struct{}{}
						altPayload := f.EvidenceDetails.Details["additional_payloads"]
						altCurl := f.EvidenceDetails.Details["alternative_curl_commands"]
						mRec := HistoricalEvidenceRecord{
							ID:                 fmt.Sprintf("ev_hist_%x", sha256.Sum256([]byte(mKey)))[:24],
							SnapshotID:         snapshotID,
							AssessmentID:       f.AssessmentID,
							ExecutionID:        f.ExecutionID,
							FindingID:          f.ID,
							FindingFingerprint: f.Fingerprint,
							TargetID:           f.TargetID,
							TargetURL:          f.TargetURL,
							EvidenceID:         mID,
							EvidenceType:       "consolidated_evidence",
							SourceEngine:       f.EvidenceDetails.Details["merged_sources"],
							DetectionMethod:    f.EvidenceDetails.DetectionMethod,
							Observation:        "Consolidated detector evidence from deduplicated finding: " + mID,
							HTTPStatus:         f.EvidenceDetails.HTTPStatus,
							HTTPMethod:         f.EvidenceDetails.HTTPMethod,
							ContentType:        f.EvidenceDetails.ContentType,
							Payload:            altPayload,
							SafeCurlCommand:    altCurl,
							VerificationStatus: f.VerificationStatus,
							VerificationResult: f.VerificationRecord.Result,
							TenantID:           tenantID,
							AccountID:          accountID,
							CreatedAt:          f.CreatedAt,
						}
						records = append(records, mRec)
					}
				}
			}
		}
	}

	return records
}

// -----------------------------------------------------------------------------
// Phase 6.6: Finding Lifecycle Management
// -----------------------------------------------------------------------------

var (
	ErrLifecycleNotFound = errors.New("finding lifecycle record not found")
)

// FindingLifecycleRecord represents the authoritative point-in-time lifecycle status of a vulnerability.
type FindingLifecycleRecord struct {
	ID                 string            `json:"id"`
	TenantID           string            `json:"tenant_id"`
	AccountID          string            `json:"account_id"`
	ClientID           string            `json:"client_id"`
	Fingerprint        string            `json:"fingerprint"`
	FingerprintVersion string            `json:"fingerprint_version"`
	CurrentState       string            `json:"current_state"` // NEW, ACTIVE, RESOLVED, REGRESSED
	PreviousState      string            `json:"previous_state,omitempty"`
	TargetID           string            `json:"target_id,omitempty"`
	TargetURL          string            `json:"target_url"`
	Title              string            `json:"title"`
	Category           string            `json:"category"`
	Severity           string            `json:"severity"`
	Score              int               `json:"score"`
	LastAssessmentID   string            `json:"last_assessment_id"`
	LastExecutionID    string            `json:"last_execution_id"`
	LastSnapshotID     string            `json:"last_snapshot_id,omitempty"`
	FirstObservedAt    time.Time         `json:"first_observed_at"`
	LastObservedAt     time.Time         `json:"last_observed_at"`
	ResolvedAt         *time.Time        `json:"resolved_at,omitempty"`
	RegressionCount    int               `json:"regression_count"`
	Metadata           map[string]string `json:"metadata,omitempty"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

// FindingLifecycleEvent captures an immutable transition event in the lifecycle of a finding.
type FindingLifecycleEvent struct {
	ID                   string            `json:"id"`
	TenantID             string            `json:"tenant_id"`
	AccountID            string            `json:"account_id"`
	ClientID             string            `json:"client_id"`
	AssessmentID         string            `json:"assessment_id"`
	ExecutionID          string            `json:"execution_id"`
	SnapshotID           string            `json:"snapshot_id,omitempty"`
	FindingID            string            `json:"finding_id"`
	Fingerprint          string            `json:"fingerprint"`
	FingerprintVersion   string            `json:"fingerprint_version"`
	TargetID             string            `json:"target_id,omitempty"`
	TargetURL            string            `json:"target_url"`
	PreviousState        string            `json:"previous_state"`
	CurrentState         string            `json:"current_state"`
	TransitionReason     string            `json:"transition_reason"`
	QualifyingAssessment bool              `json:"qualifying_assessment"`
	HistoricalFindingID  string            `json:"historical_finding_id,omitempty"`
	HistoricalEvidenceID string            `json:"historical_evidence_id,omitempty"`
	Metadata             map[string]string `json:"metadata,omitempty"`
	CreatedAt            time.Time         `json:"created_at"`
}

// FindingLifecycleListOptions specifies filters and pagination for finding lifecycle queries.
type FindingLifecycleListOptions struct {
	Auth         TenantAuthContext
	ClientID     string
	TenantID     string
	AccountID    string
	CurrentState string
	Fingerprint  string
	TargetURL    string
	Limit        int
	Offset       int
}
