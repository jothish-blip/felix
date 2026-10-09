package assessment

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

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
	ID                 string             `json:"id"`
	Ref                string             `json:"ref"` // Human-readable reference, e.g. ASM-2026-0001
	ClientID           string             `json:"client_id"`
	Name               string             `json:"name"`
	Description        string             `json:"description,omitempty"`
	AssessmentType     string             `json:"assessment_type"` // e.g. BLACK_BOX_WEB, API_AUDIT, HYBRID
	Status             AssessmentStatus   `json:"status"`
	CreatedAt          time.Time          `json:"created_at"`
	UpdatedAt          time.Time          `json:"updated_at"`
	StartedAt          *time.Time         `json:"started_at,omitempty"`
	CompletedAt        *time.Time         `json:"completed_at,omitempty"`
	ScopeMode          string             `json:"scope_mode"` // same-origin, subdomains, explicit
	ConfigSnapshotJSON string             `json:"config_snapshot_json,omitempty"`
	FindingCount       int                `json:"finding_count"`
	Targets            []AssessmentTarget `json:"targets,omitempty"`
	Authorization      *AuthorizationRecord `json:"authorization,omitempty"`
	Exclusions         []Exclusion        `json:"exclusions,omitempty"`
	ScopeRules         []ScopeRule        `json:"scope_rules,omitempty"`
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
	FelixVersion   string `json:"felix_version"`
	BuildID        string `json:"build_id,omitempty"`
}

// AssessmentExecution records a single execution run of an assessment.
type AssessmentExecution struct {
	ID             string              `json:"id"`
	AssessmentID   string              `json:"assessment_id"`
	Status         AssessmentStatus    `json:"status"` // RUNNING, COMPLETED, COMPLETED_WITH_ERRORS, FAILED, CANCELLED
	StartedAt      time.Time           `json:"started_at"`
	CompletedAt    *time.Time          `json:"completed_at,omitempty"`
	DurationMs     int64               `json:"duration_ms,omitempty"`
	RequestCount   int                 `json:"request_count,omitempty"`
	ErrorMessage   string              `json:"error_message,omitempty"`
	ConfigSnapshot ScanConfigSnapshot  `json:"config_snapshot"`
	FindingCount   int                 `json:"finding_count"`
	Findings       []AssessmentFinding `json:"findings,omitempty"`
	Reports        []ReportRecord      `json:"reports,omitempty"`
}

// AssessmentFinding links an existing Felix finding directly to its assessment, run, and target.
type AssessmentFinding struct {
	ID                 string                    `json:"id"`
	AssessmentID       string                    `json:"assessment_id"`
	ExecutionID        string                    `json:"execution_id"`
	TargetID           string                    `json:"target_id"`
	OriginalFindingID  string                    `json:"original_finding_id"` // report.Finding.ID
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
	EvidenceDetails    report.EvidenceDetails    `json:"evidence"`
	VerificationRecord report.VerificationRecord `json:"verification"`
	Remediation        string                    `json:"remediation,omitempty"`
	CreatedAt          time.Time                 `json:"created_at"`
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
