package businesslogic

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"felix/pkg/report"
)

// BLCategory defines the 8 business logic security categories.
type BLCategory string

const (
	CategoryWorkflowCircumvention    BLCategory = "BL-01" // Workflow Circumvention (Skipped Steps)
	CategoryUnexpectedStateTransition BLCategory = "BL-02" // Unexpected State Transitions
	CategoryStateManipulation        BLCategory = "BL-03" // State Manipulation & Integrity
	CategoryUnauthorizedWorkflowAccess BLCategory = "BL-04" // Unauthorized Workflow Access
	CategorySensitiveFlowAbuse       BLCategory = "BL-05" // Sensitive Business-Flow Abuse
	CategoryReplayIdempotency        BLCategory = "BL-06" // Replay & Idempotency Flaws
	CategoryPrivilegeStateMismatch   BLCategory = "BL-07" // Privilege & State Inconsistency
	CategoryDataValidationInvariants BLCategory = "BL-08" // Business Data Validation & Invariants
)

// AllCategories returns all 8 business logic security categories.
func AllCategories() []BLCategory {
	return []BLCategory{
		CategoryWorkflowCircumvention,
		CategoryUnexpectedStateTransition,
		CategoryStateManipulation,
		CategoryUnauthorizedWorkflowAccess,
		CategorySensitiveFlowAbuse,
		CategoryReplayIdempotency,
		CategoryPrivilegeStateMismatch,
		CategoryDataValidationInvariants,
	}
}

// CategoryInfo provides authoritative metadata and boundaries for each category.
type CategoryInfo struct {
	Code                 string   `json:"code"`
	Name                 string   `json:"name"`
	CWE                  string   `json:"cwe"`
	WSTG                 string   `json:"wstg"`
	Description          string   `json:"description"`
	VerificationBoundary string   `json:"verification_boundary"`
	Preconditions        []string `json:"preconditions"`
}

// CategoryMetadata maps all 8 business logic categories to authoritative metadata.
var CategoryMetadata = map[BLCategory]CategoryInfo{
	CategoryWorkflowCircumvention: {
		Code:                 "BL-01",
		Name:                 "Workflow Circumvention (Skipped Steps)",
		CWE:                  "CWE-840",
		WSTG:                 "WSTG-BUSL-01",
		Description:          "Caller invokes a terminal or later workflow step without fulfilling mandatory earlier prerequisites (e.g. downloading prior to payment or verification).",
		VerificationBoundary: "Verified only when the protected action/resource demonstrably succeeds or is granted without satisfying the established prerequisite. Difference in HTTP response code alone is CANDIDATE or INCONCLUSIVE.",
		Preconditions:        []string{"Multi-step workflow", "Established prerequisite requirement", "Terminal/protected action endpoint"},
	},
	CategoryUnexpectedStateTransition: {
		Code:                 "BL-02",
		Name:                 "Unexpected State Transitions",
		CWE:                  "CWE-372",
		WSTG:                 "WSTG-BUSL-02",
		Description:          "Application permits invalid or prohibited state machine jumps (e.g. Cancelled -> Completed, Rejected -> Approved, Disabled -> Active).",
		VerificationBoundary: "Verified only when the server-authoritative state record confirms the illegal transition occurred. Responding with 200 OK without persisted or observable transition remains CANDIDATE.",
		Preconditions:        []string{"Stateful workflow entity", "Transition endpoints", "Established valid state model"},
	},
	CategoryStateManipulation: {
		Code:                 "BL-03",
		Name:                 "State Manipulation & Parameter Integrity",
		CWE:                  "CWE-472",
		WSTG:                 "WSTG-BUSL-03",
		Description:          "Client-controlled parameters override server-authoritative state fields (e.g. status, approval, role, total, discount).",
		VerificationBoundary: "Verified only when client-supplied state fields demonstrably alter the authoritative business outcome or entitlement. Ignored fields remain NOT_VULNERABLE.",
		Preconditions:        []string{"State update or creation endpoint", "Server-authoritative state fields"},
	},
	CategoryUnauthorizedWorkflowAccess: {
		Code:                 "BL-04",
		Name:                 "Unauthorized Workflow Access",
		CWE:                  "CWE-285",
		WSTG:                 "WSTG-BUSL-04",
		Description:          "Caller invokes a privileged or restricted workflow step outside their assigned role, ownership, or verification status.",
		VerificationBoundary: "Verified only when an unprivileged or unverified actor successfully executes a restricted transition or modifies another user's workflow entity.",
		Preconditions:        []string{"Distinct role/identity contexts", "Role-restricted workflow action"},
	},
	CategorySensitiveFlowAbuse: {
		Code:                 "BL-05",
		Name:                 "Sensitive Business-Flow Abuse",
		CWE:                  "CWE-799",
		WSTG:                 "WSTG-BUSL-05",
		Description:          "Critical business actions (coupons, allocations, referral credits, reservations) lack limits or can be automated outside business constraints.",
		VerificationBoundary: "Verified only when repeated bounded probes demonstrably exceed documented business limits without rejection. Rate limits and budgets strictly enforced.",
		Preconditions:        []string{"Limited-use business flow", "Documented allocation limit", "Safe testing budget"},
	},
	CategoryReplayIdempotency: {
		Code:                 "BL-06",
		Name:                 "Replay & Idempotency Flaws",
		CWE:                  "CWE-294",
		WSTG:                 "WSTG-BUSL-06",
		Description:          "Replaying a single-use or state-changing action causes duplicate business effects (e.g. repeated redemptions, duplicated orders, double processing).",
		VerificationBoundary: "Verified only when a single-use action request produces duplicate business effects when replayed. Idempotent rejection or identical cached response is NOT_VULNERABLE.",
		Preconditions:        []string{"Single-use action request", "Observable entity effect"},
	},
	CategoryPrivilegeStateMismatch: {
		Code:                 "BL-07",
		Name:                 "Privilege & State Inconsistency",
		CWE:                  "CWE-269",
		WSTG:                 "WSTG-BUSL-07",
		Description:          "Application state and effective permissions disagree (e.g. revoked user continues performing action, unverified user has active permissions).",
		VerificationBoundary: "Verified only when an actor whose permission or workflow state was downgraded or revoked successfully continues to execute restricted actions.",
		Preconditions:        []string{"Identity state transition", "Restricted operation endpoint"},
	},
	CategoryDataValidationInvariants: {
		Code:                 "BL-08",
		Name:                 "Business Data Validation & Invariants",
		CWE:                  "CWE-20",
		WSTG:                 "WSTG-BUSL-08",
		Description:          "Application accepts contradictory, mathematically invalid, or boundary-violating business data (e.g. negative prices, conflicting status combinations).",
		VerificationBoundary: "Verified only when mathematically contradictory or invariant-violating inputs are accepted and influence persisted state or business calculation.",
		Preconditions:        []string{"Business calculation endpoint", "Known invariant constraint"},
	},
}

// VerificationState represents the procedural verification status of a business logic test.
type VerificationState string

const (
	StateObserved        VerificationState = "OBSERVED"
	StateCandidate       VerificationState = "CANDIDATE"
	StateVerified        VerificationState = "VERIFIED"
	StateInconclusive    VerificationState = "INCONCLUSIVE"
	StateBlockedBySafety VerificationState = "BLOCKED_BY_SAFETY"
	StateNotTested       VerificationState = "NOT_TESTED"
	StateNotVulnerable   VerificationState = "NOT_VULNERABLE"
)

// CoverageStatus represents the assessment status for a category.
type CoverageStatus string

const (
	CoverageUntested             CoverageStatus = "UNTESTED"
	CoverageActivelyTested       CoverageStatus = "ACTIVELY_TESTED"
	CoveragePassivelyAssessed    CoverageStatus = "PASSIVELY_ASSESSED"
	CoverageVerifiedIssueFound   CoverageStatus = "VERIFIED_ISSUE_FOUND"
	CoverageCandidateIdentified  CoverageStatus = "CANDIDATE_IDENTIFIED"
	CoverageBlockedSafety        CoverageStatus = "BLOCKED_BY_SAFETY"
	CoverageBlockedMissingPrereq CoverageStatus = "BLOCKED_MISSING_PREREQUISITES"
	CoverageSkippedScope         CoverageStatus = "SKIPPED_SCOPE"
	CoverageNotApplicable        CoverageStatus = "NOT_APPLICABLE"
)

// EvidenceSource distinguishes the provenance of workflow assumptions.
type EvidenceSource string

const (
	SourceObservedFact     EvidenceSource = "OBSERVED_FACT"     // Empirically seen in HTTP traffic
	SourceOperatorRule     EvidenceSource = "OPERATOR_RULE"     // Explicitly supplied by assessor
	SourceInferredHypothesis EvidenceSource = "INFERRED_HYPOTHESIS" // Hypothesized pattern (not an established rule)
	SourceVerifiedViolation EvidenceSource = "VERIFIED_VIOLATION" // Confirmed security breach
)

// WorkflowStep models an individual step within an ordered business workflow.
type WorkflowStep struct {
	Index                int      `json:"index"`
	Name                 string   `json:"name"`
	Endpoint             string   `json:"endpoint"`
	Method               string   `json:"method"`
	Prerequisites        []string `json:"prerequisites,omitempty"`
	IsStateChanging      bool     `json:"is_state_changing"`
	RequiredRole         string   `json:"required_role,omitempty"`
	ExpectedState        string   `json:"expected_state,omitempty"`
	VerificationEligible bool     `json:"verification_eligible"`
}

// Transition models a state change within a workflow.
type Transition struct {
	FromState            string `json:"from_state"`
	ToState              string `json:"to_state"`
	Action               string `json:"action"`
	RequiredPrecondition string `json:"required_precondition,omitempty"`
	IsProhibited         bool   `json:"is_prohibited"`
}

// Workflow models an ordered sequence of business actions and observed states.
type Workflow struct {
	ID                 string         `json:"id"`
	Name               string         `json:"name"`
	Description        string         `json:"description"`
	Steps              []WorkflowStep `json:"steps"`
	States             []string       `json:"states"`
	Preconditions      map[string]string `json:"preconditions,omitempty"`
	AllowedTransitions []Transition   `json:"allowed_transitions,omitempty"`
	ActorContext       string         `json:"actor_context,omitempty"`
	EvidenceSource     EvidenceSource `json:"evidence_source"`
	Confidence         string         `json:"confidence"`
	IsPartial          bool           `json:"is_partial"`
}

// PlanStatus defines the planning state of an individual check.
type PlanStatus string

const (
	PlanReady   PlanStatus = "READY"
	PlanBlocked PlanStatus = "BLOCKED"
	PlanSkipped PlanStatus = "SKIPPED"
)

// PlannedCheck represents a planned check in dry-run mode.
type PlannedCheck struct {
	ID                string     `json:"id"`
	Category          BLCategory `json:"category"`
	Name              string     `json:"name"`
	WorkflowID        string     `json:"workflow_id"`
	SecurityObjective string     `json:"security_objective"`
	Preconditions     []string   `json:"preconditions"`
	IsStateChanging   bool       `json:"is_state_changing"`
	ExpectedBehavior  string     `json:"expected_behavior"`
	Status            PlanStatus `json:"status"`
	BlockedReason     string     `json:"blocked_reason,omitempty"`
}

// TestPlan aggregates planned workflow checks.
type TestPlan struct {
	AssessmentID       string         `json:"assessment_id"`
	TargetURL          string         `json:"target_url"`
	GeneratedAt        time.Time      `json:"generated_at"`
	TotalWorkflows     int            `json:"total_workflows"`
	TotalPlannedChecks int            `json:"total_planned_checks"`
	ReadyChecks        int            `json:"ready_checks"`
	BlockedChecks      int            `json:"blocked_checks"`
	PlannedChecks      []PlannedCheck `json:"planned_checks"`
}

// Result records the outcome of an individual business logic evaluation.
type Result struct {
	ID                string            `json:"id"`
	AssessmentID      string            `json:"assessment_id"`
	ExecutionID       string            `json:"execution_id"`
	Category          BLCategory        `json:"category"`
	CheckID           string            `json:"check_id"`
	CheckName         string            `json:"check_name"`
	WorkflowID        string            `json:"workflow_id"`
	WorkflowName      string            `json:"workflow_name"`
	Endpoint          string            `json:"endpoint"`
	Method            string            `json:"method"`
	VerificationState VerificationState `json:"verification_state"`
	Severity          string            `json:"severity"`
	Confidence        string            `json:"confidence"`
	ObservedStatus    int               `json:"observed_status,omitempty"`
	StateBefore       string            `json:"state_before,omitempty"`
	StateAfter        string            `json:"state_after,omitempty"`
	EvidenceSummary   string            `json:"evidence_summary"`
	EvidenceDetails   map[string]string `json:"evidence_details,omitempty"`
	Finding           *report.Finding   `json:"finding,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
}

// CategoryCoverage records coverage statistics for one business logic category.
type CategoryCoverage struct {
	Category     BLCategory     `json:"category"`
	Code         string         `json:"code"`
	Name         string         `json:"name"`
	Status       CoverageStatus `json:"status"`
	ChecksRun    int            `json:"checks_run"`
	Verified     int            `json:"verified"`
	Candidates   int            `json:"candidates"`
	Observations int            `json:"observations"`
	Inconclusive int            `json:"inconclusive"`
	Blocked      int            `json:"blocked"`
	NotVulnerable int           `json:"not_vulnerable"`
	Explanation  string         `json:"explanation"`
}

// Summary aggregates business logic results and coverage across categories and workflows.
type Summary struct {
	TargetURL          string                      `json:"target_url"`
	TotalChecks        int                         `json:"total_checks"`
	CategoriesAssessed int                         `json:"categories_assessed"`
	WorkflowsModeled   int                         `json:"workflows_modeled"`
	VerifiedCount      int                         `json:"verified_count"`
	CandidateCount     int                         `json:"candidate_count"`
	ObservedCount      int                         `json:"observed_count"`
	InconclusiveCount  int                         `json:"inconclusive_count"`
	BlockedCount       int                         `json:"blocked_count"`
	NotVulnerableCount int                         `json:"not_vulnerable_count"`
	SyntheticFixture   bool                        `json:"synthetic_fixture,omitempty"`
	CategoryCoverageMap map[string]CategoryCoverage `json:"category_coverage_map"`
}

// RunRecord represents a persistent run record in SQLite.
type RunRecord struct {
	ID                 string    `json:"id"`
	AssessmentID       string    `json:"assessment_id"`
	ExecutionID        string    `json:"execution_id"`
	TargetURL          string    `json:"target_url"`
	TotalChecks        int       `json:"total_checks"`
	CategoriesAssessed int       `json:"categories_assessed"`
	WorkflowsModeled   int       `json:"workflows_modeled"`
	VerifiedCount      int       `json:"verified_count"`
	CandidateCount     int       `json:"candidate_count"`
	ObservedCount      int       `json:"observed_count"`
	InconclusiveCount  int       `json:"inconclusive_count"`
	BlockedCount       int       `json:"blocked_count"`
	NotVulnerableCount int       `json:"not_vulnerable_count"`
	SyntheticFixture   bool      `json:"synthetic_fixture,omitempty"`
	CoverageJSON       string    `json:"coverage_json"`
	CreatedAt          time.Time `json:"created_at"`
}

// DiscoveredEndpoint describes an HTTP endpoint evaluated for workflow modeling.
type DiscoveredEndpoint struct {
	Path        string            `json:"path"`
	Method      string            `json:"method"`
	Type        string            `json:"type,omitempty"` // e.g. "step", "cart", "checkout", "pay", "download", "approve"
	Parameters  []string          `json:"parameters,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	StatusCode  int               `json:"status_code,omitempty"`
	WorkflowHint string           `json:"workflow_hint,omitempty"`
}

// TestIdentity models an authorized identity context for testing.
type TestIdentity struct {
	ID             string            `json:"id"`
	Role           string            `json:"role"`
	PrivilegeLevel int               `json:"privilege_level"`
	Tokens         map[string]string `json:"tokens,omitempty"`
	Cookies        map[string]string `json:"cookies,omitempty"`
	IsVerified     bool              `json:"is_verified"`
	IsSuspended    bool              `json:"is_suspended"`
}

// AssessmentContext contains all inputs for a business logic security run.
type AssessmentContext struct {
	AssessmentID     string
	ExecutionID      string
	BaseURL          string
	Endpoints        []DiscoveredEndpoint
	Workflows        []Workflow
	Identities       []TestIdentity
	IsAllowed        func(string) bool
	IsExcluded       func(string) bool
	RequestBudget    int
	SyntheticFixture bool
	DryRun           bool
}

// Config defines operational parameters for the business logic engine.
type Config struct {
	Timeout            time.Duration
	MaxConcurrency     int
	MaxRequestsPerFlow int
	UserAgent          string
	AllowStateChanging bool
}

// DefaultConfig provides safe, bounded defaults.
func DefaultConfig() Config {
	return Config{
		Timeout:            15 * time.Second,
		MaxConcurrency:     3,
		MaxRequestsPerFlow: 10,
		UserAgent:          "Felix-BusinessLogic/2.0 (Security-Audit-Engine)",
		AllowStateChanging: false,
	}
}

// -------------------------------------------------------------------------
// Redaction & URL Sanitization Helpers
// -------------------------------------------------------------------------

var (
	tokenRegex    = regexp.MustCompile(`(?i)(bearer\s+[a-z0-9_\-\.~+/]+=*|eyj[a-z0-9_\-]{10,}\.[a-z0-9_\-]{10,}\.[a-z0-9_\-]+)`)
	creditCardRegex = regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`)
	secretParamRegex = regexp.MustCompile(`(?i)(sig|token|key|secret|password|auth|cvv|pin|card)=([^\s&"']+)`)
)

// RedactText removes sensitive credentials, tokens, and payment card numbers.
func RedactText(s string) string {
	if s == "" {
		return ""
	}
	s = tokenRegex.ReplaceAllString(s, "Bearer [REDACTED_TOKEN]")
	s = creditCardRegex.ReplaceAllString(s, "[REDACTED_CARD_NUMBER]")
	s = secretParamRegex.ReplaceAllString(s, "$1=[REDACTED]")
	return s
}

// SanitizeURL strips sensitive query parameters from target URLs.
func SanitizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return RedactText(rawURL)
	}
	q := u.Query()
	for k := range q {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "token") || strings.Contains(lower, "sig") ||
			strings.Contains(lower, "key") || strings.Contains(lower, "secret") ||
			strings.Contains(lower, "card") || strings.Contains(lower, "cvv") ||
			strings.Contains(lower, "auth") || strings.Contains(lower, "code") {
			q.Set(k, "[REDACTED]")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// HashIdentifier produces a safe one-way fingerprint of an identifier.
func HashIdentifier(id string) string {
	if id == "" {
		return ""
	}
	h := sha256.Sum256([]byte(id))
	return fmt.Sprintf("bl-%s", hex.EncodeToString(h[:6]))
}
