package workflow

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"felix/pkg/auth"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

// Category defines the workflow integrity vulnerability category codes.
type Category string

const (
	// CategoryPrerequisiteSkipping detects invoking later workflow stages without completing mandatory prerequisites.
	CategoryPrerequisiteSkipping Category = "WORKFLOW-PREREQUISITE-SKIP"

	// CategoryInvalidOrdering detects executing steps out of order or from prohibited state machine states.
	CategoryInvalidOrdering Category = "WORKFLOW-INVALID-ORDER"

	// CategoryReplayIdempotency detects repeating single-use or non-idempotent operations producing duplicate side effects.
	CategoryReplayIdempotency Category = "WORKFLOW-REPLAY-DUPLICATE"

	// CategoryTokenContinuity detects reusing consumed, expired, or cross-workflow tokens.
	CategoryTokenContinuity Category = "WORKFLOW-TOKEN-REUSE"

	// CategoryIdentityContinuity detects one identity continuing or finalizing another identity's workflow without authorization.
	CategoryIdentityContinuity Category = "WORKFLOW-IDENTITY-MISMATCH"

	// CategoryConcurrentTransition detects race conditions allowing duplicate execution during concurrent transitions.
	CategoryConcurrentTransition Category = "WORKFLOW-CONCURRENT-RACE"
)

// AllCategories returns all supported workflow integrity categories.
func AllCategories() []Category {
	return []Category{
		CategoryPrerequisiteSkipping,
		CategoryInvalidOrdering,
		CategoryReplayIdempotency,
		CategoryTokenContinuity,
		CategoryIdentityContinuity,
		CategoryConcurrentTransition,
	}
}

// CategoryInfo defines authoritative metadata for each workflow integrity category.
type CategoryInfo struct {
	Code                 string   `json:"code"`
	Name                 string   `json:"name"`
	OWASP                string   `json:"owasp"`
	CWE                  string   `json:"cwe"`
	WSTG                 string   `json:"wstg"`
	Description          string   `json:"description"`
	VerificationBoundary string   `json:"verification_boundary"`
	Preconditions        []string `json:"preconditions"`
}

// CategoryMetadata maps category constants to metadata.
var CategoryMetadata = map[Category]CategoryInfo{
	CategoryPrerequisiteSkipping: {
		Code:                 "WORKFLOW-PREREQUISITE-SKIP",
		Name:                 "Missing Prerequisite & Step Circumvention",
		OWASP:                "API10:2023 Unsafe Consumption of APIs / Business Flow Bypass",
		CWE:                  "CWE-840 Business Logic Errors",
		WSTG:                 "WSTG-BUSL-01",
		Description:          "Caller invokes a later or terminal workflow step without fulfilling mandatory earlier prerequisites.",
		VerificationBoundary: "Verified only when the protected action/resource demonstrably succeeds or persists without satisfying prerequisites. HTTP status codes alone are CANDIDATE.",
		Preconditions:        []string{"Multi-step workflow", "Established prerequisite step", "Independent verification read-back"},
	},
	CategoryInvalidOrdering: {
		Code:                 "WORKFLOW-INVALID-ORDER",
		Name:                 "Invalid Ordering & Prohibited State Transitions",
		OWASP:                "API10:2023 Unsafe Consumption of APIs / State Violation",
		CWE:                  "CWE-372 Incomplete State Machine",
		WSTG:                 "WSTG-BUSL-02",
		Description:          "Application permits invalid or prohibited state transitions (e.g. Cancelled -> Completed, Expired -> Accepted).",
		VerificationBoundary: "Verified only when server-authoritative state confirms the prohibited transition occurred. A 2xx response without state change is CANDIDATE or NOT_VULNERABLE.",
		Preconditions:        []string{"Stateful workflow entity", "Transition endpoints", "Defined valid state model"},
	},
	CategoryReplayIdempotency: {
		Code:                 "WORKFLOW-REPLAY-DUPLICATE",
		Name:                 "Replay, Duplicate Execution & Non-Idempotent Actions",
		OWASP:                "API10:2023 Unsafe Consumption of APIs / Replay",
		CWE:                  "CWE-294 Replay Vulnerabilities",
		WSTG:                 "WSTG-BUSL-06",
		Description:          "Replaying a single-use action causes duplicate side effects (e.g. repeated redemptions, duplicated transactions).",
		VerificationBoundary: "Verified only when replaying a single-use operation demonstrably repeats the business side effect. Idempotent identical responses are NOT_VULNERABLE.",
		Preconditions:        []string{"Single-use action step", "Authoritative counter or entity read-back"},
	},
	CategoryTokenContinuity: {
		Code:                 "WORKFLOW-TOKEN-REUSE",
		Name:                 "Workflow Token & State Continuity Failure",
		OWASP:                "API10:2023 Unsafe Consumption of APIs / Token Misuse",
		CWE:                  "CWE-287 Improper Authentication / Token Reuse",
		WSTG:                 "WSTG-BUSL-07",
		Description:          "Reusing consumed, expired, or cross-workflow tokens succeeds in advancing or completing a workflow.",
		VerificationBoundary: "Verified only when an invalidated or foreign workflow token demonstrably authenticates an unauthorized step.",
		Preconditions:        []string{"Tokenized workflow step", "Consumed or cross-workflow token"},
	},
	CategoryIdentityContinuity: {
		Code:                 "WORKFLOW-IDENTITY-MISMATCH",
		Name:                 "Workflow Ownership & Identity Continuity Violation",
		OWASP:                "API1:2023 Broken Object Level Authorization",
		CWE:                  "CWE-639 Authorization Bypass Through User-Controlled Key",
		WSTG:                 "WSTG-BUSL-04",
		Description:          "One identity improperly continues, approves, or finalizes another identity's workflow without authorization.",
		VerificationBoundary: "Verified only when unauthorized principal successfully advances or completes another identity's workflow.",
		Preconditions:        []string{"Distinct identity contexts", "Owner-restricted workflow step"},
	},
	CategoryConcurrentTransition: {
		Code:                 "WORKFLOW-CONCURRENT-RACE",
		Name:                 "Concurrent Transition & Race Condition Integrity",
		OWASP:                "API10:2023 Unsafe Consumption of APIs / Concurrency",
		CWE:                  "CWE-362 Race Conditions",
		WSTG:                 "WSTG-BUSL-06",
		Description:          "Simultaneous requests on single-use workflow transitions cause duplicate state changes or double processing.",
		VerificationBoundary: "Verified only when bounded concurrent requests demonstrably execute a single-use operation more than once on synthetic fixtures.",
		Preconditions:        []string{"Single-use transition", "Synthetic fixture with counter verification"},
	},
}

// VerificationState represents the procedural verification status of a workflow check.
type VerificationState string

const (
	StateVerified      VerificationState = "VERIFIED"
	StateCandidate     VerificationState = "CANDIDATE"
	StateNotVulnerable VerificationState = "NOT_VULNERABLE"
	StateInconclusive  VerificationState = "INCONCLUSIVE"
	StateSkipped       VerificationState = "SKIPPED"
)

// CoverageStatus represents category coverage status.
type CoverageStatus string

const (
	CoverageUntested             CoverageStatus = "UNTESTED"
	CoverageActivelyTested       CoverageStatus = "ACTIVELY_TESTED"
	CoveragePassivelyAssessed    CoverageStatus = "PASSIVELY_ASSESSED"
	CoverageVerifiedIssueFound   CoverageStatus = "VERIFIED_ISSUE_FOUND"
	CoverageCandidateIdentified  CoverageStatus = "CANDIDATE_IDENTIFIED"
	CoverageBlockedMissingPrereq CoverageStatus = "BLOCKED_MISSING_PREREQUISITES"
	CoverageSkippedScope         CoverageStatus = "SKIPPED_SCOPE"
)

// PlanStatus defines the planning state in dry-run mode.
type PlanStatus string

const (
	PlanReady   PlanStatus = "READY"
	PlanBlocked PlanStatus = "BLOCKED"
	PlanSkipped PlanStatus = "SKIPPED"
)

// Step represents an individual action in a multi-step business workflow.
type Step struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	Endpoint             string            `json:"endpoint"`
	Method               string            `json:"method"` // GET, POST, PUT, DELETE, PATCH
	Payload              string            `json:"payload,omitempty"`
	Headers              map[string]string `json:"headers,omitempty"`
	Preconditions        []string          `json:"preconditions,omitempty"` // Required predecessor step IDs
	FromState            string            `json:"from_state,omitempty"`
	ToState              string            `json:"to_state,omitempty"`
	IsStateChanging      bool              `json:"is_state_changing"`
	IsSingleUse          bool              `json:"is_single_use"` // If true, step must not be executed more than once
	RequiredRole         string            `json:"required_role,omitempty"`
	ExtractTokenField    string            `json:"extract_token_field,omitempty"` // JSON field or header to extract workflow token
	InjectTokenHeader    string            `json:"inject_token_header,omitempty"` // Header name where token must be forwarded
	InjectTokenField     string            `json:"inject_token_field,omitempty"`  // JSON body parameter where token is injected
	VerificationEndpoint string            `json:"verification_endpoint,omitempty"` // Independent read-back endpoint
	VerificationMethod   string            `json:"verification_method,omitempty"`   // GET (default)
	VerificationProperty string            `json:"verification_property,omitempty"` // JSON property path in read-back (e.g. "status", "counter")
	ExpectedVerifiedValue any              `json:"expected_verified_value,omitempty"`
}

// Transition defines a valid state transition in the workflow graph.
type Transition struct {
	FromState    string `json:"from_state"`
	ToState      string `json:"to_state"`
	StepID       string `json:"step_id"`
	Action       string `json:"action,omitempty"`
	IsProhibited bool   `json:"is_prohibited,omitempty"`
}

// Workflow models an ordered sequence or graph of business steps.
type Workflow struct {
	ID                     string            `json:"id"`
	Name                   string            `json:"name"`
	Description            string            `json:"description,omitempty"`
	Steps                  []Step            `json:"steps"`
	States                 []string          `json:"states,omitempty"`
	InitialState           string            `json:"initial_state,omitempty"`
	TerminalStates         []string          `json:"terminal_states,omitempty"`
	AllowedTransitions     []Transition      `json:"allowed_transitions,omitempty"`
	ProhibitedTransitions  []Transition      `json:"prohibited_transitions,omitempty"`
	OwnerRole              string            `json:"owner_role,omitempty"`
	ApproverRole           string            `json:"approver_role,omitempty"`
	AllowLoops             bool              `json:"allow_loops"`
	MaxLoopIterations      int               `json:"max_loop_iterations,omitempty"`
	SyntheticFixtureOnly   bool              `json:"synthetic_fixture_only"`
	CategoriesToAssess     []Category        `json:"categories_to_assess,omitempty"`
}

// HasStateChangingStep returns true if any step in the workflow is marked as state-changing.
func (wf Workflow) HasStateChangingStep() bool {
	for _, s := range wf.Steps {
		if s.IsStateChanging {
			return true
		}
	}
	return false
}

// PolicyFile allows configuring workflows from external JSON definitions.
type PolicyFile struct {
	Version    string         `json:"version"`
	Workflows  []Workflow     `json:"workflows"`
	Identities []TestIdentity `json:"identities,omitempty"`
}

// ValidateWorkflow validates the workflow graph, predecessor references, and dependency cycles.
func ValidateWorkflow(wf Workflow) error {
	if strings.TrimSpace(wf.ID) == "" {
		return fmt.Errorf("workflow ID cannot be empty")
	}
	if len(wf.Steps) == 0 {
		return fmt.Errorf("workflow %q has no steps defined", wf.ID)
	}

	stepMap := make(map[string]Step, len(wf.Steps))
	for _, step := range wf.Steps {
		if strings.TrimSpace(step.ID) == "" {
			return fmt.Errorf("workflow %q contains a step with an empty ID", wf.ID)
		}
		if _, exists := stepMap[step.ID]; exists {
			return fmt.Errorf("workflow %q has duplicate step ID %q", wf.ID, step.ID)
		}
		if strings.TrimSpace(step.Endpoint) == "" {
			return fmt.Errorf("workflow %q step %q has an empty endpoint", wf.ID, step.ID)
		}
		stepMap[step.ID] = step
	}

	// Validate predecessor step references
	for _, step := range wf.Steps {
		for _, prereq := range step.Preconditions {
			if _, exists := stepMap[prereq]; !exists {
				return fmt.Errorf("workflow %q step %q references unknown precondition step %q", wf.ID, step.ID, prereq)
			}
			if prereq == step.ID {
				return fmt.Errorf("workflow %q step %q has self-referential prerequisite", wf.ID, step.ID)
			}
		}
	}

	// Detect dependency cycles if loops are not explicitly permitted
	if !wf.AllowLoops {
		if err := detectCycles(wf.Steps); err != nil {
			return fmt.Errorf("workflow %q has invalid dependency cycle: %w", wf.ID, err)
		}
	}

	return nil
}

// detectCycles performs topological cycle detection using Kahn's algorithm.
func detectCycles(steps []Step) error {
	inDegree := make(map[string]int)
	adj := make(map[string][]string)

	for _, s := range steps {
		inDegree[s.ID] = 0
		adj[s.ID] = make([]string, 0)
	}

	for _, s := range steps {
		for _, prereq := range s.Preconditions {
			adj[prereq] = append(adj[prereq], s.ID)
			inDegree[s.ID]++
		}
	}

	queue := make([]string, 0)
	for id, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, id)
		}
	}

	visited := 0
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		visited++

		for _, neighbor := range adj[curr] {
			inDegree[neighbor]--
			if inDegree[neighbor] == 0 {
				queue = append(queue, neighbor)
			}
		}
	}

	if visited < len(steps) {
		return fmt.Errorf("cyclic dependency detected across steps")
	}

	return nil
}

// TestIdentity models an isolated authentication principal.
type TestIdentity struct {
	ID             string            `json:"id"`
	Alias          string            `json:"alias"`
	Role           string            `json:"role"`
	PrivilegeLevel int               `json:"privilege_level"`
	Headers        map[string]string `json:"headers,omitempty"`
	Cookies        map[string]string `json:"cookies,omitempty"`
	IsVerified     bool              `json:"is_verified"`
	IsSuspended    bool              `json:"is_suspended"`
}

// AssessmentContext contains all contextual inputs for a workflow integrity assessment.
type AssessmentContext struct {
	AssessmentID            string
	ExecutionID             string
	BaseURL                 string
	Workflows               []Workflow
	Identities              []TestIdentity
	AllowStateChangingTests bool
	SyntheticFixture        bool
	AuthorizedFixtureHosts  []string
	IsFixtureTarget         func(string) bool
	Concurrency             int
	DryRun                  bool
	MaxRequests             int
	DispatchedRequests      *int32
	Authorization           *auth.AuthorizationRecord
	IsAllowed               func(string) bool
	IsExcluded              func(string) bool
}

// Config defines operational parameters for the workflow engine.
type Config struct {
	Timeout            time.Duration
	MaxResponseBytes   int64
	MaxRequestsPerFlow int
	Concurrency        int
	UserAgent          string
}

// DefaultConfig provides safe, bounded defaults.
func DefaultConfig() Config {
	return Config{
		Timeout:            15 * time.Second,
		MaxResponseBytes:   2 * 1024 * 1024, // 2MB
		MaxRequestsPerFlow: 15,
		Concurrency:        3,
		UserAgent:          "Felix-WorkflowIntegrity/2.0 (Security-Audit-Engine)",
	}
}

// PlannedCheck represents a planned check in dry-run mode.
type PlannedCheck struct {
	ID                string     `json:"id"`
	Category          Category   `json:"category"`
	Name              string     `json:"name"`
	WorkflowID        string     `json:"workflow_id"`
	StepID            string     `json:"step_id,omitempty"`
	OWASPRef          string     `json:"owasp_ref"`
	CWERef            string     `json:"cwe_ref"`
	Endpoint          string     `json:"endpoint"`
	Method            string     `json:"method"`
	SecurityObjective string     `json:"security_objective"`
	Preconditions     []string   `json:"preconditions"`
	IsStateChanging   bool       `json:"is_state_changing"`
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
	StateChangingChecks int           `json:"state_changing_checks"`
	PlannedChecks      []PlannedCheck `json:"planned_checks"`
}

// Result records the empirical outcome of an executed workflow check.
type Result struct {
	ID                string            `json:"id"`
	AssessmentID      string            `json:"assessment_id"`
	ExecutionID       string            `json:"execution_id"`
	Category          Category          `json:"category"`
	VulnCode          string            `json:"vuln_code"`
	WorkflowID        string            `json:"workflow_id"`
	WorkflowName      string            `json:"workflow_name"`
	StepID            string            `json:"step_id,omitempty"`
	CheckID           string            `json:"check_id"`
	CheckName         string            `json:"check_name"`
	OWASPRef          string            `json:"owasp_ref"`
	CWERef            string            `json:"cwe_ref"`
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

// CategoryCoverage records statistics for one category.
type CategoryCoverage struct {
	Category      Category       `json:"category"`
	Code          string         `json:"code"`
	Name          string         `json:"name"`
	OWASPRef      string         `json:"owasp_ref"`
	Status        CoverageStatus `json:"status"`
	ChecksRun     int            `json:"checks_run"`
	Verified      int            `json:"verified"`
	Candidates    int            `json:"candidates"`
	Inconclusive  int            `json:"inconclusive"`
	Blocked       int            `json:"blocked"`
	NotVulnerable int            `json:"not_vulnerable"`
	Explanation   string         `json:"explanation"`
}

// Summary aggregates workflow integrity verification outcomes.
type Summary struct {
	TargetURL           string                      `json:"target_url"`
	TotalWorkflows      int                         `json:"total_workflows"`
	TotalChecks         int                         `json:"total_checks"`
	CategoriesAssessed  int                         `json:"categories_assessed"`
	VerifiedCount       int                         `json:"verified_count"`
	CandidateCount      int                         `json:"candidate_count"`
	NotVulnerableCount  int                         `json:"not_vulnerable_count"`
	InconclusiveCount   int                         `json:"inconclusive_count"`
	BlockedCount        int                         `json:"blocked_count"`
	SyntheticFixture    bool                        `json:"synthetic_fixture,omitempty"`
	CategoryCoverageMap map[string]CategoryCoverage `json:"category_coverage_map"`
}

// RunRecord represents a persistent run in SQLite.
type RunRecord struct {
	ID                 string    `json:"id"`
	AssessmentID       string    `json:"assessment_id"`
	ExecutionID        string    `json:"execution_id"`
	TargetURL          string    `json:"target_url"`
	TotalWorkflows     int       `json:"total_workflows"`
	TotalChecks        int       `json:"total_checks"`
	CategoriesAssessed int       `json:"categories_assessed"`
	VerifiedCount      int       `json:"verified_count"`
	CandidateCount     int       `json:"candidate_count"`
	NotVulnerableCount int       `json:"not_vulnerable_count"`
	InconclusiveCount  int       `json:"inconclusive_count"`
	BlockedCount       int       `json:"blocked_count"`
	SyntheticFixture   bool      `json:"synthetic_fixture,omitempty"`
	CoverageJSON       string    `json:"coverage_json"`
	CreatedAt          time.Time `json:"created_at"`
}

// ResponseData captures empirical response details.
type ResponseData struct {
	StatusCode    int
	Header        map[string][]string
	Body          []byte
	ContentLength int64
	ExecutionTime time.Duration
}

// ComparisonResult encapsulates differential invariant analysis.
type ComparisonResult struct {
	State           VerificationState
	Severity        string
	Confidence      string
	EvidenceSummary string
	EvidenceDetails map[string]string
}

// -------------------------------------------------------------------------
// Transport & Security Boundary Utilities
// -------------------------------------------------------------------------

// SensitiveCredentialHeaders enumerates HTTP headers containing sensitive tokens or credentials.
var SensitiveCredentialHeaders = []string{
	"Authorization",
	"Cookie",
	"Cookie2",
	"X-Auth-Token",
	"X-API-Key",
	"X-Session-ID",
	"X-Session-Token",
	"X-CSRF-Token",
	"X-XSRF-Token",
	"Proxy-Authorization",
}

// StripSensitiveCredentials strips all sensitive credentials and tokens from a request.
func StripSensitiveCredentials(req *http.Request) {
	if req == nil || req.Header == nil {
		return
	}
	for _, h := range SensitiveCredentialHeaders {
		req.Header.Del(h)
	}
}

// IsLoopbackHost checks whether a hostname or IP represents a local loopback machine.
func IsLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	return h == "localhost" || h == "127.0.0.1" || h == "::1" || strings.HasPrefix(h, "127.")
}

// EffectivePort returns the explicit or scheme-default port for a URL.
func EffectivePort(u *url.URL) string {
	if u == nil {
		return ""
	}
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

// IsSameOrigin checks whether two URLs share the exact scheme, host, and effective port.
func IsSameOrigin(u1, u2 *url.URL) bool {
	if u1 == nil || u2 == nil {
		return false
	}
	if !strings.EqualFold(u1.Scheme, u2.Scheme) {
		return false
	}
	if !strings.EqualFold(u1.Hostname(), u2.Hostname()) {
		return false
	}
	return EffectivePort(u1) == EffectivePort(u2)
}

// IsIsolatedFixtureTarget determines whether a target URL is bound to an authorized synthetic fixture
// or explicitly designated isolated test environment, preventing mutations against arbitrary production targets.
func IsIsolatedFixtureTarget(rawURL string, authorizedFixtures []string, isFixtureFunc func(string) bool) bool {
	if isFixtureFunc != nil && isFixtureFunc(rawURL) {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	hostname := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if hostname == "" {
		return false
	}

	// 1. Loopback addresses and local test harness fixtures
	if IsLoopbackHost(hostname) {
		return true
	}

	// 2. Safe local, test, or synthetic fixture domain suffixes
	fixtureSuffixes := []string{
		".local",
		".internal",
		".test",
		".example",
		".synthetic",
		".mock",
	}
	for _, suffix := range fixtureSuffixes {
		if strings.HasSuffix(hostname, suffix) {
			return true
		}
	}

	// 3. Explicitly configured authorized fixture hosts or patterns
	for _, af := range authorizedFixtures {
		clean := strings.ToLower(strings.TrimSpace(af))
		if clean == "" {
			continue
		}
		if strings.HasPrefix(clean, "*.") {
			suffix := clean[1:]
			if strings.HasSuffix(hostname, suffix) {
				return true
			}
		} else if strings.EqualFold(hostname, clean) {
			return true
		} else if parsedAF, err := url.Parse(af); err == nil && parsedAF.Hostname() != "" {
			if strings.EqualFold(hostname, parsedAF.Hostname()) {
				return true
			}
		}
	}

	return false
}

// RedactText removes credentials, tokens, session IDs, passwords, and private secrets from text.
func RedactText(input string) string {
	return secrets.RedactText(input)
}

// SanitizeURL removes query parameters and userinfo from URLs for safe logging.
func SanitizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return secrets.SanitizeURL(rawURL)
	}
	u.RawQuery = ""
	u.User = nil
	return u.String()
}

// ResolveURL combines baseURL and policy path safely.
func ResolveURL(base, path string) (string, error) {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path, nil
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	rel, err := url.Parse(path)
	if err != nil {
		return "", err
	}
	return u.ResolveReference(rel).String(), nil
}

// BuildFindingID generates a deterministic unique finding ID for reporting.
func BuildFindingID(assessmentID, workflowID, checkID string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", assessmentID, workflowID, checkID)))
	return fmt.Sprintf("felix-workflow-%s", hex.EncodeToString(h[:8]))
}
