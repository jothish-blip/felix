package correlation

import (
	"time"

	"felix/pkg/report"
)

// RelationshipType defines the semantic nature of a directed relationship between two findings.
type RelationshipType string

const (
	RelEnables         RelationshipType = "ENABLES"
	RelExposes         RelationshipType = "EXPOSES"
	RelBypasses        RelationshipType = "BYPASSES"
	RelDependsOn       RelationshipType = "DEPENDS_ON"
	RelAmplifiesImpact RelationshipType = "AMPLIFIES_IMPACT"
	RelReaches         RelationshipType = "REACHES"
	RelSharesRootCause RelationshipType = "SHARES_ROOT_CAUSE"
	RelRelatedTo       RelationshipType = "RELATED_TO"
)

// IsSequenceType returns true if the relationship type represents a valid sequential transition
// in an attack path. Root cause sharing and generic relations must not form attack path edges.
func (rt RelationshipType) IsSequenceType() bool {
	switch rt {
	case RelEnables, RelExposes, RelBypasses, RelDependsOn, RelAmplifiesImpact, RelReaches:
		return true
	default:
		return false
	}
}

// ValidationStatus represents the evidentiary support behind an individual relationship.
type ValidationStatus string

const (
	ValidationConfirmed    ValidationStatus = "CONFIRMED"
	ValidationPlausible    ValidationStatus = "PLAUSIBLE"
	ValidationInconclusive ValidationStatus = "INCONCLUSIVE"
)

// PathStatus defines the procedural verification outcome of an attack path.
type PathStatus string

const (
	PathVerified     PathStatus = "VERIFIED"
	PathCandidate    PathStatus = "CANDIDATE"
	PathInconclusive PathStatus = "INCONCLUSIVE"
	PathObserved     PathStatus = "OBSERVED"
	PathNotAssessed  PathStatus = "NOT_ASSESSED"
)

// RuleCode identifies standard Felix Stage 10 correlation rules.
type RuleCode string

const (
	RuleCOR01 RuleCode = "COR-01" // Entry Point to Vulnerable Resource
	RuleCOR02 RuleCode = "COR-02" // Authentication to Authorization
	RuleCOR03 RuleCode = "COR-03" // BOLA and Sensitive Data Exposure
	RuleCOR04 RuleCode = "COR-04" // Public Exposure to Sensitive Resource
	RuleCOR05 RuleCode = "COR-05" // Privilege Escalation
	RuleCOR06 RuleCode = "COR-06" // Business Logic Chains
	RuleCOR07 RuleCode = "COR-07" // Session and Identity Dependencies
	RuleCOR08 RuleCode = "COR-08" // Cloud and Application Dependencies
	RuleCOR09 RuleCode = "COR-09" // Common Root Cause
	RuleCOR10 RuleCode = "COR-10" // Impact Amplification
)

// RuleMetadata provides human-readable documentation and standards cross-references for a rule.
type RuleMetadata struct {
	Code        RuleCode `json:"code"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	EdgeType    RelationshipType `json:"edge_type"`
	CWE         string   `json:"cwe,omitempty"`
	WSTG        string   `json:"wstg,omitempty"`
}

// RuleCatalog stores standard correlation rule metadata.
var RuleCatalog = map[RuleCode]RuleMetadata{
	RuleCOR01: {
		Code:        RuleCOR01,
		Name:        "Entry Point to Vulnerable Resource",
		Description: "Connects an accessible entry point to a confirmed vulnerable resource on the same route or asset.",
		EdgeType:    RelReaches,
		CWE:         "CWE-200",
		WSTG:        "WSTG-INFO-01",
	},
	RuleCOR02: {
		Code:        RuleCOR02,
		Name:        "Authentication to Authorization",
		Description: "Connects authentication or session failures with authorization bypasses on protected endpoints.",
		EdgeType:    RelEnables,
		CWE:         "CWE-287",
		WSTG:        "WSTG-ATHN-01",
	},
	RuleCOR03: {
		Code:        RuleCOR03,
		Name:        "BOLA and Sensitive Data Exposure",
		Description: "Identifies object-level authorization failures directly disclosing sensitive data belonging to unauthorized principals.",
		EdgeType:    RelExposes,
		CWE:         "CWE-639",
		WSTG:        "WSTG-ATHZ-04",
	},
	RuleCOR04: {
		Code:        RuleCOR04,
		Name:        "Public Exposure to Sensitive Resource",
		Description: "Connects external storage or server environment disclosure to verified sensitive resource or credential access.",
		EdgeType:    RelExposes,
		CWE:         "CWE-552",
		WSTG:        "WSTG-CONF-04",
	},
	RuleCOR05: {
		Code:        RuleCOR05,
		Name:        "Privilege Escalation",
		Description: "Connects unprivileged role execution with vertical or horizontal access to elevated functions.",
		EdgeType:    RelEnables,
		CWE:         "CWE-269",
		WSTG:        "WSTG-ATHZ-03",
	},
	RuleCOR06: {
		Code:        RuleCOR06,
		Name:        "Business Logic Chains",
		Description: "Connects workflow circumvention, state manipulation, or replay to downstream unauthorized business outcomes.",
		EdgeType:    RelEnables,
		CWE:         "CWE-840",
		WSTG:        "WSTG-BUSL-01",
	},
	RuleCOR07: {
		Code:        RuleCOR07,
		Name:        "Session and Identity Dependencies",
		Description: "Connects session lifecycle and invalidation flaws to sustained unauthorized resource access.",
		EdgeType:    RelDependsOn,
		CWE:         "CWE-613",
		WSTG:        "WSTG-SESS-06",
	},
	RuleCOR08: {
		Code:        RuleCOR08,
		Name:        "Cloud and Application Dependencies",
		Description: "Connects cloud exposure or server-side request pivoting to application credential or database access.",
		EdgeType:    RelEnables,
		CWE:         "CWE-918",
		WSTG:        "WSTG-INPV-12",
	},
	RuleCOR09: {
		Code:        RuleCOR09,
		Name:        "Common Root Cause",
		Description: "Groups findings originating from a common configuration flaw or missing defensive middleware for triage.",
		EdgeType:    RelSharesRootCause,
		CWE:         "CWE-657",
		WSTG:        "WSTG-CONF-01",
	},
	RuleCOR10: {
		Code:        RuleCOR10,
		Name:        "Impact Amplification",
		Description: "Identifies combinations where one weakness increases the demonstrated impact of another vulnerability.",
		EdgeType:    RelAmplifiesImpact,
		CWE:         "CWE-942",
		WSTG:        "WSTG-CLNT-07",
	},
}

// AllRules returns the slice of all rule codes in canonical order COR-01 through COR-10.
func AllRules() []RuleCode {
	return []RuleCode{
		RuleCOR01, RuleCOR02, RuleCOR03, RuleCOR04, RuleCOR05,
		RuleCOR06, RuleCOR07, RuleCOR08, RuleCOR09, RuleCOR10,
	}
}

// NormalizedFinding provides standardized attributes across finding sources for correlation analysis.
type NormalizedFinding struct {
	ID                 string                    `json:"id"`
	OriginalID         string                    `json:"original_id"`
	Title              string                    `json:"title"`
	Category           string                    `json:"category"`
	NormalizedCategory string                    `json:"normalized_category"`
	Severity           string                    `json:"severity"`
	Confidence         string                    `json:"confidence"`
	VerificationStatus report.VerificationStatus `json:"verification_status"`
	Target             string                    `json:"target"`
	Host               string                    `json:"host"`
	Origin             string                    `json:"origin"`
	Endpoint           string                    `json:"endpoint"`
	Path               string                    `json:"path"`
	Method             string                    `json:"method"`
	Score              int                       `json:"score"`
	Source             string                    `json:"source"`
	Fingerprint        string                    `json:"fingerprint"`
	IsVerified         bool                      `json:"is_verified"`
	IsCandidate        bool                      `json:"is_candidate"`
	IsEntrypoint       bool                      `json:"is_entrypoint"`
	IsAuthRequirement  bool                      `json:"is_auth_requirement"`
	IsRoleRestricted   bool                      `json:"is_role_restricted"`
	IsSensitiveData    bool                      `json:"is_sensitive_data"`
	IsCloudResource    bool                      `json:"is_cloud_resource"`
	IsWorkflowStep     bool                      `json:"is_workflow_step"`
	EvidenceSummary    string                    `json:"evidence_summary"`
	EvidenceDetails    map[string]string         `json:"evidence_details,omitempty"`
	AffectedResource   string                    `json:"affected_resource,omitempty"`
	Parameters         []string                  `json:"parameters,omitempty"`
	SyntheticFixture   bool                      `json:"synthetic_fixture"`
	InferredHypothesis bool                      `json:"inferred_hypothesis"`
}

// Relationship models an evidence-backed directed connection between a source finding and a target finding.
type Relationship struct {
	ID                 string           `json:"id"`
	SourceFindingID    string           `json:"source_finding_id"`
	TargetFindingID    string           `json:"target_finding_id"`
	SourceTitle        string           `json:"source_title"`
	TargetTitle        string           `json:"target_title"`
	Type               RelationshipType `json:"type"`
	ValidationStatus   ValidationStatus `json:"validation_status"`
	Confidence         string           `json:"confidence"`
	RuleCode           RuleCode         `json:"rule_code"`
	EvidenceReferences []string         `json:"evidence_references"`
	Explanation        string           `json:"explanation"`
	Prerequisites      []string         `json:"prerequisites,omitempty"`
	Assumptions        []string         `json:"assumptions,omitempty"`
	InconclusiveReason string           `json:"inconclusive_reason,omitempty"`
}

// AttackPath models an ordered sequence of findings connected by validated relationships,
// representing a coherent multi-step security risk.
type AttackPath struct {
	ID                 string                `json:"id"`
	Title              string                `json:"title"`
	NodeIDs            []string              `json:"node_ids"`
	Nodes              []NormalizedFinding   `json:"nodes"`
	Edges              []Relationship        `json:"edges"`
	EntryPoint         string                `json:"entry_point,omitempty"`
	TargetAsset        string                `json:"target_asset"`
	PrimaryWeakness    string                `json:"primary_weakness"`
	TerminalImpact     string                `json:"terminal_impact"`
	Status             PathStatus            `json:"status"`
	Confidence         string                `json:"confidence"`
	CombinedRiskLevel  string                `json:"combined_risk_level"`
	CombinedRiskScore  int                   `json:"combined_risk_score"`
	RiskRationale      string                `json:"risk_rationale"`
	Assumptions        []string              `json:"assumptions,omitempty"`
	MissingEvidence    []string              `json:"missing_evidence,omitempty"`
	SecurityStory      report.SecurityStory  `json:"security_story"`
	Remediation        string                `json:"remediation"`
	SyntheticFixture   bool                  `json:"synthetic_fixture,omitempty"`
	CreatedAt          time.Time             `json:"created_at"`
}

// RuleCoverageStat tracks activity for a single correlation rule.
type RuleCoverageStat struct {
	Code                   RuleCode `json:"code"`
	Name                   string   `json:"name"`
	RelationshipsGenerated int      `json:"relationships_generated"`
	PathsGenerated         int      `json:"paths_generated"`
}

// Summary aggregates metrics across correlation analysis.
type Summary struct {
	TotalFindings            int                         `json:"total_findings"`
	EvaluatedFindings        int                         `json:"evaluated_findings"`
	ExcludedFindings         int                         `json:"excluded_findings"`
	CandidateRelationships   int                         `json:"candidate_relationships"`
	ConfirmedRelationships   int                         `json:"confirmed_relationships"`
	CandidatePaths           int                         `json:"candidate_paths"`
	VerifiedPaths            int                         `json:"verified_paths"`
	InconclusivePaths        int                         `json:"inconclusive_paths"`
	ObservedPaths            int                         `json:"observed_paths"`
	HighestRiskLevel         string                      `json:"highest_risk_level"`
	HighestRiskScore         int                         `json:"highest_risk_score"`
	AffectedAssets           []string                    `json:"affected_assets"`
	KeyRemediationPriorities []string                    `json:"key_remediation_priorities"`
	LimitsReached            bool                        `json:"limits_reached,omitempty"`
	TruncationReason         string                      `json:"truncation_reason,omitempty"`
	SyntheticFixture         bool                        `json:"synthetic_fixture,omitempty"`
	RuleStats                map[string]RuleCoverageStat `json:"rule_stats"`
}

// Config controls correlation engine constraints and behavior.
type Config struct {
	MaxPathDepth       int
	MaxCandidatePaths  int
	MinConfidence      string
	RulesEnabled       []RuleCode
	AllowSynthetic     bool
}

// DefaultConfig provides conservative, safe defaults preventing combinatorial explosion.
func DefaultConfig() Config {
	return Config{
		MaxPathDepth:      4,
		MaxCandidatePaths: 30,
		MinConfidence:     report.ConfidenceLow,
		RulesEnabled: []RuleCode{
			RuleCOR01, RuleCOR02, RuleCOR03, RuleCOR04, RuleCOR05,
			RuleCOR06, RuleCOR07, RuleCOR08, RuleCOR09, RuleCOR10,
		},
		AllowSynthetic: true,
	}
}

// RunRecord represents a persistent record of a correlation analysis in SQLite.
type RunRecord struct {
	ID                     string    `json:"id"`
	AssessmentID           string    `json:"assessment_id"`
	ExecutionID            string    `json:"execution_id"`
	TotalFindings          int       `json:"total_findings"`
	CandidateRelationships int       `json:"candidate_relationships"`
	CandidatePaths         int       `json:"candidate_paths"`
	VerifiedPaths          int       `json:"verified_paths"`
	HighestRisk            string    `json:"highest_risk"`
	CoverageJSON           string    `json:"coverage_json"`
	SyntheticFixture       bool      `json:"synthetic_fixture"`
	CreatedAt              time.Time `json:"created_at"`
}
