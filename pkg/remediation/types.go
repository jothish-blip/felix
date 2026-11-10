package remediation

import (
	"errors"

	"felix/pkg/correlation"
	"felix/pkg/report"
)

// Common error definitions for Phase 7.3 Remediation Engine
var (
	ErrNilFinding             = errors.New("finding cannot be nil")
	ErrUnsupportedCategory    = errors.New("unsupported vulnerability category for code remediation")
	ErrMissingSourceContext   = errors.New("source code context is missing or ambiguous")
	ErrConflictingDiffs       = errors.New("conflicting or overlapping remediation diffs detected")
	ErrUnsafePatch            = errors.New("remediation patch violates security or non-destructive safety policy")
	ErrSyntaxValidationFailed = errors.New("unified diff syntax validation failed")
)

// RemediationStatus captures the formal lifecycle and verification boundary of a remediation.
type RemediationStatus string

const (
	// StatusRecommendationOnly indicates a reference pattern or conceptual recommendation where target source code was unavailable or not validated.
	StatusRecommendationOnly RemediationStatus = "RECOMMENDATION_ONLY"

	// StatusSourceValidated indicates that target source code was located, inspected, and the vulnerable block matched context lines.
	StatusSourceValidated RemediationStatus = "SOURCE_VALIDATED"

	// StatusSyntacticallyValidated indicates that the generated unified diff was validated for syntax, valid hunk headers, and parseable line transitions.
	StatusSyntacticallyValidated RemediationStatus = "SYNTACTICALLY_VALIDATED"

	// StatusTested indicates that the remediation has passed active automated regression tests (future verification phase).
	StatusTested RemediationStatus = "TESTED"

	// StatusApplied indicates that the patch was committed/applied to the repository (strictly prohibited in Phase 7.3).
	StatusApplied RemediationStatus = "APPLIED"

	// StatusVerified indicates that the remediation was applied and verified by security/regression tests, confirming vulnerability elimination.
	StatusVerified RemediationStatus = "VERIFIED"

	// StatusUnsupported indicates that no automated remediation pattern exists for this finding type.
	StatusUnsupported RemediationStatus = "UNSUPPORTED"

	// StatusInsufficientContext indicates that source file location, lines, or context were missing or inadequate.
	StatusInsufficientContext RemediationStatus = "INSUFFICIENT_CONTEXT"

	// StatusConflicting indicates that two or more items produce conflicting or overlapping changes on the same file lines.
	StatusConflicting RemediationStatus = "CONFLICTING"

	// StatusRejected indicates that the patch was rejected due to safety violations (e.g. hardcoded secrets, weakening security controls).
	StatusRejected RemediationStatus = "REJECTED"
)

// RemediationRequest defines the input to the Remediation Engine.
type RemediationRequest struct {
	Findings       []*report.Finding           `json:"findings"`
	DAGPath        *correlation.DAGPath        `json:"dag_path,omitempty"`
	DAGGraph       *correlation.DAGAttackGraph `json:"dag_graph,omitempty"`
	RepoPath       string                      `json:"repo_path,omitempty"`
	SourceContext  map[string]string           `json:"source_context,omitempty"` // Map of relative filepath -> file content
	TargetStack    string                      `json:"target_stack,omitempty"`   // e.g. "express_postgres", "spring_boot", "flask_sqlalchemy", "go_standard"
	StrictSafety   bool                        `json:"strict_safety"`
	AllowReference bool                        `json:"allow_reference"` // If true and source is absent, emit reference patterns
}

// DiffHunk models a single hunk in a unified diff.
type DiffHunk struct {
	OldStart int      `json:"old_start"`
	OldCount int      `json:"old_count"`
	NewStart int      `json:"new_start"`
	NewCount int      `json:"new_count"`
	Heading  string   `json:"heading,omitempty"`
	Lines    []string `json:"lines"`
}

// RemediationDiff contains the unified diff and line change metadata for an item.
type RemediationDiff struct {
	TargetFile         string     `json:"target_file"`
	OriginalSource     string     `json:"original_source,omitempty"`
	PatchedSource      string     `json:"patched_source,omitempty"`
	UnifiedDiff        string     `json:"unified_diff"`
	Hunks              []DiffHunk `json:"hunks"`
	AddedLinesCount    int        `json:"added_lines_count"`
	RemovedLinesCount  int        `json:"removed_lines_count"`
	IsReferencePattern bool       `json:"is_reference_pattern"`
}

// RemediationValidation details the static and semantic validation of the remediation.
type RemediationValidation struct {
	SyntacticallyValid     bool     `json:"syntactically_valid"`
	ApplicableToSource     bool     `json:"applicable_to_source"`
	PreservesUnrelatedCode bool     `json:"preserves_unrelated_code"`
	NoSecretLeakage        bool     `json:"no_secret_leakage"`
	SafetyRulesPassed      bool     `json:"safety_rules_passed"`
	VerificationTested     bool     `json:"verification_tested"`
	ValidationErrors       []string `json:"validation_errors,omitempty"`
	ValidationWarnings     []string `json:"validation_warnings,omitempty"`
}

// ExecutionEnvironment classifies where a verification rerun or regression test was conducted.
type ExecutionEnvironment string

const (
	// EnvironmentLiveTarget indicates tests were rerun against an actual live target environment.
	EnvironmentLiveTarget ExecutionEnvironment = "LIVE_TARGET"

	// EnvironmentIsolatedFixture indicates tests were run in an isolated test fixture/sandbox.
	EnvironmentIsolatedFixture ExecutionEnvironment = "ISOLATED_FIXTURE"

	// EnvironmentMockSimulated indicates mock or simulated responses were used.
	EnvironmentMockSimulated ExecutionEnvironment = "MOCK_SIMULATED"

	// EnvironmentDeclarativeClaim indicates self-reported or declarative assertions without verifiable execution.
	EnvironmentDeclarativeClaim ExecutionEnvironment = "DECLARATIVE_CLAIM"
)

// AttackRerunResult captures the empirical output of rerunning the exploit scenario against the remediated target.
type AttackRerunResult struct {
	Executed         bool   `json:"executed"`
	Prevented        bool   `json:"prevented"`
	HTTPStatusCode   int    `json:"http_status_code,omitempty"`
	ResponseBodyHash string `json:"response_body_hash,omitempty"`
	ExecutedAt       string `json:"executed_at,omitempty"`
	CommandOrRequest string `json:"command_or_request,omitempty"`
	FailureReason    string `json:"failure_reason,omitempty"`
}

// RegressionCheckResult captures the empirical outcome of legitimate application regression test suites.
type RegressionCheckResult struct {
	Passed      bool     `json:"passed"`
	TestSuites  []string `json:"test_suites,omitempty"`
	PassedCount int      `json:"passed_count"`
	FailedCount int      `json:"failed_count"`
	TotalCount  int      `json:"total_count"`
}

// VerificationArtifact models an independently verifiable, persisted result artifact generated by an authorized verification workflow.
type VerificationArtifact struct {
	SchemaVersion        string                `json:"schema_version"`
	WorkflowID           string                `json:"workflow_id"`
	RemediationID        string                `json:"remediation_id"`
	AffectedEdgeID       string                `json:"affected_edge_id"`
	Target               string                `json:"target"`
	PatchContentHash     string                `json:"patch_content_hash"` // SHA-256 of the exact applied unified diff
	ExecutionEnvironment ExecutionEnvironment `json:"execution_environment"`
	AttackRerun          AttackRerunResult     `json:"attack_rerun"`
	RegressionChecks     RegressionCheckResult `json:"regression_checks"`
	GeneratedAt          string                `json:"generated_at"`
	IntegrityHash        string                `json:"integrity_hash"` // Deterministic SHA-256 of artifact payload excluding IntegrityHash
}

// VerificationEvidence defines the structured evidence reference required to link a remediation to a persisted verification artifact.
type VerificationEvidence struct {
	RemediationID       string                `json:"remediation_id"`
	AffectedEdgeID      string                `json:"affected_edge_id"`
	ArtifactPath        string                `json:"artifact_path,omitempty"`        // Path to persisted VerificationArtifact JSON file
	ArtifactHash        string                `json:"artifact_hash,omitempty"`        // Raw SHA-256 of the persisted artifact file
	TargetEndpoint      string                `json:"target_endpoint,omitempty"`
	PatchApplied        bool                  `json:"patch_applied"`
	AttackRerunExecuted bool                  `json:"attack_rerun_executed"`
	AttackPrevented     bool                  `json:"attack_prevented"`
	RegressionPassed    bool                  `json:"regression_passed"`
	RerunStatusCode     int                   `json:"rerun_status_code,omitempty"`
	RegressionTestNames []string              `json:"regression_test_names,omitempty"`
	ProofReceiptHash    string                `json:"proof_receipt_hash,omitempty"`
	VerificationNotes   string                `json:"verification_notes,omitempty"`
	Artifact            *VerificationArtifact `json:"artifact,omitempty"`             // Loaded in-memory artifact representation
}

// RemediationEvidence captures provenance linking the fix to findings and DAG nodes.
type RemediationEvidence struct {
	FindingID          string                `json:"finding_id"`
	Category           string                `json:"category"`
	SourceLocation     string                `json:"source_location,omitempty"`
	MatchedContext     string                `json:"matched_context,omitempty"`
	Provenance         string                `json:"provenance,omitempty"`
	DAGNodeID          string                `json:"dag_node_id,omitempty"`
	IsHypothesis       bool                  `json:"is_hypothesis"`
	EvidenceReferences []string              `json:"evidence_references,omitempty"`
	VerificationProof  string                `json:"verification_proof,omitempty"`
	StructuredEvidence *VerificationEvidence `json:"structured_evidence,omitempty"`
}

// RemediationItem represents a single developer-ready code fix for a finding or DAG node.
type RemediationItem struct {
	ID                            string                 `json:"id"`
	FindingID                     string                 `json:"finding_id"`
	Category                      string                 `json:"category"`
	Title                         string                 `json:"title"`
	TargetFile                    string                 `json:"target_file"`
	StartLine                     int                    `json:"start_line"`
	EndLine                       int                    `json:"end_line"`
	Status                        RemediationStatus      `json:"status"`
	Priority                      int                    `json:"priority"` // 1 = highest / critical entrypoint
	SecurityImpact                string                 `json:"security_impact"`
	Rationale                     string                 `json:"rationale"`
	Diff                          *RemediationDiff       `json:"diff,omitempty"`
	Validation                    *RemediationValidation `json:"validation"`
	RegressionTestRecommendations []string               `json:"regression_test_recommendations"`
	Evidence                      *RemediationEvidence   `json:"evidence"`
	VerificationEvidence          *VerificationEvidence  `json:"verification_evidence,omitempty"`
	PotentialBreakingChanges      []string               `json:"potential_breaking_changes,omitempty"`
	RequiredImports               []string               `json:"required_imports,omitempty"`
}

// SharedRootCause identifies findings that share a single underlying vulnerability root cause.
type SharedRootCause struct {
	ID                 string   `json:"id"`
	Title              string   `json:"title"`
	TargetFile         string   `json:"target_file"`
	LineRange          string   `json:"line_range"`
	FindingIDs         []string `json:"finding_ids"`
	Explanation        string   `json:"explanation"`
	ConsolidatedItemID string   `json:"consolidated_item_id"`
}

// PathBreakStatus classifies the evidentiary standing of an attack path break.
type PathBreakStatus string

const (
	// PathBreakStatusNone indicates that no attack path interruption has been proposed or verified.
	PathBreakStatusNone PathBreakStatus = "NONE"

	// PathBreakStatusProposed indicates a validated or applied patch is projected to interrupt the path upon application/verification.
	PathBreakStatusProposed PathBreakStatus = "PROPOSED_PATH_BREAK"

	// PathBreakStatusVerified indicates an empirically verified path interruption confirmed by regression or security tests.
	PathBreakStatusVerified PathBreakStatus = "VERIFIED_PATH_BREAK"
)

// DAGBreakAnalysis explains how remediating nodes in this plan disrupts the attack graph.
type DAGBreakAnalysis struct {
	PathID                  string          `json:"path_id,omitempty"`
	Status                  PathBreakStatus `json:"status"`
	BrokenPathCount         int             `json:"broken_path_count"`
	EliminatedEdges         []string        `json:"eliminated_edges"`
	ProposedBrokenPathCount int             `json:"proposed_broken_path_count"`
	ProposedEliminatedEdges []string        `json:"proposed_eliminated_edges"`
	ProtectedAssets         []string        `json:"protected_assets"`
	BottleneckNodeIDs       []string        `json:"bottleneck_node_ids"`
	EntrypointNodeIDs       []string        `json:"entrypoint_node_ids"`
	BreakageNarrative       string          `json:"breakage_narrative"`
}

// RemediationMetadata records runtime attributes excluded from canonical content hashing.
type RemediationMetadata struct {
	EngineVersion      string `json:"engine_version"`
	GeneratedAt        string `json:"generated_at,omitempty"`
	TotalFindingsCount int    `json:"total_findings_count"`
	TotalItemsCount    int    `json:"total_items_count"`
	RepoPath           string `json:"repo_path,omitempty"`
}

// RemediationPlan represents a complete, consolidated remediation package.
type RemediationPlan struct {
	ID                       string              `json:"id"`
	Title                    string              `json:"title"`
	Target                   string              `json:"target"`
	TargetStack              string              `json:"target_stack"`
	Status                   RemediationStatus   `json:"status"`
	Items                    []*RemediationItem  `json:"items"`
	ConsolidatedDiff         string              `json:"consolidated_diff,omitempty"`
	DAGBreakAnalysis         *DAGBreakAnalysis   `json:"dag_break_analysis,omitempty"`
	Prioritization           []string            `json:"prioritization"` // Ordered list of Item IDs
	SharedRootCauses         []*SharedRootCause  `json:"shared_root_causes,omitempty"`
	DeterministicContentHash string              `json:"deterministic_content_hash"`
	Metadata                 RemediationMetadata `json:"metadata"`
}
