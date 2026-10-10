package verification

import (
	"time"

	"felix/pkg/report"
)

// Canonical Verification Statuses (Stage 11).
const (
	StatusObserved    = report.VerificationObserved    // "OBSERVED" - raw signal/asset recorded, not yet detected as vulnerability
	StatusDetected    = report.VerificationDetected    // "DETECTED" - detector matched pattern, verification not yet satisfied
	StatusNotVerified = report.VerificationNotVerified // "NOT_VERIFIED" - detected but proof incomplete, unsupported, or blocked
	StatusVerified    = report.VerificationVerified    // "VERIFIED" - empirical proof satisfied all mandatory policy criteria
	StatusNotExposed  = report.VerificationNotExposed  // "NOT_EXPOSED" - affirmative evidence of protection under tested conditions
)

// ProvenanceType classifies where evidence originated.
type ProvenanceType string

const (
	ProvenanceLive     ProvenanceType = "LIVE"
	ProvenanceStatic   ProvenanceType = "STATIC"
	ProvenanceFixture  ProvenanceType = "FIXTURE"
	ProvenanceMock     ProvenanceType = "MOCK"
	ProvenanceImported ProvenanceType = "IMPORTED"
)

// CriterionStatus defines the result of evaluating an individual verification criterion.
type CriterionStatus string

const (
	CriterionPassed       CriterionStatus = "PASSED"
	CriterionFailed       CriterionStatus = "FAILED"
	CriterionInconclusive CriterionStatus = "INCONCLUSIVE"
	CriterionSkipped      CriterionStatus = "SKIPPED"
	CriterionBlocked      CriterionStatus = "BLOCKED"
)

// VerificationCriterion defines an individual proof requirement in a verification policy.
type VerificationCriterion struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	IsMandatory bool   `json:"is_mandatory"`
	IsNegative  bool   `json:"is_negative"` // True if passing this criterion proves the exposure is absent (NOT_EXPOSED)
}

// CriterionResult records the evaluation outcome for a single criterion.
type CriterionResult struct {
	CriterionID   string          `json:"criterion_id"`
	Name          string          `json:"name"`
	Status        CriterionStatus `json:"status"`
	Evidence      string          `json:"evidence"`
	Rationale     string          `json:"rationale"`
	ObservedValue string          `json:"observed_value,omitempty"`
	ExpectedValue string          `json:"expected_value,omitempty"`
}

// ReproductionContext captures deterministic, safe instructions to reproduce a finding.
type ReproductionContext struct {
	Target             string            `json:"target"`
	Endpoint           string            `json:"endpoint"`
	Method             string            `json:"method"`
	Headers            map[string]string `json:"headers,omitempty"`
	Params             map[string]string `json:"params,omitempty"`
	Payload            string            `json:"payload,omitempty"`
	RequiredIdentity   string            `json:"required_identity,omitempty"`
	Preconditions      []string          `json:"preconditions,omitempty"`
	ExpectedBehavior   string            `json:"expected_behavior"`
	ObservedBehavior   string            `json:"observed_behavior"`
	ReproductionSteps  []string          `json:"reproduction_steps"`
	SafeCurlCommand    string            `json:"safe_curl_command,omitempty"`
	Reproducibility    string            `json:"reproducibility"` // REPRODUCED, EVIDENCE_COLLECTED, CANDIDATE, NOT_REPRODUCIBLE
	Limitations        []string          `json:"limitations,omitempty"`
}

// EvidenceReference indexes concrete supporting observations.
type EvidenceReference struct {
	ID          string            `json:"id"`
	Observation string            `json:"observation"`
	Location    string            `json:"location"`
	HTTPMethod  string            `json:"http_method,omitempty"`
	HTTPStatus  int               `json:"http_status,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
	Provenance  ProvenanceType    `json:"provenance"`
	Details     map[string]string `json:"details,omitempty"`
	Hash        string            `json:"hash,omitempty"`
}

// VerificationResult provides the full structured verification assessment for a finding.
type VerificationResult struct {
	ID                     string                    `json:"id"`
	FindingID              string                    `json:"finding_id"`
	AssessmentID           string                    `json:"assessment_id,omitempty"`
	ExecutionID            string                    `json:"execution_id,omitempty"`
	TargetURL              string                    `json:"target_url"`
	Endpoint               string                    `json:"endpoint"`
	Category               string                    `json:"category"`
	Status                 report.VerificationStatus `json:"status"`
	VerificationMethod     string                    `json:"verification_method"`
	PolicyID               string                    `json:"policy_id"`
	PolicyVersion          string                    `json:"policy_version"`
	Attempted              bool                      `json:"attempted"`
	DetectionConfidence    string                    `json:"detection_confidence"`
	VerificationConfidence string                    `json:"verification_confidence"`
	OverallConfidence      string                    `json:"overall_confidence"`
	ConfidenceScore        int                       `json:"confidence_score"` // 0-100
	ConfidenceRationale    string                    `json:"confidence_rationale"`
	EvidenceReferences     []string                  `json:"evidence_references"`
	EvidenceList           []EvidenceReference       `json:"evidence_list,omitempty"`
	Reproduction           ReproductionContext       `json:"reproduction"`
	Preconditions          []string                  `json:"preconditions,omitempty"`
	ExpectedBehavior       string                    `json:"expected_behavior"`
	ObservedBehavior       string                    `json:"observed_behavior"`
	CriteriaResults        []CriterionResult         `json:"criteria_results"`
	Limitations            []string                  `json:"limitations,omitempty"`
	FailureReason          string                    `json:"failure_reason,omitempty"`
	InconclusiveReason     string                    `json:"inconclusive_reason,omitempty"`
	SafetyDecision         string                    `json:"safety_decision"` // ALLOWED, BLOCKED, READ_ONLY_FALLBACK
	BlockReason            string                    `json:"block_reason,omitempty"`
	SyntheticFixture       bool                      `json:"synthetic_fixture,omitempty"`
	VerifierVersion        string                    `json:"verifier_version"`
	StartedAt              time.Time                 `json:"started_at"`
	CompletedAt            time.Time                 `json:"completed_at"`
}

// CategoryVerificationStat summarizes verification coverage for a single finding category.
type CategoryVerificationStat struct {
	Category    string `json:"category"`
	Total       int    `json:"total"`
	Verified    int    `json:"verified"`
	Detected    int    `json:"detected"`
	Observed    int    `json:"observed"`
	NotVerified int    `json:"not_verified"`
	NotExposed  int    `json:"not_exposed"`
	Blocked     int    `json:"blocked"`
}

// VerificationSummary aggregates verification metrics across an assessment execution.
type VerificationSummary struct {
	TotalFindings            int                                 `json:"total_findings"`
	AttemptedCount           int                                 `json:"attempted_count"`
	VerifiedCount            int                                 `json:"verified_count"`
	DetectedCount            int                                 `json:"detected_count"`
	ObservedCount            int                                 `json:"observed_count"`
	NotVerifiedCount         int                                 `json:"not_verified_count"`
	NotExposedCount          int                                 `json:"not_exposed_count"`
	BlockedCount             int                                 `json:"blocked_count"`
	InconclusiveCount        int                                 `json:"inconclusive_count"`
	UnsupportedCount         int                                 `json:"unsupported_count"`
	SyntheticCount           int                                 `json:"synthetic_count"`
	VerificationRateAttempted float64                            `json:"verification_rate_attempted"` // Verified / Attempted
	VerificationRateTotal    float64                             `json:"verification_rate_total"`     // Verified / Total
	CategoryStats            map[string]CategoryVerificationStat `json:"category_stats"`
	Limitations              []string                            `json:"limitations,omitempty"`
}

// VerificationRunRecord models database persistence for assessment verification runs.
type VerificationRunRecord struct {
	ID               string    `json:"id"`
	AssessmentID     string    `json:"assessment_id"`
	ExecutionID      string    `json:"execution_id"`
	TotalFindings    int       `json:"total_findings"`
	AttemptedCount   int       `json:"attempted_count"`
	VerifiedCount    int       `json:"verified_count"`
	DetectedCount    int       `json:"detected_count"`
	ObservedCount    int       `json:"observed_count"`
	NotVerifiedCount int       `json:"not_verified_count"`
	NotExposedCount  int       `json:"not_exposed_count"`
	BlockedCount     int       `json:"blocked_count"`
	InconclusiveCount int      `json:"inconclusive_count"`
	SyntheticCount   int       `json:"synthetic_count"`
	CoverageJSON     string    `json:"coverage_json"`
	VerifierVersion  string    `json:"verifier_version"`
	CreatedAt        time.Time `json:"created_at"`
}
