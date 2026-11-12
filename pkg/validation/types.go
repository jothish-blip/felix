package validation

import "time"

// GroundTruthStatus defines the independently verified state of a ground-truth case
// prior to running any FELIX assessment.
type GroundTruthStatus string

const (
	GTVulnerable      GroundTruthStatus = "VULNERABLE"
	GTNegativeControl GroundTruthStatus = "SECURE_NEGATIVE_CONTROL"
	GTExcludedScope   GroundTruthStatus = "EXCLUDED_SCOPE"
	GTOutOfScope      GroundTruthStatus = "OUT_OF_SCOPE"
)

// OutcomeClassification defines the mutually exclusive accuracy accounting states.
type OutcomeClassification string

const (
	OutcomeTP             OutcomeClassification = "TP"
	OutcomeFP             OutcomeClassification = "FP"
	OutcomeFN             OutcomeClassification = "FN"
	OutcomeTN             OutcomeClassification = "TN"
	OutcomeInconclusive   OutcomeClassification = "INCONCLUSIVE"
	OutcomeNotTested      OutcomeClassification = "NOT_TESTED"
	OutcomeNotConfigured  OutcomeClassification = "NOT_CONFIGURED"
	OutcomeSafetyExcluded OutcomeClassification = "SAFETY_EXCLUDED"
	OutcomeOutOfScope     OutcomeClassification = "OUT_OF_SCOPE"
)

// AuthorizationContract captures explicit owner authorization, scope, exclusions,
// permitted methods, and an enforceable UTC testing window before active testing.
type AuthorizationContract struct {
	AuthorizingParty  string    `json:"authorizing_party"`
	SignedBy          string    `json:"signed_by,omitempty"`
	AuthorizationRef  string    `json:"authorization_ref"`
	Confirmed         bool      `json:"confirmed"`
	AuthorizedTargets []string  `json:"authorized_targets"`
	ScopeMode         string    `json:"scope_mode,omitempty"`
	AllowedMethods    []string  `json:"allowed_methods,omitempty"`
	ExcludedPaths     []string  `json:"excluded_paths,omitempty"`
	ExcludedURLs      []string  `json:"excluded_urls,omitempty"`
	ExcludedHosts     []string  `json:"excluded_hosts,omitempty"`
	WindowStart       time.Time `json:"window_start,omitempty"`
	WindowEnd         time.Time `json:"window_end,omitempty"`
	Notes             string    `json:"notes,omitempty"`
}

// CampaignManifest records reproducible campaign configuration and tamper-evident
// ground-truth binding for blind evaluation.
type CampaignManifest struct {
	ManifestID              string                `json:"manifest_id"`
	TargetName              string                `json:"target_name"`
	TargetURL               string                `json:"target_url"`
	Environment             string                `json:"environment"` // DEPLOYED_AUTHORIZED, LOCAL_CONTROLLED_LAB, EPHEMERAL_HARNESS
	Authorization           AuthorizationContract `json:"authorization"`
	GroundTruthRegistryID   string                `json:"ground_truth_registry_id"`
	GroundTruthSHA256       string                `json:"ground_truth_sha256"`
	GroundTruthRegisteredAt time.Time             `json:"ground_truth_registered_at"`
	BlindExecution          bool                  `json:"blind_execution"`
	FELIXVersion            string                `json:"felix_version,omitempty"`
	GitCommit               string                `json:"git_commit,omitempty"`
	Profile                 string                `json:"profile"`
	RolesConfigured         []string              `json:"roles_configured,omitempty"`
	SafeMode                bool                  `json:"safe_mode"`
	AllowStateChanging      bool                  `json:"allow_state_changing"`
	ReportPath              string                `json:"report_path,omitempty"`
	AuthzSummaryPath        string                `json:"authz_summary_path,omitempty"`
	RetestReportPath        string                `json:"retest_report_path,omitempty"`
	ExecutedAt              time.Time             `json:"executed_at"`
	ExecutionDurationMs     int64                 `json:"execution_duration_ms,omitempty"`
	ReportSHA256            string                `json:"report_sha256,omitempty"`
}

// MatcherRule describes how an independent ground-truth entry maps to FELIX findings
// or authorization coverage records without leaking target hints to the scanner.
type MatcherRule struct {
	VulnClasses   []string `json:"vuln_classes,omitempty"`
	PathContains  []string `json:"path_contains,omitempty"`
	TitleContains []string `json:"title_contains,omitempty"`
	Methods       []string `json:"methods,omitempty"`
}

// GroundTruthEntry represents a single independently documented application behavior,
// vulnerability, negative control, or excluded path established before scanning.
type GroundTruthEntry struct {
	ID                 string            `json:"id"`
	EndpointPattern    string            `json:"endpoint_pattern"`
	Method             string            `json:"method"`
	VulnClass          string            `json:"vuln_class"`
	ExpectedStatus     GroundTruthStatus `json:"expected_status"`
	RequiredIdentities []string          `json:"required_identities,omitempty"`
	InScope            bool              `json:"in_scope"`
	SafetyExcluded     bool              `json:"safety_excluded,omitempty"`
	RequiresConfig     string            `json:"requires_config,omitempty"` // e.g. "MULTI_ROLE", "STATE_CHANGING", "OAST", "BROWSER_DOM"
	Matcher            MatcherRule       `json:"matcher,omitempty"`
	SourceReference    string            `json:"source_reference,omitempty"`
	Description        string            `json:"description"`
}

// GroundTruthRegistry is an immutable, hash-locked independent ground-truth dataset.
type GroundTruthRegistry struct {
	RegistryID         string             `json:"registry_id"`
	Application        string             `json:"application"`
	Version            string             `json:"version,omitempty"`
	TargetOrigin       string             `json:"target_origin"`
	EstablishedAt      time.Time          `json:"established_at"`
	EstablishedBy      string             `json:"established_by"`
	ProvenanceNote     string             `json:"provenance_note"`
	DerivedFromScanner bool               `json:"derived_from_scanner"` // Must strictly be false
	Entries            []GroundTruthEntry `json:"entries"`
}

// ConfusionCounts records all 9 explicit evaluation outcome categories plus diagnostic tallies.
type ConfusionCounts struct {
	TP                          int `json:"tp"`
	FP                          int `json:"fp"`
	FN                          int `json:"fn"`
	TN                          int `json:"tn"`
	Inconclusive                int `json:"inconclusive"`
	NotTested                   int `json:"not_tested"`
	NotConfigured               int `json:"not_configured"`
	SafetyExcluded              int `json:"safety_excluded"`
	OutOfScope                  int `json:"out_of_scope"`
	CandidateOnlyMatches        int `json:"candidate_only_matches"`
	CandidateFPs                int `json:"candidate_fps"`
	VerifiedFPs                 int `json:"verified_fps"`
	DiscoveryObservationsIgnored int `json:"discovery_observations_ignored"`
}

// WilsonInterval stores a 95% Wilson score confidence interval for a binomial proportion.
type WilsonInterval struct {
	Valid   bool    `json:"valid"`
	Lower95 float64 `json:"lower_95"`
	Upper95 float64 `json:"upper_95"`
}

// MetricRate represents a bounded metric along with denominator validity and 95% CI.
type MetricRate struct {
	Value         float64        `json:"value"`
	Numerator     int            `json:"numerator"`
	Denominator   int            `json:"denominator"`
	Valid         bool           `json:"valid"`
	InvalidReason string         `json:"invalid_reason,omitempty"`
	CI95          WilsonInterval `json:"ci_95"`
}

// ClassMetrics holds per-vulnerability-class confusion counts and derived metrics.
type ClassMetrics struct {
	VulnClass         string          `json:"vuln_class"`
	EvaluatedPop      int             `json:"evaluated_population"`
	Counts            ConfusionCounts `json:"counts"`
	Precision         MetricRate      `json:"precision"`
	Recall            MetricRate      `json:"recall"`
	Specificity       MetricRate      `json:"specificity"`
	ExecutionCoverage MetricRate      `json:"execution_coverage"`
}

// FindingComparisonItem records the trace between an individual GT entry / finding and its outcome.
type FindingComparisonItem struct {
	GroundTruthID    string                `json:"ground_truth_id,omitempty"`
	FindingID        string                `json:"finding_id,omitempty"`
	FindingTitle     string                `json:"finding_title,omitempty"`
	Endpoint         string                `json:"endpoint,omitempty"`
	VulnClass        string                `json:"vuln_class"`
	Outcome          OutcomeClassification `json:"outcome"`
	VerificationTier string                `json:"verification_tier,omitempty"`
	EvidencePresent  bool                  `json:"evidence_present"`
	Rationale        string                `json:"rationale"`
}

// RetestExpectedItem defines the expected ground truth state during remediation retesting.
type RetestExpectedItem struct {
	FindingID      string `json:"finding_id"`
	GroundTruthID  string `json:"ground_truth_id,omitempty"`
	ExpectedAction string `json:"expected_action"` // "FIXED" or "STILL_PRESENT"
}

// RetestAccuracyMetrics quantifies remediation verification accuracy separately from discovery recall.
type RetestAccuracyMetrics struct {
	ExpectedTotal      int        `json:"expected_total"`
	CorrectFixed       int        `json:"correct_fixed"`
	CorrectStillPresent int       `json:"correct_still_present"`
	IncorrectVerdict   int        `json:"incorrect_verdict"`
	InconclusiveCount  int        `json:"inconclusive_count"`
	MissingVerdict     int        `json:"missing_verdict"`
	RetestAccuracy     MetricRate `json:"retest_accuracy"`
}

// RedactionAuditResult reports whether any unredacted credential/secret pattern appears in a report.
type RedactionAuditResult struct {
	Clean         bool     `json:"clean"`
	FindingCount  int      `json:"finding_count"`
	LeakLocations []string `json:"leak_locations,omitempty"`
}

// AccuracyEvaluationReport is the machine-readable output of an independent blind accuracy evaluation.
type AccuracyEvaluationReport struct {
	SchemaVersion             string                   `json:"schema_version"`
	TargetName                string                   `json:"target_name"`
	RegistryID                string                   `json:"registry_id"`
	CampaignID                string                   `json:"campaign_id,omitempty"`
	EvaluatedAt               time.Time                `json:"evaluated_at"`
	GroundTruthSHA256         string                   `json:"ground_truth_sha256"`
	ManifestIntegrityOK       bool                     `json:"manifest_integrity_ok"`
	BlindExecutionVerified    bool                     `json:"blind_execution_verified"`
	BlindnessNotes            []string                 `json:"blindness_notes,omitempty"`
	EvaluatedPopulation       int                      `json:"evaluated_population"`
	ExecutablePositivePop     int                      `json:"executable_positive_population"`
	EvaluatedNegativePop      int                      `json:"evaluated_negative_population"`
	Counts                    ConfusionCounts          `json:"counts"`
	Precision                 MetricRate               `json:"precision"`
	Recall                    MetricRate               `json:"recall"`
	Specificity               MetricRate               `json:"specificity"`
	F1Score                   MetricRate               `json:"f1_score"`
	ExecutionCoverage         MetricRate               `json:"execution_coverage"`
	ClassBreakdown            map[string]*ClassMetrics `json:"class_breakdown"`
	EvidenceComparison        []FindingComparisonItem  `json:"evidence_comparison"`
	RetestAccuracy            *RetestAccuracyMetrics   `json:"retest_accuracy,omitempty"`
	RedactionAudit            RedactionAuditResult     `json:"redaction_audit"`
	ReportSummaryConsistent   bool                     `json:"report_summary_consistent"`
	FindingsCountReported     int                      `json:"findings_count_reported"`
	SummaryTotalReported      int                      `json:"summary_total_reported"`
	UniversalAccuracyClaimed  bool                     `json:"universal_accuracy_claimed"` // Always false by policy
	Disclaimer                string                   `json:"disclaimer"`
}
