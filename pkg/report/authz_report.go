package report

import "felix/pkg/secrets"

// AuthorizationReportSummary captures structured Phase 4 identity, BOLA, BFLA, and BOPLA coverage
// without embedding any raw tokens, session cookies, or passwords.
type AuthorizationReportSummary struct {
	Status               string                      `json:"status"` // TESTED, PARTIAL, NOT_CONFIGURED, SKIPPED
	Limitation           string                      `json:"limitation,omitempty"`
	FixtureVerification  *FixtureVerificationSummary `json:"fixture_verification,omitempty"`
	QuantitativeCoverage AuthzQuantitativeCoverage   `json:"quantitative_coverage"`
	IdentityCoverage     []IdentityCoverageEntry     `json:"identity_coverage,omitempty"`
	BOLA                 *BOLACoverageSection        `json:"bola,omitempty"`
	BFLA                 *BFLACoverageSection        `json:"bfla,omitempty"`
	BOPLA                *BOPLACoverageSection       `json:"bopla,omitempty"`
	CoverageItems        []AuthzItemCoverageEntry    `json:"coverage_items,omitempty"`
	RequestsSent         int                         `json:"requests_sent"`
	GeneratedAt          string                      `json:"generated_at,omitempty"`
}

// FixtureVerificationSummary records whether state-changing mutations were permitted and how the fixture was verified.
type FixtureVerificationSummary struct {
	RequestedStateChanging bool     `json:"requested_state_changing"`
	SyntheticFixtureFlag   bool     `json:"synthetic_fixture_flag"`
	Verified               bool     `json:"verified"`
	Method                 string   `json:"method"`
	AuthorizedHosts        []string `json:"authorized_hosts,omitempty"`
	Reason                 string   `json:"reason,omitempty"`
}

// AuthzQuantitativeCoverage captures concrete discovered vs planned vs executed vs outcome ratios.
type AuthzQuantitativeCoverage struct {
	EndpointsObserved        int     `json:"endpoints_observed"`
	IdentitiesConfigured     int     `json:"identities_configured"`
	IdentitiesVerified       int     `json:"identities_verified"`
	ObjectsDiscovered        int     `json:"objects_discovered"`
	FunctionsDiscovered      int     `json:"functions_discovered"`
	PropertiesDiscovered     int     `json:"properties_discovered"`
	TotalChecksPlanned       int     `json:"total_checks_planned"`
	TotalChecksExecuted      int     `json:"total_checks_executed"`
	VerifiedTotal            int     `json:"verified_total"`
	CandidateTotal           int     `json:"candidate_total"`
	NotVulnerableTotal       int     `json:"not_vulnerable_total"`
	InconclusiveTotal        int     `json:"inconclusive_total"`
	SkippedTotal             int     `json:"skipped_total"`
	ExcludedDestructiveCount int     `json:"excluded_destructive_count"`
	ExecutionCoveragePct     float64 `json:"execution_coverage_pct"`
	DeterminativeOutcomePct  float64 `json:"determinative_outcome_pct"`
}

// IdentityCoverageEntry describes one configured or absent identity context and its test coverage.
type IdentityCoverageEntry struct {
	Identity         string `json:"identity"`
	Role             string `json:"role"`
	Username         string `json:"username,omitempty"`
	CredentialScheme string `json:"credential_scheme,omitempty"`
	Configured       bool   `json:"configured"`
	Verified         bool   `json:"verified"`
	VerificationNote string `json:"verification_note,omitempty"`
	CrawledEndpoints int    `json:"crawled_endpoints"`
	TestsExecuted    int    `json:"tests_executed"`
}

// BOLACoverageSection summarizes dynamic object discovery and BOLA test outcomes.
type BOLACoverageSection struct {
	Status               string   `json:"status"` // TESTED, NOT_CONFIGURED, SKIPPED, INCONCLUSIVE
	ObjectsDiscovered    int      `json:"objects_discovered"`
	ObjectsWithOwnership int      `json:"objects_with_ownership"`
	TotalTests           int      `json:"total_tests"`
	VerifiedCount        int      `json:"verified_count"`
	CandidateCount       int      `json:"candidate_count"`
	NotVulnerableCount   int      `json:"not_vulnerable_count"`
	InconclusiveCount    int      `json:"inconclusive_count"`
	SkippedCount         int      `json:"skipped_count"`
	Limitations          []string `json:"limitations,omitempty"`
}

// BFLACoverageSection summarizes function discovery and BFLA test outcomes.
type BFLACoverageSection struct {
	Status                       string   `json:"status"` // TESTED, NOT_CONFIGURED, SKIPPED, INCONCLUSIVE
	FunctionsDiscovered          int      `json:"functions_discovered"`
	FunctionsWithEstablishedRole int      `json:"functions_with_established_role"`
	PrivilegeComparisons         int      `json:"privilege_comparisons"`
	TotalTests                   int      `json:"total_tests"`
	VerifiedCount                int      `json:"verified_count"`
	CandidateCount               int      `json:"candidate_count"`
	NotVulnerableCount           int      `json:"not_vulnerable_count"`
	InconclusiveCount            int      `json:"inconclusive_count"`
	SkippedCount                 int      `json:"skipped_count"`
	ExcludedDestructive          []string `json:"excluded_destructive,omitempty"`
	Limitations                  []string `json:"limitations,omitempty"`
}

// BOPLACoverageSection summarizes property discovery and BOPLA exposure/mass-assignment outcomes.
type BOPLACoverageSection struct {
	Status               string   `json:"status"` // TESTED, NOT_CONFIGURED, SKIPPED, INCONCLUSIVE
	PropertiesDiscovered int      `json:"properties_discovered"`
	PropertiesWithPolicy int      `json:"properties_with_policy"`
	ExposureTests        int      `json:"exposure_tests"`
	ModificationTests    int      `json:"modification_tests"`
	TotalTests           int      `json:"total_tests"`
	VerifiedCount        int      `json:"verified_count"`
	CandidateCount       int      `json:"candidate_count"`
	NotVulnerableCount   int      `json:"not_vulnerable_count"`
	InconclusiveCount    int      `json:"inconclusive_count"`
	SkippedCount         int      `json:"skipped_count"`
	StateChangingGated   bool     `json:"state_changing_gated,omitempty"`
	CleanupAttempted     int      `json:"cleanup_attempted,omitempty"`
	CleanupRestored      int      `json:"cleanup_restored,omitempty"`
	CleanupFailed        int      `json:"cleanup_failed,omitempty"`
	CleanupUnverified    int      `json:"cleanup_unverified,omitempty"`
	Limitations          []string `json:"limitations,omitempty"`
}

// AuthzItemCoverageEntry documents how each discovered object/function/property was evaluated or skipped.
type AuthzItemCoverageEntry struct {
	Engine          string   `json:"engine"` // BOLA, BFLA, BOPLA
	Item            string   `json:"item"`
	Method          string   `json:"method,omitempty"`
	DiscoverySource string   `json:"discovery_source,omitempty"`
	Outcome         string   `json:"outcome"` // VERIFIED, CANDIDATE, NOT_VULNERABLE, INCONCLUSIVE, SKIPPED, NOT_CONFIGURED
	TestedAs        []string `json:"tested_as,omitempty"`
	Reason          string   `json:"reason,omitempty"`
}

// SanitizeAuthorizationReport creates a redacted copy of AuthorizationReportSummary.
func SanitizeAuthorizationReport(src *AuthorizationReportSummary) *AuthorizationReportSummary {
	if src == nil {
		return nil
	}
	out := *src
	out.Limitation = SanitizeEvidence(src.Limitation)
	if src.FixtureVerification != nil {
		fv := *src.FixtureVerification
		fv.Reason = SanitizeEvidence(fv.Reason)
		fv.AuthorizedHosts = sanitizeStringList(fv.AuthorizedHosts)
		out.FixtureVerification = &fv
	}

	if len(src.IdentityCoverage) > 0 {
		out.IdentityCoverage = make([]IdentityCoverageEntry, len(src.IdentityCoverage))
		for i, id := range src.IdentityCoverage {
			clean := id
			clean.Username = SanitizeEvidence(id.Username)
			clean.CredentialScheme = SanitizeEvidence(id.CredentialScheme)
			clean.VerificationNote = SanitizeEvidence(id.VerificationNote)
			out.IdentityCoverage[i] = clean
		}
	}

	if src.BOLA != nil {
		b := *src.BOLA
		b.Limitations = sanitizeStringList(src.BOLA.Limitations)
		out.BOLA = &b
	}
	if src.BFLA != nil {
		b := *src.BFLA
		b.ExcludedDestructive = sanitizeStringList(src.BFLA.ExcludedDestructive)
		b.Limitations = sanitizeStringList(src.BFLA.Limitations)
		out.BFLA = &b
	}
	if src.BOPLA != nil {
		b := *src.BOPLA
		b.Limitations = sanitizeStringList(src.BOPLA.Limitations)
		out.BOPLA = &b
	}

	if len(src.CoverageItems) > 0 {
		out.CoverageItems = make([]AuthzItemCoverageEntry, len(src.CoverageItems))
		for i, item := range src.CoverageItems {
			clean := item
			clean.Item = secrets.SanitizeURL(SanitizeEvidence(item.Item))
			clean.Reason = SanitizeEvidence(item.Reason)
			clean.DiscoverySource = SanitizeEvidence(item.DiscoverySource)
			out.CoverageItems[i] = clean
		}
	}
	return &out
}

func sanitizeStringList(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = SanitizeEvidence(s)
	}
	return out
}
