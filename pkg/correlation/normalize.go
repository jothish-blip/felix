package correlation

import (
	"net/url"
	"strings"

	"felix/pkg/report"
)

// NormalizeFinding translates a raw report.Finding into a normalized structure
// equipped with semantic tags for correlation analysis.
func NormalizeFinding(f report.Finding) NormalizedFinding {
	normCat := report.NormalizeCategory(f.Category)
	normSev := report.NormalizeSeverity(f.Severity)
	normConf := report.NormalizeConfidence(f.Confidence)
	normVer := report.NormalizeVerificationStatus(f.Verification.Status)

	host, origin, path := extractHostAndPath(f.Target, f.Endpoint)

	score := f.Score
	if score == 0 {
		score = report.CalculateFindingScore(f)
	}

	details := make(map[string]string)
	if f.EvidenceDetails.Details != nil {
		for k, v := range f.EvidenceDetails.Details {
			details[k] = v
		}
	}

	titleLower := strings.ToLower(f.Title)
	catLower := strings.ToLower(f.Category)
	epLower := strings.ToLower(f.Endpoint)

	isVer := normVer == report.VerificationVerified
	isCand := normVer == report.VerificationDetected || normVer == report.VerificationNotVerified ||
		strings.Contains(titleLower, "(candidate)") || strings.Contains(titleLower, "candidate")

	isEntry := strings.Contains(catLower, "route") ||
		strings.Contains(catLower, "endpoint") ||
		strings.Contains(catLower, "api-docs") ||
		strings.Contains(catLower, "discovery") ||
		strings.Contains(titleLower, "entry point") ||
		strings.Contains(titleLower, "accessible") ||
		f.Source == report.SourceCrawler ||
		(f.Source == report.SourceAPI && !strings.Contains(catLower, "bola") && !strings.Contains(catLower, "auth"))

	isAuthReq := strings.Contains(catLower, "auth") ||
		strings.Contains(catLower, "session") ||
		strings.Contains(catLower, "token") ||
		strings.Contains(catLower, "jwt") ||
		details["auth_required"] == "true" ||
		details["auth_state"] == "AUTH_REQUIRED"

	isRoleRestricted := strings.Contains(catLower, "bfla") ||
		strings.Contains(catLower, "role") ||
		strings.Contains(catLower, "privilege") ||
		strings.Contains(catLower, "admin") ||
		strings.Contains(titleLower, "role") ||
		details["role"] != "" ||
		details["required_role"] != ""

	isSensData := strings.Contains(catLower, "secret") ||
		strings.Contains(catLower, "token") ||
		strings.Contains(catLower, "key") ||
		strings.Contains(catLower, "pii") ||
		strings.Contains(catLower, "card") ||
		strings.Contains(catLower, "data-leak") ||
		strings.Contains(catLower, "sensitive") ||
		strings.Contains(catLower, "exposure") ||
		strings.Contains(catLower, "credential") ||
		strings.Contains(catLower, "backup") ||
		strings.Contains(titleLower, "sensitive") ||
		strings.Contains(titleLower, "credential") ||
		strings.Contains(titleLower, "token") ||
		strings.Contains(titleLower, "leak") ||
		strings.Contains(titleLower, "backup") ||
		details["sensitive_data"] == "true" ||
		f.Source == report.SourceSecrets

	isCloud := f.Source == report.SourceCloud ||
		strings.Contains(catLower, "s3") ||
		strings.Contains(catLower, "blob") ||
		strings.Contains(catLower, "gcs") ||
		strings.Contains(catLower, "cloud") ||
		strings.Contains(epLower, "amazonaws.com") ||
		strings.Contains(epLower, "blob.core.windows.net") ||
		strings.Contains(epLower, "storage.googleapis.com")

	isWf := strings.Contains(catLower, "workflow") ||
		strings.Contains(catLower, "transition") ||
		strings.Contains(catLower, "state-manipulation") ||
		strings.Contains(catLower, "replay") ||
		strings.Contains(catLower, "invariant") ||
		strings.Contains(catLower, "bl-") ||
		details["workflow"] != "" ||
		details["workflow_id"] != ""

	synthFixture := details["synthetic_fixture"] == "true" ||
		strings.Contains(f.Title, "[SYNTHETIC SIMULATION]")

	inferredHyp := details["hypothesis"] != "" ||
		strings.Contains(details["hypothesis"], "INFERRED") ||
		strings.Contains(f.Title, "Inferred Workflow")

	var params []string
	if paramStr, ok := details["parameters"]; ok && paramStr != "" {
		for _, p := range strings.Split(paramStr, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				params = append(params, p)
			}
		}
	}
	if p, ok := details["affected_param"]; ok && p != "" {
		params = append(params, p)
	}

	affectedRes := details["resource_id"]
	if affectedRes == "" {
		affectedRes = details["object_id"]
	}
	if affectedRes == "" {
		affectedRes = details["bucket"]
	}

	return NormalizedFinding{
		ID:                 f.ID,
		OriginalID:         f.ID,
		Title:              f.Title,
		Category:           f.Category,
		NormalizedCategory: normCat,
		Severity:           normSev,
		Confidence:         normConf,
		VerificationStatus: normVer,
		Target:             f.Target,
		Host:               host,
		Origin:             origin,
		Endpoint:           f.Endpoint,
		Path:               path,
		Method:             strings.ToUpper(f.Method),
		Score:              score,
		Source:             f.Source,
		Fingerprint:        f.Fingerprint,
		IsVerified:         isVer,
		IsCandidate:        isCand,
		IsEntrypoint:       isEntry,
		IsAuthRequirement:  isAuthReq,
		IsRoleRestricted:   isRoleRestricted,
		IsSensitiveData:    isSensData,
		IsCloudResource:    isCloud,
		IsWorkflowStep:     isWf,
		EvidenceSummary:    f.Evidence,
		EvidenceDetails:    details,
		AffectedResource:   affectedRes,
		Parameters:         params,
		SyntheticFixture:   synthFixture,
		InferredHypothesis: inferredHyp,
	}
}

// NormalizeFindings normalizes a collection of findings.
func NormalizeFindings(findings []report.Finding) []NormalizedFinding {
	out := make([]NormalizedFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, NormalizeFinding(f))
	}
	return out
}

func extractHostAndPath(target, endpoint string) (string, string, string) {
	raw := endpoint
	if raw == "" {
		raw = target
	}
	if raw == "" {
		return "", "", ""
	}

	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", "", endpoint
	}

	host := u.Hostname()
	origin := u.Scheme + "://" + u.Host
	path := u.Path
	if path == "" {
		path = "/"
	}

	return host, origin, path
}
