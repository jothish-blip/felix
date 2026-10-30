package correlation

import (
	"crypto/sha256"
	"fmt"
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

	rawURLVal := f.Endpoint
	if rawURLVal == "" {
		rawURLVal = f.Target
	}
	dispEndpointVal := rawURLVal
	if rawURLVal != "" {
		if c, err := CanonicalizeURL(rawURLVal); err == nil {
			if c.RawURL != "" {
				rawURLVal = c.RawURL
			}
			if c.DisplayEndpoint != "" {
				dispEndpointVal = c.DisplayEndpoint
			}
		}
	}

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

	isHeaderOrOmission := strings.Contains(catLower, "missing-") ||
		strings.Contains(catLower, "header") ||
		strings.Contains(catLower, "csp") ||
		strings.Contains(catLower, "runtime") ||
		strings.Contains(catLower, "fingerprint") ||
		strings.Contains(catLower, "source-map")

	isEntry := !isHeaderOrOmission && (strings.Contains(catLower, "route") ||
		strings.Contains(catLower, "endpoint") ||
		strings.Contains(catLower, "api-docs") ||
		strings.Contains(catLower, "discovery") ||
		strings.Contains(titleLower, "entry point") ||
		strings.Contains(titleLower, "accessible") ||
		(f.Source == report.SourceCrawler && !strings.Contains(catLower, "source-map")) ||
		(f.Source == report.SourceAPI && !strings.Contains(catLower, "bola") && !strings.Contains(catLower, "auth")))

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

	isSensData := (strings.Contains(catLower, "secret") ||
		strings.Contains(catLower, "token") ||
		strings.Contains(catLower, "key") ||
		strings.Contains(catLower, "pii") ||
		strings.Contains(catLower, "card") ||
		strings.Contains(catLower, "data-leak") ||
		strings.Contains(catLower, "sensitive") ||
		(strings.Contains(catLower, "exposure") && !strings.Contains(catLower, "runtime") && !strings.Contains(catLower, "header")) ||
		strings.Contains(catLower, "credential") ||
		strings.Contains(catLower, "backup") ||
		strings.Contains(titleLower, "sensitive") ||
		strings.Contains(titleLower, "credential") ||
		strings.Contains(titleLower, "token") ||
		strings.Contains(titleLower, "leak") ||
		strings.Contains(titleLower, "backup") ||
		details["sensitive_data"] == "true" ||
		f.Source == report.SourceSecrets) &&
		!strings.Contains(catLower, "node-runtime") &&
		!strings.Contains(catLower, "runtime") &&
		!strings.Contains(catLower, "framework")

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
	primaryAsset, _ := ResolveFindingAsset(f, nil)
	affectedAssets := ResolveFindingAffectedAssets(f, primaryAsset, nil)

	primaryID := f.PrimaryAssetID
	if primaryID == "" && primaryAsset != nil {
		primaryID = primaryAsset.ID
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
		DisplayEndpoint:    dispEndpointVal,
		RawURL:             rawURLVal,
		Path:               path,
		Method:             strings.ToUpper(f.Method),
		Score:              score,
		Source:             f.Source,
		Fingerprint:        f.Fingerprint,
		PrimaryAssetID:     primaryID,
		AffectedAssetIDs:   affectedAssets,
		AssetType:          primaryAsset.Type,
		CanonicalAssetKey:  primaryAsset.CanonicalKey,
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

// NormalizeFindings normalizes a collection of findings, ensuring deterministic surrogate IDs
// for empty or duplicate finding IDs so that relationships and asset mappings never collide.
func NormalizeFindings(findings []report.Finding) []NormalizedFinding {
	out := make([]NormalizedFinding, 0, len(findings))
	seenIDs := make(map[string]int)

	for i, f := range findings {
		norm := NormalizeFinding(f)

		cleanID := strings.TrimSpace(norm.ID)
		if cleanID == "" {
			// Deterministic surrogate ID based on index, title, category, endpoint
			h := sha256.Sum256([]byte(fmt.Sprintf("%d:%s:%s:%s", i, f.Title, f.Category, f.Endpoint)))
			norm.ID = fmt.Sprintf("synth_%x", h[:6])
		} else if count := seenIDs[cleanID]; count > 0 {
			// Disambiguate duplicate ID deterministically
			h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", cleanID, count, f.Endpoint)))
			norm.ID = fmt.Sprintf("%s_dup%d_%x", cleanID, count, h[:4])
		}
		seenIDs[cleanID]++
		out = append(out, norm)
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

	canon, err := CanonicalizeURL(raw)
	if err == nil {
		return canon.Host, canon.Origin, canon.Path
	}

	// Fallback to basic parse if CanonicalizeURL fails
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", endpoint
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	origin := strings.ToLower(u.Scheme) + "://" + u.Host
	p := u.Path
	if p == "" {
		p = "/"
	}
	return host, origin, p
}
