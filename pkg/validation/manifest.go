package validation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

// ParseAuthOrCampaignManifest decodes raw JSON as either a CampaignManifest or a standalone AuthorizationContract.
func ParseAuthOrCampaignManifest(raw []byte) (AuthorizationContract, *CampaignManifest, error) {
	var cm CampaignManifest
	if err := json.Unmarshal(raw, &cm); err == nil {
		isCampaign := cm.ManifestID != "" ||
			cm.TargetURL != "" ||
			cm.GroundTruthSHA256 != "" ||
			cm.BlindExecution ||
			cm.Authorization.AuthorizingParty != "" ||
			cm.Authorization.AuthorizationRef != "" ||
			cm.Authorization.Confirmed ||
			len(cm.Authorization.AuthorizedTargets) > 0
		if isCampaign {
			return cm.Authorization, &cm, nil
		}
	}
	var contract AuthorizationContract
	if err := json.Unmarshal(raw, &contract); err != nil {
		return AuthorizationContract{}, nil, err
	}
	return contract, nil, nil
}

// ValidateGroundTruthSHA256Format ensures a pre-locked campaign ground-truth digest uses sha256:<64-hex>.
func ValidateGroundTruthSHA256Format(digest string) error {
	trimmed := strings.TrimSpace(digest)
	if trimmed == "" {
		return fmt.Errorf("ground_truth_sha256 is empty; pre-locked ground-truth digest is required")
	}
	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, "sha256:") {
		return fmt.Errorf("ground_truth_sha256 %q must use sha256:<64-hex> format", trimmed)
	}
	hexPart := strings.TrimPrefix(lower, "sha256:")
	if len(hexPart) != 64 {
		return fmt.Errorf("ground_truth_sha256 %q must contain 64 hex characters", trimmed)
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return fmt.Errorf("ground_truth_sha256 %q contains invalid hex characters", trimmed)
	}
	return nil
}

// CanonicalGroundTruthSHA256 computes a deterministic SHA-256 digest over a GroundTruthRegistry.
func CanonicalGroundTruthSHA256(reg *GroundTruthRegistry) (string, error) {
	if reg == nil {
		return "", fmt.Errorf("ground-truth registry is nil")
	}
	b, err := json.Marshal(reg)
	if err != nil {
		return "", fmt.Errorf("marshal ground-truth registry: %w", err)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ComputeFileSHA256 computes the SHA-256 digest of a file on disk.
func ComputeFileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// BuildScopeValidator constructs an assessment.ScopeValidator from an AuthorizationContract.
func BuildScopeValidator(contract AuthorizationContract, extraTargets ...string) *assessment.ScopeValidator {
	var targets []string
	var rules []assessment.ScopeRule
	var exclusions []assessment.Exclusion

	seenTarget := make(map[string]bool)
	for _, t := range append(contract.AuthorizedTargets, extraTargets...) {
		trimmed := strings.TrimSpace(t)
		if trimmed != "" && !seenTarget[trimmed] {
			seenTarget[trimmed] = true
			targets = append(targets, trimmed)
			if parsed, err := url.Parse(trimmed); err == nil && parsed.Hostname() != "" {
				rules = append(rules, assessment.ScopeRule{
					RuleType: "EXACT_ORIGIN",
					Pattern:  strings.ToLower(parsed.Hostname()),
				})
			}
		}
	}

	mode := strings.TrimSpace(contract.ScopeMode)
	if mode == "" {
		mode = "same-origin"
	}

	for _, p := range contract.ExcludedPaths {
		if clean := strings.TrimSpace(p); clean != "" {
			exclusions = append(exclusions, assessment.Exclusion{
				ExclusionType: "PATH_PREFIX",
				Pattern:       clean,
				Reason:        "authorized manifest path exclusion",
			})
		}
	}
	for _, u := range contract.ExcludedURLs {
		if clean := strings.TrimSpace(u); clean != "" {
			exclusions = append(exclusions, assessment.Exclusion{
				ExclusionType: "EXACT_URL",
				Pattern:       clean,
				Reason:        "authorized manifest exact URL exclusion",
			})
		}
	}
	for _, h := range contract.ExcludedHosts {
		if clean := strings.TrimSpace(h); clean != "" {
			exclusions = append(exclusions, assessment.Exclusion{
				ExclusionType: "HOSTNAME",
				Pattern:       clean,
				Reason:        "authorized manifest host exclusion",
			})
		}
	}

	return assessment.NewScopeValidator(mode, targets, rules, exclusions)
}

// ValidateAuthorizationGate enforces explicit owner certification, target scope membership,
// non-excluded path status, and testing-window bounds prior to active testing.
func ValidateAuthorizationGate(contract AuthorizationContract, targetURL string, now time.Time) error {
	if !contract.Confirmed {
		return fmt.Errorf("authorization gate refused: contract.confirmed is false")
	}
	if strings.TrimSpace(contract.AuthorizingParty) == "" {
		return fmt.Errorf("authorization gate refused: authorizing_party is empty")
	}
	if len(contract.AuthorizedTargets) == 0 {
		return fmt.Errorf("authorization gate refused: no authorized_targets declared")
	}

	parsedTarget, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || parsedTarget.Hostname() == "" {
		return fmt.Errorf("authorization gate refused: invalid target URL %q", targetURL)
	}

	if !contract.WindowStart.IsZero() && now.Before(contract.WindowStart) {
		return fmt.Errorf("authorization gate refused: current UTC time %s is before authorized window start %s",
			now.UTC().Format(time.RFC3339), contract.WindowStart.UTC().Format(time.RFC3339))
	}
	if !contract.WindowEnd.IsZero() && now.After(contract.WindowEnd) {
		return fmt.Errorf("authorization gate refused: current UTC time %s is after authorized window end %s",
			now.UTC().Format(time.RFC3339), contract.WindowEnd.UTC().Format(time.RFC3339))
	}

	sv := BuildScopeValidator(contract)
	if !sv.IsAllowed(targetURL) {
		return fmt.Errorf("authorization gate refused: target %s is outside authorized targets or explicitly excluded", targetURL)
	}
	return nil
}

// VerifyCampaignBlindness verifies that an independent ground-truth registry was neither derived
// from FELIX output nor modified after campaign execution began.
func VerifyCampaignBlindness(reg *GroundTruthRegistry, manifest *CampaignManifest) ([]string, bool, bool) {
	var notes []string
	if reg == nil {
		return []string{"ground-truth registry missing"}, false, false
	}
	if reg.DerivedFromScanner {
		notes = append(notes, "ground-truth registry failed independence check: derived_from_scanner=true")
		return notes, false, false
	}
	if len(reg.Entries) == 0 {
		notes = append(notes, "ground-truth registry has zero entries")
		return notes, false, false
	}

	computedHash, err := CanonicalGroundTruthSHA256(reg)
	if err != nil {
		notes = append(notes, fmt.Sprintf("failed hashing ground-truth registry: %v", err))
		return notes, false, false
	}

	if manifest == nil {
		notes = append(notes, "no campaign manifest supplied; pre-scan hash lock unverified")
		return notes, false, false
	}

	manifestOK := true
	if strings.TrimSpace(manifest.GroundTruthSHA256) == "" || !strings.EqualFold(manifest.GroundTruthSHA256, computedHash) {
		notes = append(notes, fmt.Sprintf("ground-truth hash mismatch: manifest=%q computed=%q", manifest.GroundTruthSHA256, computedHash))
		manifestOK = false
	}
	if !manifest.BlindExecution {
		notes = append(notes, "manifest.blind_execution is false")
		manifestOK = false
	}
	if manifest.ExecutedAt.IsZero() || reg.EstablishedAt.IsZero() {
		notes = append(notes, "missing established_at or executed_at timestamp for chronological blindness check")
		manifestOK = false
	} else if reg.EstablishedAt.After(manifest.ExecutedAt) {
		notes = append(notes, fmt.Sprintf("ground-truth established_at (%s) is after campaign executed_at (%s)",
			reg.EstablishedAt.UTC().Format(time.RFC3339), manifest.ExecutedAt.UTC().Format(time.RFC3339)))
		manifestOK = false
	}

	if err := ValidateAuthorizationGate(manifest.Authorization, manifest.TargetURL, manifest.ExecutedAt); err != nil {
		notes = append(notes, fmt.Sprintf("manifest authorization validation failed: %v", err))
		manifestOK = false
	}

	return notes, manifestOK, manifestOK
}

// AuditReportRedaction scans persisted report findings for accidental unredacted credentials/secrets.
func AuditReportRedaction(rep *report.Report) RedactionAuditResult {
	res := RedactionAuditResult{Clean: true}
	if rep == nil {
		return res
	}
	res.FindingCount = len(rep.Findings)
	detector := secrets.NewDetector()

	checkField := func(location, content string) {
		if strings.TrimSpace(content) == "" {
			return
		}
		if redacted := secrets.RedactText(content); redacted != content {
			res.Clean = false
			res.LeakLocations = append(res.LeakLocations, fmt.Sprintf("%s (unredacted credential/token)", location))
			return
		}
		hits := detector.ScanContent(location, []byte(content))
		for _, h := range hits {
			// Skip already masked snippets that carry asterisks/redaction markers.
			if strings.Contains(h.Redacted, "****") || strings.Contains(content, "[REDACTED") {
				continue
			}
			res.Clean = false
			res.LeakLocations = append(res.LeakLocations, fmt.Sprintf("%s (%s)", location, h.Type))
		}
	}

	for _, f := range rep.Findings {
		prefix := f.ID
		if prefix == "" {
			prefix = f.Title
		}
		checkField(prefix+".evidence", f.Evidence)
		checkField(prefix+".evidence.observation", f.EvidenceDetails.Observation)
		checkField(prefix+".description", f.Description)
		checkField(prefix+".verification.rationale", f.Verification.Rationale)
		checkField(prefix+".verification.safe_curl", f.Verification.SafeCurlCommand)
		for k, v := range f.EvidenceDetails.Details {
			checkField(fmt.Sprintf("%s.details[%s]", prefix, k), v)
		}
	}
	return res
}
