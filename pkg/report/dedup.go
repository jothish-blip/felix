package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// ComputeFingerprint generates a stable SHA-256 identity fingerprint for deduplication.
// It incorporates security identity without relying on variable evidence phrasing.
func ComputeFingerprint(target, category, endpoint, method, identityKey string) string {
	h := sha256.New()
	cleanTarget := strings.ToLower(strings.TrimSpace(target))
	cleanCategory := strings.ToLower(strings.TrimSpace(category))
	cleanEndpoint := strings.ToLower(strings.TrimSpace(endpoint))
	cleanMethod := strings.ToUpper(strings.TrimSpace(method))
	cleanKey := strings.TrimSpace(identityKey)

	payload := fmt.Sprintf("%s|%s|%s|%s|%s", cleanTarget, cleanCategory, cleanEndpoint, cleanMethod, cleanKey)
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

// ComputeFindingFingerprint computes a canonical SHA-256 fingerprint for finding deduplication.
func ComputeFindingFingerprint(target, category, endpoint, method, identityKey string) string {
	return ComputeFingerprint(target, category, endpoint, method, identityKey)
}

// ComputeStableFindingID generates a deterministic, stable finding identifier (fnd_<hex>).
func ComputeStableFindingID(target, ruleID, category, endpoint, method, identityKey string) string {
	h := sha256.New()
	cleanTarget := NormalizeURL(target)
	cleanRule := strings.ToUpper(strings.TrimSpace(ruleID))
	cleanCategory := NormalizeCategory(category)
	cleanEndpoint := NormalizeURL(endpoint)
	cleanMethod := NormalizeMethod(method)
	cleanKey := strings.TrimSpace(identityKey)

	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%s", cleanTarget, cleanRule, cleanCategory, cleanEndpoint, cleanMethod, cleanKey)
	h.Write([]byte(payload))
	sum := h.Sum(nil)
	return fmt.Sprintf("fnd_%s", hex.EncodeToString(sum[:12])) // 24 hex characters
}

// DeduplicateFindings merges equivalent findings into a single canonical entry with aggregated evidence.
func DeduplicateFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}

	seen := make(map[string]*Finding)
	var order []string

	for _, f := range findings {
		norm := NormalizeFinding(f)
		fp := norm.Fingerprint

		if existing, exists := seen[fp]; exists {
			// Merge string evidence if different without duplicate substrings
			if norm.Evidence != "" && !strings.Contains(existing.Evidence, norm.Evidence) {
				if existing.Evidence == "" {
					existing.Evidence = norm.Evidence
				} else {
					existing.Evidence = existing.Evidence + "; Also: " + norm.Evidence
				}
			}

			// Merge structured evidence observation
			if existing.EvidenceDetails.Observation == "" {
				existing.EvidenceDetails.Observation = norm.EvidenceDetails.Observation
			} else if norm.EvidenceDetails.Observation != "" && !strings.Contains(existing.EvidenceDetails.Observation, norm.EvidenceDetails.Observation) {
				existing.EvidenceDetails.Observation = existing.EvidenceDetails.Observation + "; Also: " + norm.EvidenceDetails.Observation
			}

			// Merge location if different (e.g. multiple lines or assets where candidate occurs)
			if norm.EvidenceDetails.Location != "" && !strings.Contains(existing.EvidenceDetails.Location, norm.EvidenceDetails.Location) {
				if existing.EvidenceDetails.Location == "" {
					existing.EvidenceDetails.Location = norm.EvidenceDetails.Location
				} else {
					existing.EvidenceDetails.Location = existing.EvidenceDetails.Location + ", " + norm.EvidenceDetails.Location
				}
			}

			// Merge negative evidence
			if existing.EvidenceDetails.NegativeEvidence == "" {
				existing.EvidenceDetails.NegativeEvidence = norm.EvidenceDetails.NegativeEvidence
			} else if norm.EvidenceDetails.NegativeEvidence != "" && !strings.Contains(existing.EvidenceDetails.NegativeEvidence, norm.EvidenceDetails.NegativeEvidence) {
				existing.EvidenceDetails.NegativeEvidence = existing.EvidenceDetails.NegativeEvidence + " " + norm.EvidenceDetails.NegativeEvidence
			}

			// Merge details map
			if len(norm.EvidenceDetails.Details) > 0 {
				if existing.EvidenceDetails.Details == nil {
					existing.EvidenceDetails.Details = make(map[string]string)
				}
				for k, v := range norm.EvidenceDetails.Details {
					if oldV, has := existing.EvidenceDetails.Details[k]; !has {
						existing.EvidenceDetails.Details[k] = v
					} else if oldV != v && !strings.Contains(oldV, v) {
						existing.EvidenceDetails.Details[k] = oldV + ", " + v
					}
				}
			}

			// Merge PrimaryAssetID
			if existing.PrimaryAssetID == "" && norm.PrimaryAssetID != "" {
				existing.PrimaryAssetID = norm.PrimaryAssetID
			}

			// Merge AffectedAssetIDs
			if len(norm.AffectedAssetIDs) > 0 {
				assetMap := make(map[string]struct{}, len(existing.AffectedAssetIDs)+len(norm.AffectedAssetIDs))
				for _, a := range existing.AffectedAssetIDs {
					assetMap[a] = struct{}{}
				}
				for _, a := range norm.AffectedAssetIDs {
					if _, has := assetMap[a]; !has {
						assetMap[a] = struct{}{}
						existing.AffectedAssetIDs = append(existing.AffectedAssetIDs, a)
					}
				}
				sort.Strings(existing.AffectedAssetIDs)
			}

			// Merge RemediationAdvice
			if existing.RemediationAdvice == nil && norm.RemediationAdvice != nil {
				existing.RemediationAdvice = norm.RemediationAdvice
			} else if existing.RemediationAdvice != nil && norm.RemediationAdvice != nil {
				for _, s := range norm.RemediationAdvice.Steps {
					has := false
					for _, es := range existing.RemediationAdvice.Steps {
						if es == s {
							has = true
							break
						}
					}
					if !has {
						existing.RemediationAdvice.Steps = append(existing.RemediationAdvice.Steps, s)
					}
				}
				for _, r := range norm.RemediationAdvice.References {
					has := false
					for _, er := range existing.RemediationAdvice.References {
						if er == r {
							has = true
							break
						}
					}
					if !has {
						existing.RemediationAdvice.References = append(existing.RemediationAdvice.References, r)
					}
				}
			}

			// Merge Provenance
			if existing.Provenance == nil && norm.Provenance != nil {
				existing.Provenance = norm.Provenance
				existing.EvidenceDetails.Provenance = norm.Provenance
			} else if existing.Provenance != nil && norm.Provenance != nil {
				if existing.Provenance.AssetID == "" && norm.Provenance.AssetID != "" {
					existing.Provenance.AssetID = norm.Provenance.AssetID
				}
				if existing.Provenance.VerificationContext == "" && norm.Provenance.VerificationContext != "" {
					existing.Provenance.VerificationContext = norm.Provenance.VerificationContext
				}
				existing.EvidenceDetails.Provenance = existing.Provenance
			}

			// Merge Verification Limitations and Rationale
			if len(norm.Verification.Limitations) > 0 {
				limMap := make(map[string]struct{}, len(existing.Verification.Limitations)+len(norm.Verification.Limitations))
				for _, lim := range existing.Verification.Limitations {
					limMap[lim] = struct{}{}
				}
				for _, lim := range norm.Verification.Limitations {
					if _, has := limMap[lim]; !has {
						limMap[lim] = struct{}{}
						existing.Verification.Limitations = append(existing.Verification.Limitations, lim)
					}
				}
			}
			if existing.Verification.Rationale == "" && norm.Verification.Rationale != "" {
				existing.Verification.Rationale = norm.Verification.Rationale
			} else if norm.Verification.Rationale != "" && !strings.Contains(existing.Verification.Rationale, norm.Verification.Rationale) {
				existing.Verification.Rationale = existing.Verification.Rationale + "; " + norm.Verification.Rationale
			}

			// Deterministic precedence:
			// 1. Status precedence & Honest Verification Invariant:
			// Deterministic order: CONFIRMED > SUSPECTED > INCONCLUSIVE > NOT_TESTED > ERROR.
			// Guard: NEVER upgrade any unverified finding (SUSPECTED, NOT_TESTED, INCONCLUSIVE, ERROR) to CONFIRMED unless:
			//   a) Active verification genuinely ran and succeeded (ACTIVE_VERIFICATION + VERIFIED), OR
			//   b) Direct empirical static observation proved the asset exists (e.g. source map downloaded).
			if FindingStatusRank(norm.Status) > FindingStatusRank(existing.Status) {
				allowUpgrade := true
				if norm.Status == FindingStatusConfirmed {
					if norm.AnalysisMethod == AnalysisMethodActive && norm.Verification.Status != VerificationVerified {
						allowUpgrade = false
					}
					if norm.AnalysisMethod == AnalysisMethodStatic && (norm.Verification.Status == VerificationNotVerified || norm.Verification.Status == VerificationDetected) {
						allowUpgrade = false
					}
				}
				if allowUpgrade {
					existing.Status = norm.Status
					if norm.AnalysisMethod == AnalysisMethodActive && norm.Verification.Status == VerificationVerified {
						existing.AnalysisMethod = AnalysisMethodActive
					}
				}
			}

			// Merge AnalysisMethod: ACTIVE_VERIFICATION takes precedence if active check verified
			if norm.AnalysisMethod == AnalysisMethodActive && norm.Verification.Status == VerificationVerified {
				existing.AnalysisMethod = AnalysisMethodActive
			} else if existing.AnalysisMethod == "" {
				existing.AnalysisMethod = norm.AnalysisMethod
			}

			// 2. Keep highest verification status (VERIFIED > DETECTED > NOT_VERIFIED > OBSERVED > NOT_EXPOSED)
			if VerificationRank(norm.Verification.Status) > VerificationRank(existing.Verification.Status) {
				existing.Verification = norm.Verification
			} else if norm.Verification.Result != "" && !strings.Contains(existing.Verification.Result, norm.Verification.Result) {
				// Preserve material changes in verification results without concealing contradictory checks
				existing.Verification.Result = existing.Verification.Result + "; Note: " + norm.Verification.Result
			}

			if existing.Verification.SafeCurlCommand == "" && norm.Verification.SafeCurlCommand != "" {
				existing.Verification.SafeCurlCommand = norm.Verification.SafeCurlCommand
			}
			if len(existing.Verification.ReproductionSteps) == 0 && len(norm.Verification.ReproductionSteps) > 0 {
				existing.Verification.ReproductionSteps = norm.Verification.ReproductionSteps
			}

			// 3. Keep highest severity (CRITICAL > HIGH > MEDIUM > LOW > INFO)
			if SeverityRank(norm.Severity) > SeverityRank(existing.Severity) {
				existing.Severity = norm.Severity
			}

			// 4. Keep highest confidence (HIGH > MEDIUM > LOW)
			if ConfidenceRank(norm.Confidence) > ConfidenceRank(existing.Confidence) {
				existing.Confidence = norm.Confidence
			}

			// 5. Merge Framework classification fields
			if existing.Framework == "" && norm.Framework != "" {
				existing.Framework = norm.Framework
			}
			if existing.FrameworkVersion == "" && norm.FrameworkVersion != "" {
				existing.FrameworkVersion = norm.FrameworkVersion
			}
			if existing.ClassificationOutcome == "" || (norm.ClassificationOutcome == OutcomeConfirmed && existing.ClassificationOutcome != OutcomeConfirmed) {
				existing.ClassificationOutcome = norm.ClassificationOutcome
			}
			if existing.Reachability == "" || (norm.Reachability == ReachabilityConfirmedReachable && existing.Reachability != ReachabilityConfirmedReachable) {
				existing.Reachability = norm.Reachability
			}
			if existing.AuthContext == "" || existing.AuthContext == AuthContextUnknown {
				existing.AuthContext = norm.AuthContext
			}

			// Update score with updated severity, confidence, and verification status
			existing.Score = CalculateFindingScore(*existing)
		} else {
			copyFinding := norm
			seen[fp] = &copyFinding
			order = append(order, fp)
		}
	}

	result := make([]Finding, 0, len(order))
	for _, fp := range order {
		result = append(result, *seen[fp])
	}

	return result
}
