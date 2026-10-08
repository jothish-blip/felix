package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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
			// Merge string evidence if different
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

			// Merge negative evidence if missing
			if existing.EvidenceDetails.NegativeEvidence == "" && norm.EvidenceDetails.NegativeEvidence != "" {
				existing.EvidenceDetails.NegativeEvidence = norm.EvidenceDetails.NegativeEvidence
			}

			// Merge details map
			if len(norm.EvidenceDetails.Details) > 0 {
				if existing.EvidenceDetails.Details == nil {
					existing.EvidenceDetails.Details = make(map[string]string)
				}
				for k, v := range norm.EvidenceDetails.Details {
					if _, has := existing.EvidenceDetails.Details[k]; !has {
						existing.EvidenceDetails.Details[k] = v
					}
				}
			}

			// Keep highest verification status
			if VerificationRank(norm.Verification.Status) > VerificationRank(existing.Verification.Status) {
				existing.Verification = norm.Verification
			}

			// Keep highest severity
			if SeverityRank(norm.Severity) > SeverityRank(existing.Severity) {
				existing.Severity = norm.Severity
			}

			// Keep highest confidence
			if ConfidenceRank(norm.Confidence) > ConfidenceRank(existing.Confidence) {
				existing.Confidence = norm.Confidence
			}

			// Update score with updated severity/confidence
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
