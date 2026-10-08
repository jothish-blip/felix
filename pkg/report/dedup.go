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
			// Merge evidence if different
			if norm.Evidence != "" && !strings.Contains(existing.Evidence, norm.Evidence) {
				if existing.Evidence == "" {
					existing.Evidence = norm.Evidence
				} else {
					existing.Evidence = existing.Evidence + "; Also: " + norm.Evidence
				}
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
