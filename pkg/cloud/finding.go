package cloud

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Severity and Confidence ratings for cloud findings.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"

	ConfidenceHigh   = "High"
	ConfidenceMedium = "Medium"
	ConfidenceLow    = "Low"
)

// CloudFinding represents an assessed cloud exposure or configuration observation.
type CloudFinding struct {
	Provider    Provider `json:"provider"`
	Category    string   `json:"category"`
	Endpoint    string   `json:"endpoint"`
	Description string   `json:"description"`
	Evidence    string   `json:"evidence"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	Fingerprint string   `json:"fingerprint"`
}

// GenerateFingerprint generates a unique SHA-256 deduplication fingerprint for the finding.
func GenerateFingerprint(p Provider, endpoint, category string) string {
	h := sha256.New()
	cleanEndpoint := strings.ToLower(strings.TrimSpace(endpoint))
	cleanCategory := strings.ToLower(strings.TrimSpace(category))
	h.Write([]byte(string(p) + ":" + cleanCategory + ":" + cleanEndpoint))
	return hex.EncodeToString(h.Sum(nil))
}
