package correlation

import (
	"encoding/hex"
	"strings"
	"testing"

	"felix/pkg/report"
)

func FuzzComputeStableFingerprint(f *testing.F) {
	// Seed corpus: (category, ruleID, title, severity, target, endpoint, method, param, header)
	f.Add("Injection", "CWE-89", "SQL Injection", "HIGH", "https://example.com/api", "/users", "GET", "id", "")
	f.Add("XSS", "CWE-79", "Reflected XSS", "MEDIUM", "https://example.com", "/search", "POST", "q", "")
	f.Add("Configuration", "CWE-16", "Missing Security Headers", "LOW", "https://example.com", "/", "GET", "", "Content-Security-Policy")
	f.Add("Cloud", "AWS-S3-01", "Public S3 Bucket", "CRITICAL", "s3://my-corp-bucket", "", "", "", "")
	f.Add("Mobile", "APK-PERM-01", "Dangerous Permission", "MEDIUM", "com.example.app", "", "", "", "")
	f.Add("Secret", "SEC-001", "Hardcoded API Key", "CRITICAL", "https://example.com/config.js", "/config.js", "GET", "", "")
	f.Add("", "", "", "", "", "", "", "", "")
	f.Add("Hostile", "R!@#$%", "Title\x00with\nnulls", "UNKNOWN", "https://evil.com/../../etc/passwd", "///invalid", "INVALID_METHOD", strings.Repeat("A", 1000), "Header: Malformed")
	f.Add("Injection", "CWE-89", "SQL Injection", "high", "http://127.0.0.1:8080/test?foo=bar#frag", "/test", "get", "param", "")

	f.Fuzz(func(t *testing.T, category, ruleID, title, severity, target, endpoint, method, param, header string) {
		finding := report.Finding{
			Category: category,
			RuleID:   ruleID,
			Title:    title,
			Severity: severity,
			Target:   target,
			Endpoint: endpoint,
			EvidenceDetails: report.EvidenceDetails{
				Details: map[string]string{
					"http_method": method,
					"parameter":   param,
					"header":      header,
				},
			},
		}

		fp1 := ComputeStableFingerprint(finding)
		details := ComputeFingerprintDetails(finding, nil)

		// Invariant 1: Fingerprint must always be non-empty
		if fp1 == "" {
			t.Fatalf("ComputeStableFingerprint produced empty string")
		}

		// Invariant 2: Fingerprint must be exactly 64 hex characters (lowercase SHA-256)
		if len(fp1) != 64 {
			t.Fatalf("ComputeStableFingerprint returned invalid length %d, expected 64: %q", len(fp1), fp1)
		}
		if _, decErr := hex.DecodeString(fp1); decErr != nil {
			t.Fatalf("ComputeStableFingerprint returned non-hex string %q: %v", fp1, decErr)
		}
		if fp1 != strings.ToLower(fp1) {
			t.Fatalf("ComputeStableFingerprint returned non-lowercase hex: %q", fp1)
		}

		// Invariant 3: Determinism / Idempotency: recomputing must produce exact same fingerprint
		fp2 := ComputeStableFingerprint(finding)
		if fp1 != fp2 {
			t.Fatalf("ComputeStableFingerprint is non-deterministic: first=%q second=%q", fp1, fp2)
		}

		// Invariant 4: Details value must match fp1 and have AlgorithmVersion
		if details.Value != fp1 {
			t.Fatalf("ComputeFingerprintDetails value mismatch: details=%q, fp=%q", details.Value, fp1)
		}
		if details.Version != AlgorithmVersion {
			t.Fatalf("ComputeFingerprintDetails version mismatch: got %q, expected %q", details.Version, AlgorithmVersion)
		}
	})
}

func FuzzCompareFindings(f *testing.F) {
	// Seed corpus: (titleA, titleB, sevA, sevB, statusA, statusB)
	f.Add("Finding 1", "Finding 1", "HIGH", "HIGH", "OPEN", "OPEN")
	f.Add("Finding 1", "Finding 1", "HIGH", "CRITICAL", "OPEN", "OPEN")
	f.Add("Finding 1", "Finding 2", "HIGH", "HIGH", "OPEN", "OPEN")
	f.Add("Finding 1", "Finding 1", "HIGH", "HIGH", "OPEN", "FIXED")
	f.Add("", "", "", "", "", "")

	f.Fuzz(func(t *testing.T, titleA, titleB, sevA, sevB, statusA, statusB string) {
		fA := report.Finding{
			ID:       "A",
			Title:    titleA,
			Severity: sevA,
			Status:   report.FindingStatus(statusA),
			Target:   "https://example.com",
			Endpoint: "/api",
			Category: "Injection",
		}
		fB := report.Finding{
			ID:       "B",
			Title:    titleB,
			Severity: sevB,
			Status:   report.FindingStatus(statusB),
			Target:   "https://example.com",
			Endpoint: "/api",
			Category: "Injection",
		}

		// Must never panic on any comparison combinations
		cmp := CompareFindings([]report.Finding{fA}, []report.Finding{fB})
		_ = cmp
		cmpSelf := CompareFindings([]report.Finding{fA}, []report.Finding{fA})
		_ = cmpSelf
	})
}
