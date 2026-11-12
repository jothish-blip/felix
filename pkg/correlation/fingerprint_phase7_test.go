package correlation

import (
	"testing"

	"felix/pkg/report"
)

func TestPhase7_DistinctSecurityHeadersDoNotDeduplicate(t *testing.T) {
	findings := []report.Finding{
		{
			ID:          "HDR-CSP-11111111",
			Category:    "Missing Security Header",
			Title:       "Missing Content-Security-Policy (CSP)",
			Severity:    "Medium",
			Confidence:  "High",
			Target:      "http://127.0.0.1:5000",
			Endpoint:    "/",
			Method:      "GET",
			AuthContext: report.AuthContextNoChallenge,
		},
		{
			ID:          "HDR-NOSNIFF-22222222",
			Category:    "Missing Security Header",
			Title:       "Missing or Misconfigured X-Content-Type-Options",
			Severity:    "Low",
			Confidence:  "High",
			Target:      "http://127.0.0.1:5000",
			Endpoint:    "/",
			Method:      "GET",
			AuthContext: report.AuthContextNoChallenge,
		},
		{
			ID:          "HDR-HSTS-33333333",
			Category:    "Missing Security Header",
			Title:       "Missing HTTP Strict Transport Security (HSTS)",
			Severity:    "Medium",
			Confidence:  "High",
			Target:      "https://127.0.0.1:5443",
			Endpoint:    "/",
			Method:      "GET",
			AuthContext: report.AuthContextNoChallenge,
		},
		{
			ID:          "HDR-XFO-44444444",
			Category:    "Clickjacking Defense Missing",
			Title:       "Missing Anti-Clickjacking Header (X-Frame-Options)",
			Severity:    "Low",
			Confidence:  "High",
			Target:      "http://127.0.0.1:5000",
			Endpoint:    "/",
			Method:      "GET",
			AuthContext: report.AuthContextNoChallenge,
		},
	}

	deduped := DeduplicateFindings(findings)
	if len(deduped) != 4 {
		t.Fatalf("expected all 4 distinct security header findings to remain distinct, got %d", len(deduped))
	}

	// True duplicate CSP findings should still collapse into 1
	withDupCSP := append(findings, report.Finding{
		ID:          "HDR-CSP-99999999",
		Category:    "Missing Security Header",
		Title:       "Missing Content-Security-Policy (CSP)",
		Severity:    "Medium",
		Confidence:  "High",
		Target:      "http://127.0.0.1:5000",
		Endpoint:    "/",
		Method:      "GET",
		AuthContext: report.AuthContextNoChallenge,
	})
	deduped2 := DeduplicateFindings(withDupCSP)
	if len(deduped2) != 4 {
		t.Fatalf("expected duplicate CSP finding to collapse to 4 unique header findings, got %d", len(deduped2))
	}
}
