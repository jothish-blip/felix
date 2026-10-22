package report

import (
	"encoding/json"
	"strings"
	"testing"
)

func FuzzParseReport(f *testing.F) {
	// Seed corpus: minimal valid report
	minRep := Report{
		Target: "https://example.com",
		Summary: Summary{
			TotalFindings: 0,
		},
		Findings: []Finding{},
	}
	minJSON, _ := json.Marshal(minRep)
	f.Add(minJSON)

	// Seed corpus: report with 1 finding
	rep1 := Report{
		Target: "https://example.com/api",
		Summary: Summary{
			TotalFindings: 1,
			HighCount:     1,
		},
		Findings: []Finding{
			{
				ID:       "FIND-001",
				Title:    "SQL Injection in /login",
				Severity: "HIGH",
				Target:   "https://example.com/api",
				Endpoint: "/login",
				Category: "Injection",
			},
		},
	}
	rep1JSON, _ := json.Marshal(rep1)
	f.Add(rep1JSON)

	// Seed corpus: malformed / boundary inputs
	f.Add([]byte("{}"))
	f.Add([]byte("[]"))
	f.Add([]byte(`{"target": "https://example.com", "findings": null}`))
	f.Add([]byte(`{"target": "https://example.com", "summary": {"total_findings": 1}, "findings": []}`))
	f.Add([]byte(`{"target": "", "targets": []}`))
	f.Add([]byte(`{"target": "http://user:secret@example.com", "findings": [{"title": "pass=supersecret"}]}`))
	f.Add([]byte(`{"completion_status": "FAILED", "risk_score_available": true, "risk_score": 50}`))
	f.Add([]byte(`{"target": "https://example.com", "summary": {"critical": 2, "high": 1, "total": 3}, "findings": [{"severity": "CRITICAL"}, {"severity": "CRITICAL"}]}`))
	f.Add([]byte("not valid json at all"))
	f.Add([]byte(`{"nested": {"deeply": {"broken": true}}`))
	f.Add([]byte{0x00, 0x01, 0x02, 0xff, 0xfe})
	f.Add([]byte(strings.Repeat(`{"a":`, 50) + "1" + strings.Repeat("}", 50)))

	f.Fuzz(func(t *testing.T, data []byte) {
		rep, err := ParseReport(data)
		if err != nil {
			// Parsing failure is expected on arbitrary or malformed bytes
			return
		}

		// Invariant 1: If parsing succeeded, GenerateJSON must not panic
		genJSON, genErr := GenerateJSON(rep)
		if genErr != nil {
			t.Fatalf("GenerateJSON failed on parsed report: %v", genErr)
		}
		if len(genJSON) == 0 {
			t.Fatalf("GenerateJSON returned empty bytes for parsed report")
		}

		// Invariant 2: ValidateReportIntegrity must execute without panic
		valErr := ValidateReportIntegrity(rep)
		if valErr == nil {
			// If integrity validation passes:
			// Invariant 2a: Target or Targets must be non-empty
			if strings.TrimSpace(rep.Target) == "" && len(rep.Targets) == 0 {
				t.Fatalf("ValidateReportIntegrity passed but target and targets are both empty")
			}

			// Invariant 2b: If summary claims findings exist, findings slice cannot be empty
			sumTotal := rep.Summary.CriticalCount + rep.Summary.HighCount + rep.Summary.MediumCount + rep.Summary.LowCount + rep.Summary.InfoCount
			if rep.Summary.TotalFindings > 0 && sumTotal == 0 {
				sumTotal = rep.Summary.TotalFindings
			}
			if sumTotal > 0 && len(rep.Findings) == 0 {
				t.Fatalf("ValidateReportIntegrity passed but summary claims findings while slice is empty")
			}
		}
	})
}

func FuzzValidateSARIF(f *testing.F) {
	// Seed corpus: minimal valid SARIF 2.1.0 document
	minimalSARIF := `{
		"$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [
			{
				"tool": {
					"driver": {
						"name": "FELIX",
						"version": "1.0.0"
					}
				},
				"results": []
			}
		]
	}`
	f.Add([]byte(minimalSARIF))

	// Seed corpus: SARIF with a result
	sarifWithResult := `{
		"$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [
			{
				"tool": {
					"driver": {
						"name": "FELIX",
						"rules": [
							{
								"id": "SEC-001",
								"name": "HardcodedSecret"
							}
						]
					}
				},
				"results": [
					{
						"ruleId": "SEC-001",
						"message": {
							"text": "Found hardcoded secret in config."
						},
						"level": "error"
					}
				]
			}
		]
	}`
	f.Add([]byte(sarifWithResult))

	// Boundary / malformed seeds
	f.Add([]byte("{}"))
	f.Add([]byte(`{"version": "2.1.0"}`))
	f.Add([]byte(`{"version": "1.0.0", "runs": []}`))
	f.Add([]byte(`{"version": "2.1.0", "runs": "not an array"}`))
	f.Add([]byte(""))
	f.Add([]byte("not json"))
	f.Add([]byte{0x00, 0x7f, 0x80, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		err := ValidateSARIF(data)
		_ = err
		// Invariant: ValidateSARIF must never panic on any arbitrary byte sequence
	})
}
