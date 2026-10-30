package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildPremiumDossierFixture creates an exhaustive, client-ready Report containing
// verified criticals, high, medium, low, defensive boundaries, attack path,
// correlated stories, frameworks, and cloud service scope.
func buildPremiumDossierFixture() Report {
	now := time.Now().UTC()
	timestampStr := now.Format("2006-01-02 15:04:05 UTC")

	findings := []Finding{
		{
			ID:             "fnd_crit_01",
			RuleID:         "AUTH-RCE-01",
			Title:          "Unauthenticated Remote Code Execution in Management Endpoint",
			Category:       "Injection & Execution",
			Severity:       SeverityCritical,
			Confidence:     ConfidenceHigh,
			Status:         FindingStatusConfirmed,
			AnalysisMethod: AnalysisMethodActive,
			Target:         "https://app.apex-fintech.io",
			Endpoint:       "/api/v1/management/exec",
			Method:         "POST",
			Description:    "The management debug endpoint evaluates unvalidated JSON expressions under privileged system context, permitting arbitrary code execution without authentication.",
			Evidence:       "POST /api/v1/management/exec HTTP/1.1\r\nHost: app.apex-fintech.io\r\nContent-Type: application/json\r\n\r\n{\"cmd\":\"id\"}\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"output\":\"uid=0(root) gid=0(root)\"}",
			EvidenceDetails: EvidenceDetails{
				Observation:     "Command execution corroborated via non-destructive ID token payload.",
				Location:        "/api/v1/management/exec",
				HTTPMethod:      "POST",
				HTTPStatus:      200,
				DetectionMethod: "active_probe",
			},
			Verification: VerificationRecord{
				Status:             VerificationVerified,
				Result:             "Empirical probe returned affirmative execution signature under root uid.",
				PolicyID:           "POL-RCE-ACTIVE-01",
				VerificationMethod: "deterministic_payload_response",
				AnalysisMethod:     AnalysisMethodActive,
				ConfidenceScore:    98,
				SafeCurlCommand:    "curl -s -X POST https://app.apex-fintech.io/api/v1/management/exec -H 'Content-Type: application/json' -d '{\"probe\":\"verify_active\"}'",
			},
			Remediation: "Immediately disable external access to /api/v1/management endpoints at the reverse proxy. Enforce strict mutual TLS (mTLS) or remove the debug handler from production builds.",
			RemediationAdvice: &RemediationAdvice{
				Summary: "Disable debug interface and enforce role-based API gateway authorization.",
				Steps: []string{
					"Block /api/v1/management/* at ingress reverse proxy",
					"Remove development debug router registrations from production builds",
					"Audit execution logs for unauthorized invocations",
				},
				CodeSnippet: "// Go: restrict debug router to internal interfaces\nif os.Getenv(\"ENVIRONMENT\") != \"production\" {\n    r.Mount(\"/api/v1/management\", debugHandler)\n}",
			},
			Score:  38,
			Source: "api_scanner",
		},
		{
			ID:             "fnd_high_02",
			RuleID:         "SSRF-OAST-02",
			Title:          "Blind Server-Side Request Forgery via Webhook Dispatcher",
			Category:       "Server-Side Request Forgery",
			Severity:       SeverityHigh,
			Confidence:     ConfidenceHigh,
			Status:         FindingStatusConfirmed,
			AnalysisMethod: AnalysisMethodActive,
			Target:         "https://app.apex-fintech.io",
			Endpoint:       "/api/v1/webhooks/subscribe",
			Method:         "POST",
			Description:    "The webhook subscription service triggers outbound HTTP requests to user-supplied URLs without private IP subnet (RFC 1918) filtering or loopback protections.",
			Evidence:       "POST /api/v1/webhooks/subscribe HTTP/1.1\r\nHost: app.apex-fintech.io\r\nContent-Type: application/json\r\n\r\n{\"callback_url\":\"https://canary-7f9a.oast.felix.internal/callback\"}\r\n\r\nHTTP/1.1 202 Accepted",
			EvidenceDetails: EvidenceDetails{
				Observation:     "Controlled OAST canary token received DNS and HTTP callback from target worker egress IP.",
				Location:        "/api/v1/webhooks/subscribe",
				HTTPMethod:      "POST",
				HTTPStatus:      202,
				DetectionMethod: "oast_canary_probe",
			},
			Verification: VerificationRecord{
				Status:             VerificationVerified,
				Result:             "OAST callback confirmed with matching canary probe nonce within 340ms.",
				PolicyID:           "POL-SSRF-OAST-01",
				VerificationMethod: "canary_token_exchange",
				AnalysisMethod:     AnalysisMethodActive,
				ConfidenceScore:    95,
				SafeCurlCommand:    "curl -s -X POST https://app.apex-fintech.io/api/v1/webhooks/subscribe -d '{\"callback_url\":\"https://felix-safe-canary.local\"}'",
			},
			Remediation: "Implement an allowlist-only egress proxy for external webhooks. Enforce strict DNS resolution checks that reject loopback, RFC 1918, link-local, and cloud metadata (169.254.169.254) IP addresses.",
			Score:       28,
			Source:      "api_scanner",
		},
		{
			ID:             "fnd_med_03",
			RuleID:         "AUTH-BOLA-03",
			Title:          "Broken Object Level Authorization in Customer Invoice Lookup",
			Category:       "Broken Authorization",
			Severity:       SeverityMedium,
			Confidence:     ConfidenceMedium,
			Status:         FindingStatusSuspected,
			AnalysisMethod: AnalysisMethodStatic,
			Target:         "https://app.apex-fintech.io",
			Endpoint:       "/api/v1/invoices/:id",
			Method:         "GET",
			Description:    "Sequential integer invoice identifiers are exposed in client frontend bundles without documented tenant scoping or tenant validation guards.",
			EvidenceDetails: EvidenceDetails{
				Observation:     "Client router configuration exposes un-namespaced integer invoice parameters.",
				Location:        "/api/v1/invoices/:id",
				DetectionMethod: "static_pattern_analysis",
			},
			Verification: VerificationRecord{
				Status:          VerificationDetected,
				Result:          "Heuristic candidate identified; empirical cross-tenant retrieval was not attempted under authorized non-destructive scope.",
				ConfidenceScore: 70,
			},
			Remediation: "Enforce ownership validation checks on every invoice query (e.g. WHERE invoice_id = ? AND tenant_id = ?). Replace sequential identifiers with cryptographic UUIDv4 tokens.",
			Score:       16,
			Source:      "crawler",
		},
		{
			ID:             "fnd_low_04",
			RuleID:         "HDR-HSTS-04",
			Title:          "Missing Strict-Transport-Security Header",
			Category:       "Cryptographic & Header Hardening",
			Severity:       SeverityLow,
			Confidence:     ConfidenceHigh,
			Status:         FindingStatusConfirmed,
			AnalysisMethod: AnalysisMethodActive,
			Target:         "https://app.apex-fintech.io",
			Endpoint:       "/",
			Method:         "HEAD",
			Description:    "The target root HTTP response does not include a Strict-Transport-Security (HSTS) header to enforce secure TLS transport.",
			Evidence:       "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n(No Strict-Transport-Security header present)",
			EvidenceDetails: EvidenceDetails{
				Observation:     "HSTS response header absent on HTTPS root endpoint.",
				Location:        "/",
				HTTPMethod:      "HEAD",
				HTTPStatus:      200,
				DetectionMethod: "header_inspection",
			},
			Verification: VerificationRecord{
				Status:             VerificationVerified,
				Result:             "Header affirmatively absent across 3 test requests.",
				VerificationMethod: "header_audit",
				ConfidenceScore:    99,
			},
			Remediation: "Configure the reverse proxy to include: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.",
			Score:       6,
			Source:      "crawler",
		},
		{
			ID:             "fnd_defended_05",
			RuleID:         "S3-PERM-05",
			Title:          "Cloud Storage Bucket Public Access Safely Denied",
			Category:       "Cloud Storage Hardening",
			Severity:       SeverityInfo,
			Confidence:     ConfidenceHigh,
			Status:         FindingStatusConfirmed,
			AnalysisMethod: AnalysisMethodActive,
			Target:         "https://app.apex-fintech.io",
			Endpoint:       "https://apex-production-artifacts.s3.amazonaws.com",
			Method:         "GET",
			Description:    "Discovered Amazon S3 asset bucket correctly denies public unauthenticated anonymous access.",
			EvidenceDetails: EvidenceDetails{
				Observation:      "Bucket returned HTTP 403 AccessDenied with enforced Block Public Access configuration.",
				Location:         "https://apex-production-artifacts.s3.amazonaws.com",
				HTTPMethod:       "GET",
				HTTPStatus:       403,
				NegativeEvidence: "Verified affirmative control: AWS S3 AccessDenied response returned with SigV4 policy intact. Anonymous enumeration rejected.",
				DetectionMethod:  "cloud_security_detector",
			},
			Verification: VerificationRecord{
				Status:             VerificationNotExposed,
				Result:             "Verified non-exposed: Anonymous public bucket listing and object download rejected (HTTP 403).",
				VerificationMethod: "safe_storage_boundary_probe",
				ConfidenceScore:    100,
			},
			Remediation: "Maintain existing S3 Block Public Access policies and perform periodic IAM permission audits.",
			Score:       0,
			Source:      "cloud_detector",
		},
	}

	attackPaths := []AttackPathSummary{
		{
			ID:                "atk_path_01",
			Title:             "Perimeter SSRF to Internal Infrastructure Pivoting",
			Status:            "VERIFIED",
			Confidence:        "HIGH",
			CombinedRiskLevel: "CRITICAL",
			CombinedRiskScore: 92,
			RiskRationale:     "Combining the unauthenticated webhook SSRF with internal management execution provides an end-to-end traversal vector into backend datastores.",
			EntryPoint:        "/api/v1/webhooks/subscribe",
			TargetAsset:       "Internal Datastore & Root Execution Cluster",
			PrimaryWeakness:   "Unvalidated Webhook Destination & Localhost Management Trust",
			TerminalImpact:    "Arbitrary host compromise, credential harvesting, and persistent cluster takeover.",
			Transitions: []string{
				"1. Attacker sends malicious webhook registration pointing to loopback management port.",
				"2. Server executes outbound HTTP request from trusted local loopback interface.",
				"3. Management endpoint interprets internal probe as authorized administrative command.",
			},
			Assumptions: []string{
				"Worker process has network route to internal management interface.",
			},
			MissingEvidence: []string{
				"Automated pivot was bounded and stopped before lateral movement.",
			},
			Remediation: "Implement network segmentation separating webhook worker pods from internal administrative clusters. Enforce strict egress IP controls.",
			NodeIDs:     []string{"fnd_high_02", "fnd_crit_01"},
		},
	}

	securityStories := []SecurityStory{
		{
			ID:               "story_01",
			Title:            "Compound Administrative Vulnerability Surface",
			Summary:          "Simultaneous exposure of unauthenticated management routes and SSRF vectors creates a critical compound risk posture.",
			Description:      "The presence of both an unauthenticated management evaluation interface and an outbound request dispatcher significantly elevates the severity of individual vulnerabilities.",
			Impact:           "Complete takeover of application processing units and unauthorized access to customer records.",
			Severity:         SeverityCritical,
			Confidence:       ConfidenceHigh,
			RiskContribution: 10,
			InvestigateFirst: "/api/v1/management/exec",
			Remediation:      "Decommission the debug management endpoint immediately and isolate webhook dispatchers.",
			Evidence: []string{
				"Verified root code execution on /api/v1/management/exec",
				"Verified outbound SSRF via OAST canary probe on /api/v1/webhooks/subscribe",
			},
			RelatedIDs: []string{"fnd_crit_01", "fnd_high_02"},
		},
	}

	summary := Summary{
		TotalFindings:     len(findings),
		CriticalCount:     1,
		HighCount:         1,
		MediumCount:       1,
		LowCount:          1,
		InfoCount:         1,
		VerifiedCount:     3, // crit, high, low
		DetectedCount:     1, // med
		ObservedCount:     0,
		NotExposedCount:   1, // defended s3
		ScoreAvailable:    true,
		ConfirmedCount:    3,
		SuspectedCount:    1,
		BySource:          map[string]int{"api_scanner": 2, "crawler": 2, "cloud_detector": 1},
	}

	rep := Report{
		Version:            "2.5.0",
		Target:             "https://app.apex-fintech.io",
		Targets:            []string{"https://app.apex-fintech.io"},
		Timestamp:          timestampStr,
		Duration:           "2.45s",
		DurationMs:         2450,
		RequestCount:       84,
		CompletionStatus:   "COMPLETED",
		RiskScoreAvailable: true,
		RiskScore:          84,
		RiskLevel:          SeverityCritical,
		Summary:            summary,
		TopPriorities:      []Finding{findings[0], findings[1]},
		Findings:           findings,
		SecurityStories:    securityStories,
		AttackPaths:        attackPaths,
		Metadata: map[string]any{
			"crawled_assets_count": 42,
			"cloud_services_assessed": []any{
				map[string]any{"name": "Amazon S3", "has_findings": false, "findings_count": 0, "status_text": "Protected (Defensive Controls Verified)"},
				map[string]any{"name": "PostgreSQL RDS", "has_findings": false, "findings_count": 0, "status_text": "Clean (No Public Endpoints)"},
			},
			"detected_frameworks": []any{
				map[string]any{
					"name":           "Gin Web Framework",
					"version":        "1.9.1",
					"status":         "VERIFIED_VULNERABILITY",
					"status_text":    "Verified Exposure Present",
					"total_findings": 2,
					"endpoints":      []any{"/api/v1/management/exec", "/api/v1/webhooks/subscribe"},
				},
			},
		},
	}

	commRep := BuildCommercialReport(rep)
	rep.CommercialReport = &commRep

	return rep
}

func TestPremiumClientDossierGenerationAndVisualValidation(t *testing.T) {
	rep := buildPremiumDossierFixture()

	// 1. Generate Standard HTML
	htmlContent, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	// 2. Generate Commercial HTML
	commContent, err := GenerateCommercialHTML(*rep.CommercialReport)
	if err != nil {
		t.Fatalf("GenerateCommercialHTML failed: %v", err)
	}

	// 3. Write files to root directory for client inspection
	stdPath := filepath.Join("..", "..", "test_client_dossier.html")
	if err := os.WriteFile(stdPath, []byte(htmlContent), 0600); err != nil {
		// Fallback to local dir if path resolution differs
		_ = os.WriteFile("test_client_dossier.html", []byte(htmlContent), 0600)
	}

	commPath := filepath.Join("..", "..", "test_client_commercial_dossier.html")
	if err := os.WriteFile(commPath, []byte(commContent), 0600); err != nil {
		_ = os.WriteFile("test_client_commercial_dossier.html", []byte(commContent), 0600)
	}

	// Assertions for Standard HTML
	t.Run("StandardHTML_Requirements", func(t *testing.T) {
		// Pure black dark theme token (#000000)
		if !strings.Contains(htmlContent, "--bg-canvas: #000000;") {
			t.Errorf("Standard HTML missing pure black #000000 dark mode canvas token")
		}

		// Precision score card with horizontal meter track
		if !strings.Contains(htmlContent, "score-card") || !strings.Contains(htmlContent, "score-meter-track") || !strings.Contains(htmlContent, "score-meter-fill") {
			t.Errorf("Standard HTML missing precision score card elements")
		}
		if !strings.Contains(htmlContent, `score-val color-`) {
			t.Errorf("Standard HTML missing required score-val color marker")
		}

		// Light and Dark theme tokens
		if !strings.Contains(htmlContent, `data-theme="dark"`) || !strings.Contains(htmlContent, `data-theme="light"`) {
			t.Errorf("Standard HTML missing explicit light/dark theme CSS token definitions")
		}

		// Export PDF button and function
		if !strings.Contains(htmlContent, "exportPDF") || !strings.Contains(htmlContent, "Export PDF") {
			t.Errorf("Standard HTML missing Export PDF button or exportPDF() function")
		}

		// Zero emoji verification
		forbiddenEmojis := []string{"🌓", "✓", "📋", "▾", "🛡"}
		for _, em := range forbiddenEmojis {
			if strings.Contains(htmlContent, em) {
				t.Errorf("Standard HTML contains forbidden decorative emoji %q", em)
			}
		}

		// Theme toggle button and JavaScript
		if !strings.Contains(htmlContent, "themeToggleBtn") || !strings.Contains(htmlContent, "toggleTheme") {
			t.Errorf("Standard HTML missing interactive theme toggle controls")
		}

		// Expandable details cards
		if !strings.Contains(htmlContent, "<details") || !strings.Contains(htmlContent, "<summary") {
			t.Errorf("Standard HTML missing expandable <details>/<summary> finding card structure")
		}

		// Dedicated Defensive Boundaries section
		if !strings.Contains(htmlContent, "Defensive Boundaries & Verified Controls") {
			t.Errorf("Standard HTML missing dedicated Defensive Boundaries section")
		}
		if !strings.Contains(htmlContent, "Amazon S3") && !strings.Contains(htmlContent, "S3-PERM-05") {
			t.Errorf("Standard HTML missing verified defensive control record")
		}

		// Attack Path visual flow
		if !strings.Contains(htmlContent, "attack-flow-diagram") || !strings.Contains(htmlContent, "ENTRY POINT") {
			t.Errorf("Standard HTML missing visual attack path diagram elements")
		}

		// Sanitized evidence copy button
		if !strings.Contains(htmlContent, "copy-btn") || !strings.Contains(htmlContent, "copyEvidence") {
			t.Errorf("Standard HTML missing client evidence copy button")
		}

		// Zero external CDNs (strict offline compliance)
		if strings.Contains(htmlContent, "https://cdn") || strings.Contains(htmlContent, "https://fonts.googleapis") || strings.Contains(htmlContent, "https://unpkg") {
			t.Errorf("Standard HTML contains unauthorized external CDN or Google Fonts link")
		}

		// Print media stylesheet
		if !strings.Contains(htmlContent, "@media print") {
			t.Errorf("Standard HTML missing @media print rules")
		}
	})

	// Assertions for Commercial HTML
	t.Run("CommercialHTML_Requirements", func(t *testing.T) {
		// Pure black dark theme token (#000000)
		if !strings.Contains(commContent, "--bg-canvas: #000000;") {
			t.Errorf("Commercial HTML missing pure black #000000 dark mode canvas token")
		}

		// Precision score card with score-val marker
		if !strings.Contains(commContent, "score-card") || !strings.Contains(commContent, "score-val color-") {
			t.Errorf("Commercial HTML missing precision score card elements")
		}

		// Export PDF button and function
		if !strings.Contains(commContent, "exportPDF") || !strings.Contains(commContent, "Export PDF") {
			t.Errorf("Commercial HTML missing Export PDF button or exportPDF() function")
		}

		// Zero emoji verification
		forbiddenEmojis := []string{"🌓", "✓", "📋", "▾", "🛡"}
		for _, em := range forbiddenEmojis {
			if strings.Contains(commContent, em) {
				t.Errorf("Commercial HTML contains forbidden decorative emoji %q", em)
			}
		}

		if !strings.Contains(commContent, "themeToggleBtn") || !strings.Contains(commContent, "toggleTheme") {
			t.Errorf("Commercial HTML missing theme toggle controls")
		}
		if !strings.Contains(commContent, "1. Executive Summary") || !strings.Contains(commContent, "8. Technical Appendix") {
			t.Errorf("Commercial HTML missing canonical 8-section report structure")
		}
		if !strings.Contains(commContent, "<details") || !strings.Contains(commContent, "<summary") {
			t.Errorf("Commercial HTML missing expandable finding cards")
		}
		if strings.Contains(commContent, "https://cdn") || strings.Contains(commContent, "https://fonts.googleapis") {
			t.Errorf("Commercial HTML contains unauthorized external CDN calls")
		}
	})
}
