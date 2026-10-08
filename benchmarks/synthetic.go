package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"felix/pkg/api"
	"felix/pkg/cloud"
	"felix/pkg/crawler"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

// runSyntheticBenchmark runs the deterministic certification test against a local synthetic test server.
func runSyntheticBenchmark(repoRoot string, expected TargetExpected) (TargetResult, error) {
	start := time.Now()

	// 1. Load Fixture Contents
	tpSecrets, err := os.ReadFile(filepath.Join(repoRoot, "benchmarks", "fixtures", "secrets", "true_positives.js"))
	if err != nil {
		return TargetResult{}, fmt.Errorf("failed to read true_positives.js: %w", err)
	}

	fpSecrets, err := os.ReadFile(filepath.Join(repoRoot, "benchmarks", "fixtures", "secrets", "false_positives.js"))
	if err != nil {
		return TargetResult{}, fmt.Errorf("failed to read false_positives.js: %w", err)
	}

	mockConfigs, err := os.ReadFile(filepath.Join(repoRoot, "benchmarks", "fixtures", "cloud", "mock_configs.js"))
	if err != nil {
		return TargetResult{}, fmt.Errorf("failed to read mock_configs.js: %w", err)
	}

	spaApp, err := os.ReadFile(filepath.Join(repoRoot, "benchmarks", "fixtures", "spa", "app.js"))
	if err != nil {
		return TargetResult{}, fmt.Errorf("failed to read spa/app.js: %w", err)
	}

	// 2. Setup Ephemeral Synthetic HTTP Server
	var requestCount int32
	var serviceRoleProbes int32
	var destructiveProbes int32

	bundleContent := string(tpSecrets) + "\n\n" + string(fpSecrets) + "\n\n" + string(mockConfigs) + "\n\n" + string(spaApp) + "\n//# sourceMappingURL=/bundle.js.map\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)

		// Guard: Verify no destructive methods
		if r.Method == "DELETE" || r.Method == "PUT" || r.Method == "PATCH" {
			atomic.AddInt32(&destructiveProbes, 1)
		}

		// Guard: Verify no service_role token transmission
		authHeader := r.Header.Get("Authorization")
		if strings.Contains(authHeader, "service_role") || strings.Contains(authHeader, "mock_service_role") {
			atomic.AddInt32(&serviceRoleProbes, 1)
		}

		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			// Deliberately omit CSP, HSTS, X-Content-Type-Options to trigger security header checks
			fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head>
  <title>Felix Synthetic Certification Suite</title>
  <link rel="stylesheet" href="/styles.css">
  <link rel="manifest" href="/site.webmanifest">
</head>
<body>
  <h1>Felix Synthetic Benchmark Environment</h1>
  <script src="/bundle.js"></script>
</body>
</html>`)

		case "/bundle.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, bundleContent)

		case "/styles.css":
			w.Header().Set("Content-Type", "text/css")
			fmt.Fprint(w, "body { background: rgba(255, 255, 255, 0.85); color: #2f8a9c; }")

		case "/site.webmanifest":
			w.Header().Set("Content-Type", "application/manifest+json")
			fmt.Fprint(w, `{"name": "Synthetic App", "short_name": "Synthetic", "start_url": "/"}`)

		case "/bundle.js.map":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"version": 3, "file": "bundle.js", "sources": ["app.ts"], "mappings": "AAAA"}`)

		case "/.env":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "DATABASE_URL=postgres://app_user:secret_password@db.internal:5432/app\nAPI_SECRET=production_secret_key\n")

		case "/.git/HEAD":
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "ref: refs/heads/main\n")

		case "/graphql":
			w.Header().Set("Content-Type", "application/json")
			if r.Method == http.MethodPost {
				bodyBytes, _ := io.ReadAll(r.Body)
				if strings.Contains(string(bodyBytes), "__schema") || strings.Contains(string(bodyBytes), "IntrospectionQuery") {
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, `{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User"},{"name":"Auth"}]}}}`)
					return
				}
			}
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"errors":[{"message":"query required"}]}`)

		case "/api/profile":
			w.Header().Set("Content-Type", "application/json")
			origin := r.Header.Get("Origin")
			if origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"user": "admin", "email": "admin@example.corp"}`)

		case "/api/public":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"public": true, "version": "1.0.0"}`)

		case "/api/v1/admin":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error": "Access denied"}`)

		case "/rest/v1/exposed_users":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `[{"id": 1, "username": "admin", "role": "superuser"}]`)

		case "/rest/v1/protected_vault":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"message": "JWT expired or missing"}`)

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	// 3. Execute Felix Pipeline on Synthetic Server
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	crawlCfg := crawler.Config{
		Concurrency:  5,
		Timeout:      5 * time.Second,
		MaxAssetSize: 10 * 1024 * 1024,
		MaxAssets:    20,
		ScopeMode:    crawler.ScopeSameOrigin,
		UserAgent:    "Felix-Benchmark-Suite/1.0",
		Client:       server.Client(),
	}
	c := crawler.New(crawlCfg)

	resChan := c.CrawlConcurrently(ctx, []string{server.URL})
	var crawlResult crawler.Result
	for cr := range resChan {
		crawlResult = cr
	}

	if crawlResult.Err != nil {
		return TargetResult{}, fmt.Errorf("synthetic crawl failed: %w", crawlResult.Err)
	}

	// 4. Run Security Engines
	secDetector := secrets.NewDetector()
	secretFindings := secDetector.ScanAssets(crawlResult.Assets)

	// Run False-Positive Secret Scan directly on FP fixture to confirm 0 findings
	fpOnlyFindings := secDetector.ScanContent("false_positives.js", fpSecrets)

	cloudClient := cloud.NewClient(cloud.ClientOptions{HTTPClient: server.Client()})
	cloudAuditor := cloud.NewDetector(cloudClient)
	cloudResult := cloudAuditor.Audit(ctx, crawlResult.Assets, secretFindings)

	// Direct audit on mock cloud endpoints to certify verification status
	supabaseSvc := cloud.Service{
		Provider: cloud.ProviderSupabase,
		URL:      server.URL,
	}
	directSupabaseFindings := cloud.AuditSupabase(ctx, cloudClient, supabaseSvc, []string{"/rest/v1/exposed_users", "/rest/v1/protected_vault"}, "mock-anon-key", "")

	apiClient := api.NewClient(api.ClientOptions{HTTPClient: server.Client()})
	apiAuditor := api.NewDetector(apiClient)
	apiResult := apiAuditor.Audit(ctx, server.URL, crawlResult.Assets)

	// 5. Aggregate Unified Report
	var allReportFindings []report.Finding
	for _, a := range crawlResult.Assets {
		if f, ok := report.FromCrawlerAsset(server.URL, a); ok {
			allReportFindings = append(allReportFindings, f)
		}
	}
	for _, f := range secretFindings {
		allReportFindings = append(allReportFindings, report.FromSecretFinding(server.URL, f))
	}
	for _, f := range cloudResult.Findings {
		allReportFindings = append(allReportFindings, report.FromCloudFinding(server.URL, f))
	}
	for _, f := range directSupabaseFindings {
		allReportFindings = append(allReportFindings, report.FromCloudFinding(server.URL, f))
	}
	for _, f := range apiResult.Findings {
		allReportFindings = append(allReportFindings, report.FromAPIFinding(server.URL, f))
	}

	rep := report.BuildReport(server.URL, allReportFindings)
	elapsed := time.Since(start)
	rep.Duration = elapsed.Round(time.Millisecond).String()
	rep.DurationMs = elapsed.Milliseconds()
	rep.RequestCount = int(atomic.LoadInt32(&requestCount))

	// 6. Evaluate Hard Assertions
	var assertionDetails []AssertionResult
	var regressions []string
	var warnings []string
	assertionsPassed := 0
	assertionsFailed := 0
	falsePositives := len(fpOnlyFindings)
	falseNegatives := 0

	for _, ha := range expected.HardAssertions {
		passed := false
		detail := ""

		switch ha.Category {
		case "secrets":
			for _, f := range rep.Findings {
				if f.Source == report.SourceSecrets && strings.Contains(f.Title, ha.Pattern) {
					passed = true
					if ha.ExpectedSeverity != "" && f.Severity != ha.ExpectedSeverity {
						passed = false
						detail = fmt.Sprintf("severity mismatch: expected %s, got %s", ha.ExpectedSeverity, f.Severity)
					}
					if ha.ExpectedVerification != "" && string(f.Verification.Status) != ha.ExpectedVerification {
						passed = false
						detail = fmt.Sprintf("verification mismatch: expected %s, got %s", ha.ExpectedVerification, f.Verification.Status)
					}
					break
				}
			}
			if !passed && detail == "" {
				detail = fmt.Sprintf("secret pattern %q not found in findings", ha.Pattern)
				falseNegatives++
			}

		case "false_positive":
			if ha.ExpectedFalsePositives != nil {
				if falsePositives == *ha.ExpectedFalsePositives {
					passed = true
				} else {
					detail = fmt.Sprintf("expected %d false positives, got %d", *ha.ExpectedFalsePositives, falsePositives)
				}
			}

		case "api":
			if ha.EndpointContains != "" {
				for _, f := range rep.Findings {
					if strings.Contains(f.Endpoint, ha.EndpointContains) {
						if ha.ExpectedVerification != "" {
							if string(f.Verification.Status) == ha.ExpectedVerification {
								passed = true
								detail = ""
								break
							} else {
								detail = fmt.Sprintf("verification mismatch for %s: expected %s, got %s", ha.EndpointContains, ha.ExpectedVerification, f.Verification.Status)
							}
						} else if ha.MustNotVerifyCredentials {
							if f.Verification.Status != report.VerificationVerified {
								passed = true
								detail = ""
								break
							} else {
								detail = "wildcard CORS was unexpectedly verified as credentials exposure"
							}
						}
					}
				}
			}
			if !passed && detail == "" {
				detail = fmt.Sprintf("API expectation for %s not met", ha.EndpointContains)
			}

		case "cloud":
			if ha.EndpointContains != "" {
				for _, f := range rep.Findings {
					if f.Source == report.SourceCloud && strings.Contains(f.Endpoint, ha.EndpointContains) {
						if ha.ExpectedVerification != "" && string(f.Verification.Status) == ha.ExpectedVerification {
							passed = true
							break
						}
					}
				}
			}
			if !passed && detail == "" {
				detail = fmt.Sprintf("cloud finding for %s not verified", ha.EndpointContains)
			}

		case "safety":
			if ha.DestructiveMethodsUsed != nil && int(atomic.LoadInt32(&destructiveProbes)) <= *ha.DestructiveMethodsUsed &&
				int(atomic.LoadInt32(&serviceRoleProbes)) == 0 {
				passed = true
			} else {
				detail = fmt.Sprintf("safety violation: destructive=%d, service_role_probes=%d", atomic.LoadInt32(&destructiveProbes), atomic.LoadInt32(&serviceRoleProbes))
			}
		}

		if passed {
			assertionsPassed++
		} else {
			assertionsFailed++
			regressions = append(regressions, fmt.Sprintf("[%s] %s: %s", ha.ID, ha.Description, detail))
		}

		assertionDetails = append(assertionDetails, AssertionResult{
			AssertionID: ha.ID,
			Category:    ha.Category,
			Passed:      passed,
			Description: ha.Description,
			Details:     detail,
		})
	}

	// 7. Evaluate Behavioral Bounds
	bounds := expected.BehavioralBounds
	boundsChecked := 0
	boundsPassed := 0

	if bounds.Requests.Max > 0 {
		boundsChecked++
		if rep.RequestCount <= bounds.Requests.Max {
			boundsPassed++
		} else {
			warnings = append(warnings, fmt.Sprintf("requests exceeded max bound: %d > %d", rep.RequestCount, bounds.Requests.Max))
		}
	}
	if bounds.DurationMs.Max > 0 {
		boundsChecked++
		if rep.DurationMs <= int64(bounds.DurationMs.Max) {
			boundsPassed++
		} else {
			warnings = append(warnings, fmt.Sprintf("duration exceeded max bound: %dms > %dms", rep.DurationMs, bounds.DurationMs.Max))
		}
	}
	if bounds.Assets.Max > 0 {
		boundsChecked++
		if len(crawlResult.Assets) <= bounds.Assets.Max {
			boundsPassed++
		} else {
			warnings = append(warnings, fmt.Sprintf("assets exceeded max bound: %d > %d", len(crawlResult.Assets), bounds.Assets.Max))
		}
	}

	// Determine overall status
	status := "PASS"
	if len(regressions) > 0 || falsePositives > 0 || falseNegatives > 0 {
		status = "REGRESSION"
	} else if len(warnings) > 0 {
		status = "WARNING"
	}

	return TargetResult{
		Name:             expected.Name,
		TargetID:         expected.TargetID,
		URL:              server.URL,
		BenchmarkType:    "DETERMINISTIC",
		Status:           status,
		DurationMs:       rep.DurationMs,
		Duration:         rep.Duration,
		Requests:         rep.RequestCount,
		Assets:           len(crawlResult.Assets),
		Endpoints:        apiResult.EndpointsScanned,
		Findings:         len(rep.Findings),
		VerifiedCount:    rep.Summary.VerifiedCount,
		DetectedCount:    rep.Summary.DetectedCount,
		ObservedCount:    rep.Summary.ObservedCount,
		NotVerifiedCount: rep.Summary.NotVerifiedCount,
		NotExposedCount:  rep.Summary.NotExposedCount,
		RiskScore:        rep.RiskScore,
		RiskLevel:        rep.RiskLevel,
		AssertionsPassed: assertionsPassed,
		AssertionsFailed: assertionsFailed,
		FalsePositives:   falsePositives,
		FalseNegatives:   falseNegatives,
		BoundsChecked:    boundsChecked,
		BoundsPassed:     boundsPassed,
		Regressions:      regressions,
		Warnings:         warnings,
		AssertionDetails: assertionDetails,
	}, nil
}
