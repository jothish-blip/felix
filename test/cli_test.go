package test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"felix/pkg/report"
)

// getFelixBinPath locates or builds the felix executable for tests.
func getFelixBinPath(t *testing.T) string {
	root := findRepoRoot()
	binName := "felix"
	if os.PathSeparator == '\\' {
		binName = "felix.exe"
	}
	binPath := filepath.Join(root, "bin", binName)

	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		// Build binary
		cmd := exec.Command("go", "build", "-o", binPath, filepath.Join(root, "cmd", "felix"))
		cmd.Env = os.Environ()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Failed to build felix binary: %v, output: %s", err, string(out))
		}
	}
	return binPath
}

// runFelix executes the compiled binary with arguments.
func runFelix(t *testing.T, args ...string) (string, int) {
	binPath := getFelixBinPath(t)
	cmd := exec.Command(binPath, args...)
	cmd.Env = os.Environ()
	outBytes, err := cmd.CombinedOutput()
	out := string(outBytes)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return out, exitErr.ExitCode()
		}
		return out, -1
	}
	return out, 0
}

func TestCLI_Version(t *testing.T) {
	out, code := runFelix(t, "version")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, output: %s", code, out)
	}
	if !strings.Contains(out, "Felix Security Auditor") {
		t.Errorf("expected version output to contain 'Felix Security Auditor', got: %s", out)
	}
	if !strings.Contains(out, "1.0.0") {
		t.Errorf("expected version output to contain '1.0.0', got: %s", out)
	}
}

func TestCLI_Doctor(t *testing.T) {
	out, code := runFelix(t, "doctor")
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d, output: %s", code, out)
	}
	if !strings.Contains(out, "Executable Integrity") {
		t.Errorf("expected doctor output to include Executable Integrity, got: %s", out)
	}
	if !strings.Contains(out, "Runtime Environment") {
		t.Errorf("expected doctor output to include Runtime Environment, got: %s", out)
	}
}

func TestCLI_Config(t *testing.T) {
	// 1. Show config
	out, code := runFelix(t, "config", "show")
	if code != 0 {
		t.Fatalf("expected exit code 0 for config show, got %d, out: %s", code, out)
	}
	if !strings.Contains(out, "timeout:") {
		t.Errorf("expected config show to contain 'timeout:', got: %s", out)
	}

	// 2. Get specific key
	out, code = runFelix(t, "config", "get", "timeout")
	if code != 0 {
		t.Fatalf("expected exit code 0 for config get timeout, got %d, out: %s", code, out)
	}

	// 3. Set key
	out, code = runFelix(t, "config", "set", "timeout", "25")
	if code != 0 {
		t.Fatalf("expected exit code 0 for config set, got %d, out: %s", code, out)
	}

	// 4. Verify new value
	out, code = runFelix(t, "config", "get", "timeout")
	if code != 0 || !strings.Contains(out, "25") {
		t.Fatalf("expected timeout to be 25, got %d, out: %s", code, out)
	}

	// 5. Reset key
	out, code = runFelix(t, "config", "reset", "timeout")
	if code != 0 {
		t.Fatalf("expected exit code 0 for config reset, got %d, out: %s", code, out)
	}

	// 6. Verify restored default
	out, code = runFelix(t, "config", "get", "timeout")
	if code != 0 || !strings.Contains(out, "10") {
		t.Fatalf("expected timeout to reset to 10, got %d, out: %s", code, out)
	}
}

func TestCLI_Completion(t *testing.T) {
	shells := []string{"bash", "zsh", "fish", "powershell"}
	for _, sh := range shells {
		out, code := runFelix(t, "completion", sh)
		if code != 0 {
			t.Errorf("expected exit code 0 for completion %s, got %d", sh, code)
		}
		if len(out) < 20 {
			t.Errorf("expected non-empty completion script for %s, got %d chars", sh, len(out))
		}
	}
}

func TestCLI_ReportZeroNetwork(t *testing.T) {
	// Set up an HTTP test server to track if any network request is attempted
	var requestCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Create a mock scan result pointing to the test server
	cleanReport := report.Report{
		Version:   "1.0.0",
		Target:    ts.URL,
		Timestamp: "2026-10-08T12:00:00Z",
		RiskScore: 0,
		RiskLevel: "CLEAN",
		Summary: report.Summary{
			TotalFindings: 0,
			InfoCount:     0,
		},
		Findings: []report.Finding{},
	}

	tmpDir := t.TempDir()
	scanJSONPath := filepath.Join(tmpDir, "scan_result.json")
	htmlReportPath := filepath.Join(tmpDir, "report.html")
	jsonReportPath := filepath.Join(tmpDir, "report.json")

	data, err := json.MarshalIndent(cleanReport, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal clean report: %v", err)
	}
	if err := os.WriteFile(scanJSONPath, data, 0644); err != nil {
		t.Fatalf("failed to write scan result: %v", err)
	}

	// Run felix report with the saved JSON
	out, code := runFelix(t, "report", scanJSONPath, "--html", htmlReportPath, "--json", jsonReportPath)
	if code != 0 {
		t.Fatalf("expected exit code 0 for clean report, got %d, out: %s", code, out)
	}

	// ASSERTION: ZERO network requests must have been made to the test server!
	if atomic.LoadInt32(&requestCount) != 0 {
		t.Fatalf("ZERO network requests expected during felix report, but %d requests were received!", requestCount)
	}

	// Validate exported HTML
	htmlBytes, err := os.ReadFile(htmlReportPath)
	if err != nil {
		t.Fatalf("failed to read generated HTML report: %v", err)
	}
	htmlContent := string(htmlBytes)

	// Strict black mode assertion
	if !strings.Contains(htmlContent, "#000000") {
		t.Errorf("HTML report must contain strict black foundation #000000")
	}

	// No internal engine numbering
	if strings.Contains(htmlContent, "Engine 1") || strings.Contains(htmlContent, "Engine 2") ||
		strings.Contains(htmlContent, "Engine 3") || strings.Contains(htmlContent, "Engine 4") ||
		strings.Contains(htmlContent, "Engine 5") {
		t.Errorf("HTML report must not expose internal Engine numbers")
	}

	// Validate exported JSON
	jsonBytes, err := os.ReadFile(jsonReportPath)
	if err != nil {
		t.Fatalf("failed to read generated JSON report: %v", err)
	}
	var loadedRep report.Report
	if err := json.Unmarshal(jsonBytes, &loadedRep); err != nil {
		t.Fatalf("failed to unmarshal exported JSON: %v", err)
	}
	if loadedRep.Target != ts.URL {
		t.Errorf("expected target %s, got %s", ts.URL, loadedRep.Target)
	}
}

func TestCLI_ReportExitCodes(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Report with actionable findings (LOW) -> Exit code 1
	actionableReport := report.Report{
		Version:   "1.0.0",
		Target:    "https://example.com",
		Timestamp: "2026-10-08T12:00:00Z",
		RiskScore: 20,
		RiskLevel: "LOW",
		Summary: report.Summary{
			TotalFindings: 1,
			LowCount:      1,
		},
		Findings: []report.Finding{
			{
				ID:          "find-1",
				Title:       "Missing Security Header",
				Severity:    "LOW",
				Category:    "Headers",
				Confidence:  "HIGH",
				Description: "CSP header is missing.",
				Verification: report.VerificationRecord{
					Status: report.VerificationVerified,
				},
			},
		},
	}
	actionablePath := filepath.Join(tmpDir, "actionable.json")
	actData, _ := json.Marshal(actionableReport)
	os.WriteFile(actionablePath, actData, 0644)

	_, code := runFelix(t, "report", actionablePath)
	if code != 1 {
		t.Errorf("expected exit code 1 for actionable findings, got %d", code)
	}

	// 2. Report with only INFO findings -> Exit code 0
	infoReport := report.Report{
		Version:   "1.0.0",
		Target:    "https://example.com",
		Timestamp: "2026-10-08T12:00:00Z",
		RiskScore: 0,
		RiskLevel: "CLEAN",
		Summary: report.Summary{
			TotalFindings: 1,
			InfoCount:     1,
		},
		Findings: []report.Finding{
			{
				ID:          "info-1",
				Title:       "Informational Finding",
				Severity:    "INFO",
				Category:    "Discovery",
				Confidence:  "HIGH",
				Description: "Standard client script detected.",
			},
		},
	}
	infoPath := filepath.Join(tmpDir, "info.json")
	infoData, _ := json.Marshal(infoReport)
	os.WriteFile(infoPath, infoData, 0644)

	_, code = runFelix(t, "report", infoPath)
	if code != 0 {
		t.Errorf("expected exit code 0 for info-only findings, got %d", code)
	}

	// 3. Non-existent file -> Exit code 2
	_, code = runFelix(t, "report", filepath.Join(tmpDir, "non_existent.json"))
	if code != 2 {
		t.Errorf("expected exit code 2 for missing file, got %d", code)
	}

	// 4. Missing required args -> Exit code 2
	_, code = runFelix(t, "report")
	if code != 2 {
		t.Errorf("expected exit code 2 for missing args, got %d", code)
	}
}

func TestCLI_ScanAndReportDecoupled(t *testing.T) {
	// Spin up local test HTTP server serving a test asset
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!DOCTYPE html><html><head><script src="/bundle.js"></script></head><body>Felix Test</body></html>`)
		case "/bundle.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `console.log("Felix client app"); const apiUrl = "/api/v1/users";`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	tmpDir := t.TempDir()
	outJSON := filepath.Join(tmpDir, "scan_result.json")
	outHTML := filepath.Join(tmpDir, "scan_result.html")

	// 1. Run single scan saving scan result and HTML
	out, code := runFelix(t, "scan", ts.URL, "--out", outJSON, "--html", outHTML)
	// Check that scan finished (code is 0 or 1 depending on security header findings)
	if code == 2 {
		t.Fatalf("scan failed with runtime error (code 2), out: %s", out)
	}

	// Terminal output must not contain "ENGINE 1", "ENGINE 2", etc.
	if strings.Contains(out, "ENGINE 1") || strings.Contains(out, "ENGINE 2") {
		t.Errorf("scan terminal output must not contain ENGINE 1/2, got: %s", out)
	}

	// Verify scan result file was written
	if _, err := os.Stat(outJSON); os.IsNotExist(err) {
		t.Fatalf("scan result file was not created: %s", outJSON)
	}
	if _, err := os.Stat(outHTML); os.IsNotExist(err) {
		t.Fatalf("HTML report was not created: %s", outHTML)
	}

	// 2. Run felix report consuming that scan result (zero network rescans)
	reloadedHTML := filepath.Join(tmpDir, "reloaded.html")
	repOut, repCode := runFelix(t, "report", outJSON, "--html", reloadedHTML)
	if repCode != code {
		t.Errorf("expected report exit code %d to match scan exit code %d, got %d", code, code, repCode)
	}
	if _, err := os.Stat(reloadedHTML); os.IsNotExist(err) {
		t.Fatalf("reloaded HTML report was not created from scan result: %s", reloadedHTML)
	}
	_ = repOut
}

func TestCLI_TimeoutControl(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<!DOCTYPE html><html><body>OK</body></html>`)
	}))
	defer ts.Close()

	// 1. Valid timeout syntax (10s, 1m)
	_, code := runFelix(t, "scan", ts.URL, "--timeout", "5s")
	if code == 2 {
		t.Errorf("expected timeout 5s to be accepted, got code: %d", code)
	}
	_, code = runFelix(t, "scan", ts.URL, "--timeout", "1m")
	if code == 2 {
		t.Errorf("expected timeout 1m to be accepted, got code: %d", code)
	}

	// 2. Invalid timeout values (0, negative, invalid string) -> must exit 2
	invalidTimeouts := []string{"0", "0s", "-5s", "abc"}
	for _, inv := range invalidTimeouts {
		out, errCode := runFelix(t, "scan", ts.URL, "--timeout", inv)
		if errCode != 2 {
			t.Errorf("expected invalid timeout %q to exit with code 2, got %d (out: %s)", inv, errCode, out)
		}
	}
}

func TestCLI_ConcurrencyControl(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<!DOCTYPE html><html><body>OK</body></html>`)
	}))
	defer ts.Close()

	// 1. Valid concurrency
	_, code := runFelix(t, "scan", ts.URL, "--concurrency", "4")
	if code == 2 {
		t.Errorf("expected concurrency 4 to be accepted, got code: %d", code)
	}

	// 2. Zero and negative concurrency -> must exit 2
	invalidConcurrencies := []string{"0", "-1", "-10", "abc"}
	for _, inv := range invalidConcurrencies {
		out, errCode := runFelix(t, "scan", ts.URL, "--concurrency", inv)
		if errCode != 2 {
			t.Errorf("expected invalid concurrency %q to exit with code 2, got %d (out: %s)", inv, errCode, out)
		}
	}
}

func TestCLI_ScopeControl(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<!DOCTYPE html><html><body>OK</body></html>`)
	}))
	defer ts.Close()

	// 1. Valid scope modes
	validScopes := []string{"same-origin", "subdomains", "explicit"}
	for _, sc := range validScopes {
		_, code := runFelix(t, "scan", ts.URL, "--scope", sc)
		if code == 2 {
			t.Errorf("expected valid scope %q to be accepted, got code: %d", sc, code)
		}
	}

	// 2. Invalid scope values -> must exit 2
	invalidScopes := []string{"global", "any", "unrestricted", "invalid"}
	for _, inv := range invalidScopes {
		out, errCode := runFelix(t, "scan", ts.URL, "--scope", inv)
		if errCode != 2 {
			t.Errorf("expected invalid scope %q to exit with code 2, got %d (out: %s)", inv, errCode, out)
		}
	}
}

func TestCLI_MaxAssetsControl(t *testing.T) {
	// Mock server serving HTML that links to 5 distinct scripts
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!DOCTYPE html><html><head>
				<script src="/s1.js"></script>
				<script src="/s2.js"></script>
				<script src="/s3.js"></script>
				<script src="/s4.js"></script>
				<script src="/s5.js"></script>
			</head><body>Test</body></html>`)
		default:
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `console.log("script");`)
		}
	}))
	defer ts.Close()

	// 1. Invalid values -> must exit 2
	invalidValues := []string{"0", "-1", "-5", "abc"}
	for _, inv := range invalidValues {
		out, errCode := runFelix(t, "scan", ts.URL, "--max-assets", inv)
		if errCode != 2 {
			t.Errorf("expected invalid max-assets %q to exit 2, got %d (out: %s)", inv, errCode, out)
		}
	}

	// 2. Enforcement verification: limit to 2 assets
	tmpDir := t.TempDir()
	outJSON := filepath.Join(tmpDir, "max_assets.json")
	_, code := runFelix(t, "scan", ts.URL, "--max-assets", "2", "--json", outJSON)
	if code == 2 {
		t.Fatalf("scan failed with code 2")
	}

	// Verify loaded result contains at most 2 assets
	data, err := os.ReadFile(outJSON)
	if err != nil {
		t.Fatalf("failed to read json result: %v", err)
	}
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("failed to unmarshal report: %v", err)
	}
	// Asset discovery count in report metadata or findings
	assetCount := 0
	for _, f := range rep.Findings {
		if f.Category == "asset" || f.Source == "crawler" {
			assetCount++
		}
	}
	if assetCount > 2 {
		t.Errorf("expected max-assets enforcement <= 2, got %d crawler assets", assetCount)
	}
}

func TestCLI_MaxResponseSizeControl(t *testing.T) {
	// Mock server serving 500KB script
	largePayload := strings.Repeat("x", 500*1024)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<!DOCTYPE html><html><head><script src="/large.js"></script></head><body>Test</body></html>`)
		case "/large.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, largePayload)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	// 1. Invalid size syntax -> must exit 2
	invalidSizes := []string{"0", "0MB", "-5MB", "abc"}
	for _, inv := range invalidSizes {
		out, errCode := runFelix(t, "scan", ts.URL, "--max-response-size", inv)
		if errCode != 2 {
			t.Errorf("expected invalid max-response-size %q to exit 2, got %d (out: %s)", inv, errCode, out)
		}
	}

	// 2. Enforcement: allow up to 100KB -> 500KB asset exceeds limit and is rejected / skipped
	tmpDir := t.TempDir()
	outJSON := filepath.Join(tmpDir, "size_test.json")
	_, code := runFelix(t, "scan", ts.URL, "--max-response-size", "100KB", "--json", outJSON)
	if code == 2 {
		t.Fatalf("scan failed with code 2")
	}

	data, err := os.ReadFile(outJSON)
	if err != nil {
		t.Fatalf("failed to read json result: %v", err)
	}
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("failed to unmarshal report: %v", err)
	}
	// The 500KB asset must NOT have been downloaded successfully into full inventory content
	for _, f := range rep.Findings {
		if strings.Contains(f.Endpoint, "/large.js") && strings.Contains(f.Evidence, largePayload) {
			t.Errorf("large asset content should not be present when max-response-size is 100KB")
		}
	}
}

func TestCLI_ExportControl(t *testing.T) {
	var requestCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body>Export Test</body></html>`)
	}))
	defer ts.Close()

	tmpDir := t.TempDir()
	exportPath := filepath.Join(tmpDir, "canonical_export.html")

	// Canonical syntax: felix scan <target> --export report.html
	out, code := runFelix(t, "scan", ts.URL, "--export", exportPath)
	if code == 2 {
		t.Fatalf("scan failed with code 2, out: %s", out)
	}

	// Must generate the requested HTML report
	if _, err := os.Stat(exportPath); os.IsNotExist(err) {
		t.Fatalf("expected --export to generate %s", exportPath)
	}

	htmlData, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatalf("failed to read exported HTML: %v", err)
	}
	if !strings.Contains(string(htmlData), "#000000") {
		t.Errorf("expected HTML report to have #000000 background")
	}
}

func TestCLI_JSONControl(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body>JSON Test</body></html>`)
	}))
	defer ts.Close()

	tmpDir := t.TempDir()

	// 1. felix scan target --json <file.json>
	customJSON := filepath.Join(tmpDir, "custom.json")
	_, code := runFelix(t, "scan", ts.URL, "--json", customJSON)
	if code == 2 {
		t.Fatalf("scan failed with code 2")
	}
	if _, err := os.Stat(customJSON); os.IsNotExist(err) {
		t.Fatalf("expected custom JSON file %s to be created", customJSON)
	}

	// 2. felix scan target --json (bare flag)
	defer os.Remove("scan-result.json")
	out, code := runFelix(t, "scan", ts.URL, "--json")
	if code == 2 {
		t.Fatalf("scan failed with code 2 for bare --json, out: %s", out)
	}
	var rep report.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("bare --json stdout must be valid machine-readable JSON: %v, out: %s", err, out)
	}
	if rep.Target != ts.URL {
		t.Errorf("expected target %s, got %s", ts.URL, rep.Target)
	}
}

func TestCLI_QuietControl(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body>Quiet Test</body></html>`)
	}))
	defer ts.Close()

	tmpDir := t.TempDir()
	outJSON := filepath.Join(tmpDir, "quiet_result.json")

	// --quiet should suppress human progress and banners
	out, code := runFelix(t, "scan", ts.URL, "--quiet", "--json", outJSON)
	if code == 2 {
		t.Fatalf("scan failed with code 2 in quiet mode")
	}

	// Terminal output should be minimal/empty
	if strings.Contains(out, "ASSET DISCOVERY") || strings.Contains(out, "FELIX ::") {
		t.Errorf("quiet mode must suppress banners and stage milestones, got: %s", out)
	}

	// File must still be generated cleanly
	if _, err := os.Stat(outJSON); os.IsNotExist(err) {
		t.Fatalf("quiet mode must still generate requested export file")
	}
}

func TestCLI_VerboseControl(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body>Verbose Test</body></html>`)
	}))
	defer ts.Close()

	out, code := runFelix(t, "scan", ts.URL, "--verbose")
	if code == 2 {
		t.Fatalf("scan failed with code 2 in verbose mode")
	}

	if !strings.Contains(out, "Active Scan Configuration") {
		t.Errorf("verbose mode must display operational configuration, out: %s", out)
	}
	if !strings.Contains(out, "Concurrency:") || !strings.Contains(out, "Timeout:") {
		t.Errorf("verbose mode must display timeout and concurrency settings")
	}
}

func TestCLI_Conflicts(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `OK`)
	}))
	defer ts.Close()

	// --quiet and --verbose cannot be used together -> exit 2
	out, code := runFelix(t, "scan", ts.URL, "--quiet", "--verbose")
	if code != 2 {
		t.Errorf("expected exit code 2 for conflicting flags --quiet and --verbose, got %d", code)
	}
	if !strings.Contains(out, "--quiet and --verbose cannot be used together") {
		t.Errorf("expected conflict error message, got: %s", out)
	}
}

func TestCLI_ScanReportZeroRescanSeparation(t *testing.T) {
	var requestCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><body>Single Scan Test</body></html>`)
	}))
	defer ts.Close()

	tmpDir := t.TempDir()
	jsonPath := filepath.Join(tmpDir, "scan_single.json")
	htmlPath := filepath.Join(tmpDir, "scan_single.html")

	// 1. Run felix scan: must perform ONE scan pass
	_, scanCode := runFelix(t, "scan", ts.URL, "--json", jsonPath, "--export", htmlPath)
	if scanCode == 2 {
		t.Fatalf("scan failed with code 2")
	}

	initialRequests := atomic.LoadInt32(&requestCount)
	if initialRequests == 0 {
		t.Fatalf("expected initial requests during scan")
	}

	// 2. Run felix report consuming scan_single.json: must perform ZERO network requests!
	reloadedHTML := filepath.Join(tmpDir, "offline.html")
	_, repCode := runFelix(t, "report", jsonPath, "--html", reloadedHTML)
	if repCode != scanCode {
		t.Errorf("expected report code %d to match scan code %d", scanCode, repCode)
	}

	finalRequests := atomic.LoadInt32(&requestCount)
	if finalRequests != initialRequests {
		t.Fatalf("ZERO network requests expected during felix report, but %d additional requests were made!", finalRequests-initialRequests)
	}
}

