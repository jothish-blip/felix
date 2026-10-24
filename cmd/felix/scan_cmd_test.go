package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"felix/pkg/cloud"
	"felix/pkg/config"
	"felix/pkg/crawler"
	"felix/pkg/report"
)

func TestParseTimeout(t *testing.T) {
	tests := []struct {
		input     string
		want      time.Duration
		wantError bool
	}{
		{"10s", 10 * time.Second, false},
		{"30s", 30 * time.Second, false},
		{"1m", 1 * time.Minute, false},
		{"500ms", 500 * time.Millisecond, false},
		{"25", 25 * time.Second, false},
		{" 15s ", 15 * time.Second, false},
		{"0s", 0, true},
		{"-5s", 0, true},
		{"0", 0, true},
		{"-1", 0, true},
		{"", 0, true},
		{"invalid", 0, true},
	}

	for _, tt := range tests {
		got, err := parseTimeout(tt.input)
		if tt.wantError {
			if err == nil {
				t.Errorf("parseTimeout(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("parseTimeout(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("parseTimeout(%q) = %v, want %v", tt.input, got, tt.want)
			}
		}
	}
}

func TestParseResponseSize(t *testing.T) {
	tests := []struct {
		input     string
		want      int64
		wantError bool
	}{
		{"10MB", 10 * 1024 * 1024, false},
		{"10M", 10 * 1024 * 1024, false},
		{"512KB", 512 * 1024, false},
		{"512K", 512 * 1024, false},
		{"1GB", 1024 * 1024 * 1024, false},
		{"1G", 1024 * 1024 * 1024, false},
		{"2048B", 2048, false},
		{"4096", 4096, false},
		{" 5MB ", 5 * 1024 * 1024, false},
		{"0MB", 0, true},
		{"0", 0, true},
		{"-10MB", 0, true},
		{"", 0, true},
		{"invalid_size", 0, true},
	}

	for _, tt := range tests {
		got, err := parseResponseSize(tt.input)
		if tt.wantError {
			if err == nil {
				t.Errorf("parseResponseSize(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("parseResponseSize(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("parseResponseSize(%q) = %d, want %d", tt.input, got, tt.want)
			}
		}
	}
}

func TestValidateScope(t *testing.T) {
	tests := []struct {
		input     string
		want      crawler.ScopeMode
		wantError bool
	}{
		{"same-origin", crawler.ScopeSameOrigin, false},
		{"subdomains", crawler.ScopeSubdomains, false},
		{"explicit", crawler.ScopeExplicit, false},
		{"SAME-ORIGIN", crawler.ScopeSameOrigin, false},
		{"SubDomains", crawler.ScopeSubdomains, false},
		{"", "", true},
		{"open", "", true},
		{"wildcard", "", true},
	}

	for _, tt := range tests {
		got, err := validateScope(tt.input)
		if tt.wantError {
			if err == nil {
				t.Errorf("validateScope(%q) expected error, got nil", tt.input)
			}
		} else {
			if err != nil {
				t.Errorf("validateScope(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("validateScope(%q) = %q, want %q", tt.input, got, tt.want)
			}
		}
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{500, "500B"},
		{1024, "1.0KB"},
		{2048, "2.0KB"},
		{5 * 1024 * 1024, "5.0MB"},
		{2 * 1024 * 1024 * 1024, "2.0GB"},
	}

	for _, tt := range tests {
		got := formatBytes(tt.input)
		if got != tt.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestRunScan_CLIPrecedenceAndValidation(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	// Save custom configuration to disk:
	// Disk config sets timeout=15s, concurrency=25, scope=subdomains
	diskCfg := config.Default()
	diskCfg.Timeout = 15
	diskCfg.Concurrency = 25
	diskCfg.Scope = "subdomains"
	diskCfg.MaxSizeMB = 20
	diskCfg.UserAgent = "DiskUserAgent/1.0"
	if err := config.Save(diskCfg); err != nil {
		t.Fatalf("failed to save disk config: %v", err)
	}

	// 1. Conflict check: --quiet and --verbose must return 2
	t.Run("quiet and verbose conflict", func(t *testing.T) {
		code := runScan([]string{"--quiet", "--verbose", "http://localhost:8080"})
		if code != 2 {
			t.Errorf("expected exit code 2 for conflicting --quiet and --verbose, got %d", code)
		}
	})

	// 2. Missing target URLs: must return 2
	t.Run("missing targets", func(t *testing.T) {
		code := runScan([]string{"--concurrency", "5"})
		if code != 2 {
			t.Errorf("expected exit code 2 for missing targets, got %d", code)
		}
	})

	// 3. Invalid timeout flag: must return 2
	t.Run("invalid timeout flag", func(t *testing.T) {
		code := runScan([]string{"--timeout", "invalid", "http://localhost:8080"})
		if code != 2 {
			t.Errorf("expected exit code 2 for invalid timeout, got %d", code)
		}
	})

	// 4. Invalid concurrency flag: must return 2
	t.Run("invalid concurrency flag", func(t *testing.T) {
		code := runScan([]string{"--concurrency", "-5", "http://localhost:8080"})
		if code != 2 {
			t.Errorf("expected exit code 2 for negative concurrency, got %d", code)
		}
	})

	// 5. Invalid scope flag: must return 2
	t.Run("invalid scope flag", func(t *testing.T) {
		code := runScan([]string{"--scope", "everything", "http://localhost:8080"})
		if code != 2 {
			t.Errorf("expected exit code 2 for invalid scope, got %d", code)
		}
	})

	// 6. Invalid max-response-size flag: must return 2
	t.Run("invalid max-size flag", func(t *testing.T) {
		code := runScan([]string{"--max-size", "-10MB", "http://localhost:8080"})
		if code != 2 {
			t.Errorf("expected exit code 2 for invalid max-size, got %d", code)
		}
	})

	// 7. Unknown flag: must return 2
	t.Run("unknown flag", func(t *testing.T) {
		code := runScan([]string{"--unknown-arbitrary-flag", "http://localhost:8080"})
		if code != 2 {
			t.Errorf("expected exit code 2 for unknown flag, got %d", code)
		}
	})

	// 8. Help flag: must return 0
	t.Run("help flag", func(t *testing.T) {
		code := runScan([]string{"--help"})
		if code != 0 {
			t.Errorf("expected exit code 0 for --help, got %d", code)
		}
	})

	// 9. Target list file missing: must return 2
	t.Run("missing target file", func(t *testing.T) {
		code := runScan([]string{"-l", filepath.Join(tempDir, "nonexistent-targets.txt")})
		if code != 2 {
			t.Errorf("expected exit code 2 for missing targets file, got %d", code)
		}
	})

	// 10. Embedded credentials in target URL: must return 2
	t.Run("embedded credentials in target URL", func(t *testing.T) {
		code := runScan([]string{"http://user:secret@target.local"})
		if code != 2 {
			t.Errorf("expected exit code 2 for embedded credentials, got %d", code)
		}
	})

	// 11. Unsupported target scheme: must return 2
	t.Run("unsupported target scheme", func(t *testing.T) {
		code := runScan([]string{"file:///etc/passwd"})
		if code != 2 {
			t.Errorf("expected exit code 2 for unsupported scheme, got %d", code)
		}
	})

	// 12. Malformed target URL: must return 2
	t.Run("malformed target URL", func(t *testing.T) {
		code := runScan([]string{"http://"})
		if code != 2 {
			t.Errorf("expected exit code 2 for malformed URL, got %d", code)
		}
	})

	// 13. Loopback target is blocked by default, but allowed with --allow-loopback
	t.Run("loopback default blocking and allow-loopback flag", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body><h1>Felix Test</h1></body></html>`))
		}))
		defer ts.Close()

		// Without --allow-loopback: connection to 127.0.0.1 is blocked by safe dialer -> exit code 2
		blockedCode := runScan([]string{"--quiet", ts.URL})
		if blockedCode != 2 {
			t.Errorf("expected exit code 2 (blocked by SSRF protection) without --allow-loopback, got %d", blockedCode)
		}

		// With --allow-loopback: connection is permitted and scan executes (exit code 0 or 1, but NOT 2)
		allowedCode := runScan([]string{"--allow-loopback", "--quiet", ts.URL})
		if allowedCode == 2 {
			t.Errorf("expected scan to proceed when --allow-loopback is enabled, but got exit code 2 (blocked/failed)")
		}

		// With env var FELIX_ALLOW_LOOPBACK=true: connection is permitted without flag
		t.Setenv("FELIX_ALLOW_LOOPBACK", "true")
		envAllowedCode := runScan([]string{"--quiet", ts.URL})
		if envAllowedCode == 2 {
			t.Errorf("expected scan to proceed when FELIX_ALLOW_LOOPBACK=true is set, but got exit code 2")
		}
	})

	// 14. Malformed environment variable: must return 2
	t.Run("malformed env var returns exit code 2", func(t *testing.T) {
		t.Setenv("FELIX_TIMEOUT", "invalid-duration")
		code := runScan([]string{"http://localhost:8080"})
		if code != 2 {
			t.Errorf("expected exit code 2 for malformed FELIX_TIMEOUT, got %d", code)
		}
	})

	// 15. Insecure and Active verification flags accepted
	t.Run("insecure and active verification flags", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		code := runScan([]string{"--allow-loopback", "--insecure", "--active", "--quiet", ts.URL})
		if code == 2 {
			t.Errorf("expected scan to proceed with --insecure and --active flags, got exit code 2")
		}
	})
}

// captureStdoutStderr is a helper to capture stdout and stderr for testing CLI commands.
func captureOutput(f func()) (string, string) {
	oldStdout := os.Stdout
	oldStderr := os.Stderr

	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()

	os.Stdout = wOut
	os.Stderr = wErr

	outC := make(chan string)
	errC := make(chan string)

	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, rOut)
		outC <- buf.String()
	}()

	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, rErr)
		errC <- buf.String()
	}()

	f()

	wOut.Close()
	wErr.Close()

	os.Stdout = oldStdout
	os.Stderr = oldStderr

	stdout := <-outC
	stderr := <-errC

	return stdout, stderr
}

func TestRunScan_FourLevelPrecedenceIntegration(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body><p>Precedence Test</p></body></html>`))
	}))
	defer ts.Close()

	// Level 1: Default configuration has AllowLoopback=false
	// Scanning loopback target without flags or env fails with exit code 2
	code := runScan([]string{"--quiet", ts.URL})
	if code != 2 {
		t.Fatalf("Level 1 (Default): expected exit code 2 (loopback blocked), got %d", code)
	}

	// Level 2: Configuration file on disk sets AllowLoopback=true
	fileCfg := config.Default()
	fileCfg.AllowLoopback = true
	fileCfg.Timeout = 15
	if err := config.Save(fileCfg); err != nil {
		t.Fatalf("failed to save config file: %v", err)
	}

	// Now running without flags succeeds because config file enabled loopback
	code = runScan([]string{"--quiet", ts.URL})
	if code == 2 {
		t.Fatalf("Level 2 (Config file): expected loopback allowed by config file, but got exit code 2")
	}

	// Level 3: Environment variable overrides configuration file
	// FELIX_ALLOW_LOOPBACK=false overrides config file's AllowLoopback=true!
	t.Setenv("FELIX_ALLOW_LOOPBACK", "false")
	code = runScan([]string{"--quiet", ts.URL})
	if code != 2 {
		t.Fatalf("Level 3 (Environment): expected env var FELIX_ALLOW_LOOPBACK=false to override file, got %d", code)
	}

	// Level 4: Explicit CLI flag overrides environment variable and file
	// CLI flag --allow-loopback wins over FELIX_ALLOW_LOOPBACK=false!
	code = runScan([]string{"--allow-loopback", "--quiet", ts.URL})
	if code == 2 {
		t.Fatalf("Level 4 (CLI flag): expected --allow-loopback to override env var and succeed, but got exit code 2")
	}

	// CLI flag --allow-loopback=false wins over FELIX_ALLOW_LOOPBACK=true!
	t.Setenv("FELIX_ALLOW_LOOPBACK", "true")
	code = runScan([]string{"--allow-loopback=false", "--quiet", ts.URL})
	if code != 2 {
		t.Fatalf("Level 4 (CLI flag): expected --allow-loopback=false to override env var and block loopback, got %d", code)
	}

	// CLI flag --no-allow-loopback also wins over FELIX_ALLOW_LOOPBACK=true!
	code = runScan([]string{"--no-allow-loopback", "--quiet", ts.URL})
	if code != 2 {
		t.Fatalf("Level 4 (CLI flag): expected --no-allow-loopback to override env var and block loopback, got %d", code)
	}
}

func TestRunScan_RuntimeLimitsEnforcement(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	// 1. Redirect limit enforcement:
	// A server that redirects more than DefaultMaxRedirects (5) times
	redirectCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectCount++
		// Loop redirects indefinitely
		http.Redirect(w, r, fmt.Sprintf("/hop-%d", redirectCount), http.StatusFound)
	}))
	defer ts.Close()

	// With --allow-loopback, crawler executes but halts when redirect limit is reached
	code := runScan([]string{"--allow-loopback", "--quiet", ts.URL})
	// Exit code will reflect that targets failed reachability due to redirect policy
	if code == 0 {
		t.Errorf("expected scan to fail or report issue on infinite redirect loop, got exit code 0")
	}
}

func TestRunScan_ScopeSafetyAndMetadataBlocking(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	// 1. Redirect from allowed loopback target to AWS metadata 169.254.169.254
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer ts.Close()

	// With --allow-loopback enabled, initial connection succeeds, but redirect to 169.254.169.254 is blocked
	code := runScan([]string{"--allow-loopback", "--quiet", ts.URL})
	if code == 0 {
		t.Errorf("expected scan to fail when redirecting to cloud metadata, got exit code 0")
	}

	// 2. Embedded credentials in target URL rejected before network calls
	code = runScan([]string{"--quiet", "http://canaryuser:CANARY_PASS@target.local/path"})
	if code != 2 {
		t.Errorf("expected exit code 2 when embedded credentials are in target URL, got %d", code)
	}
}

func TestFormatServiceAccessState(t *testing.T) {
	tests := []struct {
		name          string
		ds            cloud.DiscoveredService
		accessRecords []cloud.AccessVerificationRecord
		expected      string
	}{
		{
			name: "outside authorized scope",
			ds: cloud.DiscoveredService{
				Technology: cloud.TechAWSS3,
				InScope:    false,
			},
			expected: "Outside authorized scope",
		},
		{
			name: "access verified when public access confirmed",
			ds: cloud.DiscoveredService{
				Technology:   cloud.TechAWSS3,
				InScope:      true,
				PublicAccess: true,
			},
			expected: "Access verified",
		},
		{
			name: "authentication observed when auth is required",
			ds: cloud.DiscoveredService{
				Technology:   cloud.TechRedis,
				InScope:      true,
				AuthRequired: true,
				PublicAccess: false,
			},
			expected: "Authentication observed",
		},
		{
			name: "access not verified when service reachable but data access not verified (Redis PONG)",
			ds: cloud.DiscoveredService{
				Technology:   cloud.TechRedis,
				InScope:      true,
				AuthRequired: false,
				PublicAccess: false,
			},
			expected: "Access not verified",
		},
		{
			name: "access not verified for PostgreSQL SSL negotiation",
			ds: cloud.DiscoveredService{
				Technology:   cloud.TechPostgreSQL,
				InScope:      true,
				AuthRequired: false,
				PublicAccess: false,
			},
			expected: "Access not verified",
		},
		{
			name: "access not verified for MinIO health check 200 OK",
			ds: cloud.DiscoveredService{
				Technology:   cloud.TechMinIO,
				InScope:      true,
				AuthRequired: false,
				PublicAccess: false,
			},
			expected: "Access not verified",
		},
		{
			name: "access record ReadAllowed with scope",
			ds: cloud.DiscoveredService{
				Technology: cloud.TechAWSS3,
				Endpoint:   "test-bucket.s3.amazonaws.com",
				InScope:    true,
			},
			accessRecords: []cloud.AccessVerificationRecord{
				{
					Technology:    cloud.TechAWSS3,
					Target:        "test-bucket.s3.amazonaws.com",
					Status:        cloud.StatusReadAllowed,
					ResourceScope: "bucket-read",
				},
			},
			expected: "Read verified (bucket-read)",
		},
		{
			name: "access record AuthChallenged",
			ds: cloud.DiscoveredService{
				Technology: cloud.TechRedis,
				Host:       "127.0.0.1",
				Port:       6379,
				InScope:    true,
			},
			accessRecords: []cloud.AccessVerificationRecord{
				{
					Technology: cloud.TechRedis,
					Target:     "127.0.0.1:6379",
					Status:     cloud.StatusAuthChallenged,
				},
			},
			expected: "Authentication challenge observed",
		},
		{
			name: "access record ReadDenied",
			ds: cloud.DiscoveredService{
				Technology: cloud.TechPostgreSQL,
				Host:       "127.0.0.1",
				Port:       5432,
				InScope:    true,
			},
			accessRecords: []cloud.AccessVerificationRecord{
				{
					Technology: cloud.TechPostgreSQL,
					Target:     "127.0.0.1:5432",
					Status:     cloud.StatusReadDenied,
				},
			},
			expected: "Access restricted (denied)",
		},
		{
			name: "access record ServiceReachable",
			ds: cloud.DiscoveredService{
				Technology: cloud.TechRedis,
				Host:       "127.0.0.1",
				Port:       6379,
				InScope:    true,
			},
			accessRecords: []cloud.AccessVerificationRecord{
				{
					Technology: cloud.TechRedis,
					Target:     "127.0.0.1:6379",
					Status:     cloud.StatusServiceReachable,
				},
			},
			expected: "Service reachable (data access not verified)",
		},
		{
			name: "access record VerificationSkipped",
			ds: cloud.DiscoveredService{
				Technology: cloud.TechRedis,
				Host:       "127.0.0.1",
				Port:       6379,
				InScope:    true,
			},
			accessRecords: []cloud.AccessVerificationRecord{
				{
					Technology: cloud.TechRedis,
					Target:     "127.0.0.1:6379",
					Status:     cloud.StatusVerificationSkipped,
				},
			},
			expected: "Verification skipped (active verify disabled)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			if len(tt.accessRecords) > 0 {
				got = FormatServiceAccessState(tt.ds, tt.accessRecords)
			} else {
				got = FormatServiceAccessState(tt.ds)
			}
			if got != tt.expected {
				t.Errorf("FormatServiceAccessState() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestRunScan_RateLimitingAndSubpathEnforcement(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	jsonOut := filepath.Join(tempDir, "result.json")

	var requestedPaths []string
	var mu sync.Mutex

	// Server with subpath app and outside paths
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestedPaths = append(requestedPaths, r.URL.Path)
		mu.Unlock()

		switch r.URL.Path {
		case "/subapp":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<!doctype html><html><head><script src="/assets/app.js"></script><a href="/outside">Outside</a></head><body><h1>SubApp</h1></body></html>`))
		case "/assets/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`console.log("loaded");`))
		case "/outside":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"admin": true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	// 1. Invalid rate-limit flag value returns exit code 2
	code := runScan([]string{"--allow-loopback", "--rate-limit=-1", "--quiet", ts.URL + "/subapp"})
	if code != 2 {
		t.Errorf("expected exit code 2 for negative --rate-limit, got %d", code)
	}

	// 2. Scan with valid rate-limit and subpath
	code = runScan([]string{
		"--allow-loopback",
		"--rate-limit=10.0",
		"--json=" + jsonOut,
		"--quiet",
		ts.URL + "/subapp",
	})
	if code != 0 && code != 1 {
		t.Fatalf("expected exit code 0 or 1 for completed scan, got %d", code)
	}

	// Verify path containment: /outside must NOT have been requested
	mu.Lock()
	for _, p := range requestedPaths {
		if p == "/outside" {
			t.Errorf("expected /outside to NOT be requested due to subpath containment, but it was requested")
		}
	}
	mu.Unlock()

	// Verify JSON output records transport_requests_count and wire_requests_count
	data, err := os.ReadFile(jsonOut)
	if err != nil {
		t.Fatalf("failed reading result JSON: %v", err)
	}
	var rep report.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("failed unmarshaling report JSON: %v", err)
	}
	if rep.RequestCount <= 0 {
		t.Errorf("expected rep.RequestCount > 0, got %d", rep.RequestCount)
	}
	if transportCount, ok := rep.Metadata["transport_requests_count"].(float64); !ok || transportCount <= 0 {
		t.Errorf("expected Metadata.transport_requests_count > 0, got %v", rep.Metadata["transport_requests_count"])
	}
	if wireCount, ok := rep.Metadata["wire_requests_count"].(float64); !ok || wireCount <= 0 {
		t.Errorf("expected Metadata.wire_requests_count > 0, got %v", rep.Metadata["wire_requests_count"])
	}
}

func TestRunScan_RedirectBlockedOutsidePathScope(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	visitedAdmin := false
	var mu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/subapp":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<!doctype html><html><head><a href="/subapp/redirect">Go</a></head></html>`))
		case "/subapp/redirect":
			// Redirects outside the /subapp path boundary
			http.Redirect(w, r, "/admin-secret", http.StatusFound)
		case "/admin-secret":
			visitedAdmin = true
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`sensitive admin data`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	code := runScan([]string{
		"--allow-loopback",
		"--quiet",
		ts.URL + "/subapp",
	})
	if code != 0 && code != 1 {
		t.Fatalf("expected scan exit code 0 or 1, got %d", code)
	}

	mu.Lock()
	defer mu.Unlock()
	if visitedAdmin {
		t.Errorf("redirect out of subpath to /admin-secret was followed, but should have been blocked")
	}
}

func TestRunScan_HithaOneStrictBoundaryProof(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	var recordedRequests []string
	var mu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		recordedRequests = append(recordedRequests, r.URL.Path)
		mu.Unlock()

		switch r.URL.Path {
		case "/hithaone":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<!doctype html>
<html>
<head>
    <script src="/assets/app-123.js"></script>
    <script src="/admin.js"></script>
    <script src="/_next/../admin.js"></script>
    <script src="/assets/%2e%2e/secret.js"></script>
    <script src="/assets/%252e%252e/secret2.js"></script>
    <script src="/assets/%25252e%25252e/secret3.js"></script>
    <script src="/assets/%2525252e%2525252e/secret4.js"></script>
    <script src="/assets/%00/evil.js"></script>
    <script src="/assets/%2500/evil2.js"></script>
    <script src="/assets/%2f%2e%2e%2fadmin.js"></script>
    <script src="/assets\..\evil.js"></script>
    <a href="/root-page">Root Page</a>
    <a href="/hithaone-admin">Lookalike Prefix</a>
    <a href="/hithaone/../hithaone/escape">Escape Traversal</a>
    <a href="/hithaone/%25252e%25252e/admin">Deep Encoded Escape</a>
    <a href="/hithaone%5cadmin">Backslash Lookalike</a>
    <a href="/other/app">Other App</a>
</head>
<body>
    <h1>HithaOne Application</h1>
</body>
</html>`))
		case "/assets/app-123.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`
console.log("HithaOne bundle loaded");
const apiEndpoint = "/admin";
const detailsEndpoint = "/hithaone/details";
const userEndpoint = "/api/v1/users";
`))
		case "/hithaone/details":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	code := runScan([]string{
		"--allow-loopback",
		"--rate-limit=20.0",
		"--quiet",
		ts.URL + "/hithaone",
	})
	if code != 0 && code != 1 {
		t.Fatalf("expected scan exit code 0 or 1, got %d", code)
	}

	mu.Lock()
	defer mu.Unlock()

	prohibitedPaths := []string{
		"/admin.js",
		"/_next/../admin.js",
		"/secret.js",
		"/secret2.js",
		"/secret3.js",
		"/secret4.js",
		"/evil.js",
		"/evil2.js",
		"/root-page",
		"/hithaone-admin",
		"/hithaone/escape",
		"/escape",
		"/hithaone/../hithaone/escape",
		"/other/app",
		"/admin",
		"/.env",
		"/.git/HEAD",
		"/api/v1/users",
		"/swagger.json",
		"/openapi.json",
	}

	for _, prohibited := range prohibitedPaths {
		for _, req := range recordedRequests {
			if req == prohibited {
				t.Errorf("VIOLATION: prohibited out-of-scope path %q was requested by scanner!", prohibited)
			}
		}
	}

	foundTarget := false
	foundAsset := false
	for _, req := range recordedRequests {
		if req == "/hithaone" {
			foundTarget = true
		}
		if req == "/assets/app-123.js" {
			foundAsset = true
		}
	}
	if !foundTarget {
		t.Errorf("expected target /hithaone to be requested")
	}
	if !foundAsset {
		t.Errorf("expected referenced asset /assets/app-123.js to be downloaded")
	}
}

func TestScanCLI_SpecFlag_HelpText(t *testing.T) {
	code, out, _ := captureStdoutStderr(func() int {
		return runScan([]string{"--help"})
	})
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if !strings.Contains(out, "--spec") {
		t.Errorf("expected help output to mention --spec")
	}
}

func TestScanCLI_SpecFlag_MissingArgument(t *testing.T) {
	code, _, errOut := captureStdoutStderr(func() int {
		return runScan([]string{"--spec"})
	})
	if code != 2 {
		t.Errorf("expected exit code 2 for missing --spec argument, got %d", code)
	}
	if !strings.Contains(errOut, "--spec requires a file path or URL argument") {
		t.Errorf("expected error message for missing --spec argument, got %q", errOut)
	}
}

func TestScanCLI_SpecFlag_Execution(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><script src="/app.js"></script></html>`)
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `
				axios.get("/api/v1/users");
				fetch("/api/v1/tenants/42/roles", { method: "POST" });
			`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	specFile := filepath.Join(tmpDir, "openapi.json")
	specJSON := `{
		"openapi": "3.0.0",
		"info": { "title": "Test App", "version": "1.0.0" },
		"paths": {
			"/api/v1/users": {
				"get": { "operationId": "getUsers" }
			}
		}
	}`
	if err := os.WriteFile(specFile, []byte(specJSON), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	jsonOut := filepath.Join(tmpDir, "report.json")
	args := []string{
		"--allow-loopback",
		"--spec", specFile,
		"--json", jsonOut,
		server.URL,
	}

	code, _, _ := captureStdoutStderr(func() int {
		return runScan(args)
	})

	if code != 0 && code != 1 {
		t.Fatalf("runScan failed with unexpected operational error %d", code)
	}

	reportData, err := os.ReadFile(jsonOut)
	if err != nil {
		t.Fatalf("failed reading output report.json: %v", err)
	}

	var rep report.Report
	if err := json.Unmarshal(reportData, &rep); err != nil {
		t.Fatalf("failed unmarshaling report.json: %v", err)
	}

	if rep.Reconciliation == nil {
		t.Fatalf("expected non-nil Reconciliation in report")
	}
	if rep.Reconciliation.TotalDocumentedMatches < 1 {
		t.Errorf("expected at least 1 documented match, got %d", rep.Reconciliation.TotalDocumentedMatches)
	}
	if rep.Reconciliation.TotalUndocumentedCandidates < 1 {
		t.Errorf("expected at least 1 undocumented candidate, got %d", rep.Reconciliation.TotalUndocumentedCandidates)
	}
	if rep.Reconciliation.TotalSensitiveShadowRoutes < 1 {
		t.Errorf("expected at least 1 sensitive shadow route, got %d", rep.Reconciliation.TotalSensitiveShadowRoutes)
	}
}

func TestScan_P14_4_DeclarativeMultiTenantScanProfileEndToEnd(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body>Authorized Test Portal</body></html>`)
		case "/api/v1/documents/doc_alpha_101":
			auth := r.Header.Get("Authorization")
			if auth != "Bearer token_beta_secure" {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `{"error": "invalid token"}`)
				return
			}
			// Simulate BOLA vulnerability: beta accessed alpha's document
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"resource_id": "doc_alpha_101", "owner": "tenant_alpha", "data": "CONFIDENTIAL_ALPHA_DATA"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	host := u.Hostname()

	tmpDir := t.TempDir()
	profileFile := filepath.Join(tmpDir, "felix.target.yml")
	jsonOut := filepath.Join(tmpDir, "report.json")

	profileYAML := fmt.Sprintf(`version: 1
target:
  name: "End-to-End Multi-Tenant Test"
  base_urls:
    - "%s"
  allowed_hosts:
    - "%s"
    - "127.0.0.1"
    - "localhost"
  allowed_methods:
    - "GET"
    - "HEAD"

safety:
  mode: "non_destructive"
  allow_cross_tenant_checks: true
  max_requests: 20
  requests_per_second: 10
  timeout_seconds: 5

tenants:
  - id: "tenant_alpha"
    identity: "alpha@example.corp"
    credential_env: "FELIX_TEST_E2E_TOKEN_ALPHA"
    resource_ids:
      - "doc_alpha_101"
  - id: "tenant_beta"
    identity: "beta@example.corp"
    credential_env: "FELIX_TEST_E2E_TOKEN_BETA"
    resource_ids:
      - "doc_beta_201"

cross_tenant_tests:
  enabled: true
  comparisons:
    - requester_tenant: "tenant_beta"
      resource_owner_tenant: "tenant_alpha"
      resource_id: "doc_alpha_101"
      path: "/api/v1/documents/{id}"
      expected_marker: "CONFIDENTIAL_ALPHA_DATA"
`, server.URL, host)

	if err := os.WriteFile(profileFile, []byte(profileYAML), 0600); err != nil {
		t.Fatalf("failed writing temp profile: %v", err)
	}

	t.Setenv("FELIX_TEST_E2E_TOKEN_ALPHA", "token_alpha_secure")
	t.Setenv("FELIX_TEST_E2E_TOKEN_BETA", "token_beta_secure")

	args := []string{
		"--allow-loopback",
		"--profile", profileFile,
		"--cross-tenant",
		"--json", jsonOut,
	}

	code, _, _ := captureStdoutStderr(func() int {
		return runScan(args)
	})

	if code != 0 && code != 1 {
		t.Fatalf("runScan failed with unexpected operational error %d", code)
	}

	reportData, err := os.ReadFile(jsonOut)
	if err != nil {
		t.Fatalf("failed reading output report.json: %v", err)
	}

	var rep report.Report
	if err := json.Unmarshal(reportData, &rep); err != nil {
		t.Fatalf("failed unmarshaling report.json: %v", err)
	}

	if rep.CrossTenantResults == nil {
		t.Fatalf("expected non-nil CrossTenantResults in report")
	}
	if rep.CrossTenantResults.TotalExecuted != 1 {
		t.Errorf("expected 1 executed comparison, got %d", rep.CrossTenantResults.TotalExecuted)
	}
	if rep.CrossTenantResults.TotalCrossTenantAccessObserved != 1 {
		t.Errorf("expected 1 BOLA observed, got %d", rep.CrossTenantResults.TotalCrossTenantAccessObserved)
	}

	// Verify that the BOLA finding was added to report findings
	hasBOLAFinding := false
	for _, f := range rep.Findings {
		if strings.Contains(f.Category, "BOLA") {
			hasBOLAFinding = true
			break
		}
	}
	if !hasBOLAFinding {
		t.Errorf("expected BOLA finding in rep.Findings, but none found")
	}
}

func TestScanCLI_ProbeAndProbeLive_Equivalence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><script src="/static/app.js"></script></head><body><h1>Test</h1></body></html>`))
		case "/static/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte(`fetch('/api/v1/orders', {method: 'GET'});`))
		case "/api/v1/orders":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"orders": [{"id": 1}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	specFile := filepath.Join(tmpDir, "openapi.json")
	specJSON := `{
		"openapi": "3.0.0",
		"info": {"title": "Test API", "version": "1.0.0"},
		"paths": {
			"/api/v1/catalog": {
				"get": {
					"responses": {"200": {"description": "Catalog list"}}
				}
			}
		}
	}`
	if err := os.WriteFile(specFile, []byte(specJSON), 0600); err != nil {
		t.Fatalf("failed to write spec file: %v", err)
	}

	outProbe := filepath.Join(tmpDir, "out_probe.json")
	outProbeLive := filepath.Join(tmpDir, "out_probe_live.json")

	// 1. Run with canonical --probe
	codeProbe, _, _ := captureStdoutStderr(func() int {
		return runScan([]string{
			"--allow-loopback",
			"--spec", specFile,
			"--probe",
			"--json", outProbe,
			server.URL,
		})
	})

	// 2. Run with alias --probe-live
	codeProbeLive, _, _ := captureStdoutStderr(func() int {
		return runScan([]string{
			"--allow-loopback",
			"--spec", specFile,
			"--probe-live",
			"--json", outProbeLive,
			server.URL,
		})
	})

	if codeProbe != codeProbeLive {
		t.Fatalf("expected identical exit codes: --probe got %d, --probe-live got %d", codeProbe, codeProbeLive)
	}

	dataProbe, err := os.ReadFile(outProbe)
	if err != nil {
		t.Fatalf("failed to read out_probe.json: %v", err)
	}
	dataProbeLive, err := os.ReadFile(outProbeLive)
	if err != nil {
		t.Fatalf("failed to read out_probe_live.json: %v", err)
	}

	var repProbe, repProbeLive report.Report
	if err := json.Unmarshal(dataProbe, &repProbe); err != nil {
		t.Fatalf("failed unmarshaling out_probe.json: %v", err)
	}
	if err := json.Unmarshal(dataProbeLive, &repProbeLive); err != nil {
		t.Fatalf("failed unmarshaling out_probe_live.json: %v", err)
	}

	if repProbe.ProberResults == nil || repProbeLive.ProberResults == nil {
		t.Fatalf("expected ProberResults to be non-nil in both reports")
	}

	if repProbe.ProberResults.TotalCandidatesEvaluated != repProbeLive.ProberResults.TotalCandidatesEvaluated {
		t.Errorf("candidate counts differ: probe=%d, probe-live=%d",
			repProbe.ProberResults.TotalCandidatesEvaluated, repProbeLive.ProberResults.TotalCandidatesEvaluated)
	}
	if repProbe.ProberResults.TotalProbesAttempted != repProbeLive.ProberResults.TotalProbesAttempted {
		t.Errorf("attempted probe counts differ: probe=%d, probe-live=%d",
			repProbe.ProberResults.TotalProbesAttempted, repProbeLive.ProberResults.TotalProbesAttempted)
	}
	if repProbe.ProberResults.TotalReachable != repProbeLive.ProberResults.TotalReachable {
		t.Errorf("reachable counts differ: probe=%d, probe-live=%d",
			repProbe.ProberResults.TotalReachable, repProbeLive.ProberResults.TotalReachable)
	}

	// 3. Verify scope protection: when loopback is disallowed (default), loopback dials are blocked identically
	outBlockedProbe := filepath.Join(tmpDir, "blocked_probe.json")
	outBlockedProbeLive := filepath.Join(tmpDir, "blocked_probe_live.json")

	codeBlocked1, _, _ := captureStdoutStderr(func() int {
		return runScan([]string{
			"--allow-loopback=false",
			"--spec", specFile,
			"--probe",
			"--json", outBlockedProbe,
			server.URL,
		})
	})
	codeBlocked2, _, _ := captureStdoutStderr(func() int {
		return runScan([]string{
			"--allow-loopback=false",
			"--spec", specFile,
			"--probe-live",
			"--json", outBlockedProbeLive,
			server.URL,
		})
	})

	if codeBlocked1 != codeBlocked2 {
		t.Errorf("blocked exit codes differ: probe=%d, probe-live=%d", codeBlocked1, codeBlocked2)
	}
}

func TestScanCLI_4TierConfigurationPrecedence(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("FELIX_DIR", tempDir)

	// Ensure no environment variables are set for tier 1/2
	os.Unsetenv("FELIX_CONCURRENCY")
	os.Unsetenv("FELIX_TIMEOUT")
	defer func() {
		os.Unsetenv("FELIX_CONCURRENCY")
		os.Unsetenv("FELIX_TIMEOUT")
	}()

	// Tier 1: Defaults
	cfgDefault, err := config.LoadWithEnv("")
	if err != nil {
		t.Fatalf("LoadWithEnv default error: %v", err)
	}
	if cfgDefault.Concurrency != config.DefaultConcurrency {
		t.Fatalf("Tier 1 Default: expected concurrency %d, got %d", config.DefaultConcurrency, cfgDefault.Concurrency)
	}
	if cfgDefault.Timeout != config.DefaultTimeoutSeconds {
		t.Fatalf("Tier 1 Default: expected timeout %d, got %d", config.DefaultTimeoutSeconds, cfgDefault.Timeout)
	}

	// Tier 2: Config file overrides defaults
	diskCfg := config.Default()
	diskCfg.Concurrency = 25
	diskCfg.Timeout = 25
	if err := config.Save(diskCfg); err != nil {
		t.Fatalf("Save config failed: %v", err)
	}
	cfgFile, err := config.LoadWithEnv("")
	if err != nil {
		t.Fatalf("LoadWithEnv file error: %v", err)
	}
	if cfgFile.Concurrency != 25 {
		t.Fatalf("Tier 2 File: expected concurrency 25, got %d", cfgFile.Concurrency)
	}
	if cfgFile.Timeout != 25 {
		t.Fatalf("Tier 2 File: expected timeout 25, got %d", cfgFile.Timeout)
	}

	// Tier 3: Environment variables override config file
	t.Setenv("FELIX_CONCURRENCY", "40")
	t.Setenv("FELIX_TIMEOUT", "40s")
	cfgEnv, err := config.LoadWithEnv("")
	if err != nil {
		t.Fatalf("LoadWithEnv env error: %v", err)
	}
	if cfgEnv.Concurrency != 40 {
		t.Fatalf("Tier 3 Env: expected concurrency 40, got %d", cfgEnv.Concurrency)
	}
	if cfgEnv.Timeout != 40 {
		t.Fatalf("Tier 3 Env: expected timeout 40, got %d", cfgEnv.Timeout)
	}

	// Tier 4: Explicit CLI flags override environment variables, config file, and defaults
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><h1>Precedence Test</h1></body></html>`))
	}))
	defer server.Close()

	jsonOut := filepath.Join(tempDir, "precedence_report.json")
	code, _, _ := captureStdoutStderr(func() int {
		return runScan([]string{
			"--allow-loopback",
			"--concurrency", "55",
			"--timeout", "55s",
			"--json", jsonOut,
			server.URL,
		})
	})
	if code != 0 && code != 1 {
		t.Fatalf("runScan failed with error code %d", code)
	}

	// Verify that an invalid CLI flag overrides valid environment setting and fails closed (Exit 2)
	codeInvalidCLI, _, _ := captureStdoutStderr(func() int {
		return runScan([]string{
			"--allow-loopback",
			"--concurrency", "0",
			server.URL,
		})
	})
	if codeInvalidCLI != 2 {
		t.Fatalf("expected CLI flag error exit 2, got %d", codeInvalidCLI)
	}
}
