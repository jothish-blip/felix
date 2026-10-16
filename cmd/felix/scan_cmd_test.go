package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

	// Server with subpath app and outside paths
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/subapp":
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<!doctype html><html><head><script src="/assets/app.js"></script></head><body><h1>SubApp</h1></body></html>`))
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

	// Verify JSON output records wire_requests_count
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
	if wireCount, ok := rep.Metadata["wire_requests_count"].(float64); !ok || wireCount <= 0 {
		t.Errorf("expected Metadata.wire_requests_count > 0, got %v", rep.Metadata["wire_requests_count"])
	}
}
