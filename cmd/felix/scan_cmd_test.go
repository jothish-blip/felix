package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"felix/pkg/config"
	"felix/pkg/crawler"
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
