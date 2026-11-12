package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/report"
	"felix/pkg/validation"
)

func TestPhase9_ScopePolicy_PathNormalizationBypassBlocked(t *testing.T) {
	opts := &AssessOptions{
		ExcludePaths: []string{"/admin/reset"},
	}
	allowed, excluded, _, err := buildAssessScopePolicy(opts, "https://app.authorized.example:8443", time.Now().UTC())
	if err != nil {
		t.Fatalf("buildAssessScopePolicy error: %v", err)
	}

	bypassAttempts := []string{
		"https://app.authorized.example:8443/admin/reset",
		"https://app.authorized.example:8443/%61dmin/reset",
		"https://app.authorized.example:8443/foo/../admin/reset",
		"https://app.authorized.example:8443//admin//reset",
		`https://app.authorized.example:8443/\admin\reset`,
	}
	for _, cand := range bypassAttempts {
		if !excluded(cand) {
			t.Errorf("expected scopeExcluded(%q)=true", cand)
		}
		if allowed(cand) {
			t.Errorf("expected scopeAllowed(%q)=false", cand)
		}
	}
	// Scheme/port enforcement
	if allowed("http://app.authorized.example:8443/api/health") {
		t.Errorf("expected scheme downgrade http:// to be rejected by scopeAllowed")
	}
	if allowed("https://app.authorized.example:9443/api/health") {
		t.Errorf("expected wrong port 9443 to be rejected by scopeAllowed")
	}
	if !allowed("https://app.authorized.example:8443/api/health") {
		t.Errorf("expected exact target origin+port path to be allowed")
	}
}

func TestPhase9_MidScanAuthorizationWindowExpiry_HaltsRequests(t *testing.T) {
	var reqAfterWindow int32
	var windowEndUnixNano int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endNs := atomic.LoadInt64(&windowEndUnixNano)
		if endNs > 0 && time.Now().UTC().UnixNano() > endNs+int64(250*time.Millisecond) {
			atomic.AddInt32(&reqAfterWindow, 1)
		}
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body><a href="/slow">slow</a></body></html>`))
			return
		}
		time.Sleep(180 * time.Millisecond)
		_, _ = w.Write([]byte(`ok`))
	}))
	defer srv.Close()

	now := time.Now().UTC()
	windowEnd := now.Add(350 * time.Millisecond)
	atomic.StoreInt64(&windowEndUnixNano, windowEnd.UnixNano())

	contract := validation.AuthorizationContract{
		AuthorizingParty:  "WindowExpiryTest",
		AuthorizationRef:  "AUTH-P9-WIN",
		Confirmed:         true,
		AuthorizedTargets: []string{srv.URL},
		WindowStart:       now.Add(-1 * time.Minute),
		WindowEnd:         windowEnd,
	}
	manifestBytes, _ := json.MarshalIndent(contract, "", "  ")
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "window.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	outDir := filepath.Join(tmpDir, "out")
	code := runAssess([]string{
		"--target", srv.URL,
		"--profile", "standard",
		"--output", outDir,
		"--allow-loopback",
		"--scope-manifest", manifestPath,
		"--crawl-max-pages", "25",
		"--crawl-max-requests", "40",
	})
	if code != 2 {
		t.Errorf("expected expired mid-scan window to fail-closed with exit code 2, got %d", code)
	}
	if got := atomic.LoadInt32(&reqAfterWindow); got != 0 {
		t.Errorf("expected 0 requests dispatched >250ms past WindowEnd, got %d", got)
	}
}

func TestPhase9_TLSVerificationDefault_RejectsUntrustedCertWithoutInsecureFlag(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><h1>TLS Target</h1></body></html>`))
	}))
	defer tlsSrv.Close()

	tmpDir := t.TempDir()
	outRejected := filepath.Join(tmpDir, "rejected")
	codeNoInsecure := runAssess([]string{
		"--target", tlsSrv.URL,
		"--profile", "quick",
		"--output", outRejected,
		"--allow-loopback",
		"--auth-confirm",
		"--authorizing-party", "Phase9-TLSTest",
	})
	if codeNoInsecure != 2 {
		t.Errorf("expected self-signed TLS target WITHOUT --insecure to fail closed with exit 2, got %d", codeNoInsecure)
	}

	outInsecure := filepath.Join(tmpDir, "allowed_insecure")
	codeWithInsecure := runAssess([]string{
		"--target", tlsSrv.URL,
		"--profile", "quick",
		"--output", outInsecure,
		"--allow-loopback",
		"--auth-confirm",
		"--authorizing-party", "Phase9-TLSTest",
		"--insecure",
	})
	if codeWithInsecure == 2 {
		t.Errorf("expected self-signed TLS target WITH explicit --insecure to complete assessment, got exit 2")
	}

	repBytes, err := os.ReadFile(filepath.Join(outInsecure, "assessment_report.json"))
	if err != nil {
		t.Fatalf("expected assessment_report.json written: %v", err)
	}
	if len(repBytes) == 0 {
		t.Fatalf("expected non-empty assessment_report.json")
	}
}

func TestPhase9_HTMLReport_XSSEscaping(t *testing.T) {
	xssPayload := `<script>alert('xss-phase9')</script><img src=x onerror=alert(1)>`
	rep := report.BuildReport("https://app.authorized.example", []report.Finding{
		{
			ID:       "XSS-PROBE-1",
			Category: "Cross-Site Scripting",
			Title:    "Reflected XSS " + xssPayload,
			Severity: "HIGH",
			Endpoint: "/search?q=" + xssPayload,
			Evidence: "Body echoed: " + xssPayload,
		},
	})
	htmlOut, err := report.GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML error: %v", err)
	}
	if strings.Contains(htmlOut, "<script>alert('xss-phase9')</script>") || strings.Contains(htmlOut, "<img src=x onerror=alert(1)>") {
		t.Errorf("HTML report rendered unescaped script/event-handler payload from target finding!")
	}
}
