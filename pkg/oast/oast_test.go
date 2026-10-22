package oast_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"felix/pkg/apisec"
	"felix/pkg/assessment"
	"felix/pkg/oast"
	"felix/pkg/webvuln"
)

// 1. Test token unpredictability and uniqueness
func TestOAST_TokenGeneration(t *testing.T) {
	tokens := make(map[string]bool)
	const count = 1000

	for i := 0; i < count; i++ {
		tok, err := oast.GenerateInteractionToken()
		if err != nil {
			t.Fatalf("unexpected error generating token: %v", err)
		}
		if len(tok) != 32 {
			t.Fatalf("expected 32-character hex token, got length %d (%q)", len(tok), tok)
		}
		if tokens[tok] {
			t.Fatalf("collision detected on iteration %d: %q", i, tok)
		}
		tokens[tok] = true
	}
}

// 2. Test Probe lifecycle: Generation, Correlation, Wait
func TestOAST_ProbeLifecycle_Success(t *testing.T) {
	cfg := oast.DefaultConfig()
	cfg.BaseURL = "http://canary.example.com"
	correlator, err := oast.NewCorrelator(cfg)
	if err != nil {
		t.Fatalf("failed to create correlator: %v", err)
	}
	defer correlator.Close()

	probe, err := correlator.GenerateProbe("asm-1", "exec-1", "http://target.local", "/fetch", "url", oast.ProtocolHTTP, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to generate probe: %v", err)
	}

	if probe.Token == "" || len(probe.Token) != 32 {
		t.Fatalf("invalid probe token: %q", probe.Token)
	}
	if probe.Status != oast.ProbeStatusPending {
		t.Fatalf("expected status PENDING, got %s", probe.Status)
	}
	if !strings.Contains(probe.CallbackURL, probe.Token) {
		t.Fatalf("callback URL %q does not contain token %q", probe.CallbackURL, probe.Token)
	}

	// Verify probe retrieval
	got, exists := correlator.GetProbe(probe.Token)
	if !exists || got.ID != probe.ID {
		t.Fatalf("expected to retrieve probe by token %s", probe.Token)
	}

	// Record interaction asynchronously
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, recErr := correlator.RecordInteraction(context.Background(), oast.Interaction{
			Token:        probe.Token,
			AssessmentID: "asm-1",
			Protocol:     oast.ProtocolHTTP,
			ClientIP:     "198.51.100.22",
			Method:       "GET",
			Path:         "/c/" + probe.Token,
		})
		if recErr != nil {
			t.Errorf("failed to record interaction: %v", recErr)
		}
	}()

	// Wait for interaction
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	inter, err := correlator.WaitForInteraction(ctx, probe.Token, 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error waiting for interaction: %v", err)
	}
	if inter.ClientIP != "198.51.100.22" {
		t.Fatalf("expected client IP 198.51.100.22, got %s", inter.ClientIP)
	}

	// Check probe status promoted to CORRELATED
	p2, _ := correlator.GetProbe(probe.Token)
	if p2.Status != oast.ProbeStatusCorrelated {
		t.Fatalf("expected status CORRELATED, got %s", p2.Status)
	}
	if len(p2.Interactions) != 1 {
		t.Fatalf("expected 1 recorded interaction, got %d", len(p2.Interactions))
	}
}

// 3. Test Duplicate Callback Detection and Suppression
func TestOAST_DuplicateCallbackSuppression(t *testing.T) {
	cfg := oast.DefaultConfig()
	cfg.BaseURL = "http://canary.example.com"
	correlator, _ := oast.NewCorrelator(cfg)
	defer correlator.Close()

	probe, _ := correlator.GenerateProbe("asm-1", "exec-1", "http://target.local", "/fetch", "url", oast.ProtocolHTTP, 5*time.Second)

	// First callback
	res1, err := correlator.RecordInteraction(context.Background(), oast.Interaction{
		Token:    probe.Token,
		ClientIP: "198.51.100.1",
		Method:   "GET",
	})
	if err != nil {
		t.Fatalf("first interaction should succeed, got %v", err)
	}
	if res1.IsDuplicate {
		t.Fatalf("first interaction must not be flagged duplicate")
	}

	// Second callback (duplicate)
	res2, err := correlator.RecordInteraction(context.Background(), oast.Interaction{
		Token:    probe.Token,
		ClientIP: "198.51.100.2",
		Method:   "GET",
	})
	if err != oast.ErrDuplicateCallback {
		t.Fatalf("expected ErrDuplicateCallback, got %v", err)
	}
	if res2 == nil || !res2.IsDuplicate {
		t.Fatalf("expected duplicate flag true in correlation result")
	}

	// Probe interactions list should contain both, but status remains CORRELATED
	p, _ := correlator.GetProbe(probe.Token)
	if p.Status != oast.ProbeStatusCorrelated {
		t.Fatalf("expected CORRELATED, got %s", p.Status)
	}
	if len(p.Interactions) != 2 {
		t.Fatalf("expected 2 recorded interactions on probe, got %d", len(p.Interactions))
	}
	if !p.Interactions[1].IsDuplicate {
		t.Fatalf("expected second interaction to be marked duplicate")
	}
}

// 4. Test Probe Expiration (TTL)
func TestOAST_ProbeExpiration(t *testing.T) {
	cfg := oast.DefaultConfig()
	cfg.BaseURL = "http://canary.example.com"
	correlator, _ := oast.NewCorrelator(cfg)
	defer correlator.Close()

	// 50ms TTL
	probe, _ := correlator.GenerateProbe("asm-1", "exec-1", "http://target.local", "/fetch", "url", oast.ProtocolHTTP, 50*time.Millisecond)

	time.Sleep(75 * time.Millisecond)

	// Attempt interaction after expiry
	_, err := correlator.RecordInteraction(context.Background(), oast.Interaction{
		Token: probe.Token,
	})
	if err != oast.ErrProbeExpired {
		t.Fatalf("expected ErrProbeExpired, got %v", err)
	}

	p, _ := correlator.GetProbe(probe.Token)
	if p.Status != oast.ProbeStatusExpired {
		t.Fatalf("expected status EXPIRED, got %s", p.Status)
	}

	// Waiting for expired probe should fail immediately
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, err = correlator.WaitForInteraction(ctx, probe.Token, 500*time.Millisecond)
	if err != oast.ErrProbeExpired {
		t.Fatalf("expected ErrProbeExpired when waiting for expired probe, got %v", err)
	}
}

// 5. Test Cross-Assessment Callback Isolation
func TestOAST_CrossAssessmentIsolation(t *testing.T) {
	cfg := oast.DefaultConfig()
	cfg.BaseURL = "http://canary.example.com"
	correlator, _ := oast.NewCorrelator(cfg)
	defer correlator.Close()

	probeA, _ := correlator.GenerateProbe("asm-A", "exec-A", "http://target.local", "/fetch", "url", oast.ProtocolHTTP, 5*time.Second)

	// Callback purporting to be from Assessment B targeting Assessment A's token
	_, err := correlator.RecordInteraction(context.Background(), oast.Interaction{
		Token:        probeA.Token,
		AssessmentID: "asm-B",
	})
	if err != oast.ErrCrossAssessment {
		t.Fatalf("expected ErrCrossAssessment, got %v", err)
	}

	// Valid callback with matching assessment succeeds
	_, err = correlator.RecordInteraction(context.Background(), oast.Interaction{
		Token:        probeA.Token,
		AssessmentID: "asm-A",
	})
	if err != nil {
		t.Fatalf("expected successful correlation for matching assessment, got %v", err)
	}
}

// 6. Test Assessment Probe Cancellation
func TestOAST_ProbeCancellation(t *testing.T) {
	cfg := oast.DefaultConfig()
	cfg.BaseURL = "http://canary.example.com"
	correlator, _ := oast.NewCorrelator(cfg)
	defer correlator.Close()

	probe, _ := correlator.GenerateProbe("asm-cancel", "exec-1", "http://target.local", "/fetch", "url", oast.ProtocolHTTP, 5*time.Second)

	waitErrCh := make(chan error, 1)
	go func() {
		ctx := context.Background()
		_, err := correlator.WaitForInteraction(ctx, probe.Token, 3*time.Second)
		waitErrCh <- err
	}()

	// Allow goroutine to block in waiter
	time.Sleep(30 * time.Millisecond)

	// Cancel probes for this assessment
	correlator.CancelAssessmentProbes("asm-cancel")

	select {
	case err := <-waitErrCh:
		if err != oast.ErrProbeCancelled {
			t.Fatalf("expected ErrProbeCancelled, got %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("waiter did not unblock upon probe cancellation")
	}

	p, _ := correlator.GetProbe(probe.Token)
	if p.Status != oast.ProbeStatusCancelled {
		t.Fatalf("expected status CANCELLED, got %s", p.Status)
	}
}

// 7. Test LocalSimulator End-to-End
func TestOAST_LocalSimulator_EndToEnd(t *testing.T) {
	cfg := oast.DefaultConfig()
	correlator, _ := oast.NewCorrelator(cfg)
	sim := oast.NewLocalSimulator(correlator)
	defer sim.Close()

	probe, err := correlator.GenerateProbe("asm-sim", "exec-sim", "http://example.local", "/api/fetch", "dest", oast.ProtocolHTTP, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to generate probe: %v", err)
	}

	// 1. Verify unknown token returns 404
	resp404, err := http.Get(sim.URL + "/c/unknown-token-123")
	if err != nil || resp404.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown token, got %v (resp: %+v)", err, resp404)
	}
	resp404.Body.Close()

	// 2. Successful callback via path /c/{token}
	req, _ := http.NewRequest("POST", sim.URL+"/c/"+probe.Token, strings.NewReader("payload=canary_evidence"))
	req.Header.Set("User-Agent", "VictimApp/1.0")
	req.Header.Set("Authorization", "Bearer sensitive-secret-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for valid probe callback, got %v (status: %d)", err, resp.StatusCode)
	}
	var resMap map[string]any
	json.NewDecoder(resp.Body).Decode(&resMap)
	resp.Body.Close()

	if resMap["status"] != "correlated" {
		t.Fatalf("expected status correlated, got %+v", resMap)
	}

	// Verify interaction sanitized secret
	p, _ := correlator.GetProbe(probe.Token)
	if len(p.Interactions) != 1 {
		t.Fatalf("expected 1 interaction, got %d", len(p.Interactions))
	}
	inter := p.Interactions[0]
	if strings.Contains(inter.Headers["authorization"], "sensitive-secret-token") {
		t.Fatalf("secret in Authorization header was not redacted: %v", inter.Headers)
	}

	// 3. Duplicate callback returns 200 with duplicate flag
	reqDup, _ := http.NewRequest("GET", sim.URL+"/c/"+probe.Token, nil)
	respDup, err := http.DefaultClient.Do(reqDup)
	if err != nil || respDup.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for duplicate, got status %d", respDup.StatusCode)
	}
	var dupMap map[string]any
	json.NewDecoder(respDup.Body).Decode(&dupMap)
	respDup.Body.Close()
	if dupMap["duplicate"] != true {
		t.Fatalf("expected duplicate true in response, got %+v", dupMap)
	}

	// 4. Query param style callback ?token={token} on a second probe
	probe2, _ := correlator.GenerateProbe("asm-sim", "exec-sim", "http://example.local", "/api/fetch", "dest", oast.ProtocolHTTP, 5*time.Second)
	respQ, err := http.Get(sim.URL + "/?token=" + probe2.Token)
	if err != nil || respQ.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for query token callback, got %d", respQ.StatusCode)
	}
	respQ.Body.Close()
	p2, _ := correlator.GetProbe(probe2.Token)
	if p2.Status != oast.ProbeStatusCorrelated {
		t.Fatalf("expected probe2 to be correlated, got %s", p2.Status)
	}
}

// 8. Test Payload Size Limit Enforcement (HTTP 413)
func TestOAST_LocalSimulator_PayloadLimit(t *testing.T) {
	cfg := oast.DefaultConfig()
	cfg.MaxBodyBytes = 1024 // 1 KB limit
	correlator, _ := oast.NewCorrelator(cfg)
	sim := oast.NewLocalSimulator(correlator)
	defer sim.Close()

	probe, _ := correlator.GenerateProbe("asm-limit", "exec-1", "http://target.local", "/test", "u", oast.ProtocolHTTP, 5*time.Second)

	// Send oversized body (2 KB)
	largeBody := bytes.Repeat([]byte("A"), 2048)
	resp, err := http.Post(sim.URL+"/c/"+probe.Token, "text/plain", bytes.NewReader(largeBody))
	if err != nil {
		t.Fatalf("unexpected HTTP post error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected HTTP 413 Payload Too Large, got status %d", resp.StatusCode)
	}
}

// 9. Test Destination Guardrails & Scope Security Policy
func TestOAST_Guardrails_PolicyEnforcement(t *testing.T) {
	cases := []struct {
		name        string
		url         string
		cfg         oast.Config
		expectValid bool
	}{
		{
			name:        "Valid Public HTTPS",
			url:         "https://canary.sec.corp.example.com/c/123",
			cfg:         oast.DefaultConfig(),
			expectValid: true,
		},
		{
			name:        "Empty URL",
			url:         "",
			cfg:         oast.DefaultConfig(),
			expectValid: false,
		},
		{
			name:        "Unsupported Scheme File",
			url:         "file:///etc/passwd",
			cfg:         oast.DefaultConfig(),
			expectValid: false,
		},
		{
			name:        "Unsupported Scheme Gopher",
			url:         "gopher://canary.example.com:70/",
			cfg:         oast.DefaultConfig(),
			expectValid: false,
		},
		{
			name:        "Embedded Credentials Prohibited",
			url:         "https://admin:secret@canary.example.com",
			cfg:         oast.DefaultConfig(),
			expectValid: false,
		},
		{
			name:        "Loopback 127.0.0.1 Blocked By Default",
			url:         "http://127.0.0.1:8080/canary",
			cfg:         oast.DefaultConfig(),
			expectValid: false,
		},
		{
			name:        "Loopback Localhost Blocked By Default",
			url:         "http://localhost:9000/canary",
			cfg:         oast.DefaultConfig(),
			expectValid: false,
		},
		{
			name: "Loopback Allowed When Explicitly Configured",
			url:  "http://127.0.0.1:8080/canary",
			cfg: func() oast.Config {
				c := oast.DefaultConfig()
				c.AllowLoopback = true
				return c
			}(),
			expectValid: true,
		},
		{
			name:        "Private IP RFC 1918 (10.x.x.x) Blocked By Default",
			url:         "http://10.20.30.40/canary",
			cfg:         oast.DefaultConfig(),
			expectValid: false,
		},
		{
			name:        "Private IP RFC 1918 (172.16.x.x) Blocked By Default",
			url:         "http://172.16.0.5/canary",
			cfg:         oast.DefaultConfig(),
			expectValid: false,
		},
		{
			name:        "Private IP RFC 1918 (192.168.x.x) Blocked By Default",
			url:         "http://192.168.1.100/canary",
			cfg:         oast.DefaultConfig(),
			expectValid: false,
		},
		{
			name:        "AWS Cloud Metadata IP Strictly Prohibited",
			url:         "http://169.254.169.254/latest/meta-data/",
			cfg:         oast.DefaultConfig(),
			expectValid: false,
		},
		{
			name:        "GCP Metadata Hostname Strictly Prohibited",
			url:         "http://metadata.google.internal/computeMetadata/v1/",
			cfg:         oast.DefaultConfig(),
			expectValid: false,
		},
		{
			name:        "Dword Encoded Loopback Blocked (2130706433)",
			url:         "http://2130706433/canary",
			cfg:         oast.DefaultConfig(),
			expectValid: false,
		},
		{
			name:        "Octal Encoded Loopback Blocked (0177.0.0.1)",
			url:         "http://0177.0.0.1/canary",
			cfg:         oast.DefaultConfig(),
			expectValid: false,
		},
		{
			name: "Authorized Hosts Whitelist - Match Allowed",
			url:  "https://canary.allowed.org/callback",
			cfg: func() oast.Config {
				c := oast.DefaultConfig()
				c.AuthorizedHosts = []string{"canary.allowed.org"}
				return c
			}(),
			expectValid: true,
		},
		{
			name: "Authorized Hosts Whitelist - Subdomain Match Allowed",
			url:  "https://sub1.canary.allowed.org/callback",
			cfg: func() oast.Config {
				c := oast.DefaultConfig()
				c.AuthorizedHosts = []string{"*.canary.allowed.org"}
				return c
			}(),
			expectValid: true,
		},
		{
			name: "Authorized Hosts Whitelist - Unauthorized Host Rejected",
			url:  "https://evil.unauthorized.com/callback",
			cfg: func() oast.Config {
				c := oast.DefaultConfig()
				c.AuthorizedHosts = []string{"canary.allowed.org"}
				return c
			}(),
			expectValid: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := oast.ValidateCanaryDestination(tc.url, tc.cfg)
			if tc.expectValid && err != nil {
				t.Fatalf("expected valid for %q, got error: %v", tc.url, err)
			}
			if !tc.expectValid && err == nil {
				t.Fatalf("expected error for %q, but validation succeeded", tc.url)
			}
		})
	}
}

// 10. Test Input Sanitization and Secrets Redaction
func TestOAST_SanitizationAndRedaction(t *testing.T) {
	rawInput := "Hello\x00World\r\nBearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDN\x07Password: supersecret123"
	clean := oast.SanitizeInteractionData(rawInput)

	if strings.Contains(clean, "\x00") {
		t.Error("null bytes not stripped")
	}
	if strings.Contains(clean, "\x07") {
		t.Error("bell control character not stripped")
	}
	// JWT should be redacted
	if strings.Contains(clean, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") {
		t.Error("JWT token was not redacted by SanitizeInteractionData")
	}
}

// 11. Test WebVuln SSRF Integration: Promotion to StateVerified on Verified Callback
func TestOAST_WebVuln_SSRF_PromotionToVerified(t *testing.T) {
	// Start local OAST simulator
	cfg := oast.DefaultConfig()
	correlator, _ := oast.NewCorrelator(cfg)
	sim := oast.NewLocalSimulator(correlator)
	defer sim.Close()

	// Target application server simulating an SSRF vulnerability
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dest := r.URL.Query().Get("url")
		if dest != "" {
			// Trigger HTTP callback to the canary destination
			go func(callbackURL string) {
				time.Sleep(20 * time.Millisecond)
				resp, err := http.Get(callbackURL)
				if err == nil {
					resp.Body.Close()
				}
			}(dest)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer targetServer.Close()

	webCfg := webvuln.DefaultConfig()
	webCfg.OASTCorrelator = correlator
	webCfg.OASTTimeout = 500 * time.Millisecond

	engine := webvuln.NewEngine(targetServer.Client(), webCfg)

	actx := &webvuln.AssessmentContext{
		AssessmentID: "asm-web-ssrf",
		ExecutionID:  "exec-web-ssrf",
		BaseURL:      targetServer.URL,
		Endpoints: []webvuln.TargetEndpoint{
			{
				Path:       "/fetch",
				Method:     "GET",
				Parameters: []string{"url"},
			},
		},
	}

	res, _, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected engine error: %v", err)
	}

	cov := summary.CoverageMap[string(webvuln.CategorySSRF)]
	if cov.Verified != 1 {
		t.Fatalf("expected 1 verified finding in coverage, got %d (candidates: %d)", cov.Verified, cov.Candidates)
	}

	foundVerified := false
	for _, r := range res {
		if r.Category == webvuln.CategorySSRF && r.VerificationState == webvuln.StateVerified {
			foundVerified = true
			if r.Severity != "HIGH" {
				t.Errorf("expected HIGH severity for verified SSRF, got %s", r.Severity)
			}
			if !strings.Contains(r.EvidenceSummary, "Verified SSRF out-of-band callback") {
				t.Errorf("unexpected evidence summary: %s", r.EvidenceSummary)
			}
		}
	}
	if !foundVerified {
		t.Fatalf("expected at least one StateVerified result, got %+v", res)
	}
}

// 12. Test APISec SSRF Integration: Promotion to StateVerified on Verified Callback
func TestOAST_APISec_SSRF_PromotionToVerified(t *testing.T) {
	cfg := oast.DefaultConfig()
	correlator, _ := oast.NewCorrelator(cfg)
	sim := oast.NewLocalSimulator(correlator)
	defer sim.Close()

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dest := r.URL.Query().Get("dest")
		if dest != "" {
			go func(cb string) {
				time.Sleep(20 * time.Millisecond)
				resp, err := http.Get(cb)
				if err == nil {
					resp.Body.Close()
				}
			}(dest)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success"}`))
	}))
	defer targetServer.Close()

	apiCfg := apisec.DefaultConfig()
	apiCfg.OASTCorrelator = correlator
	apiCfg.OASTTimeout = 500 * time.Millisecond

	engine := apisec.NewEngine(targetServer.Client(), apiCfg)

	actx := &apisec.AssessmentContext{
		AssessmentID: "asm-api-ssrf",
		ExecutionID:  "exec-api-ssrf",
		BaseURL:      targetServer.URL,
		Endpoints: []apisec.APIEndpoint{
			{
				Path:         "/api/v1/import",
				Method:       "GET",
				HasURLParam:  true,
				URLParamName: "dest",
			},
		},
	}

	res, findings, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected engine error: %v", err)
	}

	cov := summary.CoverageMap[string(apisec.CategoryAPI7_SSRF)]
	if cov.Verified != 1 {
		t.Fatalf("expected 1 verified finding in coverage, got %d (candidates: %d)", cov.Verified, cov.Candidates)
	}

	foundFinding := false
	for _, f := range findings {
		if strings.Contains(f.Title, "API7:2023") {
			foundFinding = true
			break
		}
	}
	if !foundFinding {
		t.Fatalf("expected at least 1 API7 report finding emitted, got %+v", findings)
	}

	foundVerified := false
	for _, r := range res {
		if r.Category == apisec.CategoryAPI7_SSRF && r.VerificationState == apisec.StateVerified {
			foundVerified = true
			if r.Severity != "HIGH" {
				t.Errorf("expected HIGH severity for verified SSRF, got %s", r.Severity)
			}
			if !strings.Contains(r.EvidenceSummary, "SSRF verified via out-of-band callback") {
				t.Errorf("unexpected evidence summary: %s", r.EvidenceSummary)
			}
		}
	}
	if !foundVerified {
		t.Fatalf("expected at least one StateVerified result, got %+v", res)
	}
}

// 13. Test No Callback Retains StateCandidate
func TestOAST_WebVuln_NoCallback_RetainsCandidate(t *testing.T) {
	cfg := oast.DefaultConfig()
	correlator, _ := oast.NewCorrelator(cfg)
	sim := oast.NewLocalSimulator(correlator)
	defer sim.Close()

	// Server that does NOT trigger the callback
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Ignored callback URL"))
	}))
	defer targetServer.Close()

	webCfg := webvuln.DefaultConfig()
	webCfg.OASTCorrelator = correlator
	webCfg.OASTTimeout = 50 * time.Millisecond // short wait

	engine := webvuln.NewEngine(targetServer.Client(), webCfg)

	actx := &webvuln.AssessmentContext{
		AssessmentID: "asm-nocallback",
		ExecutionID:  "exec-nocallback",
		BaseURL:      targetServer.URL,
		Endpoints: []webvuln.TargetEndpoint{
			{
				Path:       "/fetch",
				Method:     "GET",
				Parameters: []string{"url"},
			},
		},
	}

	res, _, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected engine error: %v", err)
	}

	cov := summary.CoverageMap[string(webvuln.CategorySSRF)]
	if cov.Verified != 0 {
		t.Fatalf("expected 0 verified findings, got %d", cov.Verified)
	}
	if cov.Candidates != 1 {
		t.Fatalf("expected 1 candidate finding, got %d", cov.Candidates)
	}
	foundCandidate := false
	for _, r := range res {
		if r.Category == webvuln.CategorySSRF && r.VerificationState == webvuln.StateCandidate {
			foundCandidate = true
			break
		}
	}
	if !foundCandidate {
		t.Fatalf("expected result state Candidate for SSRF, got %+v", res)
	}
}

// 14. Test Concurrency Safety Across 50 Goroutines
func TestOAST_ConcurrencyStress(t *testing.T) {
	cfg := oast.DefaultConfig()
	correlator, _ := oast.NewCorrelator(cfg)
	sim := oast.NewLocalSimulator(correlator)
	defer sim.Close()

	const workers = 50
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			asmID := fmt.Sprintf("asm-%d", idx)
			probe, err := correlator.GenerateProbe(asmID, "exec", "http://t.local", "/p", "q", oast.ProtocolHTTP, 2*time.Second)
			if err != nil {
				t.Errorf("worker %d failed to generate probe: %v", idx, err)
				return
			}

			// Perform callback via simulator
			resp, err := http.Get(sim.URL + "/c/" + probe.Token)
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Errorf("worker %d callback failed: %v", idx, err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			// Wait for interaction
			inter, err := correlator.WaitForInteraction(context.Background(), probe.Token, 500*time.Millisecond)
			if err != nil || inter == nil {
				t.Errorf("worker %d wait failed: %v", idx, err)
				return
			}
		}(i)
	}

	wg.Wait()
}

// 15. Adversarial Test: DNS Resolution & Rebinding
func TestOAST_Guardrails_Adversarial_DNSResolution(t *testing.T) {
	// Custom mock DNS resolver simulating various DNS responses
	dnsResponses := map[string][]net.IP{
		"loopback.rebind.attacker.com": {net.ParseIP("127.0.0.1")},
		"metadata.rebind.attacker.com": {net.ParseIP("169.254.169.254")},
		"private.rebind.attacker.com":  {net.ParseIP("10.0.0.1")},
		"dualhomed.attacker.com":       {net.ParseIP("93.184.216.34"), net.ParseIP("127.0.0.1")},
		"valid.canary.example.com":     {net.ParseIP("93.184.216.34")},
	}

	cfg := oast.DefaultConfig()
	cfg.DNSResolver = func(ctx context.Context, host string) ([]net.IP, error) {
		if ips, ok := dnsResponses[host]; ok {
			return ips, nil
		}
		return nil, fmt.Errorf("nxdomain")
	}

	cases := []struct {
		name        string
		url         string
		expectError bool
	}{
		{
			name:        "DNS Resolves to Loopback Blocked",
			url:         "http://loopback.rebind.attacker.com/canary",
			expectError: true,
		},
		{
			name:        "DNS Resolves to Cloud Metadata Blocked",
			url:         "http://metadata.rebind.attacker.com/canary",
			expectError: true,
		},
		{
			name:        "DNS Resolves to Private IP Blocked",
			url:         "http://private.rebind.attacker.com/canary",
			expectError: true,
		},
		{
			name:        "Dual-Homed DNS (Public + Loopback) Blocked",
			url:         "http://dualhomed.attacker.com/canary",
			expectError: true,
		},
		{
			name:        "Valid Public IP Allowed",
			url:         "http://valid.canary.example.com/canary",
			expectError: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := oast.ValidateCanaryDestination(tc.url, cfg)
			if tc.expectError && err == nil {
				t.Fatalf("expected error for %q, but validation passed", tc.url)
			}
			if !tc.expectError && err != nil {
				t.Fatalf("expected valid for %q, got error: %v", tc.url, err)
			}
		})
	}
}

// 16. Adversarial Test: Wildcard Allowlist Lookalike Suffix Boundary
func TestOAST_Guardrails_Adversarial_WildcardAllowlist(t *testing.T) {
	cfg := oast.DefaultConfig()
	cfg.AuthorizedHosts = []string{"*.corp.example.com"}

	cases := []struct {
		url         string
		expectValid bool
	}{
		{"https://corp.example.com/c", true},
		{"https://sub.corp.example.com/c", true},
		{"https://a.b.corp.example.com/c", true},
		{"https://attacker-corp.example.com/c", false},     // lookalike suffix
		{"https://notcorp.example.com/c", false},          // missing dot boundary
		{"https://corp.example.com.attacker.com/c", false}, // domain as prefix of evil domain
	}

	for _, tc := range cases {
		err := oast.ValidateCanaryDestination(tc.url, cfg)
		if tc.expectValid && err != nil {
			t.Errorf("expected %q to be valid, got: %v", tc.url, err)
		}
		if !tc.expectValid && err == nil {
			t.Errorf("expected %q to be rejected, but it was accepted", tc.url)
		}
	}
}

// 17. Adversarial Test: IPv4-Mapped IPv6 and Alternate IP Representations
func TestOAST_Guardrails_Adversarial_IPv4MappedIPv6AndAlternateIPs(t *testing.T) {
	cfg := oast.DefaultConfig()

	cases := []struct {
		name string
		url  string
	}{
		{"IPv4-mapped IPv6 Loopback", "http://[::ffff:127.0.0.1]:8080/canary"},
		{"IPv4-mapped IPv6 Metadata", "http://[::ffff:169.254.169.254]/canary"},
		{"IPv4-mapped IPv6 Private", "http://[::ffff:192.168.1.1]/canary"},
		{"AWS IPv6 IMDSv2 Endpoint", "http://[fd00:ec2::254]/latest/meta-data"},
		{"Standard Loopback IPv6", "http://[::1]:8080/canary"},
		{"Standard IPv6 ULA", "http://[fc00::1]/canary"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := oast.ValidateCanaryDestination(tc.url, cfg)
			if err == nil {
				t.Fatalf("expected rejection for %q, but got nil error", tc.url)
			}
		})
	}
}

// 18. Adversarial Test: Malformed Hostnames
func TestOAST_Guardrails_Adversarial_MalformedHostnames(t *testing.T) {
	cfg := oast.DefaultConfig()

	malformed := []string{
		"http://example .com/c",
		"http://example\t.com/c",
		"http://example\r\n.com/c",
		"http://example/evil/c",
		"http://.example.com/c",
		"http://example.com./c",
		"http://example\\evil.com/c",
		"javascript:alert(1)",
		"data:text/html;base64,PHNjcmlwdD4=",
	}

	for _, u := range malformed {
		err := oast.ValidateCanaryDestination(u, cfg)
		if err == nil {
			t.Errorf("expected malformed URL %q to be rejected, but passed", u)
		}
	}
}

// 19. Adversarial Test: Transport-Level Redirect Protection
func TestOAST_Transport_RedirectToInternalBlocked(t *testing.T) {
	// Target server redirects to internal addresses
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect-metadata":
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
		case "/redirect-private":
			http.Redirect(w, r, "http://10.200.1.1/internal-secret", http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer targetServer.Close()

	engine := apisec.NewEngine(nil, apisec.DefaultConfig())
	actx := &apisec.AssessmentContext{
		AssessmentID: "asm-redir-test",
		BaseURL:      targetServer.URL,
	}
	client := engine.ScopedClient(actx)

	// 1. Redirect to cloud metadata must be refused
	_, err := client.Get(targetServer.URL + "/redirect-metadata")
	if err == nil {
		t.Fatal("expected redirect to cloud metadata to be refused by client CheckRedirect")
	}
	if !strings.Contains(err.Error(), "cloud metadata") {
		t.Errorf("expected error message to mention cloud metadata, got: %v", err)
	}

	// 2. Redirect to private IP must be refused
	_, err = client.Get(targetServer.URL + "/redirect-private")
	if err == nil {
		t.Fatal("expected redirect to private IP to be refused by client CheckRedirect")
	}
}

// 20. Adversarial Test: Terminal State Snapshot Immutability and Late Callback Rejection
func TestOAST_Adversarial_TerminalState_LateCallbackRejected(t *testing.T) {
	store, err := assessment.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer store.Close()

	if err := store.CreateClient(&assessment.Client{ID: "client-1", Name: "Test Client"}); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	asmID := "asm-term-test"
	asm := &assessment.Assessment{
		ID:             asmID,
		Ref:            "ASM-TERM-001",
		ClientID:       "client-1",
		Name:           "OAST Terminal State Test",
		AssessmentType: "WEB_SECURITY",
		Status:         assessment.StatusDraft,
		ScopeMode:      "same-origin",
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	correlator, _ := oast.NewCorrelator(oast.DefaultConfig())
	sim := oast.NewLocalSimulator(correlator)
	defer sim.Close()

	// Generate probe for this assessment
	probe, err := correlator.GenerateProbe(asm.ID, "exec-1", "http://target.local", "/fetch", "url", oast.ProtocolHTTP, 10*time.Second)
	if err != nil {
		t.Fatalf("failed to generate probe: %v", err)
	}

	// Record execution in store and finalize to COMPLETED
	exec := &assessment.AssessmentExecution{
		ID:           "exec-1",
		AssessmentID: asm.ID,
		Status:       assessment.StatusRunning,
	}
	_ = store.CreateExecution(exec)
	exec.Status = assessment.StatusCompleted
	_ = store.UpdateExecution(exec)

	// Cleanup assessment probes (as Controller defer does upon assessment termination)
	correlator.CancelAssessmentProbes(asm.ID)

	// An adversary attempts to send a late callback targeting the probe token
	resp, err := http.Get(sim.URL + "/c/" + probe.Token)
	if err != nil {
		t.Fatalf("unexpected HTTP error: %v", err)
	}
	defer resp.Body.Close()

	// Must be rejected with 410 Gone because probe was cancelled upon assessment termination
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("expected HTTP 410 Gone for late callback on terminated assessment, got %d", resp.StatusCode)
	}

	// Execution record in store remains COMPLETED with 0 findings
	finalExec, err := store.GetExecution(exec.ID)
	if err != nil {
		t.Fatalf("failed to retrieve execution: %v", err)
	}
	if finalExec.Status != assessment.StatusCompleted {
		t.Fatalf("execution status was corrupted: got %s", finalExec.Status)
	}
	if finalExec.FindingCount != 0 {
		t.Fatalf("execution finding count was mutated by late callback: got %d", finalExec.FindingCount)
	}
}

// 21. Adversarial Test: Untrusted Content Injection in Callback Receiver
func TestOAST_Adversarial_InjectionInCallback(t *testing.T) {
	correlator, _ := oast.NewCorrelator(oast.DefaultConfig())
	sim := oast.NewLocalSimulator(correlator)
	defer sim.Close()

	probe, err := correlator.GenerateProbe("asm-inj", "exec-1", "http://t.local", "/test", "u", oast.ProtocolHTTP, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to generate probe: %v", err)
	}

	// Send callback with ANSI escape codes, null bytes, XSS payload in headers and body, and API secret
	bodyPayload := "raw_evidence=<script>alert(1)</script>\x00\x1b[31;1mDanger\x1b[0m\r\nAuthorization: Bearer secret-leaked-key-12345"
	req, err := http.NewRequest("POST", sim.URL+"/c/"+probe.Token, strings.NewReader(bodyPayload))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("X-Custom-Header", "<script>alert('header-xss')</script>")
	req.Header.Set("Authorization", "Bearer sensitive-auth-token-67890")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("expected 200 OK, got error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 OK, got status %d: %s", resp.StatusCode, string(b))
	}

	p, _ := correlator.GetProbe(probe.Token)
	if len(p.Interactions) != 1 {
		t.Fatalf("expected 1 recorded interaction, got %d", len(p.Interactions))
	}

	inter := p.Interactions[0]
	// Verify null bytes and bell control characters stripped
	if strings.Contains(inter.Body, "\x00") || strings.Contains(inter.Body, "\x1b") {
		t.Error("control characters or ANSI escape codes not stripped from body")
	}
	if !strings.Contains(inter.Headers["x-custom-header"], "header-xss") {
		t.Error("expected custom header value to be preserved cleanly")
	}
	// Verify secrets in header and body were redacted
	if strings.Contains(inter.Headers["authorization"], "sensitive-auth-token-67890") {
		t.Error("raw secret in Authorization header leaked unredacted")
	}
}

// 22. Test Standalone Receiver (ServeHTTP) Mountable on Any Server
func TestOAST_StandaloneReceiver_ServeHTTP(t *testing.T) {
	correlator, _ := oast.NewCorrelator(oast.DefaultConfig())
	correlator.SetAllowLoopback(true)
	defer correlator.Close()

	receiver := oast.NewReceiver(correlator)

	mux := http.NewServeMux()
	mux.Handle("/custom/callback/", http.StripPrefix("/custom/callback", receiver))

	server := httptest.NewServer(mux)
	defer server.Close()

	correlator.SetBaseURL(server.URL + "/custom/callback")

	probe, err := correlator.GenerateProbe("asm-rcv", "exec-1", "http://t.local", "/dest", "p", oast.ProtocolHTTP, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to generate probe: %v", err)
	}

	resp, err := http.Get(probe.CallbackURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from custom mounted receiver, got %v (status: %d)", err, resp.StatusCode)
	}
	resp.Body.Close()

	p, _ := correlator.GetProbe(probe.Token)
	if p.Status != oast.ProbeStatusCorrelated {
		t.Fatalf("expected probe status CORRELATED, got %s", p.Status)
	}
}
