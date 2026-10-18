package apk

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/report"
)

// helper to create a valid authorization record for tests
func newTestAuth(party string) *assessment.AuthorizationRecord {
	validFrom := time.Now().Add(-1 * time.Hour)
	validUntil := time.Now().Add(24 * time.Hour)
	return &assessment.AuthorizationRecord{
		ID:                  "auth-test-1",
		AuthorizingParty:    party,
		AuthorizationMethod: "WRITTEN_CONTRACT",
		Status:              assessment.AuthApproved,
		ValidFrom:           &validFrom,
		ValidUntil:          &validUntil,
	}
}

// 1. Scope and Authorization Tests
func TestHandoff_ScopeAndAuthorization(t *testing.T) {
	// Local test server
	var serverRequests int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&serverRequests, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	authRecord := newTestAuth("Security Team")

	t.Run("In_Scope_Host_Eligible_And_Tested", func(t *testing.T) {
		atomic.StoreInt32(&serverRequests, 0)
		inv := &BackendInventory{
			APKSHA256: "test-sha-1",
			Endpoints: []EndpointEntry{
				{
					NormalizedURL:  ts.URL + "/api/v1/health",
					Scheme:         "http",
					Host:           ts.Listener.Addr().String(),
					Path:           "/api/v1/health",
					HostIdentity:   ts.Listener.Addr().String(),
					Category:       CategoryAPI,
					Classification: ClassificationConfirmedReference,
					Confidence:     report.ConfidenceHigh,
				},
			},
		}

		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL}
		cfg.Authorization = authRecord
		cfg.AllowLoopback = true // loopback mock server
		cfg.ScopeMode = "same-origin"

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rep.TotalTested != 1 {
			t.Errorf("expected 1 tested, got %d", rep.TotalTested)
		}
		if rep.TotalSkipped != 0 {
			t.Errorf("expected 0 skipped, got %d", rep.TotalSkipped)
		}
		if atomic.LoadInt32(&serverRequests) != 1 {
			t.Errorf("expected 1 network request, got %d", atomic.LoadInt32(&serverRequests))
		}
	})

	t.Run("Out_Of_Scope_Host_Skipped_Zero_Requests", func(t *testing.T) {
		atomic.StoreInt32(&serverRequests, 0)
		inv := &BackendInventory{
			APKSHA256: "test-sha-1",
			Endpoints: []EndpointEntry{
				{
					NormalizedURL:  "https://unauthorized.evilcorp.com/api/v1/users",
					Scheme:         "https",
					Host:           "unauthorized.evilcorp.com",
					Path:           "/api/v1/users",
					HostIdentity:   "unauthorized.evilcorp.com",
					Category:       CategoryAPI,
					Classification: ClassificationConfirmedReference,
					Confidence:     report.ConfidenceHigh,
				},
			},
		}

		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL}
		cfg.Authorization = authRecord
		cfg.AllowLoopback = true

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rep.TotalTested != 0 {
			t.Errorf("expected 0 tested, got %d", rep.TotalTested)
		}
		if rep.TotalSkipped != 1 {
			t.Errorf("expected 1 skipped, got %d", rep.TotalSkipped)
		}
		if rep.Results[0].ReasonCode != "OUT_OF_SCOPE" {
			t.Errorf("expected reason OUT_OF_SCOPE, got: %s", rep.Results[0].ReasonCode)
		}
		if rep.Results[0].RequestDispatched {
			t.Errorf("expected RequestDispatched=false")
		}
		if rep.TotalRequestsSent != 0 {
			t.Errorf("expected 0 requests sent, got %d", rep.TotalRequestsSent)
		}
	})

	t.Run("Deceptive_Domain_Suffix_Rejected", func(t *testing.T) {
		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{
					NormalizedURL:  "https://mycorp.com.attacker.test/api/v1/leak",
					Scheme:         "https",
					Host:           "mycorp.com.attacker.test",
					Path:           "/api/v1/leak",
					HostIdentity:   "mycorp.com.attacker.test",
					Category:       CategoryAPI,
					Classification: ClassificationConfirmedReference,
				},
			},
		}

		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{"https://mycorp.com"}
		cfg.Authorization = authRecord
		cfg.ScopeMode = "subdomains" // even under subdomains mode, deceptive suffix must NOT match!

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rep.TotalTested != 0 || rep.TotalSkipped != 1 {
			t.Fatalf("expected 0 tested, 1 skipped; got %d tested, %d skipped", rep.TotalTested, rep.TotalSkipped)
		}
		if rep.Results[0].ReasonCode != "OUT_OF_SCOPE" {
			t.Errorf("expected OUT_OF_SCOPE, got: %s", rep.Results[0].ReasonCode)
		}
	})

	t.Run("Unauthorized_Third_Party_Skipped", func(t *testing.T) {
		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{
					NormalizedURL:  "https://my-app.firebaseio.com/users.json",
					Scheme:         "https",
					Host:           "my-app.firebaseio.com",
					Path:           "/users.json",
					HostIdentity:   "my-app.firebaseio.com",
					Category:       CategoryFirebase,
					Classification: ClassificationConfirmedReference,
				},
				{
					NormalizedURL:  "https://my-bucket.s3.amazonaws.com/data.csv",
					Scheme:         "https",
					Host:           "my-bucket.s3.amazonaws.com",
					Path:           "/data.csv",
					HostIdentity:   "my-bucket.s3.amazonaws.com",
					Category:       CategoryStorage,
					Classification: ClassificationConfirmedReference,
				},
				{
					NormalizedURL:  "https://o12345.ingest.sentry.io/api/123/envelope/",
					Scheme:         "https",
					Host:           "o12345.ingest.sentry.io",
					Path:           "/api/123/envelope/",
					HostIdentity:   "o12345.ingest.sentry.io",
					Category:       CategoryCloudService,
					Classification: ClassificationConfirmedReference,
				},
			},
		}

		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{"https://mycorp.com"}
		cfg.Authorization = authRecord

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rep.TotalTested != 0 || rep.TotalSkipped != 3 {
			t.Fatalf("expected 0 tested, 3 skipped; got tested=%d, skipped=%d", rep.TotalTested, rep.TotalSkipped)
		}
		for _, r := range rep.Results {
			if r.ReasonCode != "OUT_OF_SCOPE" && r.ReasonCode != "UNAUTHORIZED_THIRD_PARTY" {
				t.Errorf("expected out of scope / third party exclusion, got: %s", r.ReasonCode)
			}
		}
	})

	t.Run("Explicit_Exclusion_Takes_Precedence", func(t *testing.T) {
		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{
					NormalizedURL:  ts.URL + "/admin/delete_all",
					Scheme:         "http",
					Host:           ts.Listener.Addr().String(),
					Path:           "/admin/delete_all",
					HostIdentity:   ts.Listener.Addr().String(),
					Category:       CategoryAPI,
					Classification: ClassificationConfirmedReference,
				},
			},
		}

		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL}
		cfg.Authorization = authRecord
		cfg.AllowLoopback = true
		cfg.Exclusions = []assessment.Exclusion{
			{
				ExclusionType: assessment.ExclusionPathPrefix,
				Pattern:       "/admin",
				Reason:        "Production danger",
			},
		}

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rep.TotalTested != 0 || rep.TotalSkipped != 1 {
			t.Fatalf("expected 0 tested, 1 skipped; got tested=%d, skipped=%d", rep.TotalTested, rep.TotalSkipped)
		}
		if rep.Results[0].ReasonCode != "EXCLUDED" {
			t.Errorf("expected EXCLUDED, got %s", rep.Results[0].ReasonCode)
		}
	})

	t.Run("Missing_Or_Invalid_Authorization_Fails_Closed", func(t *testing.T) {
		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{
					NormalizedURL:  ts.URL + "/api/v1/health",
					Scheme:         "http",
					Host:           ts.Listener.Addr().String(),
					Path:           "/api/v1/health",
					HostIdentity:   ts.Listener.Addr().String(),
					Category:       CategoryAPI,
					Classification: ClassificationConfirmedReference,
				},
			},
		}

		cfgNoAuth := DefaultHandoffConfig()
		cfgNoAuth.AuthorizedTargets = []string{ts.URL}
		cfgNoAuth.Authorization = nil // Missing!

		_, err := ExecuteHandoff(context.Background(), inv, cfgNoAuth)
		if err == nil || !strings.Contains(err.Error(), "authorization record is required") {
			t.Fatalf("expected missing authorization error, got: %v", err)
		}

		// Expired Auth
		expiredTime := time.Now().Add(-2 * time.Hour)
		expiredAuth := &assessment.AuthorizationRecord{
			Status:     assessment.AuthApproved,
			ValidUntil: &expiredTime,
		}
		cfgExpired := DefaultHandoffConfig()
		cfgExpired.AuthorizedTargets = []string{ts.URL}
		cfgExpired.Authorization = expiredAuth

		_, err = ExecuteHandoff(context.Background(), inv, cfgExpired)
		if err == nil || !strings.Contains(err.Error(), "invalid authorization") {
			t.Fatalf("expected invalid authorization error, got: %v", err)
		}
	})

	t.Run("Inferred_And_Unresolved_Routes_Follow_Policy", func(t *testing.T) {
		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{
					// Unresolved route
					NormalizedURL:  "/api/v1/unresolved",
					Path:           "/api/v1/unresolved",
					HostIdentity:   "(unresolved)",
					Classification: ClassificationInferredRoute,
				},
				{
					// Inferred route with resolved base
					NormalizedURL:  ts.URL + "/api/v1/inferred",
					Scheme:         "http",
					Host:           ts.Listener.Addr().String(),
					Path:           "/api/v1/inferred",
					HostIdentity:   ts.Listener.Addr().String(),
					Classification: ClassificationInferredRoute,
				},
			},
		}

		// Default: AllowInferredRoutes = false
		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL}
		cfg.Authorization = authRecord
		cfg.AllowLoopback = true
		cfg.AllowInferredRoutes = false

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rep.TotalTested != 0 || rep.TotalSkipped != 2 {
			t.Fatalf("expected 0 tested, 2 skipped; got tested=%d, skipped=%d", rep.TotalTested, rep.TotalSkipped)
		}
		if rep.Results[0].ReasonCode != "UNRESOLVED_ROUTE" {
			t.Errorf("expected UNRESOLVED_ROUTE, got %s", rep.Results[0].ReasonCode)
		}
		if rep.Results[1].ReasonCode != "INFERRED_ROUTE_DISABLED" {
			t.Errorf("expected INFERRED_ROUTE_DISABLED, got %s", rep.Results[1].ReasonCode)
		}

		// Now enable AllowInferredRoutes: resolved inferred route should be tested, but unresolved remains skipped!
		cfg.AllowInferredRoutes = true
		rep2, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rep2.TotalTested != 1 || rep2.TotalSkipped != 1 {
			t.Fatalf("expected 1 tested, 1 skipped; got tested=%d, skipped=%d", rep2.TotalTested, rep2.TotalSkipped)
		}
		if rep2.Results[0].ReasonCode != "UNRESOLVED_ROUTE" {
			t.Errorf("unresolved route must still be UNRESOLVED_ROUTE, got %s", rep2.Results[0].ReasonCode)
		}
		if rep2.Results[1].Disposition != DispositionTested {
			t.Errorf("resolved inferred route should be tested, got %s", rep2.Results[1].Disposition)
		}
	})
}

// 2. Redirect and Connection Safety Tests
func TestHandoff_RedirectAndConnectionSafety(t *testing.T) {
	authRecord := newTestAuth("Security Audit")

	t.Run("Redirect_To_Out_Of_Scope_Host_Blocked", func(t *testing.T) {
		// Mock server that attempts to redirect to an out-of-scope host
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://evil-attacker.example.com/steal", http.StatusFound)
		}))
		defer ts.Close()

		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{
					NormalizedURL:  ts.URL + "/redirect",
					Scheme:         "http",
					Host:           ts.Listener.Addr().String(),
					Path:           "/redirect",
					HostIdentity:   ts.Listener.Addr().String(),
					Category:       CategoryAPI,
					Classification: ClassificationConfirmedReference,
				},
			},
		}

		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL}
		cfg.Authorization = authRecord
		cfg.AllowLoopback = true

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rep.TotalFailed != 1 {
			t.Fatalf("expected 1 failed (redirect blocked by scope), got %d failed, %d tested, %d skipped", rep.TotalFailed, rep.TotalTested, rep.TotalSkipped)
		}
		if !strings.Contains(rep.Results[0].ReasonMessage, "redirect") {
			t.Errorf("expected redirect failure reason, got: %s", rep.Results[0].ReasonMessage)
		}
	})

	t.Run("Redirect_Loop_Terminates_Safely", func(t *testing.T) {
		var loopServer *httptest.Server
		loopServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, loopServer.URL+"/loop", http.StatusFound)
		}))
		defer loopServer.Close()

		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{
					NormalizedURL:  loopServer.URL + "/loop",
					Scheme:         "http",
					Host:           loopServer.Listener.Addr().String(),
					Path:           "/loop",
					HostIdentity:   loopServer.Listener.Addr().String(),
					Category:       CategoryAPI,
					Classification: ClassificationConfirmedReference,
				},
			},
		}

		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{loopServer.URL}
		cfg.Authorization = authRecord
		cfg.AllowLoopback = true
		cfg.MaxRedirects = 3

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rep.TotalFailed != 1 {
			t.Fatalf("expected 1 failed (stopped after redirects), got %d failed, %d tested", rep.TotalFailed, rep.TotalTested)
		}
		if !strings.Contains(rep.Results[0].ReasonMessage, "stopped after") {
			t.Errorf("expected stopped after redirects message, got: %s", rep.Results[0].ReasonMessage)
		}
	})

	t.Run("Prohibited_IP_Literals_Blocked", func(t *testing.T) {
		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{
					NormalizedURL:  "http://127.0.0.1:8080/metrics",
					Scheme:         "http",
					Host:           "127.0.0.1:8080",
					Path:           "/metrics",
					HostIdentity:   "127.0.0.1:8080",
					Category:       CategoryAPI,
					Classification: ClassificationConfirmedReference,
				},
				{
					NormalizedURL:  "http://169.254.169.254/latest/meta-data/",
					Scheme:         "http",
					Host:           "169.254.169.254",
					Path:           "/latest/meta-data/",
					HostIdentity:   "169.254.169.254",
					Category:       CategoryAPI,
					Classification: ClassificationConfirmedReference,
				},
			},
		}

		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{"http://127.0.0.1:8080", "http://169.254.169.254"}
		cfg.Authorization = authRecord
		cfg.AllowLoopback = false   // Prohibit loopback!
		cfg.AllowPrivateIPs = false // Prohibit link-local/private!

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rep.TotalSkipped != 2 || rep.TotalTested != 0 {
			t.Fatalf("expected 2 skipped for prohibited IPs, got tested=%d, skipped=%d", rep.TotalTested, rep.TotalSkipped)
		}
		for _, r := range rep.Results {
			if r.ReasonCode != "PROHIBITED_IP" {
				t.Errorf("expected PROHIBITED_IP, got: %s", r.ReasonCode)
			}
		}
	})
}

// 3. Timeouts and Budgets Tests
func TestHandoff_TimeoutsAndBudgets(t *testing.T) {
	authRecord := newTestAuth("Operations")

	t.Run("Global_Request_Budget_Enforcement", func(t *testing.T) {
		var reqCount int32
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&reqCount, 1)
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{NormalizedURL: ts.URL + "/ep1", Host: ts.Listener.Addr().String(), HostIdentity: ts.Listener.Addr().String(), Classification: ClassificationConfirmedReference},
				{NormalizedURL: ts.URL + "/ep2", Host: ts.Listener.Addr().String(), HostIdentity: ts.Listener.Addr().String(), Classification: ClassificationConfirmedReference},
				{NormalizedURL: ts.URL + "/ep3", Host: ts.Listener.Addr().String(), HostIdentity: ts.Listener.Addr().String(), Classification: ClassificationConfirmedReference},
				{NormalizedURL: ts.URL + "/ep4", Host: ts.Listener.Addr().String(), HostIdentity: ts.Listener.Addr().String(), Classification: ClassificationConfirmedReference},
			},
		}

		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL}
		cfg.Authorization = authRecord
		cfg.AllowLoopback = true
		cfg.MaxRequestsTotal = 2 // budget allows at most 2 requests!
		cfg.MaxConcurrency = 1

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rep.TotalTested != 2 {
			t.Errorf("expected exactly 2 tested, got %d", rep.TotalTested)
		}
		if rep.TotalSkipped != 2 {
			t.Errorf("expected 2 skipped due to budget exhaustion, got %d", rep.TotalSkipped)
		}
		if !rep.BudgetExhausted {
			t.Errorf("expected BudgetExhausted=true")
		}
		if rep.TotalRequestsSent != 2 {
			t.Errorf("expected TotalRequestsSent=2, got %d", rep.TotalRequestsSent)
		}
		if atomic.LoadInt32(&reqCount) != 2 {
			t.Errorf("expected server to receive exactly 2 requests, got %d", atomic.LoadInt32(&reqCount))
		}
	})

	t.Run("Per_Host_Request_Budget_Enforcement", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{NormalizedURL: ts.URL + "/a1", Host: ts.Listener.Addr().String(), HostIdentity: ts.Listener.Addr().String(), Classification: ClassificationConfirmedReference},
				{NormalizedURL: ts.URL + "/a2", Host: ts.Listener.Addr().String(), HostIdentity: ts.Listener.Addr().String(), Classification: ClassificationConfirmedReference},
				{NormalizedURL: ts.URL + "/a3", Host: ts.Listener.Addr().String(), HostIdentity: ts.Listener.Addr().String(), Classification: ClassificationConfirmedReference},
			},
		}

		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL}
		cfg.Authorization = authRecord
		cfg.AllowLoopback = true
		cfg.MaxRequestsTotal = 50
		cfg.MaxRequestsPerHost = 1 // Per-host budget = 1!
		cfg.MaxConcurrency = 1

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rep.TotalTested != 1 {
			t.Errorf("expected 1 tested, got %d", rep.TotalTested)
		}
		if rep.TotalSkipped != 2 {
			t.Errorf("expected 2 skipped due to per-host budget exhaustion, got %d", rep.TotalSkipped)
		}
	})

	t.Run("Per_Request_Timeout_Enforced", func(t *testing.T) {
		slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(300 * time.Millisecond) // slow response
			w.WriteHeader(http.StatusOK)
		}))
		defer slowServer.Close()

		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{
					NormalizedURL:  slowServer.URL + "/slow",
					Host:           slowServer.Listener.Addr().String(),
					HostIdentity:   slowServer.Listener.Addr().String(),
					Classification: ClassificationConfirmedReference,
				},
			},
		}

		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{slowServer.URL}
		cfg.Authorization = authRecord
		cfg.AllowLoopback = true
		cfg.PerRequestTimeout = 50 * time.Millisecond // shorter than server sleep!

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rep.TotalInconclusive != 1 {
			t.Fatalf("expected 1 inconclusive due to timeout, got tested=%d, inconclusive=%d, failed=%d", rep.TotalTested, rep.TotalInconclusive, rep.TotalFailed)
		}
		if rep.Results[0].ReasonCode != "INCONCLUSIVE_TIMEOUT" {
			t.Errorf("expected INCONCLUSIVE_TIMEOUT, got: %s", rep.Results[0].ReasonCode)
		}
	})
}

// 4. Accounting and Results Invariant Tests
func TestHandoff_AccountingAndResults(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "fail") {
			// hijack connection or return 500
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"items":[]}`))
	}))
	defer ts.Close()

	authRecord := newTestAuth("Audit Director")

	inv := &BackendInventory{
		APKSHA256:   "apk-sha256-sample-hash",
		APKFileName: "testapp.apk",
		Endpoints: []EndpointEntry{
			// 1. In-scope, success
			{
				NormalizedURL:  ts.URL + "/api/v1/ok",
				Host:           ts.Listener.Addr().String(),
				HostIdentity:   ts.Listener.Addr().String(),
				Category:       CategoryAPI,
				Classification: ClassificationConfirmedReference,
				Provenance:     []ProvenanceRecord{{ArtifactPath: "classes.dex"}},
			},
			// 2. Out of scope -> skipped
			{
				NormalizedURL:  "https://unauthorized.other.com/api/v1/data",
				Host:           "unauthorized.other.com",
				HostIdentity:   "unauthorized.other.com",
				Category:       CategoryAPI,
				Classification: ClassificationConfirmedReference,
			},
			// 3. Unresolved -> skipped
			{
				NormalizedURL:  "/api/unresolved/path",
				HostIdentity:   "(unresolved)",
				Classification: ClassificationInferredRoute,
			},
			// 4. Sensitive parameter endpoint (tested, verifying zero secret leaks)
			{
				NormalizedURL:  ts.URL + "/api/v1/auth?token=[REDACTED]",
				Host:           ts.Listener.Addr().String(),
				HostIdentity:   ts.Listener.Addr().String(),
				Category:       CategoryAuthentication,
				Classification: ClassificationConfirmedReference,
				Provenance:     []ProvenanceRecord{{ArtifactPath: "AndroidManifest.xml"}},
			},
		},
	}

	cfg := DefaultHandoffConfig()
	cfg.AuthorizedTargets = []string{ts.URL}
	cfg.Authorization = authRecord
	cfg.AllowLoopback = true

	rep, err := ExecuteHandoff(context.Background(), inv, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Invariant 1: TotalDiscovered == TotalTested + TotalSkipped + TotalFailed + TotalInconclusive
	sum := rep.TotalTested + rep.TotalSkipped + rep.TotalFailed + rep.TotalInconclusive
	if sum != rep.TotalDiscovered {
		t.Errorf("accounting mismatch: sum=%d != TotalDiscovered=%d", sum, rep.TotalDiscovered)
	}
	if len(rep.Results) != rep.TotalDiscovered {
		t.Errorf("results length %d != TotalDiscovered %d", len(rep.Results), rep.TotalDiscovered)
	}

	// Invariant 2: Every endpoint receives exactly one final disposition
	for _, r := range rep.Results {
		if r.Disposition != DispositionTested &&
			r.Disposition != DispositionSkipped &&
			r.Disposition != DispositionFailed &&
			r.Disposition != DispositionInconclusive {
			t.Errorf("invalid disposition: %s", r.Disposition)
		}
	}

	// Invariant 3: Skipped endpoints have 0 requests sent
	for _, r := range rep.Results {
		if r.Disposition == DispositionSkipped {
			if r.RequestDispatched || r.RequestCount != 0 {
				t.Errorf("skipped endpoint %s has non-zero request dispatch: dispatched=%v, count=%d",
					r.NormalizedURL, r.RequestDispatched, r.RequestCount)
			}
		}
	}

	// Invariant 4: Provenance survives
	if len(rep.Results[0].Provenance) == 0 || rep.Results[0].Provenance[0].ArtifactPath != "classes.dex" {
		t.Errorf("provenance lost for endpoint 0: %+v", rep.Results[0].Provenance)
	}
	if rep.Results[0].APKSHA256 != "apk-sha256-sample-hash" {
		t.Errorf("APK SHA256 lost: %s", rep.Results[0].APKSHA256)
	}

	// Invariant 5: Zero secret leaks in results or findings
	for _, r := range rep.Results {
		if strings.Contains(r.NormalizedURL, "SECRET_") || strings.Contains(r.ReasonMessage, "SECRET_") {
			t.Errorf("raw secret leaked in result: %+v", r)
		}
		for _, f := range r.APIFindings {
			if strings.Contains(f.Endpoint, "SECRET_") || strings.Contains(f.Evidence, "SECRET_") {
				t.Errorf("raw secret leaked in finding: %+v", f)
			}
		}
	}
}

// 5. Dry Run Planning Mode Tests
func TestHandoff_DryRunMode(t *testing.T) {
	authRecord := newTestAuth("Auditor")

	inv := &BackendInventory{
		Endpoints: []EndpointEntry{
			{NormalizedURL: "https://api.mycorp.com/v1/auth", Host: "api.mycorp.com", HostIdentity: "api.mycorp.com", Classification: ClassificationConfirmedReference},
			{NormalizedURL: "https://external.vendor.com/v1", Host: "external.vendor.com", HostIdentity: "external.vendor.com", Classification: ClassificationConfirmedReference},
			{NormalizedURL: "/api/unresolved", HostIdentity: "(unresolved)", Classification: ClassificationInferredRoute},
		},
	}

	cfg := DefaultHandoffConfig()
	cfg.AuthorizedTargets = []string{"https://api.mycorp.com"}
	cfg.Authorization = authRecord
	cfg.DryRun = true

	rep, err := ExecuteHandoff(context.Background(), inv, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !rep.DryRun {
		t.Errorf("expected DryRun=true")
	}
	if rep.TotalRequestsSent != 0 {
		t.Errorf("expected 0 requests sent during dry-run, got %d", rep.TotalRequestsSent)
	}
	if rep.TotalTested != 0 {
		t.Errorf("expected 0 tested during dry-run, got %d", rep.TotalTested)
	}
	if rep.TotalEligible != 1 {
		t.Errorf("expected 1 eligible candidate in dry-run plan, got %d", rep.TotalEligible)
	}
	if rep.TotalSkipped != 3 {
		t.Errorf("expected all 3 to have disposition skipped in dry run, got %d", rep.TotalSkipped)
	}
	if rep.Results[0].ReasonCode != "DRY_RUN_PLAN" {
		t.Errorf("expected DRY_RUN_PLAN for eligible endpoint, got: %s", rep.Results[0].ReasonCode)
	}
}

// ---------------------------------------------------------------------------
// Phase 4.5 Boundary Audit Tests: Authorization, DNS, Redirects, Budgets
// ---------------------------------------------------------------------------

type mockAuditResolver struct {
	hosts map[string][]net.IPAddr
}

func newMockAuditResolver(entries map[string][]string) *mockAuditResolver {
	hosts := make(map[string][]net.IPAddr)
	for h, ipStrs := range entries {
		var addrs []net.IPAddr
		for _, ipStr := range ipStrs {
			ip := net.ParseIP(ipStr)
			if ip != nil {
				addrs = append(addrs, net.IPAddr{IP: ip})
			}
		}
		hosts[strings.ToLower(h)] = addrs
	}
	return &mockAuditResolver{hosts: hosts}
}

func (m *mockAuditResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if addrs, ok := m.hosts[strings.ToLower(host)]; ok {
		return addrs, nil
	}
	return nil, &net.DNSError{
		Err:        "no such host",
		Name:       host,
		IsNotFound: true,
	}
}

// TestHandoff_Audit_AuthorizationAndThirdPartyControls verifies that:
// - Missing, invalid, or expired authorization prevents every active request.
// - --target defines a target or scope but cannot independently establish authorization.
// - --allow-third-party cannot bypass authorization, scope, exclusions, or destination-IP restrictions.
// - A third-party endpoint outside explicit scope receives zero requests.
// - Inferred and unresolved endpoints follow the configured policy.
func TestHandoff_Audit_AuthorizationAndThirdPartyControls(t *testing.T) {
	var serverRequests int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&serverRequests, 1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	authApproved := newTestAuth("Audit Authority")

	t.Run("Missing_Authorization_Fails_Closed", func(t *testing.T) {
		atomic.StoreInt32(&serverRequests, 0)
		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{NormalizedURL: ts.URL + "/api/v1/health", Host: ts.Listener.Addr().String(), HostIdentity: ts.Listener.Addr().String(), Classification: ClassificationConfirmedReference},
			},
		}
		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL}
		cfg.Authorization = nil // Missing

		_, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err == nil || !strings.Contains(err.Error(), "authorization record is required") {
			t.Fatalf("expected authorization record required error, got: %v", err)
		}
		if atomic.LoadInt32(&serverRequests) != 0 {
			t.Errorf("expected 0 network requests, got %d", atomic.LoadInt32(&serverRequests))
		}
	})

	t.Run("Expired_Authorization_Fails_Closed", func(t *testing.T) {
		atomic.StoreInt32(&serverRequests, 0)
		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{NormalizedURL: ts.URL + "/api/v1/health", Host: ts.Listener.Addr().String(), HostIdentity: ts.Listener.Addr().String(), Classification: ClassificationConfirmedReference},
			},
		}
		past := time.Now().Add(-1 * time.Hour)
		expiredAuth := &assessment.AuthorizationRecord{
			Status:     assessment.AuthApproved,
			ValidUntil: &past,
		}
		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL}
		cfg.Authorization = expiredAuth

		_, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err == nil || !strings.Contains(err.Error(), "invalid authorization") {
			t.Fatalf("expected invalid authorization error, got: %v", err)
		}
		if atomic.LoadInt32(&serverRequests) != 0 {
			t.Errorf("expected 0 network requests, got %d", atomic.LoadInt32(&serverRequests))
		}
	})

	t.Run("Future_Authorization_Fails_Closed", func(t *testing.T) {
		atomic.StoreInt32(&serverRequests, 0)
		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{NormalizedURL: ts.URL + "/api/v1/health", Host: ts.Listener.Addr().String(), HostIdentity: ts.Listener.Addr().String(), Classification: ClassificationConfirmedReference},
			},
		}
		future := time.Now().Add(2 * time.Hour)
		futureAuth := &assessment.AuthorizationRecord{
			Status:    assessment.AuthApproved,
			ValidFrom: &future,
		}
		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL}
		cfg.Authorization = futureAuth

		_, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err == nil || !strings.Contains(err.Error(), "invalid authorization") {
			t.Fatalf("expected invalid authorization error for future auth, got: %v", err)
		}
		if atomic.LoadInt32(&serverRequests) != 0 {
			t.Errorf("expected 0 network requests, got %d", atomic.LoadInt32(&serverRequests))
		}
	})

	t.Run("Pending_And_Revoked_Authorization_Fails_Closed", func(t *testing.T) {
		atomic.StoreInt32(&serverRequests, 0)
		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{NormalizedURL: ts.URL + "/api/v1/health", Host: ts.Listener.Addr().String(), HostIdentity: ts.Listener.Addr().String(), Classification: ClassificationConfirmedReference},
			},
		}
		pendingAuth := &assessment.AuthorizationRecord{
			Status: assessment.AuthPending,
		}
		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL}
		cfg.Authorization = pendingAuth

		_, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err == nil || !strings.Contains(err.Error(), "must be APPROVED") {
			t.Fatalf("expected must be APPROVED error for pending auth, got: %v", err)
		}

		revokedAuth := &assessment.AuthorizationRecord{
			Status: assessment.AuthRevoked,
		}
		cfg.Authorization = revokedAuth
		_, err = ExecuteHandoff(context.Background(), inv, cfg)
		if err == nil || !strings.Contains(err.Error(), "must be APPROVED") {
			t.Fatalf("expected must be APPROVED error for revoked auth, got: %v", err)
		}
		if atomic.LoadInt32(&serverRequests) != 0 {
			t.Errorf("expected 0 network requests, got %d", atomic.LoadInt32(&serverRequests))
		}
	})

	t.Run("Target_Flag_Cannot_Independently_Establish_Authorization", func(t *testing.T) {
		atomic.StoreInt32(&serverRequests, 0)
		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{NormalizedURL: ts.URL + "/api/v1/health", Host: ts.Listener.Addr().String(), HostIdentity: ts.Listener.Addr().String(), Classification: ClassificationConfirmedReference},
			},
		}
		// Target configured, but authorization explicitly omitted
		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL}
		cfg.Authorization = nil

		_, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err == nil {
			t.Fatalf("expected failure when target is specified without authorization")
		}
		if atomic.LoadInt32(&serverRequests) != 0 {
			t.Errorf("expected 0 network requests dispatched, got %d", atomic.LoadInt32(&serverRequests))
		}
	})

	t.Run("AllowThirdParty_Cannot_Bypass_Authorization", func(t *testing.T) {
		atomic.StoreInt32(&serverRequests, 0)
		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{NormalizedURL: ts.URL + "/api/v1/health", Host: ts.Listener.Addr().String(), HostIdentity: ts.Listener.Addr().String(), Classification: ClassificationConfirmedReference},
			},
		}
		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL}
		cfg.AllowThirdParties = true // Even with AllowThirdParties=true, authorization is mandatory
		cfg.Authorization = nil

		_, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err == nil || !strings.Contains(err.Error(), "authorization record is required") {
			t.Fatalf("expected authorization record is required, got: %v", err)
		}
		if atomic.LoadInt32(&serverRequests) != 0 {
			t.Errorf("expected 0 network requests, got %d", atomic.LoadInt32(&serverRequests))
		}
	})

	t.Run("AllowThirdParty_Cannot_Bypass_Scope", func(t *testing.T) {
		atomic.StoreInt32(&serverRequests, 0)
		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{
					NormalizedURL:  "https://unauthorized-vendor.example.com/api/v1/data",
					Host:           "unauthorized-vendor.example.com",
					HostIdentity:   "unauthorized-vendor.example.com",
					Category:       CategoryCloudService,
					Classification: ClassificationConfirmedReference,
				},
			},
		}
		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL} // ts.URL is the only authorized target
		cfg.Authorization = authApproved
		cfg.AllowThirdParties = true // third party allowed, but OUT OF SCOPE target must be blocked!

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rep.TotalTested != 0 || rep.TotalSkipped != 1 {
			t.Fatalf("expected 0 tested, 1 skipped; got tested=%d, skipped=%d", rep.TotalTested, rep.TotalSkipped)
		}
		if rep.Results[0].ReasonCode != "OUT_OF_SCOPE" {
			t.Errorf("expected OUT_OF_SCOPE, got: %s", rep.Results[0].ReasonCode)
		}
		if rep.TotalRequestsSent != 0 {
			t.Errorf("expected 0 requests sent, got %d", rep.TotalRequestsSent)
		}
		if rep.Results[0].RequestDispatched {
			t.Errorf("expected RequestDispatched=false")
		}
	})

	t.Run("AllowThirdParty_Cannot_Bypass_Exclusions", func(t *testing.T) {
		atomic.StoreInt32(&serverRequests, 0)
		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{
					NormalizedURL:  ts.URL + "/excluded/thirdparty",
					Host:           ts.Listener.Addr().String(),
					HostIdentity:   ts.Listener.Addr().String(),
					Category:       CategoryStorage,
					Classification: ClassificationConfirmedReference,
				},
			},
		}
		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL}
		cfg.Authorization = authApproved
		cfg.AllowLoopback = true
		cfg.AllowThirdParties = true
		cfg.Exclusions = []assessment.Exclusion{
			{
				ExclusionType: assessment.ExclusionPathPrefix,
				Pattern:       "/excluded",
				Reason:        "Strict exclusion",
			},
		}

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rep.TotalTested != 0 || rep.TotalSkipped != 1 {
			t.Fatalf("expected 0 tested, 1 skipped; got tested=%d, skipped=%d", rep.TotalTested, rep.TotalSkipped)
		}
		if rep.Results[0].ReasonCode != "EXCLUDED" {
			t.Errorf("expected EXCLUDED, got %s", rep.Results[0].ReasonCode)
		}
		if atomic.LoadInt32(&serverRequests) != 0 {
			t.Errorf("expected 0 network requests, got %d", atomic.LoadInt32(&serverRequests))
		}
	})

	t.Run("AllowThirdParty_Cannot_Bypass_Prohibited_IP", func(t *testing.T) {
		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{
					NormalizedURL:  "http://169.254.169.254/latest/meta-data/",
					Host:           "169.254.169.254",
					HostIdentity:   "169.254.169.254",
					Category:       CategoryCloudService,
					Classification: ClassificationConfirmedReference,
				},
			},
		}
		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{"http://169.254.169.254"}
		cfg.Authorization = authApproved
		cfg.AllowThirdParties = true // even with allow third-party, cloud metadata IP is blocked!

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if rep.TotalTested != 0 || rep.TotalSkipped != 1 {
			t.Fatalf("expected 0 tested, 1 skipped; got tested=%d, skipped=%d", rep.TotalTested, rep.TotalSkipped)
		}
		if rep.Results[0].ReasonCode != "PROHIBITED_IP" {
			t.Errorf("expected PROHIBITED_IP, got: %s", rep.Results[0].ReasonCode)
		}
	})
}

// TestHandoff_Audit_DNSConnectionAndRedirects verifies that:
// - Destination IP is subject to the same policy as validated target.
// - Prohibited IPv4, IPv6, IPv4-mapped IPv6, and mixed DNS answers are rejected.
// - Redirect chains accurately count against request budgets, per-host limits, and endpoint tracking.
// - Redirects to out-of-scope hosts and prohibited IPs are blocked before connecting.
func TestHandoff_Audit_DNSConnectionAndRedirects(t *testing.T) {
	authApproved := newTestAuth("Audit Operations")

	t.Run("Mixed_DNS_Answers_Rejected_By_SafeDialer", func(t *testing.T) {
		// Mock resolver returning a dual-homed entry: one public IP, one loopback IP
		resolver := newMockAuditResolver(map[string][]string{
			"mixed.dns.local": {"93.184.216.34", "127.0.0.1"},
		})

		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{
					NormalizedURL:  "http://mixed.dns.local:8080/v1/resource",
					Host:           "mixed.dns.local:8080",
					HostIdentity:   "mixed.dns.local:8080",
					Classification: ClassificationConfirmedReference,
				},
			},
		}

		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{"http://mixed.dns.local:8080"}
		cfg.Authorization = authApproved
		cfg.AllowLoopback = false // Prohibit loopback!
		cfg.Resolver = resolver

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rep.TotalFailed != 1 {
			t.Fatalf("expected 1 failed due to SSRF refusal, got tested=%d, failed=%d, skipped=%d",
				rep.TotalTested, rep.TotalFailed, rep.TotalSkipped)
		}
		if rep.Results[0].ReasonCode != "SSRF_BLOCKED" {
			t.Errorf("expected SSRF_BLOCKED, got: %s", rep.Results[0].ReasonCode)
		}
		if !strings.Contains(rep.Results[0].ReasonMessage, "SSRF security refusal") &&
			!strings.Contains(rep.Results[0].ReasonMessage, "loopback") {
			t.Errorf("expected SSRF refusal message, got: %s", rep.Results[0].ReasonMessage)
		}
	})

	t.Run("Prohibited_IPv6_And_Mapped_IPv6_Blocked", func(t *testing.T) {
		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{NormalizedURL: "http://[::1]:8080/v1", Host: "[::1]:8080", HostIdentity: "[::1]:8080", Classification: ClassificationConfirmedReference},
				{NormalizedURL: "http://[::ffff:127.0.0.1]:8080/v1", Host: "[::ffff:127.0.0.1]:8080", HostIdentity: "[::ffff:127.0.0.1]:8080", Classification: ClassificationConfirmedReference},
				{NormalizedURL: "http://[::ffff:169.254.169.254]/v1", Host: "[::ffff:169.254.169.254]", HostIdentity: "[::ffff:169.254.169.254]", Classification: ClassificationConfirmedReference},
				{NormalizedURL: "http://[fd00:ec2::254]/v1", Host: "[fd00:ec2::254]", HostIdentity: "[fd00:ec2::254]", Classification: ClassificationConfirmedReference},
				{NormalizedURL: "http://[fe80::1]:8080/v1", Host: "[fe80::1]:8080", HostIdentity: "[fe80::1]:8080", Classification: ClassificationConfirmedReference},
			},
		}

		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{
			"http://[::1]:8080",
			"http://[::ffff:127.0.0.1]:8080",
			"http://[::ffff:169.254.169.254]",
			"http://[fd00:ec2::254]",
			"http://[fe80::1]:8080",
		}
		cfg.Authorization = authApproved
		cfg.AllowLoopback = false
		cfg.AllowPrivateIPs = false

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rep.TotalSkipped != 5 || rep.TotalTested != 0 {
			t.Fatalf("expected 5 skipped for prohibited IPv6/IPv4-mapped addresses, got tested=%d, skipped=%d",
				rep.TotalTested, rep.TotalSkipped)
		}
		for i, r := range rep.Results {
			if r.ReasonCode != "PROHIBITED_IP" {
				t.Errorf("endpoint %d (%s) expected PROHIBITED_IP, got: %s", i, r.NormalizedURL, r.ReasonCode)
			}
		}
	})

	t.Run("Redirect_Chain_Exact_Request_Accounting", func(t *testing.T) {
		var hopRequests int32
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&hopRequests, 1)
			switch r.URL.Path {
			case "/start":
				http.Redirect(w, r, "/hop1", http.StatusFound)
			case "/hop1":
				http.Redirect(w, r, "/final", http.StatusFound)
			case "/final":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"result":"completed"}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer ts.Close()

		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{
					NormalizedURL:  ts.URL + "/start",
					Host:           ts.Listener.Addr().String(),
					HostIdentity:   ts.Listener.Addr().String(),
					Classification: ClassificationConfirmedReference,
				},
			},
		}

		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL}
		cfg.Authorization = authApproved
		cfg.AllowLoopback = true
		cfg.MaxRedirects = 5

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rep.TotalTested != 1 {
			t.Fatalf("expected 1 tested endpoint, got %d", rep.TotalTested)
		}
		// Initial request + 2 redirect hops = 3 total requests
		if rep.Results[0].RequestCount != 3 {
			t.Errorf("expected endpoint RequestCount=3, got %d", rep.Results[0].RequestCount)
		}
		if rep.TotalRequestsSent != 3 {
			t.Errorf("expected report TotalRequestsSent=3, got %d", rep.TotalRequestsSent)
		}
		if atomic.LoadInt32(&hopRequests) != 3 {
			t.Errorf("expected server to receive 3 requests, got %d", atomic.LoadInt32(&hopRequests))
		}
	})

	t.Run("Redirect_Chain_Budget_Exhaustion_Terminates_Safely", func(t *testing.T) {
		var hopRequests int32
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&hopRequests, 1)
			switch r.URL.Path {
			case "/start":
				http.Redirect(w, r, "/hop1", http.StatusFound)
			case "/hop1":
				http.Redirect(w, r, "/final", http.StatusFound)
			case "/final":
				w.WriteHeader(http.StatusOK)
			default:
				http.NotFound(w, r)
			}
		}))
		defer ts.Close()

		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{
					NormalizedURL:  ts.URL + "/start",
					Host:           ts.Listener.Addr().String(),
					HostIdentity:   ts.Listener.Addr().String(),
					Classification: ClassificationConfirmedReference,
				},
			},
		}

		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL}
		cfg.Authorization = authApproved
		cfg.AllowLoopback = true
		cfg.MaxRequestsTotal = 2 // budget allows at most 2 requests: initial + 1 hop, blocking hop 2!
		cfg.MaxRedirects = 5

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rep.TotalFailed != 1 {
			t.Fatalf("expected 1 failed endpoint due to budget exhaustion on redirect, got tested=%d, failed=%d",
				rep.TotalTested, rep.TotalFailed)
		}
		if rep.Results[0].ReasonCode != "REDIRECT_BLOCKED" {
			t.Errorf("expected REDIRECT_BLOCKED, got %s", rep.Results[0].ReasonCode)
		}
		if !strings.Contains(rep.Results[0].ReasonMessage, "budget exhausted") {
			t.Errorf("expected budget exhausted message, got: %s", rep.Results[0].ReasonMessage)
		}
		if rep.TotalRequestsSent != 2 {
			t.Errorf("expected TotalRequestsSent=2, got %d", rep.TotalRequestsSent)
		}
		if atomic.LoadInt32(&hopRequests) != 2 {
			t.Errorf("expected server to receive exactly 2 requests before cut-off, got %d", atomic.LoadInt32(&hopRequests))
		}
	})

	t.Run("Redirect_To_Prohibited_IP_Blocked_In_CheckRedirect", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
		}))
		defer ts.Close()

		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{
					NormalizedURL:  ts.URL + "/metadata-leak",
					Host:           ts.Listener.Addr().String(),
					HostIdentity:   ts.Listener.Addr().String(),
					Classification: ClassificationConfirmedReference,
				},
			},
		}

		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL}
		cfg.Authorization = authApproved
		cfg.AllowLoopback = true

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rep.TotalFailed != 1 {
			t.Fatalf("expected 1 failed, got tested=%d, failed=%d", rep.TotalTested, rep.TotalFailed)
		}
		if rep.Results[0].ReasonCode != "SSRF_BLOCKED" && rep.Results[0].ReasonCode != "REDIRECT_BLOCKED" {
			t.Errorf("expected SSRF_BLOCKED or REDIRECT_BLOCKED, got: %s", rep.Results[0].ReasonCode)
		}
		if !strings.Contains(rep.Results[0].ReasonMessage, "cloud metadata") {
			t.Errorf("expected cloud metadata reason, got: %s", rep.Results[0].ReasonMessage)
		}
	})
}

// TestHandoff_Audit_RequestBudgetsAndOutcomes verifies that:
// - Payload size limits return INCONCLUSIVE_RESPONSE_TOO_LARGE.
// - Context cancellations return INCONCLUSIVE_CANCELLED.
// - HTTP 429 returns INCONCLUSIVE_RATE_LIMITED.
// - Sum invariant strictly holds: TotalDiscovered == TotalTested + TotalSkipped + TotalFailed + TotalInconclusive.
func TestHandoff_Audit_RequestBudgetsAndOutcomes(t *testing.T) {
	authApproved := newTestAuth("Audit Director")

	t.Run("Response_Too_Large_Outcome", func(t *testing.T) {
		// Server sends body > DefaultMaxAPIResponse (1MB)
		largeBody := make([]byte, 1500*1024)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(largeBody)))
			w.WriteHeader(http.StatusOK)
			w.Write(largeBody)
		}))
		defer ts.Close()

		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{
					NormalizedURL:  ts.URL + "/large-response",
					Host:           ts.Listener.Addr().String(),
					HostIdentity:   ts.Listener.Addr().String(),
					Classification: ClassificationConfirmedReference,
				},
			},
		}

		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL}
		cfg.Authorization = authApproved
		cfg.AllowLoopback = true

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rep.TotalInconclusive != 1 {
			t.Fatalf("expected 1 inconclusive due to large response, got tested=%d, inconclusive=%d, failed=%d",
				rep.TotalTested, rep.TotalInconclusive, rep.TotalFailed)
		}
		if rep.Results[0].ReasonCode != "INCONCLUSIVE_RESPONSE_TOO_LARGE" {
			t.Errorf("expected INCONCLUSIVE_RESPONSE_TOO_LARGE, got: %s", rep.Results[0].ReasonCode)
		}
	})

	t.Run("Context_Cancellation_Outcome", func(t *testing.T) {
		blockCh := make(chan struct{})
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-blockCh
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()
		defer close(blockCh)

		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{
					NormalizedURL:  ts.URL + "/cancel-me",
					Host:           ts.Listener.Addr().String(),
					HostIdentity:   ts.Listener.Addr().String(),
					Classification: ClassificationConfirmedReference,
				},
			},
		}

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL}
		cfg.Authorization = authApproved
		cfg.AllowLoopback = true
		cfg.PerRequestTimeout = 2 * time.Second

		rep, err := ExecuteHandoff(ctx, inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rep.TotalInconclusive != 1 {
			t.Fatalf("expected 1 inconclusive due to cancellation, got tested=%d, inconclusive=%d",
				rep.TotalTested, rep.TotalInconclusive)
		}
		if rep.Results[0].ReasonCode != "INCONCLUSIVE_CANCELLED" {
			t.Errorf("expected INCONCLUSIVE_CANCELLED, got: %s", rep.Results[0].ReasonCode)
		}
	})

	t.Run("HTTP_429_Rate_Limited_Outcome", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"Too Many Requests"}`))
		}))
		defer ts.Close()

		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				{
					NormalizedURL:  ts.URL + "/rate-limited",
					Host:           ts.Listener.Addr().String(),
					HostIdentity:   ts.Listener.Addr().String(),
					Classification: ClassificationConfirmedReference,
				},
			},
		}

		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL}
		cfg.Authorization = authApproved
		cfg.AllowLoopback = true

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rep.TotalInconclusive != 1 {
			t.Fatalf("expected 1 inconclusive due to rate limiting, got: tested=%d, inconclusive=%d",
				rep.TotalTested, rep.TotalInconclusive)
		}
		if rep.Results[0].ReasonCode != "INCONCLUSIVE_RATE_LIMITED" {
			t.Errorf("expected INCONCLUSIVE_RATE_LIMITED, got: %s", rep.Results[0].ReasonCode)
		}
	})

	t.Run("Accounting_Sums_And_Disposition_Invariants", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/ok":
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"status":"success"}`))
			case "/bad":
				hj, ok := w.(http.Hijacker)
				if ok {
					conn, _, _ := hj.Hijack()
					conn.Close()
					return
				}
				http.Error(w, "server error", http.StatusInternalServerError)
			case "/slow":
				time.Sleep(600 * time.Millisecond)
				w.WriteHeader(http.StatusOK)
			default:
				http.NotFound(w, r)
			}
		}))
		defer ts.Close()

		// Warm up connection to eliminate TCP dial latency jitter
		warmResp, _ := http.Get(ts.URL + "/ok")
		if warmResp != nil {
			warmResp.Body.Close()
		}

		inv := &BackendInventory{
			Endpoints: []EndpointEntry{
				// 1. Tested
				{NormalizedURL: ts.URL + "/ok", Host: ts.Listener.Addr().String(), HostIdentity: ts.Listener.Addr().String(), Classification: ClassificationConfirmedReference},
				// 2. Skipped (out-of-scope)
				{NormalizedURL: "https://unauthorized.example.com/v1", Host: "unauthorized.example.com", HostIdentity: "unauthorized.example.com", Classification: ClassificationConfirmedReference},
				// 3. Failed (connection reset/network error)
				{NormalizedURL: ts.URL + "/bad", Host: ts.Listener.Addr().String(), HostIdentity: ts.Listener.Addr().String(), Classification: ClassificationConfirmedReference},
				// 4. Inconclusive (timed out)
				{NormalizedURL: ts.URL + "/slow", Host: ts.Listener.Addr().String(), HostIdentity: ts.Listener.Addr().String(), Classification: ClassificationConfirmedReference},
			},
		}

		cfg := DefaultHandoffConfig()
		cfg.AuthorizedTargets = []string{ts.URL}
		cfg.Authorization = authApproved
		cfg.AllowLoopback = true
		cfg.MaxConcurrency = 1
		cfg.PerRequestTimeout = 200 * time.Millisecond // /slow sleeps 600ms, reliably timing out

		rep, err := ExecuteHandoff(context.Background(), inv, cfg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if rep.TotalDiscovered != 4 {
			t.Errorf("expected TotalDiscovered=4, got %d", rep.TotalDiscovered)
		}
		if rep.TotalTested != 1 {
			t.Errorf("expected TotalTested=1, got %d", rep.TotalTested)
		}
		if rep.TotalSkipped != 1 {
			t.Errorf("expected TotalSkipped=1, got %d", rep.TotalSkipped)
		}
		if rep.TotalFailed != 1 {
			t.Errorf("expected TotalFailed=1, got %d", rep.TotalFailed)
		}
		if rep.TotalInconclusive != 1 {
			t.Errorf("expected TotalInconclusive=1, got %d", rep.TotalInconclusive)
		}

		sum := rep.TotalTested + rep.TotalSkipped + rep.TotalFailed + rep.TotalInconclusive
		if sum != rep.TotalDiscovered {
			t.Fatalf("invariant broken: sum(%d) != TotalDiscovered(%d)", sum, rep.TotalDiscovered)
		}

		for _, r := range rep.Results {
			if r.Disposition == DispositionSkipped {
				if r.RequestDispatched || r.RequestCount != 0 {
					t.Errorf("skipped endpoint had request dispatched: %+v", r)
				}
			}
		}
	})
}
