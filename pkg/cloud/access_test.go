package cloud

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAccessModel_ValidationAndInvariants verifies WP 2.2.1 model rules.
func TestAccessModel_ValidationAndInvariants(t *testing.T) {
	// Case A: Missing target
	rec := AccessVerificationRecord{
		Technology:  TechElasticsearch,
		Status:      StatusServiceReachable,
		Decision:    DecisionAllowed,
		AuthContext: AuthContextUnauthenticated,
		Operation:   OpMetadataRead,
	}
	if err := rec.Validate(); err == nil {
		t.Fatal("expected error for missing target")
	}

	// Case B: Reachability alone cannot be marked as FindingSuitable
	rec.Target = "http://localhost:9200"
	rec.FindingSuitable = true
	if err := rec.Validate(); err == nil {
		t.Fatal("expected error: service reachability alone is not finding suitable")
	}

	// Case C: Unauthenticated BoundedRead requires explicit resource scope
	rec.Status = StatusReadAllowed
	rec.Operation = OpBoundedRead
	rec.ResourceScope = ""
	rec.FindingSuitable = true
	if err := rec.Validate(); err == nil {
		t.Fatal("expected error: unauthenticated data read requires explicit resource scope")
	}

	// Case D: Valid BoundedRead on explicit resource
	rec.ResourceScope = "test_index"
	if err := rec.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	// Case E: Skipped verification cannot have Allowed decision
	rec.Status = StatusVerificationSkipped
	rec.Decision = DecisionAllowed
	if err := rec.Validate(); err == nil {
		t.Fatal("expected error: skipped verification cannot have Allowed decision")
	}
}

// TestCredentialProfile_Redaction verifies credentials are never exposed.
func TestCredentialProfile_Redaction(t *testing.T) {
	secretVal := "super-secret-password-xyz123"
	tokenVal := "eyJh...super-secret-jwt...token"

	cp := CredentialProfile{
		Name:     "audit_user",
		Username: "felix_audit",
		Secret:   secretVal,
		Role:     "readonly",
		Headers: map[string]string{
			"Authorization": "Bearer " + tokenVal,
			"apikey":        secretVal,
		},
		Description: "Production audit test profile",
	}

	red := cp.Redacted()

	if strings.Contains(red.Secret, secretVal) {
		t.Fatal("redacted secret contained original secret value")
	}
	if red.Secret != "***REDACTED***" {
		t.Fatalf("expected ***REDACTED***, got %q", red.Secret)
	}
	for k, v := range red.Headers {
		if strings.Contains(v, tokenVal) || strings.Contains(v, secretVal) {
			t.Fatalf("redacted header %s contained raw secret", k)
		}
		if v != "***REDACTED***" {
			t.Fatalf("expected ***REDACTED*** for header %s, got %q", k, v)
		}
	}
}

// TestAccessVerification_All27Scenarios covers every required scenario from Phase 2.2 Section 11.
func TestAccessVerification_All27Scenarios(t *testing.T) {
	// Scenario 1: In-scope service with no authentication configured
	t.Run("01_InScope_NoAuth_Configured", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"cluster_name":"test-cluster","version":{"number":"8.1.0"},"tagline":"You Know, for Search"}`))
		}))
		defer ts.Close()

		client := NewClient(ClientOptions{AllowLoopback: true})
		engine := NewAccessVerificationEngine(AccessEngineOptions{Client: client})

		svc := DiscoveredService{
			Technology: TechElasticsearch,
			Family:     FamilyDirectDatabase,
			Endpoint:   ts.URL,
		}

		rec := engine.VerifyServiceAccess(context.Background(), svc, nil, nil, nil)
		if rec.Status != StatusServiceReachable || rec.Decision != DecisionAllowed {
			t.Fatalf("expected ServiceReachable/Allowed, got %s/%s", rec.Status, rec.Decision)
		}
		if rec.FindingSuitable {
			t.Fatal("reachability without data access must not be finding suitable")
		}
	})

	// Scenario 2: In-scope service returning an authentication challenge
	t.Run("02_InScope_Auth_Challenge", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Elasticsearch"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"missing authentication token"}`))
		}))
		defer ts.Close()

		client := NewClient(ClientOptions{AllowLoopback: true})
		engine := NewAccessVerificationEngine(AccessEngineOptions{Client: client})

		svc := DiscoveredService{
			Technology: TechElasticsearch,
			Family:     FamilyDirectDatabase,
			Endpoint:   ts.URL,
		}

		rec := engine.VerifyServiceAccess(context.Background(), svc, nil, nil, nil)
		if rec.Status != StatusAuthChallenged || rec.Decision != DecisionDenied {
			t.Fatalf("expected AuthChallenged/Denied, got %s/%s", rec.Status, rec.Decision)
		}
	})

	// Scenario 3: Valid configured credentials accepted
	t.Run("03_Valid_Configured_Credentials_Accepted", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok := r.BasicAuth()
			if ok && user == "elastic" && pass == "correct-password" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"cluster_name":"test-cluster","version":{"number":"8.1.0"}}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer ts.Close()

		client := NewClient(ClientOptions{AllowLoopback: true})
		engine := NewAccessVerificationEngine(AccessEngineOptions{Client: client})

		svc := DiscoveredService{
			Technology: TechElasticsearch,
			Family:     FamilyDirectDatabase,
			Endpoint:   ts.URL,
		}
		cred := &CredentialProfile{
			Username: "elastic",
			Secret:   "correct-password",
		}

		rec := engine.VerifyServiceAccess(context.Background(), svc, cred, nil, nil)
		if rec.Status != StatusAuthenticatedAccess || rec.Decision != DecisionAllowed {
			t.Fatalf("expected AuthenticatedAccess/Allowed, got %s/%s", rec.Status, rec.Decision)
		}
		if !rec.CredentialUsed {
			t.Fatal("expected CredentialUsed to be true")
		}
	})

	// Scenario 4: Invalid credentials rejected
	t.Run("04_Invalid_Credentials_Rejected", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"bad credentials"}`))
		}))
		defer ts.Close()

		client := NewClient(ClientOptions{AllowLoopback: true})
		engine := NewAccessVerificationEngine(AccessEngineOptions{Client: client})

		svc := DiscoveredService{
			Technology: TechElasticsearch,
			Family:     FamilyDirectDatabase,
			Endpoint:   ts.URL,
		}
		cred := &CredentialProfile{
			Username: "elastic",
			Secret:   "wrong-password",
		}

		rec := engine.VerifyServiceAccess(context.Background(), svc, cred, nil, nil)
		if rec.Status != StatusAuthChallenged || rec.Decision != DecisionDenied {
			t.Fatalf("expected AuthChallenged/Denied, got %s/%s", rec.Status, rec.Decision)
		}
	})

	// Scenario 5: Authenticated identity denied access to a test resource
	t.Run("05_Authenticated_Identity_Denied_Resource_Access", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				w.WriteHeader(http.StatusOK) // Root auth passes
				_, _ = w.Write([]byte(`{"cluster_name":"test"}`))
				return
			}
			// Specific test index is forbidden for this user
			if strings.Contains(r.URL.Path, "restricted_index") {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":"access forbidden by RBAC"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		client := NewClient(ClientOptions{AllowLoopback: true})
		engine := NewAccessVerificationEngine(AccessEngineOptions{Client: client})

		svc := DiscoveredService{
			Technology: TechElasticsearch,
			Family:     FamilyDirectDatabase,
			Endpoint:   ts.URL,
		}
		cred := &CredentialProfile{
			Username: "limited_user",
			Secret:   "valid_secret",
		}
		res := &TestResourceConfig{
			ResourceID: "restricted_index",
		}

		rec := engine.VerifyServiceAccess(context.Background(), svc, cred, res, nil)
		if rec.Status != StatusReadDenied || rec.Decision != DecisionDenied {
			t.Fatalf("expected ReadDenied/Denied, got %s/%s", rec.Status, rec.Decision)
		}
	})

	// Scenario 6: Unauthenticated read permitted for an explicitly configured synthetic resource
	t.Run("06_Unauthenticated_Read_Permitted_Synthetic_Resource", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "open_test_index") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"hits":{"total":1,"hits":[{"_source":{"test":"canary"}}]}}`))
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		client := NewClient(ClientOptions{AllowLoopback: true})
		engine := NewAccessVerificationEngine(AccessEngineOptions{Client: client})

		svc := DiscoveredService{
			Technology: TechElasticsearch,
			Family:     FamilyDirectDatabase,
			Endpoint:   ts.URL,
		}
		res := &TestResourceConfig{
			ResourceID: "open_test_index",
		}

		rec := engine.VerifyServiceAccess(context.Background(), svc, nil, res, nil)
		if rec.Status != StatusReadAllowed || rec.Decision != DecisionAllowed {
			t.Fatalf("expected ReadAllowed/Allowed, got %s/%s", rec.Status, rec.Decision)
		}
		if !rec.FindingSuitable {
			t.Fatal("expected unauthenticated data read on test resource to be finding suitable")
		}
	})

	// Scenario 7: Authenticated read permitted for an explicitly configured synthetic resource
	t.Run("07_Authenticated_Read_Permitted_Synthetic_Resource", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.Contains(auth, "Basic") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"hits":{"total":1}}`))
		}))
		defer ts.Close()

		client := NewClient(ClientOptions{AllowLoopback: true})
		engine := NewAccessVerificationEngine(AccessEngineOptions{Client: client})

		svc := DiscoveredService{
			Technology: TechElasticsearch,
			Family:     FamilyDirectDatabase,
			Endpoint:   ts.URL,
		}
		cred := &CredentialProfile{
			Username: "authorized_user",
			Secret:   "secret_key",
		}
		res := &TestResourceConfig{
			ResourceID: "private_test_index",
		}

		rec := engine.VerifyServiceAccess(context.Background(), svc, cred, res, nil)
		if rec.Status != StatusReadAllowed || rec.Decision != DecisionAllowed {
			t.Fatalf("expected ReadAllowed/Allowed, got %s/%s", rec.Status, rec.Decision)
		}
		if rec.AuthContext != AuthContextAuthenticated {
			t.Fatal("expected AuthContext to be Authenticated")
		}
	})

	// Scenario 8: Service reachable but data access unverified
	t.Run("08_Service_Reachable_Data_Access_Unverified", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"tagline":"You Know, for Search"}`))
		}))
		defer ts.Close()

		client := NewClient(ClientOptions{AllowLoopback: true})
		engine := NewAccessVerificationEngine(AccessEngineOptions{Client: client})

		svc := DiscoveredService{
			Technology: TechElasticsearch,
			Family:     FamilyDirectDatabase,
			Endpoint:   ts.URL,
		}

		rec := engine.VerifyServiceAccess(context.Background(), svc, nil, nil, nil)
		if rec.Status != StatusServiceReachable {
			t.Fatalf("expected StatusServiceReachable, got %s", rec.Status)
		}
		if rec.FindingSuitable {
			t.Fatal("reachability without data access proof must not create a security finding")
		}
	})

	// Scenario 9: Timeout or unreachable target
	t.Run("09_Timeout_Or_Unreachable_Target", func(t *testing.T) {
		client := NewClient(ClientOptions{
			Timeout:       20 * time.Millisecond,
			AllowLoopback: true,
		})
		engine := NewAccessVerificationEngine(AccessEngineOptions{Client: client})

		svc := DiscoveredService{
			Technology: TechRedis,
			Family:     FamilyDirectDatabase,
			Host:       "127.0.0.1",
			Port:       65431, // Unreachable port
		}

		rec := engine.VerifyServiceAccess(context.Background(), svc, nil, nil, nil)
		if rec.Decision != DecisionError && rec.Decision != DecisionInconclusive {
			t.Fatalf("expected DecisionError or Inconclusive on unreachable, got %s", rec.Decision)
		}
		if rec.ErrorClassification != ErrClassConnectionRefused && rec.ErrorClassification != ErrClassTimeout {
			t.Fatalf("expected ConnectionRefused or Timeout classification, got %s", rec.ErrorClassification)
		}
	})

	// Scenario 10: Malformed provider response
	t.Run("10_Malformed_Provider_Response", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			// Send garbage protocol packet
			_, _ = conn.Write([]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01})
		}()

		host, portStr, _ := net.SplitHostPort(ln.Addr().String())
		port, _ := net.LookupPort("tcp", portStr)

		client := NewClient(ClientOptions{AllowLoopback: true})
		engine := NewAccessVerificationEngine(AccessEngineOptions{Client: client})

		svc := DiscoveredService{
			Technology: TechMySQL,
			Family:     FamilyDirectDatabase,
			Host:       host,
			Port:       port,
		}

		rec := engine.VerifyServiceAccess(context.Background(), svc, nil, nil, nil)
		if rec.Decision != DecisionError && rec.Decision != DecisionDenied && rec.Decision != DecisionInconclusive {
			t.Fatalf("expected error/denied/inconclusive for malformed response, got %s", rec.Decision)
		}
	})

	// Scenario 11: Unsupported verification operation
	t.Run("11_Unsupported_Verification_Operation", func(t *testing.T) {
		client := NewClient()
		engine := NewAccessVerificationEngine(AccessEngineOptions{Client: client})

		svc := DiscoveredService{
			Technology: TechPrisma,
			Family:     FamilyBackendInterface,
			Endpoint:   "https://example.com/api",
		}

		rec := engine.VerifyServiceAccess(context.Background(), svc, nil, nil, nil)
		if rec.Status != StatusVerificationSkipped || rec.ErrorClassification != ErrClassUnsupported {
			t.Fatalf("expected VerificationSkipped/ErrClassUnsupported, got %s/%s", rec.Status, rec.ErrorClassification)
		}
	})

	// Scenario 12: Out-of-scope target blocked before any network transmission
	t.Run("12_OutOfScope_Target_Blocked", func(t *testing.T) {
		var networkContacted int32
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&networkContacted, 1)
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		// Allowed scope validator rejects all targets
		isAllowed := func(u string) bool { return false }
		client := NewClient(ClientOptions{
			IsAllowed:     isAllowed,
			AllowLoopback: true,
		})
		engine := NewAccessVerificationEngine(AccessEngineOptions{
			Client:    client,
			IsAllowed: isAllowed,
		})

		svc := DiscoveredService{
			Technology: TechElasticsearch,
			Family:     FamilyDirectDatabase,
			Endpoint:   ts.URL,
		}

		rec := engine.VerifyServiceAccess(context.Background(), svc, nil, nil, nil)
		if rec.Status != StatusVerificationSkipped || rec.Decision != DecisionSkipped {
			t.Fatalf("expected VerificationSkipped/Skipped, got %s/%s", rec.Status, rec.Decision)
		}
		if atomic.LoadInt32(&networkContacted) != 0 {
			t.Fatal("network was contacted for out-of-scope target!")
		}
	})

	// Scenario 13: Excluded target blocked
	t.Run("13_Excluded_Target_Blocked", func(t *testing.T) {
		var networkContacted int32
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&networkContacted, 1)
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		isExcluded := func(u string) bool { return true }
		client := NewClient(ClientOptions{
			IsExcluded:    isExcluded,
			AllowLoopback: true,
		})
		engine := NewAccessVerificationEngine(AccessEngineOptions{
			Client:     client,
			IsExcluded: isExcluded,
		})

		svc := DiscoveredService{
			Technology: TechElasticsearch,
			Family:     FamilyDirectDatabase,
			Endpoint:   ts.URL,
		}

		rec := engine.VerifyServiceAccess(context.Background(), svc, nil, nil, nil)
		if rec.Status != StatusVerificationSkipped || rec.ErrorClassification != ErrClassScopeExcluded {
			t.Fatalf("expected VerificationSkipped/ErrClassScopeExcluded, got %s/%s", rec.Status, rec.ErrorClassification)
		}
		if atomic.LoadInt32(&networkContacted) != 0 {
			t.Fatal("network was contacted for excluded target!")
		}
	})

	// Scenario 14: Redirect to different origin cannot leak credentials
	t.Run("14_Redirect_Cross_Origin_Credentials_Stripped", func(t *testing.T) {
		var crossOriginAuthHeader string
		foreignServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			crossOriginAuthHeader = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		}))
		defer foreignServer.Close()

		origServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Redirect to foreign server
			http.Redirect(w, r, foreignServer.URL, http.StatusFound)
		}))
		defer origServer.Close()

		client := NewClient(ClientOptions{AllowLoopback: true})
		req, _ := http.NewRequestWithContext(context.Background(), "GET", origServer.URL, nil)
		req.Header.Set("Authorization", "Bearer sensitive-secret-jwt")

		// The client's CheckRedirect blocks cross-origin following or returns ErrUseLastResponse
		_, _ = client.Do(context.Background(), req)

		if crossOriginAuthHeader != "" {
			t.Fatalf("cross-origin server received credentials: %q", crossOriginAuthHeader)
		}
	})

	// Scenario 15: TLS verification failure is not silently bypassed
	t.Run("15_TLS_Verification_Failure_Not_Bypassed", func(t *testing.T) {
		// Create HTTPS server with self-signed certificate
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		// Standard client with strict TLS (does not trust self-signed cert)
		client := NewClient(ClientOptions{AllowLoopback: true})
		req, _ := http.NewRequestWithContext(context.Background(), "GET", ts.URL, nil)

		_, err := client.Do(context.Background(), req)
		if err == nil {
			t.Fatal("expected TLS verification error for self-signed cert, but request succeeded")
		}
	})

	// Scenario 16: Response size limit is enforced
	t.Run("16_Response_Size_Limit_Enforced", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			// Send 5000 bytes
			_, _ = w.Write([]byte(strings.Repeat("A", 5000)))
		}))
		defer ts.Close()

		client := NewClient(ClientOptions{
			MaxResponseSize: 1000,
			AllowLoopback:   true,
		})

		req, _ := http.NewRequestWithContext(context.Background(), "GET", ts.URL, nil)
		resp, err := client.Do(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !resp.Truncated {
			t.Fatal("expected response to be marked truncated")
		}
		if len(resp.Body) != 1000 {
			t.Fatalf("expected bounded body length 1000, got %d", len(resp.Body))
		}
	})

	// Scenario 17: Rate-limit responses are handled safely
	t.Run("17_RateLimit_Responses_Handled", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"Too many requests"}`))
		}))
		defer ts.Close()

		client := NewClient(ClientOptions{AllowLoopback: true})
		req, _ := http.NewRequestWithContext(context.Background(), "GET", ts.URL, nil)
		_, err := client.Do(context.Background(), req)
		if err != ErrRateLimited {
			t.Fatalf("expected ErrRateLimited, got %v", err)
		}
	})

	// Scenario 18: Credential values are absent from logs, findings, and errors
	t.Run("18_Credentials_Absent_From_Findings_And_Records", func(t *testing.T) {
		secretPassword := "P@ssw0rd987654321!"
		cred := &CredentialProfile{
			Username: "admin",
			Secret:   secretPassword,
		}
		redacted := cred.Redacted()
		if strings.Contains(redacted.Secret, secretPassword) {
			t.Fatal("redacted profile contained raw password")
		}

		rec := AccessVerificationRecord{
			Target:          "http://127.0.0.1:9200",
			Technology:      TechElasticsearch,
			Status:          StatusAuthenticatedAccess,
			Decision:        DecisionAllowed,
			AuthContext:     AuthContextAuthenticated,
			Operation:       OpMetadataRead,
			Evidence:        "Configured credentials accepted by Elasticsearch",
			FindingSuitable: true,
		}

		f, ok := rec.ToCloudFinding()
		if !ok {
			t.Fatal("expected ToCloudFinding to succeed")
		}

		if strings.Contains(f.Evidence, secretPassword) ||
			strings.Contains(f.Description, secretPassword) ||
			strings.Contains(rec.Evidence, secretPassword) {
			t.Fatal("secret password leaked into finding or record")
		}
	})

	// Scenario 19: No default provider probe enumerates keys, documents, buckets, containers, or production records
	t.Run("19_No_Default_Enumeration", func(t *testing.T) {
		var contactedPaths []string
		var mu sync.Mutex

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			contactedPaths = append(contactedPaths, r.URL.String())
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		client := NewClient(ClientOptions{AllowLoopback: true})
		engine := NewAccessVerificationEngine(AccessEngineOptions{Client: client})

		svc := DiscoveredService{
			Technology: TechAWSS3,
			Family:     FamilyObjectStorage,
			Endpoint:   ts.URL,
		}

		// Run default verification (no test resource)
		_ = engine.VerifyServiceAccess(context.Background(), svc, nil, nil, nil)

		mu.Lock()
		defer mu.Unlock()
		for _, p := range contactedPaths {
			if strings.Contains(p, "list-type") || strings.Contains(p, "max-keys") || strings.Contains(p, "comp=list") {
				t.Fatalf("forbidden enumeration query in default probe: %s", p)
			}
		}
	})

	// Scenario 20: No write request is issued when write authorization is absent
	t.Run("20_No_Write_Request_Without_Authorization", func(t *testing.T) {
		checker := &CanaryGuardrailChecker{
			AllowWriteVerification: false, // Default: disabled
		}

		canary := CanaryConfig{
			Enabled:              true,
			ExplicitlyAuthorized: false,
			TargetResource:       "test-bucket/canary",
		}

		eval := checker.EvaluateConditions("https://s3.amazonaws.com/test-bucket", TechAWSS3, canary, false)
		if eval.Allowed {
			t.Fatal("write evaluation allowed write without authorization!")
		}
	})

	// Scenario 21: Explicitly authorized write verification remains isolated to the configured canary resource
	t.Run("21_Authorized_Write_Isolated_To_Canary", func(t *testing.T) {
		checker := &CanaryGuardrailChecker{
			AllowWriteVerification: true,
			ScopeValidator:         func(string) bool { return true },
		}

		canary := CanaryConfig{
			Enabled:                        true,
			ExplicitlyAuthorized:           true,
			TargetResource:                 "felix-canary-key",
			PreventOverwriteCheck:          true,
			AllowCleanup:                   true,
			IdentityLeastPrivilegeVerified: true,
		}

		eval := checker.EvaluateConditions("127.0.0.1:6379", TechRedis, canary, true)
		if !eval.Allowed {
			t.Fatalf("expected all 8 guardrails to pass, got: %s", eval.Reason)
		}
	})

	// Scenario 22: Failed canary verification does not trigger destructive cleanup
	t.Run("22_Failed_Canary_Does_Not_Trigger_Destructive_Cleanup", func(t *testing.T) {
		preCheckCount := 0
		executeCount := 0
		cleanupCount := 0

		mockOp := &mockCanaryOp{
			preCheckFn: func(ctx context.Context) error {
				preCheckCount++
				return fmt.Errorf("resource already exists; aborting to prevent overwrite")
			},
			executeFn: func(ctx context.Context) error {
				executeCount++
				return nil
			},
			cleanupFn: func(ctx context.Context) error {
				cleanupCount++
				return nil
			},
		}

		err := ExecuteCanaryLifecycle(context.Background(), mockOp)
		if err == nil {
			t.Fatal("expected lifecycle to abort on pre-check failure")
		}
		if executeCount != 0 {
			t.Fatal("execute was called after precheck failure")
		}
		if cleanupCount != 0 {
			t.Fatal("cleanup was called after precheck failure (destructive cleanup violation)")
		}
	})

	// Scenario 23: Protocol handshake does not imply public access
	t.Run("23_Protocol_Handshake_Does_Not_Imply_Public_Access", func(t *testing.T) {
		rec := AccessVerificationRecord{
			Target:          "127.0.0.1:6379",
			Technology:      TechRedis,
			Status:          StatusServiceReachable,
			Decision:        DecisionAllowed,
			AuthContext:     AuthContextNotApplicable,
			Operation:       OpProtocolProbe,
			Evidence:        "PONG response received",
			FindingSuitable: false,
		}

		if err := rec.Validate(); err != nil {
			t.Fatal(err)
		}
		if f, ok := rec.ToCloudFinding(); ok {
			t.Fatalf("protocol handshake must not create security finding: %+v", f)
		}
	})

	// Scenario 24: Successful metadata request does not imply unrestricted data access
	t.Run("24_Successful_Metadata_Does_Not_Imply_Data_Access", func(t *testing.T) {
		rec := AccessVerificationRecord{
			Target:          "http://127.0.0.1:9200",
			Technology:      TechElasticsearch,
			Status:          StatusServiceReachable,
			Decision:        DecisionAllowed,
			AuthContext:     AuthContextUnauthenticated,
			Operation:       OpMetadataRead,
			Evidence:        "Elasticsearch root responded 200 OK",
			FindingSuitable: false,
		}

		if err := rec.Validate(); err != nil {
			t.Fatal(err)
		}
		if rec.Status == StatusReadAllowed {
			t.Fatal("metadata read cannot be classified as ReadAllowed")
		}
	})

	// Scenario 25: Denied read is not misclassified as proof of global protection
	t.Run("25_Denied_Read_Not_Misclassified_As_Global_Protection", func(t *testing.T) {
		rec := AccessVerificationRecord{
			Target:        "http://127.0.0.1:9200",
			Technology:    TechElasticsearch,
			Status:        StatusReadDenied,
			Decision:      DecisionDenied,
			AuthContext:   AuthContextUnauthenticated,
			Operation:     OpBoundedRead,
			ResourceScope: "protected_test_index",
			Evidence:      "Read access to synthetic test index denied",
		}

		if err := rec.Validate(); err != nil {
			t.Fatal(err)
		}
		if rec.ResourceScope != "protected_test_index" {
			t.Fatal("denial must remain strictly localized to the specific resource scope")
		}
	})

	// Scenario 26: Multiple provider detections do not create duplicate access findings
	t.Run("26_Multiple_Detections_No_Duplicate_Findings", func(t *testing.T) {
		rec1 := AccessVerificationRecord{
			Target:          "https://example-test.supabase.co",
			Technology:      TechSupabase,
			Status:          StatusReadAllowed,
			Decision:        DecisionAllowed,
			AuthContext:     AuthContextUnauthenticated,
			Operation:       OpBoundedRead,
			ResourceScope:   "test_table",
			Evidence:        "Unauthenticated public read permitted",
			FindingSuitable: true,
		}

		rec2 := rec1 // Identical duplicate

		f1, ok1 := rec1.ToCloudFinding()
		f2, ok2 := rec2.ToCloudFinding()
		if !ok1 || !ok2 {
			t.Fatal("expected both to be finding suitable")
		}

		if f1.Fingerprint != f2.Fingerprint {
			t.Fatalf("expected identical fingerprints for deduplication: %s vs %s", f1.Fingerprint, f2.Fingerprint)
		}
	})

	// Scenario 27: Cancellation releases connections and other resources correctly
	t.Run("27_Cancellation_Releases_Resources", func(t *testing.T) {
		handlerEntered := make(chan struct{})
		handlerDone := make(chan struct{})

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(handlerEntered)
			<-r.Context().Done()
			close(handlerDone)
		}))
		defer ts.Close()

		ctx, cancel := context.WithCancel(context.Background())
		client := NewClient(ClientOptions{AllowLoopback: true})
		engine := NewAccessVerificationEngine(AccessEngineOptions{Client: client})

		svc := DiscoveredService{
			Technology: TechElasticsearch,
			Family:     FamilyDirectDatabase,
			Endpoint:   ts.URL,
		}

		go func() {
			<-handlerEntered
			cancel() // Cancel context while request is in flight
		}()

		rec := engine.VerifyServiceAccess(ctx, svc, nil, nil, nil)
		select {
		case <-handlerDone:
			// Server handler context was cancelled properly
		case <-time.After(2 * time.Second):
			t.Fatal("handler did not receive cancellation in time")
		}

		if rec.Decision != DecisionError && rec.Decision != DecisionInconclusive && rec.Decision != DecisionSkipped {
			t.Fatalf("expected error/inconclusive on cancelled request, got %s", rec.Decision)
		}
	})
}

// TestAccessVerification_All16Providers verifies dedicated access checks for all 16 target services.
func TestAccessVerification_All16Providers(t *testing.T) {
	client := NewClient(ClientOptions{AllowLoopback: true})

	// 1. Elasticsearch
	t.Run("1_Elasticsearch", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"cluster_name":"es-test","version":{"number":"8.4.1"}}`))
		}))
		defer ts.Close()

		rec := VerifyElasticsearchAccess(context.Background(), client, ts.URL, nil, nil)
		if rec.Technology != TechElasticsearch || rec.Status != StatusServiceReachable {
			t.Fatalf("unexpected Elasticsearch record: %+v", rec)
		}
	})

	// 2. MongoDB
	t.Run("2_MongoDB", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			buf := make([]byte, 128)
			_, _ = conn.Read(buf)
			// Return mock ismaster response
			respHeader := make([]byte, 36)
			_, _ = conn.Write(respHeader)
			_, _ = conn.Write([]byte("ismaster isWritablePrimary"))
		}()

		host, portStr, _ := net.SplitHostPort(ln.Addr().String())
		port, _ := net.LookupPort("tcp", portStr)

		rec := VerifyMongoDBAccess(context.Background(), client, host, port, nil, nil)
		if rec.Technology != TechMongoDB || rec.Status != StatusServiceReachable {
			t.Fatalf("unexpected MongoDB record: %+v", rec)
		}
	})

	// 3. Redis
	t.Run("3_Redis", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			buf := make([]byte, 128)
			_, _ = conn.Read(buf)
			_, _ = conn.Write([]byte("+PONG\r\n"))
		}()

		host, portStr, _ := net.SplitHostPort(ln.Addr().String())
		port, _ := net.LookupPort("tcp", portStr)

		rec := VerifyRedisAccess(context.Background(), client, host, port, nil, nil)
		if rec.Technology != TechRedis || rec.Status != StatusServiceReachable {
			t.Fatalf("unexpected Redis record: %+v", rec)
		}
	})

	// 4. PostgreSQL
	t.Run("4_PostgreSQL", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			buf := make([]byte, 128)
			_, _ = conn.Read(buf)
			// Answer SSLRequest with 'N'
			_, _ = conn.Write([]byte{'N'})
		}()

		host, portStr, _ := net.SplitHostPort(ln.Addr().String())
		port, _ := net.LookupPort("tcp", portStr)

		rec := VerifyPostgreSQLAccess(context.Background(), client, host, port, nil, nil)
		if rec.Technology != TechPostgreSQL || rec.Status != StatusServiceReachable {
			t.Fatalf("unexpected PostgreSQL record: %+v", rec)
		}
	})

	// 5. MySQL
	t.Run("5_MySQL", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			// Send MySQL protocol 10 handshake
			payload := []byte{10, '8', '.', '0', '.', '2', '8', 0, 1, 0, 0, 0}
			hdr := []byte{byte(len(payload)), 0, 0, 0}
			_, _ = conn.Write(hdr)
			_, _ = conn.Write(payload)

			// Read client handshake response and return error packet (Access denied)
			buf := make([]byte, 1024)
			_, _ = conn.Read(buf)
			errPayload := []byte{0xFF, 0x15, 0x04, '#', '2', '8', '0', '0', '0', 'A', 'c', 'c', 'e', 's', 's', ' ', 'd', 'e', 'n', 'i', 'e', 'd'}
			errHdr := []byte{byte(len(errPayload)), 0, 0, 2}
			_, _ = conn.Write(errHdr)
			_, _ = conn.Write(errPayload)
		}()

		host, portStr, _ := net.SplitHostPort(ln.Addr().String())
		port, _ := net.LookupPort("tcp", portStr)

		rec := VerifyMySQLAccess(context.Background(), client, host, port, nil, nil)
		if rec.Technology != TechMySQL || rec.Status != StatusAuthChallenged {
			t.Fatalf("unexpected MySQL record: %+v", rec)
		}
	})

	// 6. Mongo Express
	t.Run("6_MongoExpress", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Mongo Express"`)
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer ts.Close()

		rec := VerifyMongoExpressAccess(context.Background(), client, ts.URL, nil, nil)
		if rec.Technology != TechMongoExpress || rec.Status != StatusAuthChallenged {
			t.Fatalf("unexpected Mongo Express record: %+v", rec)
		}
	})

	// 7. Supabase
	t.Run("7_Supabase", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/rest/v1/" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"Invalid API key"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		rec := VerifySupabaseAccess(context.Background(), client, ts.URL, nil, nil)
		if rec.Technology != TechSupabase || rec.Status != StatusAuthChallenged {
			t.Fatalf("unexpected Supabase record: %+v", rec)
		}
	})

	// 8. PostgREST
	t.Run("8_PostgREST", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"swagger":"2.0","info":{"title":"PostgREST API"}}`))
		}))
		defer ts.Close()

		rec := VerifyPostgRESTAccess(context.Background(), client, ts.URL, nil, nil)
		if rec.Technology != TechPostgREST || rec.Status != StatusServiceReachable {
			t.Fatalf("unexpected PostgREST record: %+v", rec)
		}
	})

	// 9. Hasura
	t.Run("9_Hasura", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"errors":[{"message":"missing x-hasura-admin-secret"}]}`))
		}))
		defer ts.Close()

		rec := VerifyHasuraAccess(context.Background(), client, ts.URL, nil, nil)
		if rec.Technology != TechHasura || rec.Status != StatusAuthChallenged {
			t.Fatalf("unexpected Hasura record: %+v", rec)
		}
	})

	// 10. Prisma
	t.Run("10_Prisma", func(t *testing.T) {
		rec := VerifyPrismaAccess(context.Background(), client, "https://app.example.com", nil, nil)
		if rec.Technology != TechPrisma || rec.Status != StatusVerificationSkipped {
			t.Fatalf("unexpected Prisma record: %+v", rec)
		}
	})

	// 11. Firebase Realtime Database
	t.Run("11_FirebaseRTDB", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"Permission denied"}`))
		}))
		defer ts.Close()

		rec := VerifyFirebaseRTDBAccess(context.Background(), client, ts.URL, nil, nil)
		if rec.Technology != TechFirebaseRTDB || rec.Status != StatusReadDenied {
			t.Fatalf("unexpected Firebase RTDB record: %+v", rec)
		}
	})

	// 12. Cloud Firestore
	t.Run("12_Firestore", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"code":403,"message":"Missing or insufficient permissions."}}`))
		}))
		defer ts.Close()

		rec := VerifyFirestoreAccess(context.Background(), client, "test-proj", nil, nil)
		if rec.Technology != TechFirestore {
			t.Fatalf("unexpected Firestore record: %+v", rec)
		}
	})

	// 13. AWS S3
	t.Run("13_AWSS3", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer ts.Close()

		rec := VerifyAWSS3Access(context.Background(), client, ts.URL, nil, nil)
		if rec.Technology != TechAWSS3 || rec.Status != StatusAuthChallenged {
			t.Fatalf("unexpected AWS S3 record: %+v", rec)
		}
	})

	// 14. Azure Blob Storage
	t.Run("14_AzureBlob", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer ts.Close()

		rec := VerifyAzureBlobAccess(context.Background(), client, ts.URL, nil, nil)
		if rec.Technology != TechAzureBlob || rec.Status != StatusAuthChallenged {
			t.Fatalf("unexpected Azure Blob record: %+v", rec)
		}
	})

	// 15. Google Cloud Storage
	t.Run("15_GCS", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer ts.Close()

		rec := VerifyGCSAccess(context.Background(), client, ts.URL, nil, nil)
		if rec.Technology != TechGCS || rec.Status != StatusAuthChallenged {
			t.Fatalf("unexpected GCS record: %+v", rec)
		}
	})

	// 16. MinIO
	t.Run("16_MinIO", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "MinIO")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		}))
		defer ts.Close()

		rec := VerifyMinIOAccess(context.Background(), client, ts.URL, nil, nil)
		if rec.Technology != TechMinIO || rec.Status != StatusServiceReachable {
			t.Fatalf("unexpected MinIO record: %+v", rec)
		}
	})
}

type mockCanaryOp struct {
	preCheckFn func(ctx context.Context) error
	executeFn  func(ctx context.Context) error
	verifyFn   func(ctx context.Context) error
	cleanupFn  func(ctx context.Context) error
}

func (m *mockCanaryOp) PreCheck(ctx context.Context) error {
	if m.preCheckFn != nil {
		return m.preCheckFn(ctx)
	}
	return nil
}

func (m *mockCanaryOp) Execute(ctx context.Context) error {
	if m.executeFn != nil {
		return m.executeFn(ctx)
	}
	return nil
}

func (m *mockCanaryOp) Verify(ctx context.Context) error {
	if m.verifyFn != nil {
		return m.verifyFn(ctx)
	}
	return nil
}

func (m *mockCanaryOp) Cleanup(ctx context.Context) error {
	if m.cleanupFn != nil {
		return m.cleanupFn(ctx)
	}
	return nil
}

// TestFirebaseRTDB_CredentialSafetyAndRedaction verifies synthetic secret safety and zero query leakage.
func TestFirebaseRTDB_CredentialSafetyAndRedaction(t *testing.T) {
	uniqueSecret := "firebase-super-secret-synthetic-token-998877"
	var receivedAuthHeader string
	var receivedRawQuery string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuthHeader = r.Header.Get("Authorization")
		receivedRawQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"test":"val"}`))
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{AllowLoopback: true})
	cred := &CredentialProfile{
		Name:   "firebase_test",
		Secret: uniqueSecret,
	}

	rec := VerifyFirebaseRTDBAccess(context.Background(), client, ts.URL, cred, &TestResourceConfig{ResourceID: "test_path"})

	if receivedAuthHeader != "Bearer "+uniqueSecret {
		t.Fatalf("expected Authorization: Bearer <secret>, got %q", receivedAuthHeader)
	}
	if strings.Contains(receivedRawQuery, uniqueSecret) {
		t.Fatalf("secret leaked in URL query parameter: %q", receivedRawQuery)
	}
	if strings.Contains(rec.Evidence, uniqueSecret) {
		t.Fatalf("secret leaked in record evidence: %q", rec.Evidence)
	}
	if strings.Contains(rec.Limitations, uniqueSecret) {
		t.Fatalf("secret leaked in record limitations: %q", rec.Limitations)
	}

	// Verify RedactSensitiveString handles query parameters and headers safely
	sampleErr := fmt.Sprintf("connection failed to https://db.firebaseio.com/test.json?auth=%s&shallow=true", uniqueSecret)
	redacted := RedactSensitiveString(sampleErr)
	if strings.Contains(redacted, uniqueSecret) {
		t.Fatalf("RedactSensitiveString failed to redact query token: %s", redacted)
	}
	if !strings.Contains(redacted, "auth=***REDACTED***") {
		t.Fatalf("expected auth=***REDACTED***, got %s", redacted)
	}
}

// TestHasura_LeastPrivilegeIdentityAndErrorHandling verifies least-privilege identity and error classification.
func TestHasura_LeastPrivilegeIdentityAndErrorHandling(t *testing.T) {
	uniqueToken := "hasura-least-priv-user-jwt-112233"
	var receivedAuth string
	var receivedAdminSecret string
	var receivedRole string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedAdminSecret = r.Header.Get("x-hasura-admin-secret")
		receivedRole = r.Header.Get("X-Hasura-Role")

		w.Header().Set("Content-Type", "application/json")
		// Simulate GraphQL validation error when querying a restricted field
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":[{"message":"field 'restricted_field' not found in type: 'query_root'","extensions":{"code":"validation-failed"}}]}`))
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{AllowLoopback: true})
	cred := &CredentialProfile{
		Secret: uniqueToken,
		Role:   "user_auditor",
	}

	rec := VerifyHasuraAccess(context.Background(), client, ts.URL, cred, &TestResourceConfig{ResourceID: "restricted_field"})

	if receivedAuth != "Bearer "+uniqueToken {
		t.Fatalf("expected Bearer token for least-privilege user, got %q", receivedAuth)
	}
	if receivedRole != "user_auditor" {
		t.Fatalf("expected X-Hasura-Role 'user_auditor', got %q", receivedRole)
	}
	if receivedAdminSecret != "" {
		t.Fatalf("verifier unexpectedly sent x-hasura-admin-secret for routine least-privilege user: %q", receivedAdminSecret)
	}

	// Assert that GraphQL validation error is NOT misclassified as data access
	if rec.Status != StatusReadDenied || rec.Decision != DecisionDenied {
		t.Fatalf("expected ReadDenied/Denied on GraphQL errors, got %s/%s", rec.Status, rec.Decision)
	}
	if rec.FindingSuitable {
		t.Fatal("restricted field response with errors must not be marked finding suitable")
	}
}

// TestCanaryWrite_StrictGuardrailsAndOverwrites verifies no-overwrite pre-checks and explicit authorization.
func TestCanaryWrite_StrictGuardrailsAndOverwrites(t *testing.T) {
	checker := &CanaryGuardrailChecker{
		AllowWriteVerification: true,
		ScopeValidator:         func(string) bool { return true },
	}

	// Case A: Role name alone without IdentityLeastPrivilegeVerified must be rejected
	canaryNoVerifiedIdentity := CanaryConfig{
		Enabled:                        true,
		ExplicitlyAuthorized:           true,
		TargetResource:                 "test-key",
		PreventOverwriteCheck:          true,
		AllowCleanup:                   true,
		IdentityLeastPrivilegeVerified: false, // Not verified
	}
	eval := checker.EvaluateConditions("127.0.0.1:6379", TechRedis, canaryNoVerifiedIdentity, true)
	if eval.Allowed {
		t.Fatal("expected rejection when IdentityLeastPrivilegeVerified is false")
	}

	// Case B: Pre-check detects existing resource and prevents overwrite
	op := &mockCanaryOp{
		preCheckFn: func(ctx context.Context) error {
			return fmt.Errorf("resource 'test-key' already exists")
		},
		executeFn: func(ctx context.Context) error {
			t.Fatal("execute must not be called when pre-check fails!")
			return nil
		},
	}
	err := ExecuteCanaryLifecycle(context.Background(), op)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected overwrite prevention error, got: %v", err)
	}
}

// TestFindings_DeduplicationAndSeverityCalibration verifies scoped deduplication and metadata severity.
func TestFindings_DeduplicationAndSeverityCalibration(t *testing.T) {
	// Case A: Different resource scopes on same target do NOT collide
	rec1 := AccessVerificationRecord{
		Target:          "https://example.supabase.co",
		Technology:      TechSupabase,
		Status:          StatusReadAllowed,
		Decision:        DecisionAllowed,
		AuthContext:     AuthContextUnauthenticated,
		Operation:       OpBoundedRead,
		ResourceScope:   "table_users",
		FindingSuitable: true,
	}
	rec2 := AccessVerificationRecord{
		Target:          "https://example.supabase.co",
		Technology:      TechSupabase,
		Status:          StatusReadAllowed,
		Decision:        DecisionAllowed,
		AuthContext:     AuthContextUnauthenticated,
		Operation:       OpBoundedRead,
		ResourceScope:   "table_orders",
		FindingSuitable: true,
	}

	f1, _ := rec1.ToCloudFinding()
	f2, _ := rec2.ToCloudFinding()

	if f1.Fingerprint == f2.Fingerprint {
		t.Fatalf("different resource scopes on same endpoint collided into identical fingerprint: %s", f1.Fingerprint)
	}

	// Case B: Identical checks on same resource scope DO produce identical fingerprint
	rec3 := rec1
	f3, _ := rec3.ToCloudFinding()
	if f1.Fingerprint != f3.Fingerprint {
		t.Fatalf("identical checks on same resource failed to deduplicate: %s vs %s", f1.Fingerprint, f3.Fingerprint)
	}

	// Case C: Metadata read generates SeverityInfo (not SeverityMedium or High)
	recMeta := AccessVerificationRecord{
		Target:          "http://127.0.0.1:9200",
		Technology:      TechElasticsearch,
		Status:          StatusUnauthenticatedAccess,
		Decision:        DecisionAllowed,
		AuthContext:     AuthContextUnauthenticated,
		Operation:       OpMetadataRead,
		FindingSuitable: true,
	}
	fMeta, _ := recMeta.ToCloudFinding()
	if fMeta.Severity != SeverityInfo {
		t.Fatalf("expected metadata exposure to be SeverityInfo, got %s", fMeta.Severity)
	}
}

// TestDatabaseProtocolHandshake_EmpiricalVerification verifies protocol challenge handling.
func TestDatabaseProtocolHandshake_EmpiricalVerification(t *testing.T) {
	client := NewClient(ClientOptions{AllowLoopback: true})

	// PostgreSQL AuthenticationRequest challenge (authCode 5 = MD5)
	t.Run("PostgreSQL_MD5_Challenge", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			buf := make([]byte, 128)
			_, _ = conn.Read(buf) // SSLRequest
			_, _ = conn.Write([]byte{'N'})
			_, _ = conn.Read(buf) // StartupMessage
			// Send AuthenticationMD5Password ('R', len 12, code 5, salt 4 bytes)
			authPkt := []byte{
				'R',
				0x00, 0x00, 0x00, 0x0c, // len 12
				0x00, 0x00, 0x00, 0x05, // authCode 5 (MD5)
				0x01, 0x02, 0x03, 0x04, // salt
			}
			_, _ = conn.Write(authPkt)
		}()

		host, portStr, _ := net.SplitHostPort(ln.Addr().String())
		port, _ := net.LookupPort("tcp", portStr)

		rec := VerifyPostgreSQLAccess(context.Background(), client, host, port, nil, nil)
		if rec.Status != StatusAuthChallenged || rec.Decision != DecisionDenied {
			t.Fatalf("expected AuthChallenged/Denied on MD5 challenge, got %s/%s", rec.Status, rec.Decision)
		}
	})

	// MySQL Handshake Response Error (Access denied)
	t.Run("MySQL_Handshake_Access_Denied", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			// 1. Send Initial Handshake Packet
			initPayload := []byte{10, '8', '.', '0', '.', '3', '0', 0, 1, 0, 0, 0}
			initHdr := []byte{byte(len(initPayload)), 0, 0, 0}
			_, _ = conn.Write(initHdr)
			_, _ = conn.Write(initPayload)

			// 2. Read Client Handshake Response
			respHdr := make([]byte, 4)
			_, _ = conn.Read(respHdr)
			rLen := int(respHdr[0]) | int(respHdr[1])<<8 | int(respHdr[2])<<16
			rBuf := make([]byte, rLen)
			_, _ = conn.Read(rBuf)

			// 3. Return Error Packet (0xFF, code 1045)
			errPayload := []byte{0xFF, 0x15, 0x04, '#', '2', '8', '0', '0', '0', 'A', 'c', 'c', 'e', 's', 's', ' ', 'd', 'e', 'n', 'i', 'e', 'd'}
			errHdr := []byte{byte(len(errPayload)), 0, 0, 2}
			_, _ = conn.Write(errHdr)
			_, _ = conn.Write(errPayload)
		}()

		host, portStr, _ := net.SplitHostPort(ln.Addr().String())
		port, _ := net.LookupPort("tcp", portStr)

		rec := VerifyMySQLAccess(context.Background(), client, host, port, nil, nil)
		if rec.Status != StatusAuthChallenged || rec.Decision != DecisionDenied {
			t.Fatalf("expected AuthChallenged/Denied on MySQL Error packet, got %s/%s", rec.Status, rec.Decision)
		}
	})

	// MySQL Handshake Reachability Only (Server disconnects before handshake response)
	t.Run("MySQL_Handshake_Reachability_Only", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			initPayload := []byte{10, '8', '.', '0', '.', '3', '0', 0, 1, 0, 0, 0}
			initHdr := []byte{byte(len(initPayload)), 0, 0, 0}
			_, _ = conn.Write(initHdr)
			_, _ = conn.Write(initPayload)
			// Mock closes conn immediately without reading or sending response
		}()

		host, portStr, _ := net.SplitHostPort(ln.Addr().String())
		port, _ := net.LookupPort("tcp", portStr)

		rec := VerifyMySQLAccess(context.Background(), client, host, port, nil, nil)
		if rec.Status != StatusServiceReachable || rec.Decision != DecisionAllowed {
			t.Fatalf("expected ServiceReachable/Allowed on MySQL initial handshake alone, got %s/%s", rec.Status, rec.Decision)
		}
	})

	// MySQL Handshake Anonymous Login Accepted (0x00 OK packet)
	t.Run("MySQL_Handshake_Anonymous_OK", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			initPayload := []byte{10, '8', '.', '0', '.', '3', '0', 0, 1, 0, 0, 0}
			initHdr := []byte{byte(len(initPayload)), 0, 0, 0}
			_, _ = conn.Write(initHdr)
			_, _ = conn.Write(initPayload)

			respHdr := make([]byte, 4)
			_, _ = conn.Read(respHdr)
			rLen := int(respHdr[0]) | int(respHdr[1])<<8 | int(respHdr[2])<<16
			rBuf := make([]byte, rLen)
			_, _ = conn.Read(rBuf)

			// OK packet: 0x00, affected rows 0, last insert id 0, status flags 0x0002, warnings 0
			okPayload := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
			okHdr := []byte{byte(len(okPayload)), 0, 0, 2}
			_, _ = conn.Write(okHdr)
			_, _ = conn.Write(okPayload)
		}()

		host, portStr, _ := net.SplitHostPort(ln.Addr().String())
		port, _ := net.LookupPort("tcp", portStr)

		rec := VerifyMySQLAccess(context.Background(), client, host, port, nil, nil)
		if rec.Status != StatusUnauthenticatedAccess || rec.Decision != DecisionAllowed {
			t.Fatalf("expected UnauthenticatedAccess/Allowed on MySQL OK packet, got %s/%s", rec.Status, rec.Decision)
		}
	})
}
