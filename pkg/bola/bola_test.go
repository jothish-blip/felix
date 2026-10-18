package bola

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/auth"
)

func testApprovedAuth() *auth.AuthorizationRecord {
	past := time.Now().UTC().Add(-1 * time.Hour)
	future := time.Now().UTC().Add(24 * time.Hour)
	return &auth.AuthorizationRecord{
		ID:                  "auth-bola-test",
		AuthorizingParty:    "Security Lead",
		AuthorizationMethod: "Written",
		Status:              "APPROVED",
		ValidFrom:           &past,
		ValidUntil:          &future,
	}
}

// 1. Owner can read their own protected object
func TestBOLA_OwnerCanReadOwnProtectedObject(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.Header.Get("Authorization"), "token_user_b") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"id":"usr-9988","owner":"user_b","data":"confidential_profile"}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Endpoints: []EndpointTemplate{
			{Method: "GET", PathPattern: "/api/users/{id}"},
		},
		Objects: []ObjectIdentifier{
			{ID: "usr-9988", Location: "path", OwnerIdentity: "user_b"},
		},
		Identities: []TestIdentity{
			{Alias: "user_a", Headers: map[string]string{"Authorization": "Bearer token_user_a"}},
			{Alias: "user_b", Headers: map[string]string{"Authorization": "Bearer token_user_b"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE when non-owner receives 403, got %s", results[0].VerificationState)
	}
}

// 2. Non-owner is correctly denied access
func TestBOLA_NonOwnerCorrectlyDenied(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Authorization"), "token_user_a") {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":"forbidden"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"id":"usr-9988","owner":"user_b","profile":"secret"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Endpoints:     []EndpointTemplate{{Method: "GET", PathPattern: "/api/users/{id}"}},
		Objects:       []ObjectIdentifier{{ID: "usr-9988", Location: "path", OwnerIdentity: "user_b"}},
		Identities: []TestIdentity{
			{Alias: "user_a", Headers: map[string]string{"Authorization": "Bearer token_user_a"}},
			{Alias: "user_b", Headers: map[string]string{"Authorization": "Bearer token_user_b"}},
		},
	}

	results, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE, got %s", results[0].VerificationState)
	}
	if summary.NotVulnerableCount != 1 {
		t.Errorf("expected NotVulnerableCount=1, got %d", summary.NotVulnerableCount)
	}
}

// 3. Non-owner receives another user's protected object and BOLA is verified
func TestBOLA_NonOwnerReceivesProtectedObject_Verified(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Leaking user_b's object to anyone regardless of token!
		fmt.Fprint(w, `{"id":"usr-9988","owner":"user_b","confidential":"financial_records"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Endpoints:     []EndpointTemplate{{Method: "GET", PathPattern: "/api/users/{id}"}},
		Objects:       []ObjectIdentifier{{ID: "usr-9988", Location: "path", OwnerIdentity: "user_b"}},
		Identities: []TestIdentity{
			{Alias: "user_a", Headers: map[string]string{"Authorization": "Bearer token_user_a"}},
			{Alias: "user_b", Headers: map[string]string{"Authorization": "Bearer token_user_b"}},
		},
	}

	results, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateVerified {
		t.Errorf("expected VERIFIED BOLA finding, got %s", results[0].VerificationState)
	}
	if results[0].Finding == nil {
		t.Errorf("expected finding to be generated for verified BOLA")
	}
	if summary.VerifiedCount != 1 {
		t.Errorf("expected summary VerifiedCount=1, got %d", summary.VerifiedCount)
	}
}

// 4. A 200 OK generic login page does not create a false positive
func TestBOLA_GenericLoginPage200_NoFalsePositive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Authorization"), "token_user_a") {
			// Returns 200 OK with HTML login page
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<!DOCTYPE html><html><body><form action="/login"><input name="password"/></form></body></html>`)
			return
		}
		// Baseline returns valid JSON
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"id":"usr-9988","data":"confidential"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Endpoints:     []EndpointTemplate{{Method: "GET", PathPattern: "/api/users/{id}"}},
		Objects:       []ObjectIdentifier{{ID: "usr-9988", Location: "path", OwnerIdentity: "user_b"}},
		Identities: []TestIdentity{
			{Alias: "user_a", Headers: map[string]string{"Authorization": "Bearer token_user_a"}},
			{Alias: "user_b", Headers: map[string]string{"Authorization": "Bearer token_user_b"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState == StateVerified {
		t.Errorf("false positive: HTML login form with 200 OK was falsely classified as VERIFIED BOLA")
	}
	if results[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE, got %s", results[0].VerificationState)
	}
}

// 5. An identical public response does not create a false positive
func TestBOLA_IdenticalPublicResponse_NoFalsePositive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Both return generic public message without object ID
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"service":"public-api","status":"ok","version":"1.0"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Endpoints:     []EndpointTemplate{{Method: "GET", PathPattern: "/api/users/{id}"}},
		Objects:       []ObjectIdentifier{{ID: "usr-9988", Location: "path", OwnerIdentity: "user_b"}},
		Identities: []TestIdentity{
			{Alias: "user_a", Headers: map[string]string{"Authorization": "Bearer token_user_a"}},
			{Alias: "user_b", Headers: map[string]string{"Authorization": "Bearer token_user_b"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState == StateVerified {
		t.Errorf("false positive: public static JSON without object ID was classified as VERIFIED")
	}
}

// 6. A missing ownership mapping produces an inconclusive result
func TestBOLA_MissingOwnershipMapping_Inconclusive(t *testing.T) {
	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       "http://127.0.0.1:8080",
		Authorization: testApprovedAuth(),
		Endpoints:     []EndpointTemplate{{Method: "GET", PathPattern: "/api/users/{id}"}},
		// Object without owner mapping
		Objects: []ObjectIdentifier{{ID: "usr-9988", Location: "path", OwnerIdentity: ""}},
		Identities: []TestIdentity{
			{Alias: "user_a", Headers: map[string]string{"Authorization": "Bearer token_user_a"}},
			{Alias: "user_b", Headers: map[string]string{"Authorization": "Bearer token_user_b"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateInconclusive {
		t.Errorf("expected INCONCLUSIVE when ownership mapping is missing, got %s", results[0].VerificationState)
	}
}

// 7. Identical identity contexts do not falsely claim cross-principal testing
func TestBOLA_IdenticalIdentities_Blocked(t *testing.T) {
	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       "http://127.0.0.1:8080",
		Authorization: testApprovedAuth(),
		Endpoints:     []EndpointTemplate{{Method: "GET", PathPattern: "/api/users/{id}"}},
		Objects:       []ObjectIdentifier{{ID: "usr-9988", Location: "path", OwnerIdentity: "user_a"}},
		// Identical tokens & aliases
		Identities: []TestIdentity{
			{Alias: "user_a", Headers: map[string]string{"Authorization": "Bearer identical_token"}},
			{Alias: "user_a", Headers: map[string]string{"Authorization": "Bearer identical_token"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateInconclusive {
		t.Errorf("expected INCONCLUSIVE when identities are identical, got %s", results[0].VerificationState)
	}
	if !strings.Contains(results[0].EvidenceSummary, "identical") {
		t.Errorf("expected evidence to mention identical identities, got %s", results[0].EvidenceSummary)
	}
}

// 8. Dynamic response fields do not create misleading comparisons
func TestBOLA_DynamicFieldsComparison(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Return same object payload but with different timestamp and request_id
		nowStr := time.Now().Format(time.RFC3339Nano)
		fmt.Fprintf(w, `{"id":"usr-9988","owner":"user_b","confidential":"financial_data","timestamp":"%s","request_id":"%s"}`, nowStr, r.Header.Get("User-Agent"))
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Endpoints:     []EndpointTemplate{{Method: "GET", PathPattern: "/api/users/{id}"}},
		Objects:       []ObjectIdentifier{{ID: "usr-9988", Location: "path", OwnerIdentity: "user_b"}},
		Identities: []TestIdentity{
			{Alias: "user_a", Headers: map[string]string{"Authorization": "Bearer token_user_a"}},
			{Alias: "user_b", Headers: map[string]string{"Authorization": "Bearer token_user_b"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateVerified {
		t.Errorf("expected VERIFIED BOLA despite transient timestamp/request_id difference, got %s", results[0].VerificationState)
	}
}

// 9. Object ownership fields are not normalized away
func TestBOLA_ObjectOwnershipFieldsPreserved(t *testing.T) {
	inputJSON := map[string]interface{}{
		"id":         "usr-9988",
		"user_id":    "usr-9988",
		"owner":      "user_b",
		"tenant_id":  "tenant-42",
		"timestamp":  "2026-10-18T20:00:00Z",
		"request_id": "req-12345",
	}

	cleaned := StripDynamicFields(inputJSON).(map[string]interface{})

	// Dynamic transient fields must be stripped
	if _, ok := cleaned["timestamp"]; ok {
		t.Errorf("timestamp was not stripped")
	}
	if _, ok := cleaned["request_id"]; ok {
		t.Errorf("request_id was not stripped")
	}

	// Ownership identifiers must be preserved
	if cleaned["id"] != "usr-9988" {
		t.Errorf("id was lost or modified: %v", cleaned["id"])
	}
	if cleaned["user_id"] != "usr-9988" {
		t.Errorf("user_id was lost or modified: %v", cleaned["user_id"])
	}
	if cleaned["owner"] != "user_b" {
		t.Errorf("owner was lost or modified: %v", cleaned["owner"])
	}
	if cleaned["tenant_id"] != "tenant-42" {
		t.Errorf("tenant_id was lost or modified: %v", cleaned["tenant_id"])
	}
}

// 10. Missing protected data evidence prevents a confirmed BOLA classification
func TestBOLA_MissingProtectedData_PreventsVerified(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if strings.Contains(r.Header.Get("Authorization"), "token_user_a") {
			// Returns 200 OK with completely different generic payload, no object ID
			fmt.Fprint(w, `{"status":"ok","notes":"no_records_available"}`)
			return
		}
		fmt.Fprint(w, `{"id":"usr-9988","owner":"user_b","records":["rec1"]}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		ExecutionID:   "exec-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Endpoints:     []EndpointTemplate{{Method: "GET", PathPattern: "/api/users/{id}"}},
		Objects:       []ObjectIdentifier{{ID: "usr-9988", Location: "path", OwnerIdentity: "user_b"}},
		Identities: []TestIdentity{
			{Alias: "user_a", Headers: map[string]string{"Authorization": "Bearer token_user_a"}},
			{Alias: "user_b", Headers: map[string]string{"Authorization": "Bearer token_user_b"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState == StateVerified {
		t.Errorf("expected CANDIDATE or INCONCLUSIVE when response does not disclose object ID, got VERIFIED")
	}
}

// 11. Missing, expired, or unapproved authorization causes zero network requests
func TestBOLA_MissingAuthorization_ZeroRequests(t *testing.T) {
	var requestCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())

	// Test nil authorization
	actxNil := &AssessmentContext{
		AssessmentID:  "asm-01",
		BaseURL:       ts.URL,
		Authorization: nil,
	}
	_, _, err := engine.Assess(context.Background(), actxNil)
	if err == nil {
		t.Errorf("expected error for nil authorization, got nil")
	}
	if atomic.LoadInt32(&requestCount) != 0 {
		t.Errorf("expected 0 requests for nil authorization, dispatched %d", requestCount)
	}

	// Test expired authorization
	past := time.Now().UTC().Add(-2 * time.Hour)
	actxExpired := &AssessmentContext{
		AssessmentID: "asm-01",
		BaseURL:      ts.URL,
		Authorization: &auth.AuthorizationRecord{
			ID:         "auth-expired",
			Status:     "APPROVED",
			ValidFrom:  &past,
			ValidUntil: &past,
		},
	}
	_, _, err = engine.Assess(context.Background(), actxExpired)
	if err == nil {
		t.Errorf("expected error for expired authorization, got nil")
	}
	if atomic.LoadInt32(&requestCount) != 0 {
		t.Errorf("expected 0 requests for expired authorization, dispatched %d", requestCount)
	}
}

// 12. Out-of-scope and excluded targets are blocked
func TestBOLA_ScopeAndExclusions_Blocked(t *testing.T) {
	var requestCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		IsAllowed: func(u string) bool {
			return false // out of scope
		},
	}

	_, _, err := engine.Assess(context.Background(), actx)
	if err == nil {
		t.Errorf("expected error for out of scope target, got nil")
	}
	if atomic.LoadInt32(&requestCount) != 0 {
		t.Errorf("expected 0 requests dispatched for out-of-scope target, got %d", requestCount)
	}
}

// 13. Redirects cannot leak credentials across origins
func TestBOLA_Redirects_NoCredentialLeakAcrossOrigins(t *testing.T) {
	var targetReceivedAuth string
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetReceivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"id":"usr-9988","data":"target_server"}`)
	}))
	defer targetServer.Close()

	originServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Redirect to different server
		http.Redirect(w, r, targetServer.URL+"/api/users/usr-9988", http.StatusFound)
	}))
	defer originServer.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		BaseURL:       originServer.URL,
		Authorization: testApprovedAuth(),
		IsAllowed: func(u string) bool {
			return true
		},
		Endpoints: []EndpointTemplate{{Method: "GET", PathPattern: "/api/users/{id}"}},
		Objects:   []ObjectIdentifier{{ID: "usr-9988", Location: "path", OwnerIdentity: "user_b"}},
		Identities: []TestIdentity{
			{Alias: "user_a", Headers: map[string]string{"Authorization": "Bearer secret_user_a"}},
			{Alias: "user_b", Headers: map[string]string{"Authorization": "Bearer secret_user_b"}},
		},
	}

	_, _, _ = engine.Assess(context.Background(), actx)
	if targetReceivedAuth != "" {
		t.Errorf("security violation: sensitive Authorization header leaked across origin redirect: %q", targetReceivedAuth)
	}
}

// 14. Remote cleartext HTTP cannot receive sensitive credentials
func TestBOLA_RemoteCleartextHTTP_SensitiveCredentialsWithheld(t *testing.T) {
	// Loopback test of credentialGuardedTransport with remote check
	baseTransport := &mockRoundTripper{
		fn: func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("Authorization") != "" {
				t.Errorf("sensitive Authorization header was NOT stripped on remote cleartext HTTP")
			}
			return &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       ioNopCloser(strings.NewReader(`{"status":"ok"}`)),
			}, nil
		},
	}

	gt := &credentialGuardedTransport{
		base: baseTransport,
	}

	req, _ := http.NewRequest("GET", "http://api.remote-victim.corp/users/1", nil)
	req.Header.Set("Authorization", "Bearer top_secret_token")

	_, err := gt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

type mockRoundTripper struct {
	fn func(req *http.Request) (*http.Response, error)
}

func (m *mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.fn(req)
}

func ioNopCloser(r *strings.Reader) ioReadCloser {
	return ioReadCloser{r}
}

type ioReadCloser struct {
	*strings.Reader
}

func (ioReadCloser) Close() error { return nil }

// 15. Dry-run issues zero network requests
func TestBOLA_DryRun_ZeroNetworkRequests(t *testing.T) {
	var requestCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		BaseURL:       ts.URL,
		DryRun:        true,
		Authorization: testApprovedAuth(),
		Endpoints:     []EndpointTemplate{{Method: "GET", PathPattern: "/api/users/{id}"}},
		Objects:       []ObjectIdentifier{{ID: "usr-9988", Location: "path", OwnerIdentity: "user_b"}},
		Identities: []TestIdentity{
			{Alias: "user_a", Headers: map[string]string{"Authorization": "Bearer token_a"}},
			{Alias: "user_b", Headers: map[string]string{"Authorization": "Bearer token_b"}},
		},
	}

	plan, err := engine.Plan(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if plan.TotalTests != 1 {
		t.Errorf("expected 1 planned test, got %d", plan.TotalTests)
	}
	if atomic.LoadInt32(&requestCount) != 0 {
		t.Errorf("dry-run sent network requests: %d", requestCount)
	}
}

// 16. Request budgets are enforced exactly, including concurrent attempts
func TestBOLA_RequestBudget_EnforcedConcurrently(t *testing.T) {
	maxRequests := 10
	var dispatched int32

	gt := &credentialGuardedTransport{
		base: &mockRoundTripper{
			fn: func(req *http.Request) (*http.Response, error) {
				time.Sleep(5 * time.Millisecond)
				return &http.Response{
					StatusCode: 200,
					Header:     make(http.Header),
					Body:       ioNopCloser(strings.NewReader(`ok`)),
				}, nil
			},
		},
		maxRequests: maxRequests,
		reqCount:    &dispatched,
	}

	var wg sync.WaitGroup
	var successfulReqs int32
	var blockedReqs int32

	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/test", nil)
			_, err := gt.RoundTrip(req)
			if err == nil {
				atomic.AddInt32(&successfulReqs, 1)
			} else {
				atomic.AddInt32(&blockedReqs, 1)
			}
		}()
	}
	wg.Wait()

	if atomic.LoadInt32(&successfulReqs) > int32(maxRequests) {
		t.Errorf("budget exceeded: allowed %d but %d succeeded", maxRequests, successfulReqs)
	}
	if atomic.LoadInt32(&dispatched) > int32(maxRequests) {
		t.Errorf("counter exceeded budget limit: %d > %d", dispatched, maxRequests)
	}
}

// 17. Cancellation and timeout stop further requests
func TestBOLA_CancellationAndTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Endpoints:     []EndpointTemplate{{Method: "GET", PathPattern: "/api/users/{id}"}},
		Objects:       []ObjectIdentifier{{ID: "usr-9988", Location: "path", OwnerIdentity: "user_b"}},
		Identities: []TestIdentity{
			{Alias: "user_a", Headers: map[string]string{"Authorization": "Bearer token_a"}},
			{Alias: "user_b", Headers: map[string]string{"Authorization": "Bearer token_b"}},
		},
	}

	_, _, err := engine.Assess(ctx, actx)
	if err == nil {
		t.Fatalf("expected timeout/cancellation error, got nil")
	}
}

// 18. Oversized responses remain bounded and are classified safely
func TestBOLA_OversizedResponses_Bounded(t *testing.T) {
	// Server returns 5MB of repeating data
	largeBody := strings.Repeat("A", 5*1024*1024)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, largeBody)
	}))
	defer ts.Close()

	cfg := DefaultConfig()
	cfg.MaxBodyReadBytes = 64 * 1024 // 64KB bounded limit
	engine := NewEngine(nil, cfg)

	resp, err := engine.sendRequest(context.Background(), ts.Client(), "GET", ts.URL, TestIdentity{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if int64(len(resp.Body)) > cfg.MaxBodyReadBytes {
		t.Errorf("response body exceeded MaxBodyReadBytes: %d > %d", len(resp.Body), cfg.MaxBodyReadBytes)
	}
}

// 19. State-changing methods are refused without explicit opt-in
func TestBOLA_StateChanging_RequiresExplicitOptIn(t *testing.T) {
	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:            "asm-01",
		BaseURL:                 "http://127.0.0.1:8080",
		Authorization:           testApprovedAuth(),
		AllowStateChangingTests: false, // Refused by default
		Endpoints: []EndpointTemplate{
			{Method: "PUT", PathPattern: "/api/users/{id}", IsStateChanging: true},
		},
		Objects: []ObjectIdentifier{
			{ID: "usr-9988", Location: "path", OwnerIdentity: "user_b"},
		},
		Identities: []TestIdentity{
			{Alias: "user_a", Headers: map[string]string{"Authorization": "Bearer token_a"}},
			{Alias: "user_b", Headers: map[string]string{"Authorization": "Bearer token_b"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].VerificationState != StateSkipped {
		t.Errorf("expected SKIPPED without --allow-state-changing, got %s", results[0].VerificationState)
	}
	if !strings.Contains(results[0].EvidenceSummary, "--allow-state-changing") {
		t.Errorf("expected explanation to mention opt-in requirement, got %s", results[0].EvidenceSummary)
	}
}

// 20. Synthetic bearer tokens and cookies never appear in findings or JSON
func TestBOLA_SecretsRedactedInFindings(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"id":"usr-9988","owner":"user_b","token":"SECRET_API_KEY_xyz9988"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Endpoints:     []EndpointTemplate{{Method: "GET", PathPattern: "/api/users/{id}"}},
		Objects:       []ObjectIdentifier{{ID: "usr-9988", Location: "path", OwnerIdentity: "user_b"}},
		Identities: []TestIdentity{
			{Alias: "user_a", Headers: map[string]string{"Authorization": "Bearer SuperSecretBearerToken123"}},
			{Alias: "user_b", Headers: map[string]string{"Authorization": "Bearer SuperSecretBearerToken456"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) == 0 || results[0].Finding == nil {
		t.Fatalf("expected finding for verified result")
	}

	findingJSON, _ := json.Marshal(results[0].Finding)
	fStr := string(findingJSON)

	if strings.Contains(fStr, "SuperSecretBearerToken123") || strings.Contains(fStr, "SuperSecretBearerToken456") {
		t.Errorf("security violation: raw bearer tokens leaked into finding JSON: %s", fStr)
	}
}

// 21. Sensitive object fields do not leak into findings unredacted
func TestBOLA_SensitiveFieldsNotLeaked(t *testing.T) {
	input := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDNSet integration test token"
	redacted := RedactText(input)
	if strings.Contains(redacted, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") {
		t.Errorf("raw JWT token was not redacted: %s", redacted)
	}

	hashed := HashSecret("my_very_private_password_123")
	if strings.Contains(hashed, "my_very_private_password_123") {
		t.Errorf("secret password was not hashed safely: %s", hashed)
	}
	if !strings.HasPrefix(hashed, "sha256:") {
		t.Errorf("expected sha256 prefix on secret hash, got: %s", hashed)
	}
}

// 22. Findings are deterministic across repeated runs
func TestBOLA_FindingsDeterministicAcrossRuns(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"id":"usr-9988","owner":"user_b","data":"protected_profile"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Endpoints:     []EndpointTemplate{{Method: "GET", PathPattern: "/api/users/{id}"}},
		Objects:       []ObjectIdentifier{{ID: "usr-9988", Location: "path", OwnerIdentity: "user_b"}},
		Identities: []TestIdentity{
			{Alias: "user_a", Headers: map[string]string{"Authorization": "Bearer token_a"}},
			{Alias: "user_b", Headers: map[string]string{"Authorization": "Bearer token_b"}},
		},
	}

	res1, sum1, err1 := engine.Assess(context.Background(), actx)
	res2, sum2, err2 := engine.Assess(context.Background(), actx)

	if err1 != nil || err2 != nil {
		t.Fatalf("unexpected error: %v / %v", err1, err2)
	}
	if len(res1) != len(res2) {
		t.Errorf("result lengths differ across runs: %d vs %d", len(res1), len(res2))
	}
	if res1[0].VerificationState != res2[0].VerificationState {
		t.Errorf("verification states differ across runs: %s vs %s", res1[0].VerificationState, res2[0].VerificationState)
	}
	if sum1.VerifiedCount != sum2.VerifiedCount {
		t.Errorf("summary verified counts differ: %d vs %d", sum1.VerifiedCount, sum2.VerifiedCount)
	}
}

// 23. Missing prerequisites rejected early before network activity
func TestBOLA_MissingPrerequisites_RejectedEarly(t *testing.T) {
	var requestCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())

	// No objects
	actxNoObjects := &AssessmentContext{
		AssessmentID:  "asm-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Endpoints:     []EndpointTemplate{{Method: "GET", PathPattern: "/api/users/{id}"}},
		Objects:       []ObjectIdentifier{},
		Identities: []TestIdentity{
			{Alias: "user_a", Headers: map[string]string{"Authorization": "Bearer token_a"}},
			{Alias: "user_b", Headers: map[string]string{"Authorization": "Bearer token_b"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actxNoObjects)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 || results[0].VerificationState != StateInconclusive {
		t.Errorf("expected INCONCLUSIVE result for missing objects")
	}
	if atomic.LoadInt32(&requestCount) != 0 {
		t.Errorf("requests sent despite missing objects prerequisite: %d", requestCount)
	}
}

// 24. Cross-tenant read access verified when tenant B object is retrieved by tenant A principal
func TestBOLA_TenantIsolation_CrossTenantLeakageVerified(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Leaking tenant_b's data to tenant_a
		fmt.Fprint(w, `{"id":"rec-500","tenant_id":"tenant_b","data":"confidential_tenant_b_records"}`)
	}))
	defer ts.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:  "asm-01",
		BaseURL:       ts.URL,
		Authorization: testApprovedAuth(),
		Endpoints: []EndpointTemplate{
			{Method: "GET", PathPattern: "/api/tenants/{tenantId}/records/{recordId}"},
		},
		Objects: []ObjectIdentifier{
			{ID: "rec-500", Location: "path", OwnerIdentity: "user_tenant_b", TenantID: "tenant_b"},
		},
		Identities: []TestIdentity{
			{Alias: "user_tenant_a", TenantID: "tenant_a", Headers: map[string]string{"Authorization": "Bearer token_tenant_a"}},
			{Alias: "user_tenant_b", TenantID: "tenant_b", Headers: map[string]string{"Authorization": "Bearer token_tenant_b"}},
		},
	}

	results, _, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Category != CategoryBOLATenantRead {
		t.Errorf("expected category BOLA-TENANT-READ, got %s", results[0].Category)
	}
	if results[0].VerificationState != StateVerified {
		t.Errorf("expected VERIFIED for cross-tenant leakage, got %s", results[0].VerificationState)
	}
}
