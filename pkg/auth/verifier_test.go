package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/report"
)

// Helper to construct a valid authorization record for tests.
func testValidAuth() *AuthorizationRecord {
	past := time.Now().UTC().Add(-1 * time.Hour)
	future := time.Now().UTC().Add(24 * time.Hour)
	return &AuthorizationRecord{
		ID:                  "auth-test-valid",
		AuthorizingParty:    "Security Team",
		AuthorizationMethod: "WRITTEN_CONTRACT",
		Status:              "APPROVED",
		ValidFrom:           &past,
		ValidUntil:          &future,
	}
}

// ---------------------------------------------------------------------
// 1. Core Classification Tests (Cases 1 - 10)
// ---------------------------------------------------------------------

func TestVerifier_PublicEndpoint_ReturnsPassed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","uptime":12345}`))
	}))
	defer ts.Close()

	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL:         ts.URL,
		Endpoints:         []string{ts.URL + "/health"},
		PublicRoutes:      []string{"/health"},
		Authorization:     testValidAuth(),
		AllowLoopback:     true,
		MaxRequestsTotal:  10,
		MaxRequestsPerHost: 10,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rep.Summary.TotalPassed != 1 {
		t.Errorf("expected 1 passed result for public endpoint, got %d", rep.Summary.TotalPassed)
	}
	if len(rep.Findings) != 0 {
		t.Errorf("expected 0 findings for public route, got %d", len(rep.Findings))
	}
}

func TestVerifier_ProtectedEndpoint_MissingCreds_ReturnsPassed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		if authHdr == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"authentication required"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":"secret user profile"}`))
	}))
	defer ts.Close()

	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL:     ts.URL,
		Endpoints:     []string{ts.URL + "/api/profile"},
		Authorization: testValidAuth(),
		AllowLoopback: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Missing cred was properly rejected with 401 Unauthorized -> Passed!
	foundPassed := false
	for _, r := range rep.Results {
		if r.TestType == TestMissingCredential && r.Disposition == DispositionPassed {
			foundPassed = true
		}
	}
	if !foundPassed {
		t.Errorf("expected TestMissingCredential to have DispositionPassed when server returns 401")
	}
	if len(rep.Findings) != 0 {
		t.Errorf("expected 0 findings when endpoint properly rejects missing credentials, got %d", len(rep.Findings))
	}
}

func TestVerifier_ProtectedEndpoint_MissingCreds_Exposure_ReturnsWeakness(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"user_id":"123","email":"admin@corp.internal","role":"superadmin"}`))
	}))
	defer ts.Close()

	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL:               ts.URL,
		Endpoints:               []string{ts.URL + "/api/v1/admin/users"},
		ExpectedProtectedRoutes: []string{"/api/v1/admin/users"},
		Authorization:           testValidAuth(),
		AllowLoopback:           true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rep.Summary.TotalWeaknesses < 1 {
		t.Errorf("expected weakness verified when protected endpoint is accessible unauthenticated, got %d", rep.Summary.TotalWeaknesses)
	}
	if len(rep.Findings) == 0 {
		t.Fatalf("expected finding for unauthenticated protected route exposure")
	}
	if rep.Findings[0].RuleID != "AUTH-ENFORCE-MISSING" {
		t.Errorf("expected rule AUTH-ENFORCE-MISSING, got %s", rep.Findings[0].RuleID)
	}
	if rep.Findings[0].Status != report.FindingStatusConfirmed {
		t.Errorf("expected status confirmed, got %s", rep.Findings[0].Status)
	}
}

func TestVerifier_InvalidSyntheticCredential_Accepted_ReturnsWeakness(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		if authHdr == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Insecure server accepts any token format as valid!
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"authenticated","user_id":"synthetic-bypass"}`))
	}))
	defer ts.Close()

	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL: ts.URL,
		Endpoints: []string{ts.URL + "/api/secure"},
		PrimaryCredential: Credential{
			Type:  CredTypeBearer,
			Value: "valid_dummy_token_abc123",
		},
		Authorization: testValidAuth(),
		AllowLoopback: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundWeakness := false
	for _, f := range rep.Findings {
		if f.RuleID == "AUTH-CRED-INVALID-ACCEPTED" {
			foundWeakness = true
		}
	}
	if !foundWeakness {
		t.Errorf("expected finding AUTH-CRED-INVALID-ACCEPTED when server accepts invalid synthetic token")
	}
}

func TestVerifier_MalformedHeader_UnhandledCrash_ReturnsWeakness(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		if authHdr == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.Contains(authHdr, "!!!malformed") {
			// Unhandled parser exception
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"NullPointerException in AuthParser"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL: ts.URL,
		Endpoints: []string{ts.URL + "/api/crash-test"},
		PrimaryCredential: Credential{
			Type:  CredTypeBearer,
			Value: "dummy_token_123",
		},
		Authorization: testValidAuth(),
		AllowLoopback: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundCrash := false
	for _, f := range rep.Findings {
		if f.RuleID == "AUTH-CRED-MALFORMED-CRASH" {
			foundCrash = true
		}
	}
	if !foundCrash {
		t.Errorf("expected AUTH-CRED-MALFORMED-CRASH finding on server 500 on malformed header")
	}
}

func TestVerifier_EmptyCredential_Handling(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		tokenVal := strings.TrimSpace(strings.TrimPrefix(authHdr, "Bearer"))
		if authHdr == "" || tokenVal == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"authenticated":true}`))
	}))
	defer ts.Close()

	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL: ts.URL,
		Endpoints: []string{ts.URL + "/api/empty-test"},
		PrimaryCredential: Credential{
			Type:  CredTypeBearer,
			Value: "dummy_token_123",
		},
		Authorization: testValidAuth(),
		AllowLoopback: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundEmptyPassed := false
	for _, res := range rep.Results {
		if res.TestType == TestEmptyCredential && res.Disposition == DispositionPassed {
			foundEmptyPassed = true
		}
	}
	if !foundEmptyPassed {
		t.Errorf("expected TestEmptyCredential to pass when server returns 401 on empty token")
	}
}

func TestVerifier_ExpiredCredential_Handling(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		if authHdr == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if strings.Contains(authHdr, "expired") {
			// Buggy server accepts expired token!
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"user":"expired_session_data"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	expiredToken := "expired_test_jwt_token_12345"
	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL: ts.URL,
		Endpoints: []string{ts.URL + "/api/exp-test"},
		PrimaryCredential: Credential{
			Type:  CredTypeBearer,
			Value: "active_token",
		},
		ExpiredCredential: &Credential{
			Type:  CredTypeBearer,
			Value: expiredToken,
		},
		Authorization: testValidAuth(),
		AllowLoopback: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundExpiredFinding := false
	for _, f := range rep.Findings {
		if f.RuleID == "AUTH-TOKEN-EXPIRED-ACCEPTED" {
			foundExpiredFinding = true
		}
	}
	if !foundExpiredFinding {
		t.Errorf("expected AUTH-TOKEN-EXPIRED-ACCEPTED finding when server accepts expired token")
	}
}

func TestVerifier_AuthenticationFailure_NotMisclassifiedAsVulnerability(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"Unauthorized"}`))
	}))
	defer ts.Close()

	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL: ts.URL,
		Endpoints: []string{ts.URL + "/api/test"},
		PrimaryCredential: Credential{
			Type:  CredTypeBearer,
			Value: "fake_token",
		},
		Authorization: testValidAuth(),
		AllowLoopback: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rep.Summary.TotalWeaknesses > 0 {
		t.Errorf("401 rejection must never be classified as a weakness; got %d weaknesses", rep.Summary.TotalWeaknesses)
	}
}

func TestVerifier_Generic200OK_WithoutPolicy_ClassifiedInconclusive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`Welcome to unknown page`))
	}))
	defer ts.Close()

	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL:     ts.URL,
		Endpoints:     []string{ts.URL + "/random-unknown-page"},
		Authorization: testValidAuth(),
		AllowLoopback: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rep.Summary.TotalInconclusive < 1 {
		t.Errorf("expected generic 200 without known policy to be inconclusive, got %d", rep.Summary.TotalInconclusive)
	}
	if len(rep.Findings) > 0 {
		t.Errorf("expected 0 confirmed findings for unknown 200 route, got %d", len(rep.Findings))
	}
}

func TestVerifier_UnsupportedChecks_ReportedHonestly(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL: ts.URL,
		Endpoints: []string{ts.URL + "/api/digest-test"},
		PrimaryCredential: Credential{
			Type:  "digest", // Unsupported credential scheme!
			Value: "unsupported_data",
		},
		Authorization: testValidAuth(),
		AllowLoopback: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rep.Summary.TotalUnsupported < 1 {
		t.Errorf("expected unsupported scheme to increment TotalUnsupported, got %d", rep.Summary.TotalUnsupported)
	}
	foundUnsupported := false
	for _, res := range rep.Results {
		if res.Disposition == DispositionUnsupported {
			foundUnsupported = true
		}
	}
	if !foundUnsupported {
		t.Errorf("expected result with DispositionUnsupported")
	}
}

// ---------------------------------------------------------------------
// 2. Comparison and Consistency Tests (Cases 11 - 16)
// ---------------------------------------------------------------------

func TestVerifier_EquivalentRequests_DeterministicComparison(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":"identical_payload","items":[1,2,3]}`))
	}))
	defer ts.Close()

	cfg := VerificationConfig{
		TargetURL: ts.URL,
		Endpoints: []string{ts.URL + "/api/identical"},
		PrimaryCredential: Credential{
			Type:  CredTypeBearer,
			Value: "test_token_123",
		},
		Authorization: testValidAuth(),
		AllowLoopback: true,
	}

	v := NewVerifier()
	rep1, err1 := v.Verify(context.Background(), cfg)
	rep2, err2 := v.Verify(context.Background(), cfg)

	if err1 != nil || err2 != nil {
		t.Fatalf("unexpected errors: %v, %v", err1, err2)
	}

	if rep1.Summary.TotalCandidates != rep2.Summary.TotalCandidates {
		t.Errorf("non-deterministic candidate count: %d vs %d", rep1.Summary.TotalCandidates, rep2.Summary.TotalCandidates)
	}
	if len(rep1.Findings) != len(rep2.Findings) {
		t.Errorf("non-deterministic findings count: %d vs %d", len(rep1.Findings), len(rep2.Findings))
	}
}

func TestVerifier_ResponseDifferences_InconclusiveWithoutSemanticProof(t *testing.T) {
	var count int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := atomic.AddInt32(&count, 1)
		w.WriteHeader(http.StatusOK)
		// Differ slightly in random text without application payload
		fmt.Fprintf(w, "server timestamp %d", c*100)
	}))
	defer ts.Close()

	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL: ts.URL,
		Endpoints: []string{ts.URL + "/dynamic"},
		PrimaryCredential: Credential{
			Type:  CredTypeBearer,
			Value: "token",
		},
		Authorization: testValidAuth(),
		AllowLoopback: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rep.Summary.TotalInconclusive < 1 {
		t.Errorf("expected inconclusive observation when responses differ without application proof")
	}
}

func TestVerifier_RouteConsistency_Detection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/users" {
			// Protected endpoint enforces auth
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		if r.URL.Path == "/api/v1/users/export" {
			// Sibling endpoint forgotten: unauthenticated 200 with sensitive data!
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"exported_users":[{"id":"1","email":"a@b.com"}]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL:     ts.URL,
		Endpoints:     []string{ts.URL + "/api/v1/users", ts.URL + "/api/v1/users/export"},
		Authorization: testValidAuth(),
		AllowLoopback: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundInconsistent := false
	for _, f := range rep.Findings {
		if f.RuleID == "AUTH-ROUTE-INCONSISTENCY" {
			foundInconsistent = true
		}
	}
	if !foundInconsistent {
		t.Errorf("expected AUTH-ROUTE-INCONSISTENCY finding when sibling route under /api/v1/users leaks data without auth")
	}
}

func TestVerifier_MethodBypass_HEAD(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			// HEAD bypass bug!
			w.WriteHeader(http.StatusOK)
			return
		}
		// GET properly rejects unauthenticated access
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer ts.Close()

	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL:     ts.URL,
		Endpoints:     []string{ts.URL + "/api/resource"},
		Authorization: testValidAuth(),
		AllowLoopback: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundBypass := false
	for _, f := range rep.Findings {
		if f.RuleID == "AUTH-METHOD-BYPASS" {
			foundBypass = true
		}
	}
	if !foundBypass {
		t.Errorf("expected AUTH-METHOD-BYPASS finding when HEAD bypasses GET auth enforcement")
	}
}

func TestVerifier_AuthVsAuthz_Distinction(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 403 Forbidden indicates authorization failure, not authentication missing
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer ts.Close()

	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL:     ts.URL,
		Endpoints:     []string{ts.URL + "/api/forbidden"},
		Authorization: testValidAuth(),
		AllowLoopback: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 403 response must be recognized as an access control barrier, not an unauthenticated exposure
	if rep.Summary.TotalWeaknesses > 0 {
		t.Errorf("403 Forbidden should never create an authentication exposure weakness, got %d", rep.Summary.TotalWeaknesses)
	}
}

func TestVerifier_DeterministicOrdering(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	cfg := VerificationConfig{
		TargetURL:     ts.URL,
		Endpoints:     []string{ts.URL + "/z-endpoint", ts.URL + "/a-endpoint", ts.URL + "/m-endpoint"},
		Authorization: testValidAuth(),
		AllowLoopback: true,
	}

	v := NewVerifier()
	rep, err := v.Verify(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify endpoints in Results are sorted alphabetically
	for i := 1; i < len(rep.Results); i++ {
		prev := rep.Results[i-1].Endpoint
		curr := rep.Results[i].Endpoint
		if prev > curr {
			t.Errorf("results not deterministically sorted: %s came after %s", curr, prev)
		}
	}
}

// ---------------------------------------------------------------------
// 3. Security Boundary Tests (Cases 17 - 26)
// ---------------------------------------------------------------------

func TestVerifier_SecurityBoundary_MissingAuthorization(t *testing.T) {
	v := NewVerifier()
	_, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL:     "http://example.com",
		Authorization: nil, // Missing!
	})

	if err == nil {
		t.Fatalf("expected ErrMissingAuthorization, got nil")
	}
	if !strings.Contains(err.Error(), "missing authorization") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestVerifier_SecurityBoundary_ExpiredOrPendingAuthorization(t *testing.T) {
	past := time.Now().UTC().Add(-2 * time.Hour)
	expiredAuth := &AuthorizationRecord{
		ID:         "auth-expired",
		Status:     "APPROVED",
		ValidUntil: &past,
	}

	v := NewVerifier()
	_, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL:     "http://example.com",
		Authorization: expiredAuth,
	})

	if err == nil {
		t.Fatalf("expected invalid authorization error, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestVerifier_SecurityBoundary_OutOfScope(t *testing.T) {
	v := NewVerifier()
	_, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL:     "https://unapproved.attacker.com",
		Authorization: testValidAuth(),
		IsAllowed: func(u string) bool {
			return strings.Contains(u, "approved.com")
		},
	})

	if err == nil {
		t.Fatalf("expected ErrTargetOutOfScope, got nil")
	}
}

func TestVerifier_SecurityBoundary_ExcludedTarget(t *testing.T) {
	v := NewVerifier()
	_, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL:     "https://approved.com/admin/delete-all",
		Authorization: testValidAuth(),
		IsAllowed:     func(u string) bool { return true },
		IsExcluded: func(u string) bool {
			return strings.Contains(u, "/delete-all")
		},
	})

	if err == nil {
		t.Fatalf("expected ErrTargetExcluded, got nil")
	}
}

func TestVerifier_SecurityBoundary_RedirectCrossOriginCredentialStripping(t *testing.T) {
	var targetHostAuthHeader string
	var secondHostAuthHeader string

	h2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHostAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer h2.Close()

	h1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHostAuthHeader = r.Header.Get("Authorization")
		// Redirect to different host!
		http.Redirect(w, r, h2.URL, http.StatusFound)
	}))
	defer h1.Close()

	v := NewVerifier()
	_, _ = v.Verify(context.Background(), VerificationConfig{
		TargetURL: h1.URL,
		PrimaryCredential: Credential{
			Type:  CredTypeBearer,
			Value: "super_secret_token",
		},
		Authorization: testValidAuth(),
		AllowLoopback: true,
		IsAllowed:     func(u string) bool { return true },
	})

	if targetHostAuthHeader == "" {
		t.Errorf("expected primary host to receive Authorization header")
	}
	if secondHostAuthHeader != "" {
		t.Errorf("credential leak: second cross-origin host received Authorization header %q", secondHostAuthHeader)
	}
}

func TestVerifier_SecurityBoundary_RedirectOutOfScopeBlocked(t *testing.T) {
	outOfScopeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer outOfScopeServer.Close()

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Attempt redirect to out-of-scope server
		http.Redirect(w, r, outOfScopeServer.URL, http.StatusFound)
	}))
	defer targetServer.Close()

	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL:     targetServer.URL,
		Authorization: testValidAuth(),
		AllowLoopback: true,
		IsAllowed: func(u string) bool {
			// Only targetServer is in scope; outOfScopeServer is out of scope!
			return strings.Contains(u, targetServer.URL)
		},
	})

	if err != nil {
		t.Fatalf("unexpected Verify error: %v", err)
	}

	// The baseline probe should fail or be recorded as failed redirect
	if rep.Summary.TotalFailed < 1 {
		t.Errorf("expected out-of-scope redirect to cause probe failure, got %d failed", rep.Summary.TotalFailed)
	}
}

func TestVerifier_SecurityBoundary_LoopbackBlockedByDefault(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL:     ts.URL,
		Authorization: testValidAuth(),
		AllowLoopback: false, // Default is false!
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// When loopback is not allowed, safe dialer blocks 127.0.0.1 immediately
	if rep.Summary.TotalFailed < 1 {
		t.Errorf("expected loopback probe to be blocked by safe transport, got %d failed", rep.Summary.TotalFailed)
	}
}

func TestVerifier_SecurityBoundary_RequestBudgetsEnforced(t *testing.T) {
	var requestCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	maxBudget := 3
	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL: ts.URL,
		Endpoints: []string{
			ts.URL + "/ep1",
			ts.URL + "/ep2",
			ts.URL + "/ep3",
			ts.URL + "/ep4",
			ts.URL + "/ep5",
		},
		MaxRequestsTotal:   maxBudget,
		MaxRequestsPerHost: maxBudget,
		Authorization:      testValidAuth(),
		AllowLoopback:      true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	actualSent := atomic.LoadInt32(&requestCount)
	if actualSent > int32(maxBudget) {
		t.Errorf("budget exceeded: allowed %d, but sent %d", maxBudget, actualSent)
	}
	if !rep.BudgetExhausted {
		t.Errorf("expected rep.BudgetExhausted to be true")
	}
}

func TestVerifier_SecurityBoundary_ContextCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately!

	v := NewVerifier()
	rep, err := v.Verify(ctx, VerificationConfig{
		TargetURL:     ts.URL,
		Authorization: testValidAuth(),
		AllowLoopback: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rep.Summary.TotalRequests != 0 {
		t.Errorf("expected 0 requests dispatched on cancelled context, got %d", rep.Summary.TotalRequests)
	}
}

func TestVerifier_SecurityBoundary_RateLimitingSafeAndBounded(t *testing.T) {
	var probeCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&probeCount, 1)
		// Server never returns 429
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL:         ts.URL,
		Endpoints:         []string{ts.URL + "/api/login"},
		CheckRateLimiting: true, // Enable safe check
		Authorization:     testValidAuth(),
		AllowLoopback:     true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sent := atomic.LoadInt32(&probeCount)
	// Must never brute force or exceed safe bounded budget (max 5 rate limit probes + baseline probes)
	if sent > 10 {
		t.Errorf("rate limiting check exceeded safe bounds: sent %d requests", sent)
	}

	foundInconclusive := false
	for _, res := range rep.Results {
		if res.TestType == TestRateLimiting && res.Disposition == DispositionInconclusive {
			foundInconclusive = true
		}
	}
	if !foundInconclusive {
		t.Errorf("expected conservative DispositionInconclusive when rate limiting is not observed within 5 probes")
	}
}

// ---------------------------------------------------------------------
// 4. Data Handling Tests (Cases 27 - 32)
// ---------------------------------------------------------------------

func TestVerifier_DataHandling_SecretRedaction(t *testing.T) {
	rawSecret := "super_secret_raw_api_key_xyz987654"
	cred := Credential{
		Type:  CredTypeBearer,
		Value: rawSecret,
	}

	// 1. JSON marshaling of Credential must not leak rawSecret
	credJSON, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if strings.Contains(string(credJSON), rawSecret) {
		t.Fatalf("critical leak: raw credential exposed in JSON serialization: %s", string(credJSON))
	}

	// 2. Scrubbed value is redacted
	if cred.Scrubbed() == rawSecret {
		t.Fatalf("Scrubbed() returned unredacted secret")
	}
}

func TestVerifier_DataHandling_QueryParamTokenRedacted(t *testing.T) {
	rawURL := "https://example.com/api/data?api_key=secret_123456789&user=alice"
	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL:     rawURL,
		Authorization: testValidAuth(),
		DryRun:        true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that TargetURL in report is sanitized
	if strings.Contains(rep.TargetURL, "secret_123456789") {
		t.Errorf("TargetURL query token not sanitized in report: %s", rep.TargetURL)
	}
}

func TestVerifier_DataHandling_HTMLEscaping(t *testing.T) {
	maliciousSnippet := `<script>alert('XSS')</script> SELECT * FROM users WHERE id=1;`
	fnd := buildVerboseErrorFinding("https://example.com/api", 500, maliciousSnippet)

	if strings.Contains(fnd.Evidence, "<script>") {
		t.Errorf("unencoded HTML script tag detected in finding evidence: %s", fnd.Evidence)
	}
	if !strings.Contains(fnd.Evidence, "&lt;script&gt;") {
		t.Errorf("expected HTML-escaped script tag in finding evidence: %s", fnd.Evidence)
	}
}

func TestVerifier_DataHandling_ResponseSizeBounded(t *testing.T) {
	// Server returns 10MB of data
	largePayload := strings.Repeat("A", 10*1024*1024)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(largePayload))
	}))
	defer ts.Close()

	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL:       ts.URL,
		MaxResponseSize: 1024, // Limit to 1KB
		Authorization:   testValidAuth(),
		AllowLoopback:   true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rep.Summary.TotalTested != 1 {
		t.Errorf("expected 1 endpoint tested, got %d", rep.Summary.TotalTested)
	}
}

func TestVerifier_DataHandling_CleartextTransport(t *testing.T) {
	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL: "http://example.com/api/login",
		PrimaryCredential: Credential{
			Type:  CredTypeBearer,
			Value: "test_secret_bearer",
		},
		Authorization: testValidAuth(),
		IsAllowed:     func(u string) bool { return true },
		DryRun:        false,
		AllowLoopback: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundCleartext := false
	for _, f := range rep.Findings {
		if f.RuleID == "AUTH-CLEARTEXT-TRANSPORT" {
			foundCleartext = true
		}
	}
	if !foundCleartext {
		t.Errorf("expected AUTH-CLEARTEXT-TRANSPORT finding when credentials configured over http://")
	}
}

func TestVerifier_DryRun_NoNetworkDispatched(t *testing.T) {
	var networkRequests int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&networkRequests, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	v := NewVerifier()
	rep, err := v.Verify(context.Background(), VerificationConfig{
		TargetURL:     ts.URL,
		Endpoints:     []string{ts.URL + "/ep1", ts.URL + "/ep2"},
		DryRun:        true,
		Authorization: testValidAuth(),
		AllowLoopback: true,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if atomic.LoadInt32(&networkRequests) != 0 {
		t.Errorf("dry-run must dispatch 0 network requests, but dispatched %d", networkRequests)
	}
	if rep.Summary.TotalSkipped != 2 {
		t.Errorf("expected 2 skipped checks in dry-run mode, got %d", rep.Summary.TotalSkipped)
	}
}
