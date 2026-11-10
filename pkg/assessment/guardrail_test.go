package assessment

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/crawler"
)

// -----------------------------------------------------------------------------
// Test 1: Valid Scope Manifest Parsing and Schema Validation
// -----------------------------------------------------------------------------
func TestGuardrail_01_ValidManifestParsingAndSchemaValidation(t *testing.T) {
	yamlData := []byte(`
version: "1.0"
metadata:
  assessment_id: "ASM-2026-PROD-01"
  client_name: "Enterprise Sovereign Banking"
  created_at: 2026-11-10T00:00:00Z
  description: "Authorized external penetration test"
scope:
  allowed_hosts:
    - "api.sovereign.bank"
    - "portal.sovereign.bank:8443"
    - "127.0.0.1:3000"
  allowed_paths:
    - "/v1"
    - "/portal"
    - "/auth/login"
  allowed_methods:
    - "GET"
    - "POST"
    - "PUT"
    - "HEAD"
    - "OPTIONS"
  allow_admin_delete:
    enabled: true
    authorized_endpoints:
      - "/v1/admin/sandbox-users/*"
    authorized_by: "secops-director@sovereign.bank"
    justification: "Automated test user teardown for CI audit"
origin_health:
  strain_threshold: 4
  rolling_window: 15s
  backoff_duration: 45s
  throttled_rate: 1.0
  throttled_concurrency: 1
`)

	manifest, err := ParsePentestManifest(yamlData)
	if err != nil {
		t.Fatalf("expected valid manifest, got error: %v", err)
	}

	if manifest.Version != "1.0" {
		t.Errorf("expected version 1.0, got %s", manifest.Version)
	}
	if len(manifest.Scope.AllowedHosts) != 3 {
		t.Errorf("expected 3 allowed hosts, got %d", len(manifest.Scope.AllowedHosts))
	}
	if len(manifest.Scope.AllowedPaths) != 3 {
		t.Errorf("expected 3 allowed paths, got %d", len(manifest.Scope.AllowedPaths))
	}
	if len(manifest.Scope.AllowedMethods) != 5 {
		t.Errorf("expected 5 allowed methods, got %d", len(manifest.Scope.AllowedMethods))
	}
	if manifest.Scope.AllowAdminDelete == nil || !manifest.Scope.AllowAdminDelete.Enabled {
		t.Errorf("expected allow_admin_delete to be enabled")
	}
	if manifest.OriginHealth.StrainThreshold != 4 {
		t.Errorf("expected strain_threshold 4, got %d", manifest.OriginHealth.StrainThreshold)
	}
	if manifest.OriginHealth.BackoffDuration != 45*time.Second {
		t.Errorf("expected backoff_duration 45s, got %v", manifest.OriginHealth.BackoffDuration)
	}
}

// -----------------------------------------------------------------------------
// Test 2: Malformed and Missing Manifest Rejection
// -----------------------------------------------------------------------------
func TestGuardrail_02_MalformedAndMissingManifestRejection(t *testing.T) {
	// Empty data
	_, err := ParsePentestManifest([]byte(""))
	if err == nil || !errors.Is(err, ErrManifestInvalid) {
		t.Errorf("expected ErrManifestInvalid on empty data, got %v", err)
	}

	// Malformed YAML
	malformed := []byte(`
version: 1.0
  scope: [invalid yaml syntax :::
`)
	_, err = ParsePentestManifest(malformed)
	if err == nil || !errors.Is(err, ErrManifestInvalid) {
		t.Errorf("expected ErrManifestInvalid on malformed YAML, got %v", err)
	}

	// Missing version
	noVersion := []byte(`
scope:
  allowed_hosts: ["example.com"]
  allowed_paths: ["/"]
  allowed_methods: ["GET"]
`)
	_, err = ParsePentestManifest(noVersion)
	if err == nil || !strings.Contains(err.Error(), "version field is required") {
		t.Errorf("expected missing version error, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Test 3: Empty Scope Fail-Closed Rejection
// -----------------------------------------------------------------------------
func TestGuardrail_03_EmptyScopeFailClosed(t *testing.T) {
	// Missing allowed_hosts
	noHosts := []byte(`
version: "1.0"
scope:
  allowed_paths: ["/"]
  allowed_methods: ["GET"]
`)
	_, err := ParsePentestManifest(noHosts)
	if err == nil || !errors.Is(err, ErrEmptyScope) {
		t.Errorf("expected ErrEmptyScope on missing hosts, got %v", err)
	}

	// Missing allowed_paths
	noPaths := []byte(`
version: "1.0"
scope:
  allowed_hosts: ["example.com"]
  allowed_methods: ["GET"]
`)
	_, err = ParsePentestManifest(noPaths)
	if err == nil || !errors.Is(err, ErrEmptyScope) {
		t.Errorf("expected ErrEmptyScope on missing paths, got %v", err)
	}

	// Missing allowed_methods
	noMethods := []byte(`
version: "1.0"
scope:
  allowed_hosts: ["example.com"]
  allowed_paths: ["/"]
`)
	_, err = ParsePentestManifest(noMethods)
	if err == nil || !errors.Is(err, ErrEmptyScope) {
		t.Errorf("expected ErrEmptyScope on missing methods, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Test 4: Host Allowlist Strict Matching and Port Handling
// -----------------------------------------------------------------------------
func TestGuardrail_04_HostAllowlistStrictMatchingAndPortHandling(t *testing.T) {
	manifest := &PentestManifest{
		Version: "1.0",
		Scope: ScopeConfig{
			AllowedHosts:   []string{"example.com", "api.example.com:8443", "127.0.0.1:3000"},
			AllowedPaths:   []string{"/"},
			AllowedMethods: []string{"GET"},
		},
	}

	// Allowed: exact host match on default port 80/443
	reqAllowed1, _ := http.NewRequest("GET", "http://example.com/index.html", nil)
	if bl := CheckScope(reqAllowed1, manifest); bl != nil {
		t.Errorf("expected http://example.com to be allowed, got blocked: %s", bl.Reason)
	}

	// Allowed: exact host with specified port
	reqAllowed2, _ := http.NewRequest("GET", "https://api.example.com:8443/v1/users", nil)
	if bl := CheckScope(reqAllowed2, manifest); bl != nil {
		t.Errorf("expected https://api.example.com:8443 to be allowed, got blocked: %s", bl.Reason)
	}

	// Blocked: wrong port for host with port requirement
	reqBlockedPort, _ := http.NewRequest("GET", "https://api.example.com:9443/v1/users", nil)
	if bl := CheckScope(reqBlockedPort, manifest); bl == nil || bl.BlacklistCategory != "OUT_OF_SCOPE_HOST" {
		t.Errorf("expected port 9443 to be blocked as OUT_OF_SCOPE_HOST, got %v", bl)
	}

	// Blocked: unlisted host
	reqBlockedHost, _ := http.NewRequest("GET", "http://evil.com/", nil)
	if bl := CheckScope(reqBlockedHost, manifest); bl == nil || bl.BlacklistCategory != "OUT_OF_SCOPE_HOST" {
		t.Errorf("expected evil.com to be blocked as OUT_OF_SCOPE_HOST, got %v", bl)
	}
}

// -----------------------------------------------------------------------------
// Test 5: Hostname Confusion and Wildcard Rejection (Prefix/Suffix Confusion)
// -----------------------------------------------------------------------------
func TestGuardrail_05_HostnameConfusionAndWildcardRejection(t *testing.T) {
	// 1. Manifest with broad wildcard must be rejected at parse time
	wildcardYAML := []byte(`
version: "1.0"
scope:
  allowed_hosts: ["*"]
  allowed_paths: ["/"]
  allowed_methods: ["GET"]
`)
	_, err := ParsePentestManifest(wildcardYAML)
	if err == nil {
		t.Fatal("expected manifest parsing to reject wildcard '*' host")
	}

	// 2. Strict matching prevents suffix and prefix confusion
	manifest := &PentestManifest{
		Version: "1.0",
		Scope: ScopeConfig{
			AllowedHosts:   []string{"target.com"},
			AllowedPaths:   []string{"/"},
			AllowedMethods: []string{"GET"},
		},
	}

	adversarialHosts := []string{
		"http://not-target.com/",
		"http://attacker-target.com/",
		"http://target.com.attacker.com/",
		"http://target.com.evil.io/",
		"http://sub.target.com/", // subdomains not allowed unless explicitly listed
	}

	for _, rawURL := range adversarialHosts {
		req, _ := http.NewRequest("GET", rawURL, nil)
		bl := CheckScope(req, manifest)
		if bl == nil || bl.BlacklistCategory != "OUT_OF_SCOPE_HOST" {
			t.Errorf("expected hostname confusion attempt %q to be blocked as OUT_OF_SCOPE_HOST, got: %v", rawURL, bl)
		}
	}
}

// -----------------------------------------------------------------------------
// Test 6: Path Allowlist and Traversal Bypass Defense
// -----------------------------------------------------------------------------
func TestGuardrail_06_PathAllowlistAndTraversalBypassDefense(t *testing.T) {
	manifest := &PentestManifest{
		Version: "1.0",
		Scope: ScopeConfig{
			AllowedHosts:   []string{"example.com"},
			AllowedPaths:   []string{"/api", "/public"},
			AllowedMethods: []string{"GET"},
		},
	}

	// Allowed: exact path and subpaths
	validRequests := []string{
		"http://example.com/api",
		"http://example.com/api/",
		"http://example.com/api/v1/items",
		"http://example.com/public/styles.css",
	}
	for _, u := range validRequests {
		req, _ := http.NewRequest("GET", u, nil)
		if bl := CheckScope(req, manifest); bl != nil {
			t.Errorf("expected %q to be allowed, got blocked: %s", u, bl.Reason)
		}
	}

	// Traversal bypass attempts: path traversal out of /api
	traversalAttempts := []string{
		"http://example.com/api/../admin",
		"http://example.com/api/%2e%2e/admin",
		"http://example.com/api/..%2fadmin",
		"http://example.com/public/../../secret",
		"http://example.com/apigateway", // prefix confusion without slash boundary
		"http://example.com/private",
	}
	for _, u := range traversalAttempts {
		req, _ := http.NewRequest("GET", u, nil)
		bl := CheckScope(req, manifest)
		if bl == nil || bl.BlacklistCategory != "OUT_OF_SCOPE_PATH" {
			t.Errorf("expected path traversal / out-of-scope %q to be blocked as OUT_OF_SCOPE_PATH, got: %v", u, bl)
		}
	}
}

// -----------------------------------------------------------------------------
// Test 7: HTTP Method Authorization
// -----------------------------------------------------------------------------
func TestGuardrail_07_HTTPMethodAuthorization(t *testing.T) {
	manifest := &PentestManifest{
		Version: "1.0",
		Scope: ScopeConfig{
			AllowedHosts:   []string{"example.com"},
			AllowedPaths:   []string{"/"},
			AllowedMethods: []string{"GET", "HEAD"},
		},
	}

	// GET & HEAD are permitted
	reqGet, _ := http.NewRequest("GET", "http://example.com/", nil)
	if bl := CheckScope(reqGet, manifest); bl != nil {
		t.Errorf("expected GET to be allowed, got: %v", bl)
	}

	reqHead, _ := http.NewRequest("HEAD", "http://example.com/", nil)
	if bl := CheckScope(reqHead, manifest); bl != nil {
		t.Errorf("expected HEAD to be allowed, got: %v", bl)
	}

	// POST, PUT, DELETE, PATCH, TRACE are unauthorized
	unauthorizedMethods := []string{"POST", "PUT", "DELETE", "PATCH", "TRACE"}
	for _, m := range unauthorizedMethods {
		req, _ := http.NewRequest(m, "http://example.com/", nil)
		bl := CheckScope(req, manifest)
		if bl == nil || bl.BlacklistCategory != "UNAUTHORIZED_METHOD" {
			t.Errorf("expected method %s to be blocked as UNAUTHORIZED_METHOD, got: %v", m, bl)
		}
	}
}

// -----------------------------------------------------------------------------
// Test 8: IPv4 and IPv6 Destination Validation
// -----------------------------------------------------------------------------
func TestGuardrail_08_IPv4AndIPv6DestinationValidation(t *testing.T) {
	manifest := &PentestManifest{
		Version: "1.0",
		Scope: ScopeConfig{
			AllowedHosts:   []string{"127.0.0.1:3000", "[::1]:3000", "192.168.1.50"},
			AllowedPaths:   []string{"/"},
			AllowedMethods: []string{"GET"},
		},
	}

	// IPv4 match
	reqV4, _ := http.NewRequest("GET", "http://127.0.0.1:3000/app", nil)
	if bl := CheckScope(reqV4, manifest); bl != nil {
		t.Errorf("expected 127.0.0.1:3000 to be allowed, got %v", bl)
	}

	// IPv6 match
	reqV6, _ := http.NewRequest("GET", "http://[::1]:3000/app", nil)
	if bl := CheckScope(reqV6, manifest); bl != nil {
		t.Errorf("expected [::1]:3000 to be allowed, got %v", bl)
	}

	// Unlisted IP blocked
	reqUnlisted, _ := http.NewRequest("GET", "http://192.168.1.99/app", nil)
	if bl := CheckScope(reqUnlisted, manifest); bl == nil || bl.BlacklistCategory != "OUT_OF_SCOPE_HOST" {
		t.Errorf("expected unlisted IP to be blocked, got %v", bl)
	}
}

// -----------------------------------------------------------------------------
// Test 9: Destructive Action Blacklist: Hardcoded Refusal of Payment Routes
// -----------------------------------------------------------------------------
func TestGuardrail_09_PaymentRouteBlacklistHardcodedRefusal(t *testing.T) {
	manifest := &PentestManifest{
		Version: "1.0",
		Scope: ScopeConfig{
			AllowedHosts:   []string{"shop.example.com"},
			AllowedPaths:   []string{"/"}, // Even full root allowlist cannot override payment blacklist!
			AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
		},
	}

	routesToBlock := []string{
		"http://shop.example.com/checkout/pay",
		"http://shop.example.com/billing/charge",
		"http://shop.example.com/payment/execute",
		"http://shop.example.com/checkout/pay/confirm",
		"http://shop.example.com/billing/charge/v2",
	}

	for _, r := range routesToBlock {
		for _, method := range []string{"GET", "POST", "DELETE"} {
			req, _ := http.NewRequest(method, r, nil)
			bl := CheckScope(req, manifest)
			if bl == nil || bl.BlacklistCategory != "PAYMENT_ROUTE" {
				t.Fatalf("expected route %s (%s) to be blocked as PAYMENT_ROUTE, got %v", r, method, bl)
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Test 10: Payment Route Encoding, Case, and Traversal Variants
// -----------------------------------------------------------------------------
func TestGuardrail_10_PaymentRouteEncodingAndTraversalVariants(t *testing.T) {
	manifest := &PentestManifest{
		Version: "1.0",
		Scope: ScopeConfig{
			AllowedHosts:   []string{"shop.example.com"},
			AllowedPaths:   []string{"/"},
			AllowedMethods: []string{"GET", "POST"},
		},
	}

	adversarialBypasses := []string{
		"http://shop.example.com/CHECKOUT/PAY",
		"http://shop.example.com/Checkout/Pay",
		"http://shop.example.com//checkout///pay",
		"http://shop.example.com/checkout/./pay",
		"http://shop.example.com/api/../checkout/pay",
		"http://shop.example.com/%63%68%65%63%6b%6f%75%74/pay",
		"http://shop.example.com/checkout/%70%61%79",
		"http://shop.example.com/billing/%63%68%61%72%67%65",
		"http://shop.example.com/%2fcheckout%2fpay",
		"http://shop.example.com/checkout/pay?token=secret123#frag",
		"http://shop.example.com/payment/%65%78%65%63%75%74%65",
	}

	for _, bypassURL := range adversarialBypasses {
		req, _ := http.NewRequest("POST", bypassURL, nil)
		bl := CheckScope(req, manifest)
		if bl == nil || bl.BlacklistCategory != "PAYMENT_ROUTE" {
			t.Errorf("CRITICAL SECURITY VULNERABILITY: bypass attempt %q succeeded or not categorized as PAYMENT_ROUTE: %v", bypassURL, bl)
		}
	}
}

// -----------------------------------------------------------------------------
// Test 11: Administrative DELETE Blocked by Default
// -----------------------------------------------------------------------------
func TestGuardrail_11_AdministrativeDeleteBlockedByDefault(t *testing.T) {
	manifest := &PentestManifest{
		Version: "1.0",
		Scope: ScopeConfig{
			AllowedHosts:   []string{"app.example.com"},
			AllowedPaths:   []string{"/"},
			AllowedMethods: []string{"GET", "POST", "DELETE"},
			AllowAdminDelete: &AdminDeleteConfig{
				Enabled: false, // Explicitly disabled
			},
		},
	}

	adminDeleteTargets := []string{
		"http://app.example.com/api/admin/users/42",
		"http://app.example.com/admin/accounts/1",
		"http://app.example.com/users/purge",
		"http://app.example.com/account/delete",
		"http://app.example.com/roles/superadmin",
	}

	for _, u := range adminDeleteTargets {
		req, _ := http.NewRequest("DELETE", u, nil)
		bl := CheckScope(req, manifest)
		if bl == nil || bl.BlacklistCategory != "UNAUTHORIZED_ADMIN_DELETE" {
			t.Errorf("expected administrative DELETE %q to be blocked, got %v", u, bl)
		}
	}
}

// -----------------------------------------------------------------------------
// Test 12: Administrative DELETE Narrow Explicit Authorization
// -----------------------------------------------------------------------------
func TestGuardrail_12_AdministrativeDeleteNarrowAuthorization(t *testing.T) {
	manifest := &PentestManifest{
		Version: "1.0",
		Scope: ScopeConfig{
			AllowedHosts:   []string{"app.example.com"},
			AllowedPaths:   []string{"/"},
			AllowedMethods: []string{"DELETE"},
			AllowAdminDelete: &AdminDeleteConfig{
				Enabled:             true,
				AuthorizedEndpoints: []string{"/api/admin/sandbox-users/*"},
				AuthorizedBy:        "audit-lead@felix.test",
				Justification:       "Purge test sandbox users generated during audit",
			},
		},
	}

	// Authorized narrow target: permitted
	reqAuth, _ := http.NewRequest("DELETE", "http://app.example.com/api/admin/sandbox-users/test-99", nil)
	if bl := CheckScope(reqAuth, manifest); bl != nil {
		t.Errorf("expected authorized DELETE to succeed, got blocked: %s", bl.Reason)
	}

	// Unauthorized administrative endpoint: still blocked
	reqUnauth, _ := http.NewRequest("DELETE", "http://app.example.com/api/admin/real-users/1", nil)
	if bl := CheckScope(reqUnauth, manifest); bl == nil || bl.BlacklistCategory != "UNAUTHORIZED_ADMIN_DELETE" {
		t.Errorf("expected unauthorized admin DELETE to be blocked, got: %v", bl)
	}
}

// -----------------------------------------------------------------------------
// Test 13: General Allowlist Cannot Override Payment Blacklist
// -----------------------------------------------------------------------------
func TestGuardrail_13_GeneralAllowlistCannotOverridePaymentBlacklist(t *testing.T) {
	manifest := &PentestManifest{
		Version: "1.0",
		Scope: ScopeConfig{
			AllowedHosts:   []string{"pay.example.com"},
			AllowedPaths:   []string{"/checkout/pay", "/billing/charge", "/payment/execute"},
			AllowedMethods: []string{"POST"},
			AllowAdminDelete: &AdminDeleteConfig{
				Enabled:             true,
				AuthorizedEndpoints: []string{"/checkout/pay"}, // Even listing it in admin delete cannot unblock!
				AuthorizedBy:        "admin",
				Justification:       "override attempt",
			},
		},
	}

	req, _ := http.NewRequest("POST", "http://pay.example.com/checkout/pay", nil)
	bl := CheckScope(req, manifest)
	if bl == nil || bl.BlacklistCategory != "PAYMENT_ROUTE" {
		t.Fatalf("CRITICAL SECURITY FLAW: general allowlist improperly overrode hardcoded payment blacklist: %v", bl)
	}
}

// -----------------------------------------------------------------------------
// Test 14: Redirect Hop Scope and Blacklist Validation
// -----------------------------------------------------------------------------
func TestGuardrail_14_RedirectHopScopeAndBlacklistValidation(t *testing.T) {
	manifest := &PentestManifest{
		Version: "1.0",
		Scope: ScopeConfig{
			AllowedHosts:   []string{"allowed.example.com"},
			AllowedPaths:   []string{"/"},
			AllowedMethods: []string{"GET"},
		},
	}

	// Target redirects to an out-of-scope host
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://evil-attacker.com/pwned", http.StatusFound)
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	manifest.Scope.AllowedHosts = append(manifest.Scope.AllowedHosts, u.Host)

	client, err := NewGuardrailHTTPClient(manifest, GuardrailOptions{
		SSRF: crawler.SafeTransportOptions{AllowLoopback: true, AllowPrivateIPs: true},
	})
	if err != nil {
		t.Fatalf("failed creating guardrail client: %v", err)
	}

	_, err = client.Get(server.URL + "/redirect")
	if err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Errorf("expected out-of-scope redirect to be blocked by CheckRedirect, got: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Test 15: Dynamic WAF: HTTP 429 Threshold Detection and 30s Backoff
// -----------------------------------------------------------------------------
func TestGuardrail_15_DynamicWAF_HTTP429ThresholdAndBackoff(t *testing.T) {
	cfg := OriginHealthConfig{
		StrainThreshold:      3,
		RollingWindow:        10 * time.Second,
		BackoffDuration:      30 * time.Second,
		ThrottledRate:        1.0,
		ThrottledConcurrency: 1,
	}

	tracker := NewOriginHealthTracker(cfg)
	simulatedTime := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	tracker.SetClock(func() time.Time { return simulatedTime }, func(ctx context.Context, d time.Duration) error {
		simulatedTime = simulatedTime.Add(d)
		return nil
	})

	origin := "https://api.target.com:443"

	// 1. Initial status: NORMAL
	state, _, errCount := tracker.GetOriginHealthStatus(origin)
	if state != HealthStateNormal || errCount != 0 {
		t.Errorf("expected initial NORMAL state, got %s", state)
	}

	// 2. Observe 2 429s (below threshold of 3)
	tracker.ObserveResponse(origin, http.StatusTooManyRequests, nil)
	tracker.ObserveResponse(origin, http.StatusTooManyRequests, nil)
	state, _, errCount = tracker.GetOriginHealthStatus(origin)
	if state != HealthStateNormal || errCount != 2 {
		t.Errorf("expected NORMAL state after 2 errors, got %s (errCount=%d)", state, errCount)
	}

	// 3. Observe 3rd 429: triggers BACKOFF
	tracker.ObserveResponse(origin, http.StatusTooManyRequests, nil)
	state, backoffUntil, _ := tracker.GetOriginHealthStatus(origin)
	if state != HealthStateBackoff {
		t.Fatalf("expected state BACKOFF, got %s", state)
	}
	expectedBackoff := simulatedTime.Add(30 * time.Second)
	if !backoffUntil.Equal(expectedBackoff) {
		t.Errorf("expected BackoffUntil %v, got %v", expectedBackoff, backoffUntil)
	}

	// 4. Calling Acquire must sleep until backoff expires and transition to PROBATION
	err := tracker.Acquire(context.Background(), origin)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	tracker.Release(origin)

	state, _, _ = tracker.GetOriginHealthStatus(origin)
	if state != HealthStateProbation {
		t.Errorf("expected state PROBATION after backoff expiration, got %s", state)
	}
}

// -----------------------------------------------------------------------------
// Test 16: Dynamic WAF: HTTP 503 and 504 Strain Detection
// -----------------------------------------------------------------------------
func TestGuardrail_16_DynamicWAF_HTTP503And504StrainDetection(t *testing.T) {
	cfg := OriginHealthConfig{
		StrainThreshold: 2,
		RollingWindow:   5 * time.Second,
		BackoffDuration: 30 * time.Second,
	}

	tracker := NewOriginHealthTracker(cfg)
	simulatedTime := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	tracker.SetClock(func() time.Time { return simulatedTime }, nil)

	origin503 := "https://service.target.com:443"
	tracker.ObserveResponse(origin503, http.StatusServiceUnavailable, nil)
	tracker.ObserveResponse(origin503, http.StatusServiceUnavailable, nil)
	state, _, _ := tracker.GetOriginHealthStatus(origin503)
	if state != HealthStateBackoff {
		t.Errorf("expected 503 errors to trigger BACKOFF, got %s", state)
	}

	origin504 := "https://gateway.target.com:443"
	tracker.ObserveResponse(origin504, http.StatusGatewayTimeout, nil)
	tracker.ObserveResponse(origin504, http.StatusGatewayTimeout, nil)
	state, _, _ = tracker.GetOriginHealthStatus(origin504)
	if state != HealthStateBackoff {
		t.Errorf("expected 504 errors to trigger BACKOFF, got %s", state)
	}
}

// -----------------------------------------------------------------------------
// Test 17: Dynamic WAF: Retry-After Header Handling
// -----------------------------------------------------------------------------
func TestGuardrail_17_DynamicWAF_RetryAfterHeaderHandling(t *testing.T) {
	cfg := OriginHealthConfig{
		StrainThreshold: 1, // Single response triggers backoff
		RollingWindow:   5 * time.Second,
		BackoffDuration: 30 * time.Second,
	}

	tracker := NewOriginHealthTracker(cfg)
	simulatedTime := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	tracker.SetClock(func() time.Time { return simulatedTime }, nil)

	origin := "https://rate-limited.target.com:443"

	// Server specifies Retry-After: 60 (larger than default 30s)
	hdr := http.Header{}
	hdr.Set("Retry-After", "60")

	tracker.ObserveResponse(origin, http.StatusTooManyRequests, hdr)
	state, backoffUntil, _ := tracker.GetOriginHealthStatus(origin)
	if state != HealthStateBackoff {
		t.Fatalf("expected BACKOFF, got %s", state)
	}

	expectedBackoff := simulatedTime.Add(60 * time.Second)
	if !backoffUntil.Equal(expectedBackoff) {
		t.Errorf("expected Retry-After 60s backoff until %v, got %v", expectedBackoff, backoffUntil)
	}
}

// -----------------------------------------------------------------------------
// Test 18: Dynamic WAF: Origin Isolation (Unrelated Origins Unaffected)
// -----------------------------------------------------------------------------
func TestGuardrail_18_DynamicWAF_OriginIsolation(t *testing.T) {
	cfg := OriginHealthConfig{
		StrainThreshold: 1,
		BackoffDuration: 30 * time.Second,
	}

	tracker := NewOriginHealthTracker(cfg)
	simulatedTime := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	tracker.SetClock(func() time.Time { return simulatedTime }, nil)

	originStrained := "https://strained.target.com:443"
	originHealthy := "https://healthy.target.com:443"

	// Trigger backoff on originStrained
	tracker.ObserveResponse(originStrained, http.StatusTooManyRequests, nil)

	stateStrained, _, _ := tracker.GetOriginHealthStatus(originStrained)
	stateHealthy, _, _ := tracker.GetOriginHealthStatus(originHealthy)

	if stateStrained != HealthStateBackoff {
		t.Errorf("expected strained origin to be in BACKOFF")
	}
	if stateHealthy != HealthStateNormal {
		t.Errorf("CRITICAL ISOLATION FLAW: healthy origin improperly affected by unrelated origin backoff: %s", stateHealthy)
	}
}

// -----------------------------------------------------------------------------
// Test 19: Concurrent Worker Coordination Under Origin Throttle
// -----------------------------------------------------------------------------
func TestGuardrail_19_DynamicWAF_ConcurrentWorkerCoordination(t *testing.T) {
	cfg := OriginHealthConfig{
		StrainThreshold:      1,
		BackoffDuration:      10 * time.Millisecond,
		ThrottledRate:        100.0, // fast rate for test execution
		ThrottledConcurrency: 1,     // strictly 1 concurrent worker
	}

	tracker := NewOriginHealthTracker(cfg)
	origin := "https://concurrency.target.com:443"
	tracker.ObserveResponse(origin, http.StatusTooManyRequests, nil)

	var activeConcurrent int32
	var maxObserved int32
	var wg sync.WaitGroup

	numWorkers := 10
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := tracker.Acquire(context.Background(), origin); err != nil {
				return
			}
			curr := atomic.AddInt32(&activeConcurrent, 1)
			for {
				peak := atomic.LoadInt32(&maxObserved)
				if curr <= peak || atomic.CompareAndSwapInt32(&maxObserved, peak, curr) {
					break
				}
			}
			time.Sleep(10 * time.Millisecond)
			atomic.AddInt32(&activeConcurrent, -1)
			tracker.Release(origin)
		}()
	}

	wg.Wait()

	if maxObserved > 1 {
		t.Errorf("concurrency violation: expected peak concurrency <= 1, got %d", maxObserved)
	}
}

// -----------------------------------------------------------------------------
// Test 20: Recovery and Probation Restoration
// -----------------------------------------------------------------------------
func TestGuardrail_20_DynamicWAF_RecoveryAndProbationRestoration(t *testing.T) {
	cfg := OriginHealthConfig{
		StrainThreshold:      1,
		BackoffDuration:      10 * time.Millisecond,
		ThrottledRate:        1.0,
		ThrottledConcurrency: 1,
	}

	tracker := NewOriginHealthTracker(cfg)
	simulatedTime := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	tracker.SetClock(func() time.Time { return simulatedTime }, func(ctx context.Context, d time.Duration) error {
		simulatedTime = simulatedTime.Add(d)
		return nil
	})

	origin := "https://recovery.target.com:443"
	tracker.ObserveResponse(origin, http.StatusTooManyRequests, nil)

	// Acquire expires backoff and enters probation
	_ = tracker.Acquire(context.Background(), origin)
	tracker.Release(origin)

	state, _, _ := tracker.GetOriginHealthStatus(origin)
	if state != HealthStateProbation {
		t.Fatalf("expected state PROBATION, got %s", state)
	}

	// Successful response clears probation back to NORMAL
	tracker.ObserveResponse(origin, http.StatusOK, nil)
	state, _, _ = tracker.GetOriginHealthStatus(origin)
	if state != HealthStateNormal {
		t.Errorf("expected state to recover to NORMAL after successful response, got %s", state)
	}
}

// -----------------------------------------------------------------------------
// Test 21: Context Cancellation and Shutdown Safety
// -----------------------------------------------------------------------------
func TestGuardrail_21_ContextCancellationAndShutdownSafety(t *testing.T) {
	cfg := OriginHealthConfig{
		StrainThreshold: 1,
		BackoffDuration: 10 * time.Hour, // long backoff
	}

	tracker := NewOriginHealthTracker(cfg)
	origin := "https://cancel.target.com:443"
	tracker.ObserveResponse(origin, http.StatusTooManyRequests, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	err := tracker.Acquire(ctx, origin)
	if err == nil {
		t.Fatal("expected context deadline error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("expected context cancellation error, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Test 22: Secret Redaction in Blocked Diagnostic Results
// -----------------------------------------------------------------------------
func TestGuardrail_22_SecretRedactionInBlockedDiagnostics(t *testing.T) {
	manifest := &PentestManifest{
		Version: "1.0",
		Scope: ScopeConfig{
			AllowedHosts:   []string{"example.com"},
			AllowedPaths:   []string{"/api"},
			AllowedMethods: []string{"GET"},
		},
	}

	sensitiveURL := "http://example.com/checkout/pay?bearer_token=secret_jwt_token_12345"
	req, _ := http.NewRequest("GET", sensitiveURL, nil)

	bl := CheckScope(req, manifest)
	if bl == nil {
		t.Fatal("expected request to be blocked")
	}

	if strings.Contains(bl.TargetURL, "secret_jwt_token_12345") {
		t.Errorf("SECRET LEAK DETECTED: blocked operation result exposed sensitive token: %s", bl.TargetURL)
	}
}

// -----------------------------------------------------------------------------
// Test 23: Local Safety Laboratory: Server-Side Proving Zero Blacklisted Requests
// -----------------------------------------------------------------------------
func TestGuardrail_23_LocalSafetyLab_ZeroBlacklistedRoutesTriggered(t *testing.T) {
	// Independent server-side request counters
	var (
		allowedRequests       int32
		checkoutPayRequests   int32
		billingChargeRequests int32
		paymentExecRequests   int32
		adminDeleteRequests   int32
		unauthorizedRequests  int32
	)

	// Local mock production server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		case strings.HasPrefix(path, "/checkout/pay"):
			atomic.AddInt32(&checkoutPayRequests, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"CHARGED_CRITICAL_FAILURE"}`))
		case strings.HasPrefix(path, "/billing/charge"):
			atomic.AddInt32(&billingChargeRequests, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"BILLED_CRITICAL_FAILURE"}`))
		case strings.HasPrefix(path, "/payment/execute"):
			atomic.AddInt32(&paymentExecRequests, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"EXECUTED_CRITICAL_FAILURE"}`))
		case strings.HasPrefix(path, "/admin/users") && r.Method == "DELETE":
			atomic.AddInt32(&adminDeleteRequests, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"USER_DELETED_CRITICAL_FAILURE"}`))
		case strings.HasPrefix(path, "/internal/unauthorized"):
			atomic.AddInt32(&unauthorizedRequests, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"UNAUTHORIZED_DATA_LEAK"}`))
		case strings.HasPrefix(path, "/api/allowed"):
			atomic.AddInt32(&allowedRequests, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"SUCCESS_ALLOWED"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	serverURL, _ := url.Parse(server.URL)

	// Create strict manifest that only allows /api/allowed
	manifest := &PentestManifest{
		Version: "1.0",
		Scope: ScopeConfig{
			AllowedHosts:     []string{serverURL.Host},
			AllowedPaths:     []string{"/api/allowed"},
			AllowedMethods:   []string{"GET", "POST", "DELETE"},
			AllowAdminDelete: &AdminDeleteConfig{Enabled: false},
		},
	}

	client, err := NewGuardrailHTTPClient(manifest, GuardrailOptions{
		SSRF: crawler.SafeTransportOptions{AllowLoopback: true, AllowPrivateIPs: true},
	})
	if err != nil {
		t.Fatalf("failed creating guardrail client: %v", err)
	}

	// 1. Dispatch allowed requests
	for i := 0; i < 5; i++ {
		resp, err := client.Get(server.URL + "/api/allowed")
		if err != nil {
			t.Fatalf("allowed request failed: %v", err)
		}
		_ = resp.Body.Close()
	}

	// 2. Adversarial crawl attempts against sensitive endpoints
	adversarialProbes := []struct {
		method string
		path   string
	}{
		{"POST", "/checkout/pay"},
		{"GET", "/checkout/pay"},
		{"POST", "/CHECKOUT/PAY"},
		{"POST", "/api/allowed/../../checkout/pay"},
		{"POST", "/billing/charge"},
		{"POST", "/billing/charge/v1"},
		{"POST", "/payment/execute"},
		{"DELETE", "/admin/users/123"},
		{"GET", "/internal/unauthorized"},
	}

	for _, probe := range adversarialProbes {
		req, _ := http.NewRequest(probe.method, server.URL+probe.path, nil)
		_, err := client.Do(req)
		if err == nil {
			t.Fatalf("expected guardrail to block %s %s, but request succeeded", probe.method, probe.path)
		}
	}

	// CRITICAL IRON GATE AUDIT: Verify server-side wire counters!
	if allowed := atomic.LoadInt32(&allowedRequests); allowed != 5 {
		t.Errorf("expected exactly 5 allowed requests, got %d", allowed)
	}

	if payCount := atomic.LoadInt32(&checkoutPayRequests); payCount != 0 {
		t.Fatalf("CRITICAL IRON GATE EXIT CONDITION FAILED: /checkout/pay received %d network requests!", payCount)
	}
	if billCount := atomic.LoadInt32(&billingChargeRequests); billCount != 0 {
		t.Fatalf("CRITICAL IRON GATE EXIT CONDITION FAILED: /billing/charge received %d network requests!", billCount)
	}
	if execCount := atomic.LoadInt32(&paymentExecRequests); execCount != 0 {
		t.Fatalf("CRITICAL IRON GATE EXIT CONDITION FAILED: /payment/execute received %d network requests!", execCount)
	}
	if delCount := atomic.LoadInt32(&adminDeleteRequests); delCount != 0 {
		t.Fatalf("CRITICAL SECURITY VIOLATION: unauthorized admin DELETE received %d network requests!", delCount)
	}
	if unauthCount := atomic.LoadInt32(&unauthorizedRequests); unauthCount != 0 {
		t.Fatalf("CRITICAL SCOPE VIOLATION: out-of-scope endpoint received %d network requests!", unauthCount)
	}
}

// -----------------------------------------------------------------------------
// Test 24: End-to-End Crawler Integration Under Guardrail
// -----------------------------------------------------------------------------
func TestGuardrail_24_EndToEndCrawlerIntegrationUnderGuardrail(t *testing.T) {
	var (
		blacklistedHits int32
		allowedHits     int32
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/billing/charge") || strings.HasPrefix(r.URL.Path, "/checkout/pay") {
			atomic.AddInt32(&blacklistedHits, 1)
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Path == "/page1" {
			atomic.AddInt32(&allowedHits, 1)
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			// HTML containing links to allowed page, out-of-scope page, and blacklisted payment page
			_, _ = w.Write([]byte(`
				<html>
				<body>
					<a href="/page2">Allowed Page 2</a>
					<a href="/billing/charge">Prohibited Billing</a>
					<a href="/checkout/pay">Prohibited Checkout</a>
				</body>
				</html>
			`))
			return
		}
		if r.URL.Path == "/page2" {
			atomic.AddInt32(&allowedHits, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body>OK</body></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	serverURL, _ := url.Parse(server.URL)
	manifest := &PentestManifest{
		Version: "1.0",
		Scope: ScopeConfig{
			AllowedHosts:   []string{serverURL.Host},
			AllowedPaths:   []string{"/"},
			AllowedMethods: []string{"GET"},
		},
	}

	client, err := NewGuardrailHTTPClient(manifest, GuardrailOptions{
		SSRF: crawler.SafeTransportOptions{AllowLoopback: true, AllowPrivateIPs: true},
	})
	if err != nil {
		t.Fatalf("failed creating guardrail client: %v", err)
	}

	// Crawl page1
	resp, err := client.Get(server.URL + "/page1")
	if err != nil {
		t.Fatalf("failed fetching page1: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if !strings.Contains(string(body), "Allowed Page 2") {
		t.Fatalf("unexpected body from page1")
	}

	// Attempt to follow blacklisted payment link from crawler queue
	reqBL, _ := http.NewRequest("GET", server.URL+"/checkout/pay", nil)
	_, errBL := client.Do(reqBL)
	if errBL == nil {
		t.Fatal("expected guardrail to block crawler link to /checkout/pay")
	}

	// Verify server counters: 0 requests to blacklisted routes!
	if hits := atomic.LoadInt32(&blacklistedHits); hits != 0 {
		t.Fatalf("crawler triggered blacklisted route %d times on the wire!", hits)
	}
	if allowed := atomic.LoadInt32(&allowedHits); allowed != 1 {
		t.Errorf("expected 1 allowed hit, got %d", allowed)
	}
}

// -----------------------------------------------------------------------------
// Test 25: DNS Resolution & Connection-Time Destination Enforcement
// -----------------------------------------------------------------------------
func TestGuardrail_25_DNSResolutionAndConnectionTimeSSRFDefense(t *testing.T) {
	manifest := &PentestManifest{
		Version: "1.0",
		Scope: ScopeConfig{
			AllowedHosts:   []string{"cloud-target.example.com", "v6-target.example.com", "loopback.example.com"},
			AllowedPaths:   []string{"/"},
			AllowedMethods: []string{"GET"},
		},
	}

	resolver := &mockResolver{
		ips: map[string][]net.IPAddr{
			// Cloud metadata IPv4
			"cloud-target.example.com": {{IP: net.ParseIP("169.254.169.254")}},
			// Cloud metadata IPv6 (IMDSv2)
			"v6-target.example.com": {{IP: net.ParseIP("fd00:ec2::254")}},
			// Loopback when disallowed
			"loopback.example.com": {{IP: net.ParseIP("127.0.0.1")}},
		},
	}

	client, err := NewGuardrailHTTPClient(manifest, GuardrailOptions{
		SSRF: crawler.SafeTransportOptions{
			AllowLoopback:   false,
			AllowPrivateIPs: false,
			Resolver:        resolver,
		},
	})
	if err != nil {
		t.Fatalf("failed constructing client: %v", err)
	}

	// 1. Prohibited Cloud Metadata IPv4 resolved hostname
	_, errV4 := client.Get("http://cloud-target.example.com/latest/meta-data")
	if errV4 == nil {
		t.Fatal("expected DNS resolution to 169.254.169.254 to be refused by safe dialer")
	}
	var ssrfErr *crawler.SSRFError
	if !errors.As(errV4, &ssrfErr) && !strings.Contains(errV4.Error(), "SSRF security refusal") {
		t.Errorf("expected SSRF security refusal for IPv4 metadata, got: %v", errV4)
	}

	// 2. Prohibited Cloud Metadata IPv6 resolved hostname
	_, errV6 := client.Get("http://v6-target.example.com/latest/meta-data")
	if errV6 == nil {
		t.Fatal("expected DNS resolution to fd00:ec2::254 to be refused by safe dialer")
	}
	if !errors.As(errV6, &ssrfErr) && !strings.Contains(errV6.Error(), "SSRF security refusal") {
		t.Errorf("expected SSRF security refusal for IPv6 metadata, got: %v", errV6)
	}

	// 3. Prohibited Loopback resolution
	_, errLoop := client.Get("http://loopback.example.com/admin")
	if errLoop == nil {
		t.Fatal("expected DNS resolution to 127.0.0.1 to be refused when loopback disallowed")
	}
	if !errors.As(errLoop, &ssrfErr) && !strings.Contains(errLoop.Error(), "SSRF security refusal") {
		t.Errorf("expected SSRF security refusal for loopback, got: %v", errLoop)
	}
}

// -----------------------------------------------------------------------------
// Test 26: DNS Rebinding & Dual-Homed Smuggling Defense at Connection Time
// -----------------------------------------------------------------------------
func TestGuardrail_26_DNSRebindingDualHomedSmugglingDefense(t *testing.T) {
	manifest := &PentestManifest{
		Version: "1.0",
		Scope: ScopeConfig{
			AllowedHosts:   []string{"rebinding.example.com", "safe.example.com"},
			AllowedPaths:   []string{"/"},
			AllowedMethods: []string{"GET"},
		},
	}

	var dialedAddr string
	var dialCount int32

	resolver := &mockResolver{
		ips: map[string][]net.IPAddr{
			// Dual-homed DNS response: returns public IP + prohibited metadata IP
			"rebinding.example.com": {
				{IP: net.ParseIP("93.184.216.34")},
				{IP: net.ParseIP("169.254.169.254")},
			},
			"safe.example.com": {
				{IP: net.ParseIP("93.184.216.34")},
			},
		},
	}

	mockDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		atomic.AddInt32(&dialCount, 1)
		dialedAddr = addr
		// Return fake connection error since we only need to verify dial address
		return nil, errors.New("mock dial terminating after address verification")
	}

	client, err := NewGuardrailHTTPClient(manifest, GuardrailOptions{
		SSRF: crawler.SafeTransportOptions{
			AllowLoopback:   false,
			AllowPrivateIPs: false,
			Resolver:        resolver,
			DialFunc:        mockDial,
		},
	})
	if err != nil {
		t.Fatalf("failed constructing client: %v", err)
	}

	// 1. Dual-homed DNS response must fail closed before dialing
	_, errRebind := client.Get("http://rebinding.example.com/api")
	if errRebind == nil {
		t.Fatal("expected dual-homed DNS smuggling attempt to be blocked")
	}
	if !strings.Contains(errRebind.Error(), "SSRF security refusal") {
		t.Errorf("expected SSRF refusal, got: %v", errRebind)
	}
	if count := atomic.LoadInt32(&dialCount); count != 0 {
		t.Errorf("CRITICAL SECURITY VIOLATION: dialer was invoked on dual-homed rebinding address! dialCount=%d", count)
	}

	// 2. Safe address must dial pinned IP directly (not hostname) to prevent race
	_, _ = client.Get("http://safe.example.com/api")
	if dialedAddr != "93.184.216.34:80" {
		t.Errorf("expected dialer to connect directly to validated IP literal '93.184.216.34:80', got %q", dialedAddr)
	}
}

// -----------------------------------------------------------------------------
// Test 27: Redirect Hop Scope and Destination Defense
// -----------------------------------------------------------------------------
func TestGuardrail_27_RedirectScopeAndBlacklistEgressDefense(t *testing.T) {
	manifest := &PentestManifest{
		Version: "1.0",
		Scope: ScopeConfig{
			AllowedHosts:   []string{"origin.example.com"},
			AllowedPaths:   []string{"/allowed", "/redirect-to-payment", "/redirect-to-attacker", "/redirect-to-metadata"},
			AllowedMethods: []string{"GET"},
		},
	}

	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect-to-attacker":
			http.Redirect(w, r, "http://attacker.example.com/evil", http.StatusFound)
		case "/redirect-to-payment":
			http.Redirect(w, r, "/checkout/pay", http.StatusFound)
		case "/redirect-to-metadata":
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer redirectServer.Close()

	srvURL, _ := url.Parse(redirectServer.URL)
	manifest.Scope.AllowedHosts = append(manifest.Scope.AllowedHosts, srvURL.Host)

	client, err := NewGuardrailHTTPClient(manifest, GuardrailOptions{
		SSRF: crawler.SafeTransportOptions{AllowLoopback: true, AllowPrivateIPs: true},
	})
	if err != nil {
		t.Fatalf("failed creating client: %v", err)
	}

	// 1. Redirect to out-of-scope host blocked
	_, errAttacker := client.Get(redirectServer.URL + "/redirect-to-attacker")
	if errAttacker == nil || !strings.Contains(errAttacker.Error(), "blocked") {
		t.Errorf("expected cross-host redirect to attacker to be blocked, got %v", errAttacker)
	}

	// 2. Redirect to blacklisted payment route blocked
	_, errPayment := client.Get(redirectServer.URL + "/redirect-to-payment")
	if errPayment == nil || !strings.Contains(errPayment.Error(), "blocked") {
		t.Errorf("expected redirect to /checkout/pay to be blocked, got %v", errPayment)
	}

	// 3. Redirect to prohibited metadata IP blocked
	_, errMeta := client.Get(redirectServer.URL + "/redirect-to-metadata")
	if errMeta == nil || !strings.Contains(errMeta.Error(), "blocked") {
		t.Errorf("expected redirect to cloud metadata to be blocked, got %v", errMeta)
	}
}

// -----------------------------------------------------------------------------
// Test 28: Quantitative WAF Verification: Pacing Timestamps and HTTP-Date Handling
// -----------------------------------------------------------------------------
func TestGuardrail_28_QuantitativeWAF_PacingTimestampsAndHTTPDate(t *testing.T) {
	cfg := OriginHealthConfig{
		StrainThreshold:      2,
		RollingWindow:        10 * time.Second,
		BackoffDuration:      30 * time.Second,
		ThrottledRate:        1.0, // 1 req/sec pacing
		ThrottledConcurrency: 1,   // max 1 simultaneous request
	}

	tracker := NewOriginHealthTracker(cfg)
	t0 := time.Date(2026, 11, 10, 14, 0, 0, 0, time.UTC)
	currTime := t0

	tracker.SetClock(
		func() time.Time { return currTime },
		func(ctx context.Context, d time.Duration) error {
			currTime = currTime.Add(d)
			return nil
		},
	)

	origin := "https://api.measured-waf.com:443"

	// 1. Trigger strain backoff with HTTP 429
	tracker.ObserveResponse(origin, http.StatusTooManyRequests, nil)
	tracker.ObserveResponse(origin, http.StatusTooManyRequests, nil)

	state, backoffUntil, _ := tracker.GetOriginHealthStatus(origin)
	if state != HealthStateBackoff {
		t.Fatalf("expected state BACKOFF, got %s", state)
	}
	expectedBackoff := t0.Add(30 * time.Second)
	if !backoffUntil.Equal(expectedBackoff) {
		t.Errorf("expected 30s backoff until %v, got %v", expectedBackoff, backoffUntil)
	}

	// 2. Dispatch 5 requests and record exact timestamps
	var dispatchTimestamps []time.Time
	for i := 0; i < 5; i++ {
		err := tracker.Acquire(context.Background(), origin)
		if err != nil {
			t.Fatalf("Acquire error on req %d: %v", i, err)
		}
		dispatchTimestamps = append(dispatchTimestamps, currTime)
		tracker.Release(origin)
	}

	// First dispatch should occur after backoff expires (t0 + 30s)
	if !dispatchTimestamps[0].Equal(expectedBackoff) {
		t.Errorf("expected first dispatch at %v, got %v", expectedBackoff, dispatchTimestamps[0])
	}

	// Verify exact 1-request-per-second pacing between consecutive dispatches
	for i := 1; i < len(dispatchTimestamps); i++ {
		delta := dispatchTimestamps[i].Sub(dispatchTimestamps[i-1])
		if delta < time.Second {
			t.Errorf("pacing violation between req %d and %d: delta %v is less than 1.0s!", i-1, i, delta)
		}
	}

	// 3. Test HTTP-Date format in Retry-After (RFC 7231)
	rfcDateOrigin := "https://date-waf.target.com:443"
	hdr := http.Header{}
	// Future date 45 seconds after currTime
	futureDate := currTime.Add(45 * time.Second).Format(http.TimeFormat)
	hdr.Set("Retry-After", futureDate)

	tracker.ObserveResponse(rfcDateOrigin, http.StatusTooManyRequests, hdr)
	tracker.ObserveResponse(rfcDateOrigin, http.StatusTooManyRequests, hdr)

	_, rfcBackoffUntil, _ := tracker.GetOriginHealthStatus(rfcDateOrigin)
	expectedRFC := currTime.Add(45 * time.Second)
	if !rfcBackoffUntil.Equal(expectedRFC) {
		t.Errorf("expected HTTP-date backoff until %v, got %v", expectedRFC, rfcBackoffUntil)
	}

	// 4. Test recovery: success during probation restores NORMAL
	// Expire backoff on origin
	currTime = currTime.Add(60 * time.Second)
	_ = tracker.Acquire(context.Background(), origin)
	tracker.Release(origin)

	st, _, _ := tracker.GetOriginHealthStatus(origin)
	if st != HealthStateProbation {
		t.Fatalf("expected state PROBATION, got %s", st)
	}

	// Record success (e.g. HTTP 200)
	tracker.ObserveResponse(origin, http.StatusOK, nil)
	stNormal, _, _ := tracker.GetOriginHealthStatus(origin)
	if stNormal != HealthStateNormal {
		t.Errorf("expected recovery to NORMAL state, got %s", stNormal)
	}
}

// -----------------------------------------------------------------------------
// Test 29: Path Normalization Security Review (Case, Semicolons, Ambiguous Encodings)
// -----------------------------------------------------------------------------
func TestGuardrail_29_PathNormalization_MatrixParamsAndAmbiguousEncoding(t *testing.T) {
	manifest := &PentestManifest{
		Version: "1.0",
		Scope: ScopeConfig{
			AllowedHosts:   []string{"target.example.com"},
			AllowedPaths:   []string{"/api/v1/public"},
			AllowedMethods: []string{"GET", "POST"},
		},
	}

	// 1. Semicolon matrix parameter bypass attempts must be stripped and caught by blacklist
	semicolonPaymentBypasses := []string{
		"http://target.example.com/checkout/pay;jsessionid=12345",
		"http://target.example.com/checkout;x=1/pay;y=2",
		"http://target.example.com/billing/charge;token=secret",
		"http://target.example.com/payment/execute;foo=bar?id=1",
	}
	for _, u := range semicolonPaymentBypasses {
		req, _ := http.NewRequest("POST", u, nil)
		bl := CheckScope(req, manifest)
		if bl == nil || bl.BlacklistCategory != "PAYMENT_ROUTE" {
			t.Errorf("CRITICAL: semicolon parameter bypass %q was not blocked as PAYMENT_ROUTE: %v", u, bl)
		}
	}

	// 2. Ambiguous, malformed, or hostile encodings must fail closed
	ambiguousPaths := []string{
		"/checkout/pay%00",          // null byte
		"/checkout/pay\x00extra",   // raw null byte
		"/checkout/%zz/pay",         // invalid hex
		"/checkout/pay%",           // incomplete percent
		"/checkout/pay%2",          // incomplete percent
		"/%25%25%252fcheckout/pay", // excessive recursive percent encoding
	}
	for _, p := range ambiguousPaths {
		_, _, isAmbiguous, reason := CanonicalPath(p)
		if !isAmbiguous {
			t.Errorf("CRITICAL: ambiguous path %q was not detected by CanonicalPath!", p)
		}

		targetURL := &url.URL{
			Scheme: "http",
			Host:   "target.example.com",
			Path:   p,
		}
		bl := CheckDestructiveAction("POST", targetURL, manifest)
		if bl == nil || bl.BlacklistCategory != "AMBIGUOUS_ENCODING" {
			t.Errorf("CRITICAL: ambiguous encoding %q was not blocked as AMBIGUOUS_ENCODING: %v (reason: %s)", p, bl, reason)
		}
	}

	// 3. Case variations of protected routes must ALL be blocked
	casePaymentBypasses := []string{
		"http://target.example.com/CHECKOUT/PAY",
		"http://target.example.com/Checkout/Pay",
		"http://target.example.com/checkOUT/pay",
		"http://target.example.com/BILLING/CHARGE",
		"http://target.example.com/Payment/Execute",
	}
	for _, u := range casePaymentBypasses {
		req, _ := http.NewRequest("POST", u, nil)
		bl := CheckScope(req, manifest)
		if bl == nil || bl.BlacklistCategory != "PAYMENT_ROUTE" {
			t.Errorf("CRITICAL: case variation %q was not blocked as PAYMENT_ROUTE: %v", u, bl)
		}
	}

	// 4. Case sensitivity of allowlist routes: lowercasing cannot authorize an unauthorized route
	// Manifest specifies allowed_paths: ["/api/v1/public"]
	// Lowercase matching of an uppercase unauthorized route must NOT succeed
	reqUpper, _ := http.NewRequest("GET", "http://target.example.com/api/v1/PUBLIC", nil)
	blUpper := CheckScope(reqUpper, manifest)
	if blUpper == nil || blUpper.BlacklistCategory != "OUT_OF_SCOPE_PATH" {
		t.Errorf("CRITICAL: uppercase path %q was improperly authorized by lowercasing! got %v", reqUpper.URL.Path, blUpper)
	}

	// Legitimate exact-case path must succeed
	reqExact, _ := http.NewRequest("GET", "http://target.example.com/api/v1/public", nil)
	blExact := CheckScope(reqExact, manifest)
	if blExact != nil {
		t.Errorf("expected exact-case path /api/v1/public to be authorized, got %v", blExact)
	}
}

type mockResolver struct {
	ips map[string][]net.IPAddr
}

func (m *mockResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if addrs, ok := m.ips[host]; ok {
		return addrs, nil
	}
	return nil, fmt.Errorf("no address for %s", host)
}
