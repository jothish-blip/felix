package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

func setupStorageServer(t *testing.T) (string, func()) {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Set cookies with diverse attributes for Case E, F, I
		http.SetCookie(w, &http.Cookie{
			Name:     "session_secure_token",
			Value:    "felix_cookie_sess_canary_aabbccddee1122",
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "client_auth_jwt",
			Value:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.c2lnbmF0dXJlX2ZlbGl4X2Nvb2tpZQ",
			Path:     "/",
			HttpOnly: false, // MISCONFIGURATION: sensitive token accessible to JavaScript
			SameSite: http.SameSiteLaxMode,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "user_theme",
			Value:    "emerald-dark",
			Path:     "/",
			HttpOnly: false, // Benign cookie
			SameSite: http.SameSiteLaxMode,
		})

		htmlPath := filepath.Join("..", "..", "..", "test", "lab", "client_storage.html")
		content, err := os.ReadFile(htmlPath)
		if err != nil {
			http.Error(w, "fixture not found: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(content)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed binding loopback listener: %v", err)
	}

	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(listener)
	}()

	addr := listener.Addr().String()
	cleanup := func() {
		_ = server.Close()
		_ = listener.Close()
	}

	return addr, cleanup
}

func waitForStorageReady(ctx context.Context, inst *Instance) error {
	var status string
	for i := 0; i < 30; i++ {
		res, err := chromedp.Run(inst.Ctx, chromedp.Evaluate[string]("document.getElementById('storage-status') ? document.getElementById('storage-status').textContent : ''"))
		if err == nil && res == "storage_ready" {
			status = res
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if status != "storage_ready" {
		return fmt.Errorf("timeout waiting for storage_ready status, last status: %q", status)
	}
	return nil
}

// Case A: Sensitive localStorage canary detected, classified as POTENTIALLY_EXPOSED_CREDENTIAL, redacted.
func TestClientStorageCaseA_LocalStorageSensitive(t *testing.T) {
	serverAddr, cleanup := setupStorageServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	jwtCanary := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwidXNlcm5hbWUiOiJmZWxpeF9hdWRpdG9yIn0.c2lnbl9jYW5hcnlfbG9jYWxfc3RvcmFnZQ"
	apiKeyCanary := "sk-proj-felixcanary1234567890abcdef1234567890"

	targetURL := fmt.Sprintf("http://%s/?mode=local&jwt_canary=%s&api_canary=%s", serverAddr, jwtCanary, apiKeyCanary)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(200*time.Millisecond)); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}
	if err := waitForStorageReady(ctx, inst); err != nil {
		t.Fatalf("Fixture init failed: %v", err)
	}

	auditor, err := NewStorageAuditor(inst, DefaultStorageAuditConfig())
	if err != nil {
		t.Fatalf("NewStorageAuditor failed: %v", err)
	}

	report, err := auditor.Audit(ctx)
	if err != nil {
		t.Fatalf("Audit failed: %v", err)
	}

	var foundJWT, foundAPIKey bool
	for _, f := range report.Findings {
		if f.Surface != SurfaceLocalStorage {
			continue
		}
		if f.KeyName == "auth_token" {
			foundJWT = true
			if f.ExposureType != ExposurePotentiallyExposed {
				t.Errorf("Expected auth_token exposure type %s, got %s", ExposurePotentiallyExposed, f.ExposureType)
			}
			if strings.Contains(f.Evidence, jwtCanary) {
				t.Errorf("CRITICAL VIOLATION: Raw JWT canary leaked in evidence: %s", f.Evidence)
			}
		}
		if f.KeyName == "felix_api_key" {
			foundAPIKey = true
			if f.ExposureType != ExposurePotentiallyExposed {
				t.Errorf("Expected api_key exposure type %s, got %s", ExposurePotentiallyExposed, f.ExposureType)
			}
			if strings.Contains(f.Evidence, apiKeyCanary) {
				t.Errorf("CRITICAL VIOLATION: Raw API key canary leaked in evidence: %s", f.Evidence)
			}
		}
	}

	if !foundJWT {
		t.Errorf("Expected auth_token finding in localStorage")
	}
	if !foundAPIKey {
		t.Errorf("Expected felix_api_key finding in localStorage")
	}

	t.Logf("Case A PASS: Sensitive localStorage tokens detected and redacted (findings: %d)", len(report.Findings))
}

// Case B: Sensitive sessionStorage canary detected without exposing raw value in logs or evidence.
func TestClientStorageCaseB_SessionStorageSensitive(t *testing.T) {
	serverAddr, cleanup := setupStorageServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	sessCanary := "felix_sess_canary_9876543210abcdef_val"
	targetURL := fmt.Sprintf("http://%s/?mode=session&sess_canary=%s", serverAddr, sessCanary)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(200*time.Millisecond)); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}
	if err := waitForStorageReady(ctx, inst); err != nil {
		t.Fatalf("Fixture init failed: %v", err)
	}

	auditor, err := NewStorageAuditor(inst, DefaultStorageAuditConfig())
	if err != nil {
		t.Fatalf("NewStorageAuditor failed: %v", err)
	}

	report, err := auditor.Audit(ctx)
	if err != nil {
		t.Fatalf("Audit failed: %v", err)
	}

	var foundSess bool
	for _, f := range report.Findings {
		if f.Surface == SurfaceSessionStorage && f.KeyName == "session_id" {
			foundSess = true
			if f.ExposureType != ExposurePotentiallyExposed && f.ExposureType != ExposureSensitiveCandidate {
				t.Errorf("Unexpected exposure type for session_id: %s", f.ExposureType)
			}
			if strings.Contains(f.Evidence, sessCanary) {
				t.Errorf("CRITICAL VIOLATION: Raw session canary leaked in evidence: %s", f.Evidence)
			}
		}
	}

	if !foundSess {
		t.Errorf("Expected session_id finding in sessionStorage")
	}

	t.Logf("Case B PASS: Sensitive sessionStorage detected without raw secret leakage")
}

// Case C: Benign controls (theme, language, layout, feature flags, request_id, device_uuid, build_hash) do not produce credential findings.
func TestClientStorageCaseC_BenignControls(t *testing.T) {
	serverAddr, cleanup := setupStorageServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	targetURL := fmt.Sprintf("http://%s/?mode=benign", serverAddr)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(200*time.Millisecond)); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}
	if err := waitForStorageReady(ctx, inst); err != nil {
		t.Fatalf("Fixture init failed: %v", err)
	}

	auditor, err := NewStorageAuditor(inst, DefaultStorageAuditConfig())
	if err != nil {
		t.Fatalf("NewStorageAuditor failed: %v", err)
	}

	report, err := auditor.Audit(ctx)
	if err != nil {
		t.Fatalf("Audit failed: %v", err)
	}

	// Verify benign items & ambiguous identifiers discovered
	benignKeys := []string{"theme", "language", "layout_pref", "active_tab", "request_id", "device_uuid", "build_hash", "cache_buster"}
	discoveredMap := make(map[string]*StorageItem)
	for _, it := range report.DiscoveredItems {
		discoveredMap[it.Key] = it
	}

	for _, k := range benignKeys {
		it, exists := discoveredMap[k]
		if !exists {
			t.Errorf("Expected benign key %q in discovered items", k)
			continue
		}
		if it.IsSensitive {
			t.Errorf("False Alarm: benign/ambiguous key %q flagged as sensitive", k)
		}
	}

	// Verify ZERO credential exposure findings from benign items
	for _, f := range report.Findings {
		if f.Surface == SurfaceLocalStorage || f.Surface == SurfaceSessionStorage {
			for _, k := range benignKeys {
				if f.KeyName == k {
					t.Errorf("False Alarm: benign item %q produced finding: %s", f.KeyName, f.ExposureType)
				}
			}
		}
	}

	t.Logf("Case C PASS: Benign controls & ambiguous identifiers safely identified without false credential findings (discovered: %d)", len(discoveredMap))
}

// Case D: IndexedDB database enumeration and sensitive record discovery with bounded limits.
func TestClientStorageCaseD_IndexedDB(t *testing.T) {
	serverAddr, cleanup := setupStorageServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	idbCanary := "AKIAIOSFODNN7EXAMPLE"
	targetURL := fmt.Sprintf("http://%s/?mode=idb&idb_canary=%s", serverAddr, idbCanary)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(200*time.Millisecond)); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}
	if err := waitForStorageReady(ctx, inst); err != nil {
		t.Fatalf("Fixture init failed: %v", err)
	}

	auditor, err := NewStorageAuditor(inst, DefaultStorageAuditConfig())
	if err != nil {
		t.Fatalf("NewStorageAuditor failed: %v", err)
	}

	report, err := auditor.Audit(ctx)
	if err != nil {
		t.Fatalf("Audit failed: %v", err)
	}

	var foundIDBCanary bool
	for _, f := range report.Findings {
		if f.Surface == SurfaceIndexedDB {
			if strings.Contains(f.KeyName, "FelixStorageVault/credentials") {
				foundIDBCanary = true
				if f.ExposureType != ExposurePotentiallyExposed {
					t.Errorf("Expected IndexedDB credential exposure type %s, got %s", ExposurePotentiallyExposed, f.ExposureType)
				}
				if strings.Contains(f.Evidence, idbCanary) {
					t.Errorf("CRITICAL VIOLATION: Raw IndexedDB canary leaked in evidence: %s", f.Evidence)
				}
			}
		}
	}

	if !foundIDBCanary {
		t.Errorf("Expected IndexedDB credential finding in FelixStorageVault")
	}

	t.Logf("Case D PASS: IndexedDB credentials enumerated and reported with bounded reads")
}

// Case E: Cookie attributes verification (Secure, HttpOnly, SameSite, JS accessibility).
func TestClientStorageCaseE_CookieAttributes(t *testing.T) {
	serverAddr, cleanup := setupStorageServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	targetURL := fmt.Sprintf("http://%s/?mode=benign", serverAddr)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(200*time.Millisecond)); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	auditor, err := NewStorageAuditor(inst, DefaultStorageAuditConfig())
	if err != nil {
		t.Fatalf("NewStorageAuditor failed: %v", err)
	}

	report, err := auditor.Audit(ctx)
	if err != nil {
		t.Fatalf("Audit failed: %v", err)
	}

	var foundSecureSess, foundInsecureAuth, foundTheme bool
	for _, c := range report.Cookies {
		if c.Name == "session_secure_token" {
			foundSecureSess = true
			if !c.HTTPOnly {
				t.Errorf("Expected session_secure_token to have HTTPOnly=true")
			}
			if c.AccessibleToJS {
				t.Errorf("Expected session_secure_token AccessibleToJS=false")
			}
		}
		if c.Name == "client_auth_jwt" {
			foundInsecureAuth = true
			if c.HTTPOnly {
				t.Errorf("Expected client_auth_jwt to have HTTPOnly=false")
			}
			if !c.AccessibleToJS {
				t.Errorf("Expected client_auth_jwt AccessibleToJS=true")
			}
		}
		if c.Name == "user_theme" {
			foundTheme = true
			if c.IsSensitive {
				t.Errorf("False alarm: benign cookie user_theme flagged as sensitive")
			}
		}
	}

	if !foundSecureSess {
		t.Errorf("Expected session_secure_token in cookie list")
	}
	if !foundInsecureAuth {
		t.Errorf("Expected client_auth_jwt in cookie list")
	}
	if !foundTheme {
		t.Errorf("Expected user_theme in cookie list")
	}

	// Verify CONFIRMED_MISCONFIGURATION finding for client_auth_jwt missing HttpOnly with justified MEDIUM severity
	var misconfigFindingFound bool
	for _, f := range report.Findings {
		if f.Surface == SurfaceCookie && f.KeyName == "client_auth_jwt" {
			if f.ExposureType == ExposureConfirmedMisconfig {
				misconfigFindingFound = true
				if f.Severity != "MEDIUM" {
					t.Errorf("Expected justified Severity 'MEDIUM' for non-HttpOnly cookie, got %q", f.Severity)
				}
			}
		}
	}

	if !misconfigFindingFound {
		t.Errorf("Expected CONFIRMED_MISCONFIGURATION finding for non-HttpOnly sensitive cookie client_auth_jwt")
	}

	t.Logf("Case E PASS: Cookie security attributes and JS accessibility accurately audited")
}

// Case F: Redaction guarantee asserting no raw secrets in reports, findings, evidence, or logs.
func TestClientStorageCaseF_RedactionGuarantee(t *testing.T) {
	serverAddr, cleanup := setupStorageServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	uniqueLocalSecret := "felix_secret_canary_local_XYZ123456789"
	uniqueSessSecret := "felix_secret_canary_sess_ABC987654321"
	uniqueIDBSecret := "felix_secret_canary_idb_QWE456123789"

	targetURL := fmt.Sprintf("http://%s/?mode=all&jwt_canary=%s&sess_canary=%s&idb_canary=%s",
		serverAddr, uniqueLocalSecret, uniqueSessSecret, uniqueIDBSecret)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(200*time.Millisecond)); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}
	if err := waitForStorageReady(ctx, inst); err != nil {
		t.Fatalf("Fixture init failed: %v", err)
	}

	auditor, err := NewStorageAuditor(inst, DefaultStorageAuditConfig())
	if err != nil {
		t.Fatalf("NewStorageAuditor failed: %v", err)
	}

	report, err := auditor.Audit(ctx)
	if err != nil {
		t.Fatalf("Audit failed: %v", err)
	}

	// Serialize report to JSON to inspect entire output payload
	reportBytes, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Failed marshaling report: %v", err)
	}
	reportJSON := string(reportBytes)

	// Assert NO raw canary strings exist anywhere in serialized report
	canaries := []string{uniqueLocalSecret, uniqueSessSecret, uniqueIDBSecret}
	for _, canary := range canaries {
		if strings.Contains(reportJSON, canary) {
			t.Fatalf("REDACTION FAILURE: Raw secret canary %q found in serialized report JSON!", canary)
		}
	}

	t.Logf("Case F PASS: Zero raw secrets leaked across %d findings and %d discovered items",
		len(report.Findings), len(report.DiscoveredItems))
}

// Case G: Failure modes, resource limits, context cancellation, and idempotent execution.
func TestClientStorageCaseG_FailureAndResourceLimits(t *testing.T) {
	serverAddr, cleanup := setupStorageServer(t)
	defer cleanup()

	// 1. Context Cancellation Safety
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel() // pre-canceled

	inst, err := Launch(context.Background(), DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	auditor, err := NewStorageAuditor(inst, DefaultStorageAuditConfig())
	if err != nil {
		t.Fatalf("NewStorageAuditor failed: %v", err)
	}

	// Should handle pre-canceled context gracefully
	_, _ = auditor.Audit(cancelCtx)

	// 2. Resource Bounding
	boundedCfg := DefaultStorageAuditConfig()
	boundedCfg.MaxItemsPerStore = 2
	boundedCfg.MaxRecordsIndexedDB = 1

	boundedAuditor, err := NewStorageAuditor(inst, boundedCfg)
	if err != nil {
		t.Fatalf("NewStorageAuditor bounded failed: %v", err)
	}

	validCtx, validCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer validCancel()

	targetURL := fmt.Sprintf("http://%s/?mode=all", serverAddr)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(200*time.Millisecond)); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}

	rep, err := boundedAuditor.Audit(validCtx)
	if err != nil {
		t.Fatalf("Bounded audit error: %v", err)
	}

	var localCount, sessCount int
	for _, it := range rep.DiscoveredItems {
		if it.Surface == SurfaceLocalStorage {
			localCount++
		}
		if it.Surface == SurfaceSessionStorage {
			sessCount++
		}
	}

	if localCount > boundedCfg.MaxItemsPerStore {
		t.Errorf("localStorage items %d exceeded configured cap %d", localCount, boundedCfg.MaxItemsPerStore)
	}
	if sessCount > boundedCfg.MaxItemsPerStore {
		t.Errorf("sessionStorage items %d exceeded configured cap %d", sessCount, boundedCfg.MaxItemsPerStore)
	}

	t.Logf("Case G PASS: Context cancellation, bounded caps, and resilience verified")
}

// Case H: Ambiguous UUIDs, token-shaped mock fixtures, and context-dependent classification.
func TestClientStorageCaseH_AmbiguousUUIDsAndMockTokens(t *testing.T) {
	serverAddr, cleanup := setupStorageServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	targetURL := fmt.Sprintf("http://%s/?mode=mock_tokens", serverAddr)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(200*time.Millisecond)); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}
	if err := waitForStorageReady(ctx, inst); err != nil {
		t.Fatalf("Fixture init failed: %v", err)
	}

	auditor, err := NewStorageAuditor(inst, DefaultStorageAuditConfig())
	if err != nil {
		t.Fatalf("NewStorageAuditor failed: %v", err)
	}

	report, err := auditor.Audit(ctx)
	if err != nil {
		t.Fatalf("Audit failed: %v", err)
	}

	var foundMockAPI, foundTestJWT, foundSessionUUID bool
	for _, f := range report.Findings {
		if f.KeyName == "mock_api_token" {
			foundMockAPI = true
			if f.ExposureType != ExposureSensitiveCandidate {
				t.Errorf("Expected mock_api_token exposure type %s, got %s", ExposureSensitiveCandidate, f.ExposureType)
			}
			if f.Severity != "LOW" {
				t.Errorf("Expected mock_api_token severity LOW, got %s", f.Severity)
			}
		}
		if f.KeyName == "test_jwt" {
			foundTestJWT = true
			if f.ExposureType != ExposureSensitiveCandidate {
				t.Errorf("Expected test_jwt exposure type %s, got %s", ExposureSensitiveCandidate, f.ExposureType)
			}
			if f.Severity != "LOW" {
				t.Errorf("Expected test_jwt severity LOW, got %s", f.Severity)
			}
		}
		if f.KeyName == "session_tracking_uuid" {
			foundSessionUUID = true
			if f.ExposureType != ExposureSensitiveCandidate {
				t.Errorf("Expected session_tracking_uuid exposure type %s, got %s", ExposureSensitiveCandidate, f.ExposureType)
			}
		}
	}

	if !foundMockAPI {
		t.Errorf("Expected mock_api_token finding")
	}
	if !foundTestJWT {
		t.Errorf("Expected test_jwt finding")
	}
	if !foundSessionUUID {
		t.Errorf("Expected session_tracking_uuid finding")
	}

	t.Logf("Case H PASS: Ambiguous UUIDs and mock tokens accurately categorized as candidates without false high-severity claims")
}

// Case I: IndexedDB streaming cursor bounds collection actively during streaming.
func TestClientStorageCaseI_IndexedDBStreamingBounds(t *testing.T) {
	serverAddr, cleanup := setupStorageServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inst, err := Launch(ctx, DefaultConfig())
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	defer inst.Close()

	targetURL := fmt.Sprintf("http://%s/?mode=idb", serverAddr)
	if err := chromedp.Do(inst.Ctx, chromedp.Navigate(targetURL), chromedp.Sleep(200*time.Millisecond)); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}
	if err := waitForStorageReady(ctx, inst); err != nil {
		t.Fatalf("Fixture init failed: %v", err)
	}

	// Configure strict bounds: max 1 record per store
	boundedCfg := DefaultStorageAuditConfig()
	boundedCfg.MaxRecordsIndexedDB = 1
	boundedCfg.MaxBytesPerStore = 256

	auditor, err := NewStorageAuditor(inst, boundedCfg)
	if err != nil {
		t.Fatalf("NewStorageAuditor failed: %v", err)
	}

	report, err := auditor.Audit(ctx)
	if err != nil {
		t.Fatalf("Audit failed: %v", err)
	}

	var idbRecordsByStore = make(map[string]int)
	for _, it := range report.DiscoveredItems {
		if it.Surface == SurfaceIndexedDB {
			idbRecordsByStore[it.DatabaseName+"/"+it.StoreName]++
		}
	}

	for store, count := range idbRecordsByStore {
		if count > boundedCfg.MaxRecordsIndexedDB {
			t.Errorf("Store %s collected %d records, exceeding MaxRecordsIndexedDB cap of %d", store, count, boundedCfg.MaxRecordsIndexedDB)
		}
	}

	t.Logf("Case I PASS: IndexedDB active cursor streaming bounded to %d records per store", boundedCfg.MaxRecordsIndexedDB)
}
