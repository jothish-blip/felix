package cloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"felix/pkg/crawler"
)

// Helper to construct test JWT tokens
func createTestJWT(claims map[string]interface{}) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	cb, _ := json.Marshal(claims)
	p := base64.RawURLEncoding.EncodeToString(cb)
	s := base64.RawURLEncoding.EncodeToString([]byte("signature-data-bytes-123456"))
	return h + "." + p + "." + s
}

// Test 1: Supabase discovery
func TestSupabaseDiscovery(t *testing.T) {
	js := `const client = createClient('https://myproject.supabase.co', 'apikey');`
	services := DiscoverServicesFromContent("app.js", []byte(js))
	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}
	if services[0].Provider != ProviderSupabase {
		t.Errorf("expected ProviderSupabase, got %s", services[0].Provider)
	}
	if services[0].URL != "https://myproject.supabase.co" {
		t.Errorf("expected https://myproject.supabase.co, got %s", services[0].URL)
	}
}

// Test 2: Firebase discovery
func TestFirebaseDiscovery(t *testing.T) {
	js := `
		const db1 = "https://app-db.firebaseio.com";
		const db2 = "https://my-app-default-rtdb.europe-west1.firebasedatabase.app";
	`
	services := DiscoverServicesFromContent("firebase.js", []byte(js))
	if len(services) < 1 {
		t.Fatalf("expected at least 1 Firebase service, got %d", len(services))
	}
	for _, s := range services {
		if s.Provider != ProviderFirebase {
			t.Errorf("expected ProviderFirebase, got %s", s.Provider)
		}
	}
}

// Test 3: S3 discovery
func TestS3Discovery(t *testing.T) {
	js := `
		const bucket1 = "https://company-assets.s3.amazonaws.com/logo.png";
		const bucket2 = "https://s3.amazonaws.com/backup-data/archive.zip";
	`
	services := DiscoverServicesFromContent("assets.js", []byte(js))
	if len(services) < 2 {
		t.Fatalf("expected at least 2 S3 services, got %d", len(services))
	}
	for _, s := range services {
		if s.Provider != ProviderAWS {
			t.Errorf("expected ProviderAWS, got %s", s.Provider)
		}
	}
}

// Test 4: GCS discovery
func TestGCSDiscovery(t *testing.T) {
	js := `
		const gcs1 = "https://storage.googleapis.com/public-media/video.mp4";
		const gcs2 = "https://static.storage.googleapis.com/style.css";
	`
	services := DiscoverServicesFromContent("media.js", []byte(js))
	if len(services) < 2 {
		t.Fatalf("expected at least 2 GCS services, got %d", len(services))
	}
	for _, s := range services {
		if s.Provider != ProviderGCP {
			t.Errorf("expected ProviderGCP, got %s", s.Provider)
		}
	}
}

// Test 5: Supabase anon key is not classified as critical secret
func TestSupabaseAnonKey(t *testing.T) {
	anonToken := createTestJWT(map[string]interface{}{
		"iss":  "supabase",
		"ref":  "test-ref",
		"role": "anon",
	})

	svc := Service{
		Provider: ProviderSupabase,
		URL:      "https://test-ref.supabase.co",
	}

	client := NewClient()
	findings := AuditSupabase(context.Background(), client, svc, nil, anonToken, "")

	for _, f := range findings {
		if f.Severity == SeverityCritical {
			t.Errorf("Supabase anon key must not produce critical findings: %+v", f)
		}
	}
}

// Test 6: Supabase service role detected without sending live requests using it
func TestSupabaseServiceRole(t *testing.T) {
	var liveRequests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&liveRequests, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	serviceRoleToken := createTestJWT(map[string]interface{}{
		"iss":  "supabase",
		"role": "service_role",
	})

	svc := Service{
		Provider: ProviderSupabase,
		URL:      server.URL,
	}

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	findings := AuditSupabase(context.Background(), client, svc, nil, "", serviceRoleToken)

	// Check finding reported
	var foundCritical bool
	for _, f := range findings {
		if f.Category == "Privileged Credential Exposure" && f.Severity == SeverityCritical {
			foundCritical = true
			break
		}
	}
	if !foundCritical {
		t.Errorf("expected CRITICAL Privileged Credential Exposure finding")
	}

	// Verify NO HTTP requests were sent using the service_role key
	if count := atomic.LoadInt32(&liveRequests); count != 0 {
		t.Errorf("scanner must NEVER send requests using service_role key; observed %d requests", count)
	}
}

// Test 7: Supabase protected resource (401/403 -> No unauthorized-access finding)
func TestSupabaseProtectedResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"message": "Permission denied"}`)
	}))
	defer server.Close()

	svc := Service{
		Provider: ProviderSupabase,
		URL:      server.URL,
	}

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	findings := AuditSupabase(context.Background(), client, svc, []string{"/rest/v1/profiles"}, "anon-key", "")

	for _, f := range findings {
		if f.Category == "Unauthorized Data Exposure" {
			t.Errorf("protected resource (403) must not be reported as unauthorized data exposure")
		}
	}
}

// Test 8: Supabase exposed resource (200 OK with records -> Unauthorized data exposure)
func TestSupabaseExposedResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `[{"id": 1, "product_name": "Felix Pro", "price": 99}]`)
	}))
	defer server.Close()

	svc := Service{
		Provider: ProviderSupabase,
		URL:      server.URL,
	}

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	findings := AuditSupabase(context.Background(), client, svc, []string{"/rest/v1/products"}, "anon-key", "")

	var foundExposure bool
	for _, f := range findings {
		if f.Category == "Unauthorized Data Exposure" && f.Severity == SeverityHigh {
			foundExposure = true
			if !strings.Contains(f.Evidence, "product_name") {
				t.Errorf("evidence should list observed field names: %s", f.Evidence)
			}
			break
		}
	}
	if !foundExposure {
		t.Errorf("expected Unauthorized Data Exposure finding for open 200 OK endpoint")
	}
}

// Test 9: Firebase protected database (401/403 -> No unauthorized data finding)
func TestFirebaseProtectedDatabase(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error": "Permission denied"}`)
	}))
	defer server.Close()

	svc := Service{
		Provider: ProviderFirebase,
		URL:      server.URL,
	}

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	findings := AuditFirebase(context.Background(), client, svc)

	if len(findings) != 0 {
		t.Errorf("protected Firebase database must not produce findings, got: %+v", findings)
	}
}

// Test 10: Firebase open database (200 OK -> Unauthenticated access finding)
func TestFirebaseOpenDatabase(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"app_config": {"env": "prod"}, "users_count": 42}`)
	}))
	defer server.Close()

	svc := Service{
		Provider: ProviderFirebase,
		URL:      server.URL,
	}

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	findings := AuditFirebase(context.Background(), client, svc)

	if len(findings) == 0 {
		t.Fatalf("expected Unauthenticated Database Access finding for open Firebase DB")
	}

	f := findings[0]
	if f.Category != "Unauthenticated Database Access" {
		t.Errorf("expected Unauthenticated Database Access, got %s", f.Category)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
}

// Test 11: S3 public listing (ListBucketResult XML -> Expected finding)
func TestS3PublicListing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>felix-bucket</Name><Contents><Key>test.txt</Key></Contents></ListBucketResult>`)
	}))
	defer server.Close()

	svc := Service{
		Provider: ProviderAWS,
		URL:      server.URL,
	}

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	findings := AuditStorage(context.Background(), client, svc)

	if len(findings) == 0 {
		t.Fatalf("expected Anonymous Bucket Listing finding for S3")
	}
	if findings[0].Category != "Anonymous Bucket Listing" {
		t.Errorf("expected Anonymous Bucket Listing, got %s", findings[0].Category)
	}
}

// Test 12: GCS public listing
func TestGCSPublicListing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<ListBucketResult><Bucket>gcs-test-bucket</Bucket><Contents><Key>report.pdf</Key></Contents></ListBucketResult>`)
	}))
	defer server.Close()

	svc := Service{
		Provider: ProviderGCP,
		URL:      server.URL,
	}

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	findings := AuditStorage(context.Background(), client, svc)

	if len(findings) == 0 {
		t.Fatalf("expected Anonymous Bucket Listing finding for GCS")
	}
	if findings[0].Category != "Anonymous Bucket Listing" {
		t.Errorf("expected Anonymous Bucket Listing, got %s", findings[0].Category)
	}
}

// Test 13: 429 rate-limit handling stops probing immediately
func TestRateLimitHandling(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	svc := Service{
		Provider: ProviderSupabase,
		URL:      server.URL,
	}

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	// Provide 5 candidate endpoints
	endpoints := []string{"/rest/v1/ep1", "/rest/v1/ep2", "/rest/v1/ep3", "/rest/v1/ep4", "/rest/v1/ep5"}

	AuditSupabase(context.Background(), client, svc, endpoints, "anon-key", "")

	// On 429, the scanner must halt without hitting all remaining endpoints
	count := atomic.LoadInt32(&requestCount)
	if count > 1 {
		t.Errorf("scanner should halt upon encountering 429; sent %d requests", count)
	}
}

// Test 14: Oversized response truncation/rejection
func TestOversizedResponse(t *testing.T) {
	oversizedBody := strings.Repeat("A", 1024*1024) // 1 MB
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(oversizedBody))
	}))
	defer server.Close()

	// Limit to 64 KB
	client := NewClient(ClientOptions{
		HTTPClient:      server.Client(),
		MaxResponseSize: 64 * 1024,
	})

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := client.Do(context.Background(), req)

	if err != nil && err != ErrResponseTooLarge {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp != nil && int64(len(resp.Body)) > 64*1024 {
		t.Errorf("body exceeded max size limit: got %d bytes", len(resp.Body))
	}
}

// Test 15: Duplicate provider discovery deduplication
func TestDuplicateProviderDiscovery(t *testing.T) {
	assets := []crawler.Asset{
		{
			URL:     "https://example.com/main.js",
			Content: []byte("const sb = 'https://demo-app.supabase.co'; const fb = 'https://fb-app.firebaseio.com';"),
		},
		{
			URL:     "https://example.com/vendor.js",
			Content: []byte("const sb2 = 'https://demo-app.supabase.co'; const fb2 = 'https://fb-app.firebaseio.com';"),
		},
		{
			URL:     "https://example.com/app.js.map",
			Content: []byte("const sb3 = 'https://demo-app.supabase.co';"),
		},
	}

	d := NewDetector(nil)
	services := d.DiscoverServices(assets)

	if len(services) != 2 {
		t.Errorf("expected exactly 2 deduplicated services (1 Supabase, 1 Firebase), got %d: %+v", len(services), services)
	}
}

// Test 16: Sensitive response redaction (no synthetic sensitive values in evidence)
func TestSensitiveResponseRedaction(t *testing.T) {
	syntheticSecret := "SuperSecretPassword123!"
	syntheticSSN := "000-12-3456"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `[{"password": "%s", "ssn": "%s", "id": 1}]`, syntheticSecret, syntheticSSN)
	}))
	defer server.Close()

	svc := Service{
		Provider: ProviderSupabase,
		URL:      server.URL,
	}

	client := NewClient(ClientOptions{HTTPClient: server.Client()})
	findings := AuditSupabase(context.Background(), client, svc, []string{"/rest/v1/customers"}, "anon-key", "")

	if len(findings) == 0 {
		t.Fatalf("expected finding")
	}

	for _, f := range findings {
		if strings.Contains(f.Evidence, syntheticSecret) {
			t.Errorf("sensitive value %s MUST NOT appear in evidence: %s", syntheticSecret, f.Evidence)
		}
		if strings.Contains(f.Evidence, syntheticSSN) {
			t.Errorf("sensitive SSN %s MUST NOT appear in evidence: %s", syntheticSSN, f.Evidence)
		}
		if strings.Contains(f.Description, syntheticSecret) {
			t.Errorf("sensitive value must not appear in description")
		}
	}
}

// Test Concurrent Cloud Safety
func TestConcurrentCloudSafety(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			js := fmt.Sprintf(`const sb = "https://app%d.supabase.co"; const fb = "https://db%d.firebaseio.com";`, id, id)
			svcs := DiscoverServicesFromContent(fmt.Sprintf("file%d.js", id), []byte(js))
			if len(svcs) < 2 {
				t.Errorf("expected at least 2 services, got %d", len(svcs))
			}
		}(i)
	}
	wg.Wait()
}

