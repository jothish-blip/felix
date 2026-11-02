package cloudsec

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CloudMetadataMock simulates AWS (IMDSv1 and IMDSv2), GCP, and Azure metadata endpoints
// strictly on local loopback. It never contacts public cloud services and contains only synthetic test data.
type CloudMetadataMock struct {
	server        *httptest.Server
	URL           string
	mu            sync.RWMutex
	imdsV2Enforce bool
	validToken    string
	deniedPaths   map[string]bool
	requestLog    []MockRequestRecord
}

// MockRequestRecord records requests received by the mock for test verification.
type MockRequestRecord struct {
	Method  string
	Path    string
	Headers http.Header
	Time    time.Time
}

// NewCloudMetadataMock starts a local loopback mock server.
func NewCloudMetadataMock() *CloudMetadataMock {
	mock := &CloudMetadataMock{
		validToken:  "AQAAABcDefSyntheticTokenForIMDSv2Testing999==",
		deniedPaths: make(map[string]bool),
	}

	mux := http.NewServeMux()

	// 1. AWS IMDS Handlers
	mux.HandleFunc("/latest/api/token", mock.handleAWSToken)
	mux.HandleFunc("/latest/meta-data/", mock.handleAWSMetadata)
	mux.HandleFunc("/latest/dynamic/instance-identity/document", mock.handleAWSInstanceIdentity)

	// 2. GCP Metadata Handlers
	mux.HandleFunc("/computeMetadata/v1/", mock.handleGCPMetadata)

	// 3. Azure Instance Metadata Handlers
	mux.HandleFunc("/metadata/instance", mock.handleAzureInstance)
	mux.HandleFunc("/metadata/identity/oauth2/token", mock.handleAzureToken)

	// 4. SSRF Relay Simulator (simulates a vulnerable web app endpoint: /ssrf?url=...)
	mux.HandleFunc("/ssrf-relay", mock.handleSSRFRelay)

	mock.server = httptest.NewServer(mux)
	mock.URL = mock.server.URL
	return mock
}

// Close shuts down the local test server.
func (m *CloudMetadataMock) Close() {
	if m.server != nil {
		m.server.Close()
	}
}

// SetIMDSv2Enforced toggles mandatory IMDSv2 token validation for /latest/meta-data/.
func (m *CloudMetadataMock) SetIMDSv2Enforced(enforce bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.imdsV2Enforce = enforce
}

// SetPathDenied marks a specific path to return 403 Forbidden.
func (m *CloudMetadataMock) SetPathDenied(path string, denied bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if denied {
		m.deniedPaths[path] = true
	} else {
		delete(m.deniedPaths, path)
	}
}

// RequestCount returns total recorded requests.
func (m *CloudMetadataMock) RequestCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.requestLog)
}

func (m *CloudMetadataMock) recordRequest(r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requestLog = append(m.requestLog, MockRequestRecord{
		Method:  r.Method,
		Path:    r.URL.Path,
		Headers: r.Header.Clone(),
		Time:    time.Now().UTC(),
	})
}

// -------------------------------------------------------------------------
// AWS Handlers
// -------------------------------------------------------------------------

func (m *CloudMetadataMock) handleAWSToken(w http.ResponseWriter, r *http.Request) {
	m.recordRequest(r)
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ttlHeader := r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds")
	if ttlHeader == "" {
		http.Error(w, "Missing X-aws-ec2-metadata-token-ttl-seconds header", http.StatusBadRequest)
		return
	}
	ttl, err := strconv.Atoi(ttlHeader)
	if err != nil || ttl <= 0 || ttl > 21600 {
		http.Error(w, "Invalid token TTL", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(m.validToken))
}

func (m *CloudMetadataMock) handleAWSMetadata(w http.ResponseWriter, r *http.Request) {
	m.recordRequest(r)

	m.mu.RLock()
	enforce := m.imdsV2Enforce
	denied := m.deniedPaths[r.URL.Path]
	m.mu.RUnlock()

	if denied {
		http.Error(w, "Access Denied by IAM Policy", http.StatusForbidden)
		return
	}

	if enforce {
		token := r.Header.Get("X-aws-ec2-metadata-token")
		if token == "" || token != m.validToken {
			http.Error(w, "Unauthorized: IMDSv2 token required", http.StatusUnauthorized)
			return
		}
	}

	path := r.URL.Path
	w.Header().Set("Server", "EC2ws")

	switch {
	case path == "/latest/meta-data" || path == "/latest/meta-data/":
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ami-id\ninstance-id\ninstance-type\niam/\nhostname\nlocal-ipv4\npublic-ipv4\n"))

	case path == "/latest/meta-data/instance-id":
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("i-0123456789abcdef0"))

	case path == "/latest/meta-data/iam/security-credentials" || path == "/latest/meta-data/iam/security-credentials/":
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("felix-synthetic-role\n"))

	case path == "/latest/meta-data/iam/security-credentials/felix-synthetic-role":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		syntheticSTS := map[string]any{
			"Code":            "Success",
			"LastUpdated":     "2026-10-31T05:00:00Z",
			"Type":            "AWS-HMAC",
			"AccessKeyId":     "ASIA-SYNTHETIC-MOCK-001",
			"SecretAccessKey": "synthetic-secret-key-mock-only-not-real-001",
			"Token":           "synthetic-session-token-data-only-not-real-123456",
			"Expiration":      "2026-10-31T17:00:00Z",
		}
		_ = json.NewEncoder(w).Encode(syntheticSTS)

	case path == "/latest/meta-data/iam/security-credentials/malformed-role":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{ invalid json data missing brackets"))

	case path == "/latest/meta-data/iam/security-credentials/missing-fields-role":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Missing SecretAccessKey and Token
		_, _ = w.Write([]byte(`{"Code":"Success","AccessKeyId":"ASIA-SYNTHETIC-INCOMPLETE"}`))

	default:
		http.NotFound(w, r)
	}
}

func (m *CloudMetadataMock) handleAWSInstanceIdentity(w http.ResponseWriter, r *http.Request) {
	m.recordRequest(r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	doc := map[string]any{
		"accountId":        "123456789012",
		"architecture":     "x86_64",
		"availabilityZone": "us-east-1a",
		"instanceId":       "i-0123456789abcdef0",
		"instanceType":     "t3.micro",
		"region":           "us-east-1",
	}
	_ = json.NewEncoder(w).Encode(doc)
}

// -------------------------------------------------------------------------
// GCP Handlers
// -------------------------------------------------------------------------

func (m *CloudMetadataMock) handleGCPMetadata(w http.ResponseWriter, r *http.Request) {
	m.recordRequest(r)

	// GCP requires "Metadata-Flavor: Google"
	flavor := r.Header.Get("Metadata-Flavor")
	if !strings.EqualFold(flavor, "Google") {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html><head><title>Error 403 (Forbidden)!!1</title></head><body><h1>403 Forbidden</h1>Must specify Metadata-Flavor: Google header</body></html>"))
		return
	}

	m.mu.RLock()
	denied := m.deniedPaths[r.URL.Path]
	m.mu.RUnlock()
	if denied {
		http.Error(w, "Access Denied by GCP IAM", http.StatusForbidden)
		return
	}

	w.Header().Set("Metadata-Flavor", "Google")
	w.Header().Set("Server", "Metadata Server on Google Compute Engine")

	path := r.URL.Path
	switch {
	case path == "/computeMetadata/v1" || path == "/computeMetadata/v1/":
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("instance/\nproject/\n"))

	case path == "/computeMetadata/v1/instance/id":
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("9876543210987654321"))

	case path == "/computeMetadata/v1/instance/zone":
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("projects/12345/zones/us-central1-a"))

	case path == "/computeMetadata/v1/instance/service-accounts/default/email":
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("synthetic-vm-sa@felix-synthetic-project.iam.gserviceaccount.com"))

	case path == "/computeMetadata/v1/instance/service-accounts/default/token":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		syntheticToken := map[string]any{
			"access_token": "ya29.c.synthetic-token-for-lab-testing-only-not-real",
			"expires_in":   3599,
			"token_type":   "Bearer",
		}
		_ = json.NewEncoder(w).Encode(syntheticToken)

	case path == "/computeMetadata/v1/instance/service-accounts/default/malformed":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{ malformed-json-payload-test"))

	default:
		http.NotFound(w, r)
	}
}

// -------------------------------------------------------------------------
// Azure Handlers
// -------------------------------------------------------------------------

func (m *CloudMetadataMock) handleAzureInstance(w http.ResponseWriter, r *http.Request) {
	m.recordRequest(r)

	// Azure requires "Metadata: true"
	metadataHeader := r.Header.Get("Metadata")
	if !strings.EqualFold(metadataHeader, "true") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": "Bad Request", "message": "Required metadata header not specified"}`))
		return
	}

	// Azure requires api-version query param
	apiVersion := r.URL.Query().Get("api-version")
	if apiVersion == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": "Bad Request", "message": "api-version query parameter required"}`))
		return
	}

	m.mu.RLock()
	denied := m.deniedPaths[r.URL.Path]
	m.mu.RUnlock()
	if denied {
		http.Error(w, "Access Denied by Azure Policy", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	computeDoc := map[string]any{
		"compute": map[string]any{
			"azEnvironment":              "AzurePublicCloud",
			"location":                   "eastus2",
			"name":                       "felix-synthetic-vm-01",
			"osType":                     "Linux",
			"resourceGroupName":          "rg-synthetic-lab",
			"resourceId":                 "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-synthetic-lab/providers/Microsoft.Compute/virtualMachines/felix-synthetic-vm-01",
			"subscriptionId":             "00000000-0000-0000-0000-000000000000",
			"vmId":                       "11111111-2222-3333-4444-555555555555",
			"vmSize":                     "Standard_B2s",
			"zone":                       "1",
		},
	}
	_ = json.NewEncoder(w).Encode(computeDoc)
}

func (m *CloudMetadataMock) handleAzureToken(w http.ResponseWriter, r *http.Request) {
	m.recordRequest(r)

	if !strings.EqualFold(r.Header.Get("Metadata"), "true") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": "Bad Request", "message": "Required metadata header not specified"}`))
		return
	}

	m.mu.RLock()
	denied := m.deniedPaths[r.URL.Path]
	m.mu.RUnlock()
	if denied {
		http.Error(w, "Managed Identity Disabled", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	tokenDoc := map[string]any{
		"access_token": "synthetic-azure-msi-access-token-lab-testing-only-001",
		"client_id":    "22222222-3333-4444-5555-666666666666",
		"expires_in":   "3599",
		"expires_on":   "1730380000",
		"not_before":   "1730376400",
		"resource":     "https://management.azure.com/",
		"token_type":   "Bearer",
	}
	_ = json.NewEncoder(w).Encode(tokenDoc)
}

// -------------------------------------------------------------------------
// SSRF Relay Simulator
// -------------------------------------------------------------------------

// handleSSRFRelay simulates a web application endpoint vulnerable to SSRF.
// Accepts: GET/POST /ssrf-relay?url=<target_url>&token=<imds_token>&flavor=<gcp_flavor>&azure_meta=<meta>
func (m *CloudMetadataMock) handleSSRFRelay(w http.ResponseWriter, r *http.Request) {
	m.recordRequest(r)

	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		http.Error(w, "missing 'url' parameter", http.StatusBadRequest)
		return
	}

	// Validate target URL format
	parsed, err := url.Parse(targetURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		http.Error(w, "invalid or unsupported target URL", http.StatusBadRequest)
		return
	}

	// Forward client request to target
	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed creating upstream request: %v", err), http.StatusInternalServerError)
		return
	}

	// Propagate simulated headers passed via query parameters or forwarded headers
	if token := r.URL.Query().Get("token"); token != "" {
		req.Header.Set("X-aws-ec2-metadata-token", token)
	} else if h := r.Header.Get("X-aws-ec2-metadata-token"); h != "" {
		req.Header.Set("X-aws-ec2-metadata-token", h)
	}

	if ttl := r.URL.Query().Get("ttl"); ttl != "" {
		req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", ttl)
	} else if h := r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds"); h != "" {
		req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", h)
	}

	if flavor := r.URL.Query().Get("flavor"); flavor != "" {
		req.Header.Set("Metadata-Flavor", flavor)
	} else if h := r.Header.Get("Metadata-Flavor"); h != "" {
		req.Header.Set("Metadata-Flavor", h)
	}

	if azureMeta := r.URL.Query().Get("azure_meta"); azureMeta != "" {
		req.Header.Set("Metadata", azureMeta)
	} else if h := r.Header.Get("Metadata"); h != "" {
		req.Header.Set("Metadata", h)
	}

	// Local mock transport (allows loopback)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("SSRF upstream request failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy headers and status code
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
