package apk

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/report"
)

func TestInventory_Normalization(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantURL       string
		wantScheme    string
		wantHost      string
		wantPort      int
		wantPath      string
		wantHostId    string
		wantRelative  bool
		wantNilOrSkip bool
	}{
		{
			name:       "Equivalent URL with root slash",
			input:      "https://api.example.com",
			wantURL:    "https://api.example.com/",
			wantScheme: "https",
			wantHost:   "api.example.com",
			wantPort:   443,
			wantPath:   "/",
			wantHostId: "api.example.com",
		},
		{
			name:       "URL with casing in scheme and host",
			input:      "HTTPS://API.Example.COM/v1/users",
			wantURL:    "https://api.example.com/v1/users",
			wantScheme: "https",
			wantHost:   "api.example.com",
			wantPort:   443,
			wantPath:   "/v1/users",
			wantHostId: "api.example.com",
		},
		{
			name:       "Default port 80 stripped for HTTP",
			input:      "http://api.example.com:80/v1/data",
			wantURL:    "http://api.example.com/v1/data",
			wantScheme: "http",
			wantHost:   "api.example.com",
			wantPort:   80,
			wantPath:   "/v1/data",
			wantHostId: "api.example.com",
		},
		{
			name:       "Default port 443 stripped for HTTPS",
			input:      "https://api.example.com:443/v1/data",
			wantURL:    "https://api.example.com/v1/data",
			wantScheme: "https",
			wantHost:   "api.example.com",
			wantPort:   443,
			wantPath:   "/v1/data",
			wantHostId: "api.example.com",
		},
		{
			name:       "Non-default port preserved for HTTP",
			input:      "http://api.example.com:8080/v1/data",
			wantURL:    "http://api.example.com:8080/v1/data",
			wantScheme: "http",
			wantHost:   "api.example.com",
			wantPort:   8080,
			wantPath:   "/v1/data",
			wantHostId: "api.example.com:8080",
		},
		{
			name:       "Non-default port preserved for HTTPS",
			input:      "https://api.example.com:8443/v1/data",
			wantURL:    "https://api.example.com:8443/v1/data",
			wantScheme: "https",
			wantHost:   "api.example.com",
			wantPort:   8443,
			wantPath:   "/v1/data",
			wantHostId: "api.example.com:8443",
		},
		{
			name:       "HTTP versus HTTPS distinction",
			input:      "http://api.example.com/v1/data",
			wantURL:    "http://api.example.com/v1/data",
			wantScheme: "http",
			wantHost:   "api.example.com",
			wantPort:   80,
			wantPath:   "/v1/data",
			wantHostId: "api.example.com",
		},
		{
			name:       "URL Fragment stripped",
			input:      "https://api.example.com/v1/docs#authentication-tokens",
			wantURL:    "https://api.example.com/v1/docs",
			wantScheme: "https",
			wantHost:   "api.example.com",
			wantPort:   443,
			wantPath:   "/v1/docs",
			wantHostId: "api.example.com",
		},
		{
			name:       "Query parameter sorting and sensitive value redaction",
			input:      "https://api.example.com/search?sort=desc&api_key=SECRET12345&filter=active&token=MY_TOKEN",
			wantURL:    "https://api.example.com/search?api_key=[REDACTED]&filter=active&sort=desc&token=[REDACTED]",
			wantScheme: "https",
			wantHost:   "api.example.com",
			wantPort:   443,
			wantPath:   "/search",
			wantHostId: "api.example.com",
		},
		{
			name:       "Userinfo credentials stripped from normalized URL",
			input:      "https://admin:superpassword@api.example.com/v1/manage",
			wantURL:    "https://api.example.com/v1/manage",
			wantScheme: "https",
			wantHost:   "api.example.com",
			wantPort:   443,
			wantPath:   "/v1/manage",
			wantHostId: "api.example.com",
		},
		{
			name:       "IPv4 address hostname",
			input:      "http://192.168.1.50:8000/api",
			wantURL:    "http://192.168.1.50:8000/api",
			wantScheme: "http",
			wantHost:   "192.168.1.50",
			wantPort:   8000,
			wantPath:   "/api",
			wantHostId: "192.168.1.50:8000",
		},
		{
			name:       "IPv6 bracketed address with non-default port",
			input:      "http://[2001:db8::1]:8080/api/v1",
			wantURL:    "http://[2001:db8::1]:8080/api/v1",
			wantScheme: "http",
			wantHost:   "2001:db8::1",
			wantPort:   8080,
			wantPath:   "/api/v1",
			wantHostId: "[2001:db8::1]:8080",
		},
		{
			name:       "IPv6 bracketed address with default port",
			input:      "https://[::1]:443/status",
			wantURL:    "https://[::1]/status",
			wantScheme: "https",
			wantHost:   "::1",
			wantPort:   443,
			wantPath:   "/status",
			wantHostId: "[::1]",
		},
		{
			name:       "Dot segments and duplicate slashes cleaned with trailing slash preserved",
			input:      "https://api.example.com//v1/../v2///users///",
			wantURL:    "https://api.example.com/v2/users/",
			wantScheme: "https",
			wantHost:   "api.example.com",
			wantPort:   443,
			wantPath:   "/v2/users/",
			wantHostId: "api.example.com",
		},
		{
			name:       "Percent encoding uppercase hex and unreserved decoding",
			input:      "https://api.example.com/files/%2f%41%7e%3a",
			wantURL:    "https://api.example.com/files/%2FA~%3A",
			wantScheme: "https",
			wantHost:   "api.example.com",
			wantPort:   443,
			wantPath:   "/files/%2FA~%3A",
			wantHostId: "api.example.com",
		},
		{
			name:         "Relative route path without scheme",
			input:        "/api/v1/catalogs/items",
			wantURL:      "/api/v1/catalogs/items",
			wantScheme:   "",
			wantHost:     "",
			wantPort:     0,
			wantPath:     "/api/v1/catalogs/items",
			wantHostId:   "(unresolved)",
			wantRelative: true,
		},
		{
			name:         "Relative route without leading slash",
			input:        "api/v1/catalogs",
			wantURL:      "/api/v1/catalogs",
			wantScheme:   "",
			wantHost:     "",
			wantPort:     0,
			wantPath:     "/api/v1/catalogs",
			wantHostId:   "(unresolved)",
			wantRelative: true,
		},
		{
			name:          "Non-endpoint Java package rejected",
			input:         "com.android.support.v4",
			wantNilOrSkip: true,
		},
		{
			name:          "Non-endpoint boolean literal rejected",
			input:         "true",
			wantNilOrSkip: true,
		},
		{
			name:          "Non-endpoint hex color rejected",
			input:         "#FFAABBCC",
			wantNilOrSkip: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			norm, err := NormalizeEndpoint(tt.input)
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.input, err)
			}
			if tt.wantNilOrSkip {
				if norm != nil {
					t.Fatalf("expected nil for non-endpoint %q, got: %+v", tt.input, norm)
				}
				return
			}
			if norm == nil {
				t.Fatalf("expected valid NormalizedEndpoint for %q, got nil", tt.input)
			}
			if norm.NormalizedURL != tt.wantURL {
				t.Errorf("NormalizedURL mismatch: got %q, want %q", norm.NormalizedURL, tt.wantURL)
			}
			if norm.Scheme != tt.wantScheme {
				t.Errorf("Scheme mismatch: got %q, want %q", norm.Scheme, tt.wantScheme)
			}
			if norm.Host != tt.wantHost {
				t.Errorf("Host mismatch: got %q, want %q", norm.Host, tt.wantHost)
			}
			if norm.Port != tt.wantPort {
				t.Errorf("Port mismatch: got %d, want %d", norm.Port, tt.wantPort)
			}
			if norm.Path != tt.wantPath {
				t.Errorf("Path mismatch: got %q, want %q", norm.Path, tt.wantPath)
			}
			if norm.HostIdentity != tt.wantHostId {
				t.Errorf("HostIdentity mismatch: got %q, want %q", norm.HostIdentity, tt.wantHostId)
			}
			if norm.IsRelative != tt.wantRelative {
				t.Errorf("IsRelative mismatch: got %v, want %v", norm.IsRelative, tt.wantRelative)
			}
		})
	}
}

func TestInventory_DeduplicationAndInputOrdering(t *testing.T) {
	// Create mock workspace
	ws := &Workspace{
		Dir:     t.TempDir(),
		APKPath: "C:\\path\\to\\app.apk",
		SHA256:  "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
	}

	limits := DefaultLimits()

	// Endpoints to generate in findings
	baseList := []string{
		"https://api.mycorp.com/v1/users",
		"https://API.MYCORP.COM/v1/users",     // equivalent casing
		"https://api.mycorp.com:443/v1/users", // equivalent default port
		"https://auth.mycorp.com/oauth/token",
		"https://auth.mycorp.com/oauth/token#hash", // equivalent fragment
		"https://storage.s3.amazonaws.com/assets",
	}

	createResultWithEndpoints := func(order []string) *ArtifactAnalysisResult {
		var findings []report.Finding
		for i, u := range order {
			rule := "APK-ART-API-BASE-URL"
			if strings.Contains(u, "s3") {
				rule = "APK-ART-SERVICE-AWS"
			}
			findings = append(findings, report.Finding{
				ID:       fmt.Sprintf("finding-%d", i),
				RuleID:   rule,
				Endpoint: u,
				Evidence: "Found endpoint " + u,
				EvidenceDetails: report.EvidenceDetails{
					Location: u,
					Details: map[string]string{
						"base_url":    u,
						"file_origin": fmt.Sprintf("classes%d.dex", (i%2)+1),
					},
				},
				Confidence: report.ConfidenceHigh,
			})
		}
		return &ArtifactAnalysisResult{
			Findings: findings,
		}
	}

	// Run inventory with original order
	res1 := createResultWithEndpoints(baseList)
	inv1, err := BuildBackendInventory(context.Background(), ws, nil, res1, limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Run inventory with shuffled order
	shuffled := append([]string{}, baseList...)
	r := rand.New(rand.NewSource(42))
	r.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})

	res2 := createResultWithEndpoints(shuffled)
	inv2, err := BuildBackendInventory(context.Background(), ws, nil, res2, limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 1. Verify exact deduplication count
	// 3 distinct endpoints:
	// 1: https://api.mycorp.com/v1/users
	// 2: https://auth.mycorp.com/oauth/token
	// 3: https://storage.s3.amazonaws.com/assets
	if inv1.TotalEndpoints != 3 {
		t.Fatalf("expected 3 deduplicated endpoints, got %d", inv1.TotalEndpoints)
	}
	if inv2.TotalEndpoints != 3 {
		t.Fatalf("expected 3 deduplicated endpoints in shuffled run, got %d", inv2.TotalEndpoints)
	}

	// 2. Verify deterministic ordering between runs
	for i := range inv1.Endpoints {
		ep1 := inv1.Endpoints[i]
		ep2 := inv2.Endpoints[i]
		if ep1.NormalizedURL != ep2.NormalizedURL {
			t.Errorf("order mismatch at index %d: %q vs %q", i, ep1.NormalizedURL, ep2.NormalizedURL)
		}
	}
	for i := range inv1.Hosts {
		h1 := inv1.Hosts[i]
		h2 := inv2.Hosts[i]
		if h1.HostIdentity != h2.HostIdentity {
			t.Errorf("host order mismatch at index %d: %q vs %q", i, h1.HostIdentity, h2.HostIdentity)
		}
	}
}

func TestInventory_HostGrouping(t *testing.T) {
	ws := &Workspace{
		Dir:     t.TempDir(),
		APKPath: "C:\\path\\to\\app.apk",
		SHA256:  "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
	}

	limits := DefaultLimits()

	// Endpoints across different hosts, subdomains, ports, and IP versions
	res := &ArtifactAnalysisResult{
		Findings: []report.Finding{
			{
				ID:       "f1",
				RuleID:   "APK-ART-API-BASE-URL",
				Endpoint: "https://api.corp.com/v1/users",
				EvidenceDetails: report.EvidenceDetails{
					Details: map[string]string{"base_url": "https://api.corp.com/v1/users", "file_origin": "classes.dex"},
				},
			},
			{
				ID:       "f2",
				RuleID:   "APK-ART-API-BASE-URL",
				Endpoint: "https://api.corp.com/v1/posts",
				EvidenceDetails: report.EvidenceDetails{
					Details: map[string]string{"base_url": "https://api.corp.com/v1/posts", "file_origin": "classes.dex"},
				},
			},
			{
				ID:       "f3",
				RuleID:   "APK-ART-API-BASE-URL",
				Endpoint: "https://api.corp.com:8443/v1/admin",
				EvidenceDetails: report.EvidenceDetails{
					Details: map[string]string{"base_url": "https://api.corp.com:8443/v1/admin", "file_origin": "classes.dex"},
				},
			},
			{
				ID:       "f4",
				RuleID:   "APK-ART-API-BASE-URL",
				Endpoint: "https://auth.corp.com/login",
				EvidenceDetails: report.EvidenceDetails{
					Details: map[string]string{"base_url": "https://auth.corp.com/login", "file_origin": "classes.dex"},
				},
			},
			{
				ID:       "f5",
				RuleID:   "APK-ART-API-BASE-URL",
				Endpoint: "http://192.168.1.100:8000/api",
				EvidenceDetails: report.EvidenceDetails{
					Details: map[string]string{"base_url": "http://192.168.1.100:8000/api", "file_origin": "classes.dex"},
				},
			},
			{
				ID:       "f6",
				RuleID:   "APK-ART-API-BASE-URL",
				Endpoint: "http://[2001:db8::1]:9000/metrics",
				EvidenceDetails: report.EvidenceDetails{
					Details: map[string]string{"base_url": "http://[2001:db8::1]:9000/metrics", "file_origin": "classes.dex"},
				},
			},
		},
	}

	inv, err := BuildBackendInventory(context.Background(), ws, nil, res, limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify distinct host groups:
	// 1: 192.168.1.100:8000
	// 2: [2001:db8::1]:9000
	// 3: api.corp.com (2 endpoints: /v1/users, /v1/posts)
	// 4: api.corp.com:8443 (1 endpoint: /v1/admin)
	// 5: auth.corp.com (1 endpoint: /login)
	if inv.TotalHosts != 5 {
		t.Fatalf("expected 5 host groups, got %d", inv.TotalHosts)
	}

	hostMap := make(map[string]HostGroup)
	for _, hg := range inv.Hosts {
		hostMap[hg.HostIdentity] = hg
	}

	// Verify api.corp.com has 2 endpoints
	apiHost, ok := hostMap["api.corp.com"]
	if !ok {
		t.Fatalf("missing host group api.corp.com")
	}
	if apiHost.EndpointCount != 2 {
		t.Errorf("expected 2 endpoints for api.corp.com, got %d", apiHost.EndpointCount)
	}

	// Verify api.corp.com:8443 is a distinct host group
	apiPortHost, ok := hostMap["api.corp.com:8443"]
	if !ok {
		t.Fatalf("missing distinct host group api.corp.com:8443")
	}
	if apiPortHost.EndpointCount != 1 {
		t.Errorf("expected 1 endpoint for api.corp.com:8443, got %d", apiPortHost.EndpointCount)
	}

	// Verify subdomains are not merged
	if _, ok := hostMap["auth.corp.com"]; !ok {
		t.Errorf("missing distinct subdomain host group auth.corp.com")
	}
}

func TestInventory_ProvenanceAndMultidexTraceability(t *testing.T) {
	ws := &Workspace{
		Dir:      t.TempDir(),
		APKPath:  "C:\\path\\to\\app.apk",
		SHA256:   "digest-001122",
		DexFiles: []string{"classes.dex", "classes2.dex"},
	}

	limits := DefaultLimits()

	// Same endpoint found in both classes.dex and classes2.dex
	res := &ArtifactAnalysisResult{
		Findings: []report.Finding{
			{
				ID:       "f-dex1",
				RuleID:   "APK-ART-API-BASE-URL",
				Endpoint: "https://api.example.com/v1",
				EvidenceDetails: report.EvidenceDetails{
					Location: "classes.dex offset 100",
					Details: map[string]string{
						"base_url":    "https://api.example.com/v1",
						"file_origin": "classes.dex",
					},
				},
			},
			{
				ID:       "f-dex2",
				RuleID:   "APK-ART-API-BASE-URL",
				Endpoint: "https://api.example.com/v1",
				EvidenceDetails: report.EvidenceDetails{
					Location: "classes2.dex offset 200",
					Details: map[string]string{
						"base_url":    "https://api.example.com/v1",
						"file_origin": "classes2.dex",
					},
				},
			},
		},
	}

	inv, err := BuildBackendInventory(context.Background(), ws, nil, res, limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if inv.TotalEndpoints != 1 {
		t.Fatalf("expected 1 deduplicated endpoint, got %d", inv.TotalEndpoints)
	}

	ep := inv.Endpoints[0]
	if len(ep.Provenance) != 2 {
		t.Fatalf("expected 2 distinct provenance records for multidex, got %d", len(ep.Provenance))
	}

	dexFilesSeen := make(map[string]bool)
	for _, p := range ep.Provenance {
		dexFilesSeen[p.ArtifactPath] = true
		if p.APKSHA256 != "digest-001122" {
			t.Errorf("expected APK SHA-256 preserved, got %q", p.APKSHA256)
		}
	}

	if !dexFilesSeen["classes.dex"] || !dexFilesSeen["classes2.dex"] {
		t.Errorf("expected both classes.dex and classes2.dex traceable in provenance: %+v", dexFilesSeen)
	}

	// Verify JSON round-trip preserves provenance and fields
	jsonBytes, err := json.Marshal(inv)
	if err != nil {
		t.Fatalf("failed marshaling inventory: %v", err)
	}

	var roundTripped BackendInventory
	if err := json.Unmarshal(jsonBytes, &roundTripped); err != nil {
		t.Fatalf("failed unmarshaling inventory: %v", err)
	}

	if roundTripped.TotalEndpoints != inv.TotalEndpoints || roundTripped.TotalHosts != inv.TotalHosts {
		t.Errorf("round-trip mismatch in counts: %+v vs %+v", roundTripped, inv)
	}
}

func TestInventory_ClassificationConfirmedVsInferred(t *testing.T) {
	ws := &Workspace{
		Dir:     t.TempDir(),
		APKPath: "C:\\path\\to\\app.apk",
		SHA256:  "sha256-test-classification",
	}

	limits := DefaultLimits()

	// Scenario A: Exactly 1 unique API Base URL -> relative route is INFERRED with that base URL
	resA := &ArtifactAnalysisResult{
		Findings: []report.Finding{
			{
				ID:       "base1",
				RuleID:   "APK-ART-API-BASE-URL",
				Endpoint: "https://api.unambiguous.com",
				EvidenceDetails: report.EvidenceDetails{
					Details: map[string]string{
						"base_url":    "https://api.unambiguous.com",
						"file_origin": "classes.dex",
					},
				},
			},
			{
				ID:       "route1",
				RuleID:   "APK-ART-API-ENDPOINT",
				Endpoint: "/api/v1/users",
				EvidenceDetails: report.EvidenceDetails{
					Details: map[string]string{
						"route":       "/api/v1/users",
						"file_origin": "classes.dex",
					},
				},
			},
		},
	}

	invA, err := BuildBackendInventory(context.Background(), ws, nil, resA, limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundInferred bool
	for _, ep := range invA.Endpoints {
		if ep.NormalizedURL == "https://api.unambiguous.com/api/v1/users" {
			foundInferred = true
			if ep.Classification != ClassificationInferredRoute {
				t.Errorf("expected InferredRoute classification, got: %s", ep.Classification)
			}
			if ep.Confidence != report.ConfidenceMedium {
				t.Errorf("expected ConfidenceMedium, got: %s", ep.Confidence)
			}
			if ep.InferredDetails == nil || ep.InferredDetails.BaseURL != "https://api.unambiguous.com" {
				t.Errorf("expected InferredDetails with base URL, got: %+v", ep.InferredDetails)
			}
		}
	}
	if !foundInferred {
		t.Fatalf("expected inferred route https://api.unambiguous.com/api/v1/users, got: %+v", invA.Endpoints)
	}

	// Scenario B: Multiple distinct API Base URLs -> relative route retained as UNRESOLVED (no fabricated URL)
	resB := &ArtifactAnalysisResult{
		Findings: []report.Finding{
			{
				ID:       "base1",
				RuleID:   "APK-ART-API-BASE-URL",
				Endpoint: "https://api-prod.corp.com",
				EvidenceDetails: report.EvidenceDetails{
					Details: map[string]string{"base_url": "https://api-prod.corp.com", "file_origin": "classes.dex"},
				},
			},
			{
				ID:       "base2",
				RuleID:   "APK-ART-API-BASE-URL",
				Endpoint: "https://api-staging.corp.com",
				EvidenceDetails: report.EvidenceDetails{
					Details: map[string]string{"base_url": "https://api-staging.corp.com", "file_origin": "classes.dex"},
				},
			},
			{
				ID:       "route1",
				RuleID:   "APK-ART-API-ENDPOINT",
				Endpoint: "/api/v1/users",
				EvidenceDetails: report.EvidenceDetails{
					Details: map[string]string{"route": "/api/v1/users", "file_origin": "classes.dex"},
				},
			},
		},
	}

	invB, err := BuildBackendInventory(context.Background(), ws, nil, resB, limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundUnresolved bool
	for _, ep := range invB.Endpoints {
		if ep.NormalizedURL == "/api/v1/users" {
			foundUnresolved = true
			if ep.HostIdentity != "(unresolved)" {
				t.Errorf("expected host identity (unresolved), got: %s", ep.HostIdentity)
			}
			if ep.Classification != ClassificationInferredRoute {
				t.Errorf("expected InferredRoute, got: %s", ep.Classification)
			}
			if ep.Confidence != report.ConfidenceLow {
				t.Errorf("expected ConfidenceLow, got: %s", ep.Confidence)
			}
			if !strings.Contains(ep.InferredDetails.Reason, "ambiguous") {
				t.Errorf("expected ambiguous reason, got: %s", ep.InferredDetails.Reason)
			}
		}
	}
	if !foundUnresolved {
		t.Fatalf("expected unresolved route /api/v1/users to be retained, got: %+v", invB.Endpoints)
	}
}

func TestInventory_SecurityRedaction_ZeroLeaks(t *testing.T) {
	ws := &Workspace{
		Dir:     t.TempDir(),
		APKPath: "C:\\path\\to\\app.apk",
		SHA256:  "sha-redaction-test",
	}

	limits := DefaultLimits()

	sentinelSecret := "SuperSecretKey9988776655"
	sentinelPassword := "P@ssword123456789"
	sentinelToken := "ghp_1234567890abcdefghijklmnopqrstuv"

	rawSecretURL := fmt.Sprintf("https://admin:%s@api.backend.com/query?token=%s&apiKey=%s",
		sentinelPassword, sentinelToken, sentinelSecret)

	res := &ArtifactAnalysisResult{
		Findings: []report.Finding{
			{
				ID:       "f-leak",
				RuleID:   "APK-ART-API-BASE-URL",
				Endpoint: rawSecretURL,
				Evidence: "Sensitive request to " + rawSecretURL,
				EvidenceDetails: report.EvidenceDetails{
					Details: map[string]string{
						"base_url":    rawSecretURL,
						"file_origin": "classes.dex",
					},
				},
			},
		},
	}

	inv, err := BuildBackendInventory(context.Background(), ws, nil, res, limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 1. Serialize complete inventory to JSON
	jsonBytes, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		t.Fatalf("failed marshaling: %v", err)
	}
	jsonStr := string(jsonBytes)

	// 2. Assert zero leaks of sentinel values across entire serialized inventory
	sentinels := []string{sentinelSecret, sentinelPassword, sentinelToken}
	for _, s := range sentinels {
		if strings.Contains(jsonStr, s) {
			t.Fatalf("SECURITY VIOLATION: Sentinel %q leaked in inventory JSON:\n%s", s, jsonStr)
		}
	}

	// 3. Verify the normalized endpoint URL is clean
	if len(inv.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(inv.Endpoints))
	}
	ep := inv.Endpoints[0]
	if strings.Contains(ep.NormalizedURL, sentinelPassword) || strings.Contains(ep.NormalizedURL, sentinelSecret) {
		t.Errorf("credentials leaked in NormalizedURL: %s", ep.NormalizedURL)
	}
	if strings.Contains(ep.RawQuery, sentinelSecret) {
		t.Errorf("raw secrets leaked in RawQuery: %s", ep.RawQuery)
	}
}

func TestInventory_ResourceLimits(t *testing.T) {
	ws := &Workspace{
		Dir:     t.TempDir(),
		APKPath: "C:\\path\\to\\app.apk",
		SHA256:  "sha-limits-test",
	}

	// Configure tight limits
	limits := Limits{
		MaxCompressedSize:             DefaultMaxCompressedSize,
		MaxArchiveEntries:             DefaultMaxArchiveEntries,
		MaxEntrySize:                  DefaultMaxEntrySize,
		MaxCumulativeDecompressedSize: DefaultMaxCumulativeDecompressedSize,
		MaxCompressionRatio:           DefaultMaxCompressionRatio,
		MaxPathLength:                 DefaultMaxPathLength,
		MaxPathDepth:                  DefaultMaxPathDepth,
		MaxInventoryEndpoints:         5,
		MaxInventoryHosts:             2,
		MaxProvenancePerEndpoint:      2,
	}

	var findings []report.Finding
	for i := 0; i < 20; i++ {
		u := fmt.Sprintf("https://host%d.corp.com/api/v1/item%d", i%5, i)
		findings = append(findings, report.Finding{
			ID:       fmt.Sprintf("f-%d", i),
			RuleID:   "APK-ART-API-BASE-URL",
			Endpoint: u,
			EvidenceDetails: report.EvidenceDetails{
				Details: map[string]string{
					"base_url":    u,
					"file_origin": fmt.Sprintf("classes%d.dex", i),
				},
			},
		})
	}

	res := &ArtifactAnalysisResult{Findings: findings}
	inv, err := BuildBackendInventory(context.Background(), ws, nil, res, limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify endpoints bounded by MaxInventoryEndpoints (5)
	if inv.TotalEndpoints > 5 {
		t.Errorf("expected total endpoints <= 5, got %d", inv.TotalEndpoints)
	}

	// Verify host groups bounded by MaxInventoryHosts (2)
	if inv.TotalHosts > 2 {
		t.Errorf("expected total hosts <= 2, got %d", inv.TotalHosts)
	}

	// Verify limitation recorded
	var foundLimitation bool
	for _, l := range inv.Limitations {
		if strings.Contains(l, "limit reached") {
			foundLimitation = true
		}
	}
	if !foundLimitation {
		t.Errorf("expected limitation recorded for limit truncation, got: %+v", inv.Limitations)
	}
}

func TestInventory_EndToEndSyntheticAPK(t *testing.T) {
	tmpDir := t.TempDir()
	apkPath := filepath.Join(tmpDir, "inventory_test.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatalf("failed to create apk file: %v", err)
	}
	zw := zip.NewWriter(f)

	// AndroidManifest.xml with Deep Link intent filter
	manifestContent := `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.felix.invtest">
    <application>
        <activity android:name=".DeepLinkActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <category android:name="android.intent.category.BROWSABLE"/>
                <data android:scheme="https" android:host="app.example.com" android:pathPrefix="/deep/link"/>
            </intent-filter>
        </activity>
    </application>
</manifest>`

	mw, _ := zw.Create("AndroidManifest.xml")
	mw.Write([]byte(manifestContent))

	// classes.dex
	cw, _ := zw.Create("classes.dex")
	cw.Write([]byte("dex-dummy-code"))

	// google-services.json
	gw, _ := zw.Create("res/raw/google-services.json")
	gw.Write([]byte(`{
		"project_info": {
			"project_id": "inv-firebase-proj",
			"storage_bucket": "inv-bucket.appspot.com",
			"firebase_url": "https://inv-firebase-proj.firebaseio.com"
		}
	}`))

	_ = zw.Close()
	_ = f.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	intakeRes, err := Intake(ctx, apkPath, IntakeOptions{
		Limits:  DefaultLimits(),
		Extract: true,
	})
	if err != nil {
		t.Fatalf("Intake failed: %v", err)
	}
	defer intakeRes.Workspace.Close()

	limits := DefaultLimits()
	manifestRes, err := AnalyzeManifest(ctx, intakeRes.Workspace, limits)
	if err != nil {
		t.Fatalf("AnalyzeManifest failed: %v", err)
	}

	artifactRes, err := AnalyzeArtifacts(ctx, intakeRes.Workspace, limits)
	if err != nil {
		t.Fatalf("AnalyzeArtifacts failed: %v", err)
	}

	inv, err := BuildBackendInventory(ctx, intakeRes.Workspace, manifestRes, artifactRes, limits)
	if err != nil {
		t.Fatalf("BuildBackendInventory failed: %v", err)
	}

	if inv.TotalEndpoints == 0 {
		t.Fatalf("expected at least 1 discovered endpoint in end-to-end APK")
	}

	var foundDeepLink, foundFirebase bool
	for _, ep := range inv.Endpoints {
		if strings.Contains(ep.NormalizedURL, "app.example.com/deep/link") {
			foundDeepLink = true
			if ep.Category != CategoryDeepLink {
				t.Errorf("expected CategoryDeepLink, got: %s", ep.Category)
			}
			if ep.Classification != ClassificationConfirmedReference {
				t.Errorf("expected ConfirmedReference for deep link, got: %s", ep.Classification)
			}
		}
		if strings.Contains(ep.NormalizedURL, "inv-firebase-proj.firebaseio.com") {
			foundFirebase = true
			if ep.Category != CategoryFirebase {
				t.Errorf("expected CategoryFirebase, got: %s", ep.Category)
			}
		}
	}

	if !foundDeepLink {
		t.Errorf("expected manifest deep link endpoint in inventory")
	}
	if !foundFirebase {
		t.Errorf("expected Firebase backend endpoint in inventory")
	}
}

func TestInventory_Regression_URLSemantics(t *testing.T) {
	// 1. /api//v1 versus /api/v1 (duplicate slashes collapsed)
	normDoubleSlash, err := NormalizeEndpoint("https://api.example.com/api//v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	normSingleSlash, err := NormalizeEndpoint("https://api.example.com/api/v1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if normDoubleSlash.NormalizedURL != normSingleSlash.NormalizedURL {
		t.Errorf("expected /api//v1 to normalize to /api/v1, got %q vs %q", normDoubleSlash.NormalizedURL, normSingleSlash.NormalizedURL)
	}

	// 2. /a/../b versus /b (dot segment resolution)
	normDotDot, err := NormalizeEndpoint("https://api.example.com/a/../b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	normB, err := NormalizeEndpoint("https://api.example.com/b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if normDotDot.NormalizedURL != normB.NormalizedURL {
		t.Errorf("expected /a/../b to normalize to /b, got %q vs %q", normDotDot.NormalizedURL, normB.NormalizedURL)
	}

	// 3. /path versus /path/ (distinct endpoints: trailing slash preserved)
	normNoSlash, err := NormalizeEndpoint("https://api.example.com/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	normWithSlash, err := NormalizeEndpoint("https://api.example.com/path/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if normNoSlash.NormalizedURL == normWithSlash.NormalizedURL {
		t.Errorf("expected /path and /path/ to remain distinct endpoints, but both got %q", normNoSlash.NormalizedURL)
	}
	if normNoSlash.Path != "/path" || normWithSlash.Path != "/path/" {
		t.Errorf("paths not properly preserved: %q vs %q", normNoSlash.Path, normWithSlash.Path)
	}

	// 4. Repeated query keys with different ordering (value order preserved)
	normRepeatedBA, err := NormalizeEndpoint("https://api.example.com/items?tag=beta&tag=alpha")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	normRepeatedAB, err := NormalizeEndpoint("https://api.example.com/items?tag=alpha&tag=beta")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if normRepeatedBA.NormalizedURL == normRepeatedAB.NormalizedURL {
		t.Errorf("repeated query parameter values with different order should remain distinct, but both got: %s", normRepeatedBA.NormalizedURL)
	}
	if !strings.Contains(normRepeatedBA.NormalizedURL, "tag=beta&tag=alpha") {
		t.Errorf("expected tag=beta&tag=alpha preserved in order, got: %s", normRepeatedBA.NormalizedURL)
	}
	if !strings.Contains(normRepeatedAB.NormalizedURL, "tag=alpha&tag=beta") {
		t.Errorf("expected tag=alpha&tag=beta preserved in order, got: %s", normRepeatedAB.NormalizedURL)
	}

	// 5. Query parameters whose multiplicity affects semantics
	normSingleParam, err := NormalizeEndpoint("https://api.example.com/items?id=1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	normDuplicateParam, err := NormalizeEndpoint("https://api.example.com/items?id=1&id=1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if normSingleParam.NormalizedURL == normDuplicateParam.NormalizedURL {
		t.Errorf("expected ?id=1 and ?id=1&id=1 to remain distinct due to multiplicity, but both got %q", normSingleParam.NormalizedURL)
	}

	// 6. Percent-encoded reserved characters: %2F versus /
	normEncodedSlash, err := NormalizeEndpoint("https://api.example.com/a%2Fb")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	normLiteralSlash, err := NormalizeEndpoint("https://api.example.com/a/b")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if normEncodedSlash.NormalizedURL == normLiteralSlash.NormalizedURL {
		t.Errorf("expected /a%%2Fb and /a/b to remain distinct, but both got %q", normEncodedSlash.NormalizedURL)
	}
	if normEncodedSlash.Path != "/a%2Fb" {
		t.Errorf("expected percent-encoded %%2F preserved in path, got %q", normEncodedSlash.Path)
	}

	// 7. Default and non-default ports across all supported schemes
	schemePorts := []struct {
		scheme      string
		defaultPort int
		altPort     int
	}{
		{"http", 80, 8080},
		{"https", 443, 8443},
		{"ws", 80, 8080},
		{"wss", 443, 8443},
		{"redis", 6379, 6380},
		{"rediss", 6380, 6381},
		{"postgres", 5432, 5433},
		{"mysql", 3306, 3307},
		{"mongodb", 27017, 27018},
		{"mongodb+srv", 27017, 27018},
	}

	for _, sp := range schemePorts {
		// Default port stripped
		defURL := fmt.Sprintf("%s://srv.corp.internal:%d/db", sp.scheme, sp.defaultPort)
		normDef, err := NormalizeEndpoint(defURL)
		if err != nil {
			t.Fatalf("failed normalizing %s: %v", defURL, err)
		}
		if strings.Contains(normDef.NormalizedURL, fmt.Sprintf(":%d", sp.defaultPort)) {
			t.Errorf("scheme %s default port %d should be stripped, got: %s", sp.scheme, sp.defaultPort, normDef.NormalizedURL)
		}
		if normDef.Port != sp.defaultPort {
			t.Errorf("scheme %s effective port mismatch: got %d, want %d", sp.scheme, normDef.Port, sp.defaultPort)
		}

		// Non-default port preserved
		altURL := fmt.Sprintf("%s://srv.corp.internal:%d/db", sp.scheme, sp.altPort)
		normAlt, err := NormalizeEndpoint(altURL)
		if err != nil {
			t.Fatalf("failed normalizing %s: %v", altURL, err)
		}
		if !strings.Contains(normAlt.NormalizedURL, fmt.Sprintf(":%d", sp.altPort)) {
			t.Errorf("scheme %s non-default port %d should be preserved, got: %s", sp.scheme, sp.altPort, normAlt.NormalizedURL)
		}
		if normAlt.Port != sp.altPort {
			t.Errorf("scheme %s alt port mismatch: got %d, want %d", sp.scheme, normAlt.Port, sp.altPort)
		}
	}
}

func TestInventory_Regression_InferenceCorrectness(t *testing.T) {
	ws := &Workspace{
		Dir:     t.TempDir(),
		APKPath: "C:\\path\\to\\app.apk",
		SHA256:  "sha-inference-audit",
	}
	limits := DefaultLimits()

	// Scenario 1: One API URL and one unrelated telemetry URL
	// Relative route MUST combine with the API URL, NOT telemetry, and NOT falsely marked ambiguous!
	t.Run("API_URL_and_Unrelated_Telemetry_URL", func(t *testing.T) {
		res := &ArtifactAnalysisResult{
			Findings: []report.Finding{
				{
					ID:       "f-api",
					RuleID:   "APK-ART-API-BASE-URL",
					Endpoint: "https://api.mycorp.com",
					EvidenceDetails: report.EvidenceDetails{
						Details: map[string]string{"base_url": "https://api.mycorp.com", "file_origin": "classes.dex"},
					},
				},
				{
					ID:       "f-telemetry",
					RuleID:   "APK-ART-API-BASE-URL",
					Endpoint: "https://telemetry.analytics-cloud.com",
					EvidenceDetails: report.EvidenceDetails{
						Details: map[string]string{"base_url": "https://telemetry.analytics-cloud.com", "file_origin": "classes.dex"},
					},
				},
				{
					ID:       "f-route",
					RuleID:   "APK-ART-API-ENDPOINT",
					Endpoint: "/api/v1/orders",
					EvidenceDetails: report.EvidenceDetails{
						Details: map[string]string{"route": "/api/v1/orders", "file_origin": "classes.dex"},
					},
				},
			},
		}

		inv, err := BuildBackendInventory(context.Background(), ws, nil, res, limits)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var foundInferredAPI bool
		for _, ep := range inv.Endpoints {
			if ep.NormalizedURL == "https://api.mycorp.com/api/v1/orders" {
				foundInferredAPI = true
				if ep.Classification != ClassificationInferredRoute {
					t.Errorf("expected ClassificationInferredRoute, got: %s", ep.Classification)
				}
				if ep.Confidence != report.ConfidenceMedium {
					t.Errorf("expected ConfidenceMedium, got: %s", ep.Confidence)
				}
				if ep.InferredDetails == nil || ep.InferredDetails.BaseURL != "https://api.mycorp.com" {
					t.Errorf("expected InferredDetails base URL https://api.mycorp.com, got: %+v", ep.InferredDetails)
				}
			}
			// Verify route was NEVER combined with telemetry
			if strings.Contains(ep.NormalizedURL, "telemetry.analytics-cloud.com/api/v1/orders") {
				t.Fatalf("SECURITY/SEMANTIC DEFECT: API route was erroneously combined with telemetry vendor: %s", ep.NormalizedURL)
			}
		}
		if !foundInferredAPI {
			t.Fatalf("expected route /api/v1/orders combined with unique API base URL https://api.mycorp.com")
		}
	})

	// Scenario 2: Authentication and API URLs together
	// API routes pair with API URL; Auth routes pair with Auth URL
	t.Run("Authentication_and_API_URLs_Together", func(t *testing.T) {
		res := &ArtifactAnalysisResult{
			Findings: []report.Finding{
				{
					ID:       "f-api",
					RuleID:   "APK-ART-API-BASE-URL",
					Endpoint: "https://api.mycorp.com",
					EvidenceDetails: report.EvidenceDetails{
						Details: map[string]string{"base_url": "https://api.mycorp.com", "file_origin": "classes.dex"},
					},
				},
				{
					ID:       "f-auth",
					RuleID:   "APK-ART-API-BASE-URL",
					Endpoint: "https://auth.mycorp.com",
					EvidenceDetails: report.EvidenceDetails{
						Details: map[string]string{"base_url": "https://auth.mycorp.com", "file_origin": "classes.dex"},
					},
				},
				{
					ID:       "f-api-route",
					RuleID:   "APK-ART-API-ENDPOINT",
					Endpoint: "/api/v1/users",
					EvidenceDetails: report.EvidenceDetails{
						Details: map[string]string{"route": "/api/v1/users", "file_origin": "classes.dex"},
					},
				},
				{
					ID:       "f-auth-route",
					RuleID:   "APK-ART-API-ENDPOINT",
					Endpoint: "/oauth/token",
					EvidenceDetails: report.EvidenceDetails{
						Details: map[string]string{"route": "/oauth/token", "file_origin": "classes.dex"},
					},
				},
			},
		}

		inv, err := BuildBackendInventory(context.Background(), ws, nil, res, limits)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var foundAPIRoute, foundAuthRoute bool
		for _, ep := range inv.Endpoints {
			if ep.NormalizedURL == "https://api.mycorp.com/api/v1/users" {
				foundAPIRoute = true
				if ep.Classification != ClassificationInferredRoute {
					t.Errorf("expected InferredRoute for API route, got: %s", ep.Classification)
				}
			}
			if ep.NormalizedURL == "https://auth.mycorp.com/oauth/token" {
				foundAuthRoute = true
				if ep.Classification != ClassificationInferredRoute {
					t.Errorf("expected InferredRoute for Auth route, got: %s", ep.Classification)
				}
				if ep.Category != CategoryAuthentication {
					t.Errorf("expected CategoryAuthentication, got: %s", ep.Category)
				}
			}
		}

		if !foundAPIRoute {
			t.Errorf("expected API route https://api.mycorp.com/api/v1/users")
		}
		if !foundAuthRoute {
			t.Errorf("expected Auth route https://auth.mycorp.com/oauth/token")
		}
	})

	// Scenario 3: Multiple API base URLs -> routes remain unresolved (no fabricated URLs)
	t.Run("Multiple_API_Base_URLs_Unresolved", func(t *testing.T) {
		res := &ArtifactAnalysisResult{
			Findings: []report.Finding{
				{
					ID:       "f-api1",
					RuleID:   "APK-ART-API-BASE-URL",
					Endpoint: "https://api-east.mycorp.com",
					EvidenceDetails: report.EvidenceDetails{
						Details: map[string]string{"base_url": "https://api-east.mycorp.com", "file_origin": "classes.dex"},
					},
				},
				{
					ID:       "f-api2",
					RuleID:   "APK-ART-API-BASE-URL",
					Endpoint: "https://api-west.mycorp.com",
					EvidenceDetails: report.EvidenceDetails{
						Details: map[string]string{"base_url": "https://api-west.mycorp.com", "file_origin": "classes.dex"},
					},
				},
				{
					ID:       "f-route",
					RuleID:   "APK-ART-API-ENDPOINT",
					Endpoint: "/api/v1/products",
					EvidenceDetails: report.EvidenceDetails{
						Details: map[string]string{"route": "/api/v1/products", "file_origin": "classes.dex"},
					},
				},
			},
		}

		inv, err := BuildBackendInventory(context.Background(), ws, nil, res, limits)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var foundUnresolved bool
		for _, ep := range inv.Endpoints {
			if ep.NormalizedURL == "/api/v1/products" {
				foundUnresolved = true
				if ep.HostIdentity != "(unresolved)" {
					t.Errorf("expected HostIdentity (unresolved), got: %s", ep.HostIdentity)
				}
				if ep.Classification != ClassificationInferredRoute {
					t.Errorf("expected ClassificationInferredRoute, got: %s", ep.Classification)
				}
				if ep.Confidence != report.ConfidenceLow {
					t.Errorf("expected ConfidenceLow, got: %s", ep.Confidence)
				}
				if !strings.Contains(ep.InferredDetails.Reason, "ambiguous") {
					t.Errorf("expected ambiguous reason, got: %s", ep.InferredDetails.Reason)
				}
			}
		}
		if !foundUnresolved {
			t.Fatalf("expected route /api/v1/products to remain unresolved when multiple API bases exist")
		}
	})

	// Scenario 4: No absolute base URL -> routes and GraphQL remain unresolved
	t.Run("No_Absolute_Base_URL", func(t *testing.T) {
		res := &ArtifactAnalysisResult{
			Findings: []report.Finding{
				{
					ID:       "f-route",
					RuleID:   "APK-ART-API-ENDPOINT",
					Endpoint: "/api/v1/checkout",
					EvidenceDetails: report.EvidenceDetails{
						Details: map[string]string{"route": "/api/v1/checkout", "file_origin": "classes.dex"},
					},
				},
				{
					ID:       "f-gql",
					RuleID:   "APK-ART-GRAPHQL",
					Endpoint: "/graphql",
					EvidenceDetails: report.EvidenceDetails{
						Details: map[string]string{"reference": "/graphql", "file_origin": "classes.dex"},
					},
				},
			},
		}

		inv, err := BuildBackendInventory(context.Background(), ws, nil, res, limits)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, ep := range inv.Endpoints {
			if ep.HostIdentity != "(unresolved)" {
				t.Errorf("endpoint %s should have HostIdentity (unresolved), got %s", ep.NormalizedURL, ep.HostIdentity)
			}
			if ep.Classification != ClassificationInferredRoute {
				t.Errorf("expected InferredRoute, got: %s", ep.Classification)
			}
			if ep.Confidence != report.ConfidenceLow {
				t.Errorf("expected ConfidenceLow, got: %s", ep.Confidence)
			}
		}
	})

	// Scenario 5: Firebase and Cloud Storage URLs -> routes MUST NOT be combined with them
	t.Run("Firebase_and_CloudStorage_URLs_Not_Combined", func(t *testing.T) {
		res := &ArtifactAnalysisResult{
			Findings: []report.Finding{
				{
					ID:       "f-fb",
					RuleID:   "APK-ART-SERVICE-FIREBASE",
					Endpoint: "https://app-firebase.firebaseio.com",
					EvidenceDetails: report.EvidenceDetails{
						Details: map[string]string{"firebase_url": "https://app-firebase.firebaseio.com", "file_origin": "google-services.json"},
					},
				},
				{
					ID:       "f-s3",
					RuleID:   "APK-ART-SERVICE-AWS",
					Endpoint: "https://my-bucket.s3.amazonaws.com",
					EvidenceDetails: report.EvidenceDetails{
						Details: map[string]string{"bucket_host": "my-bucket.s3.amazonaws.com", "file_origin": "classes.dex"},
					},
				},
				{
					ID:       "f-route",
					RuleID:   "APK-ART-API-ENDPOINT",
					Endpoint: "/api/v1/items",
					EvidenceDetails: report.EvidenceDetails{
						Details: map[string]string{"route": "/api/v1/items", "file_origin": "classes.dex"},
					},
				},
			},
		}

		inv, err := BuildBackendInventory(context.Background(), ws, nil, res, limits)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		for _, ep := range inv.Endpoints {
			// Verify route /api/v1/items was NEVER combined with Firebase or S3!
			if strings.Contains(ep.NormalizedURL, "firebaseio.com/api/v1/items") {
				t.Fatalf("SECURITY/SEMANTIC DEFECT: API route was combined with Firebase URL: %s", ep.NormalizedURL)
			}
			if strings.Contains(ep.NormalizedURL, "amazonaws.com/api/v1/items") {
				t.Fatalf("SECURITY/SEMANTIC DEFECT: API route was combined with S3 URL: %s", ep.NormalizedURL)
			}
		}

		// Ensure the route was retained as unresolved
		var foundUnresolved bool
		for _, ep := range inv.Endpoints {
			if ep.NormalizedURL == "/api/v1/items" && ep.HostIdentity == "(unresolved)" {
				foundUnresolved = true
			}
		}
		if !foundUnresolved {
			t.Fatalf("expected route /api/v1/items to be retained as unresolved")
		}
	})
}

func TestInventory_Regression_DeduplicationAndProvenanceIntegrity(t *testing.T) {
	ws := &Workspace{
		Dir:     t.TempDir(),
		APKPath: "C:\\path\\to\\app.apk",
		SHA256:  "sha-provenance-audit-12345",
	}
	limits := DefaultLimits()

	// Same endpoint discovered from 3 distinct sources: Manifest, DEX bytecode, and Config
	res := &ArtifactAnalysisResult{
		Findings: []report.Finding{
			{
				ID:       "f-dex",
				RuleID:   "APK-ART-API-BASE-URL",
				Endpoint: "https://api.mycorp.com/v1/sync",
				Evidence: "DEX string reference",
				EvidenceDetails: report.EvidenceDetails{
					Location: "classes.dex:0x1234",
					Details: map[string]string{
						"base_url":    "https://api.mycorp.com/v1/sync",
						"file_origin": "classes.dex",
					},
				},
				Confidence: report.ConfidenceHigh,
			},
			{
				ID:       "f-cfg",
				RuleID:   "APK-ART-API-BASE-URL",
				Endpoint: "https://api.mycorp.com/v1/sync",
				Evidence: "Configuration property reference",
				EvidenceDetails: report.EvidenceDetails{
					Location: "res/values/strings.xml:server_url",
					Details: map[string]string{
						"base_url":    "https://api.mycorp.com/v1/sync",
						"file_origin": "res/values/strings.xml",
					},
				},
				Confidence: report.ConfidenceHigh,
			},
		},
	}

	manifestRes := &ManifestAnalysisResult{
		Document: &ManifestDocument{
			Application: ApplicationInfo{
				Activities: []ComponentInfo{
					{
						Type: ComponentActivity,
						Name: "com.mycorp.SyncActivity",
						IntentFilters: []IntentFilterInfo{
							{
								Data: []IntentFilterData{
									{Scheme: "https", Host: "api.mycorp.com", Path: "/v1/sync"},
								},
							},
						},
					},
				},
			},
		},
	}

	inv, err := BuildBackendInventory(context.Background(), ws, manifestRes, res, limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if inv.TotalEndpoints != 1 {
		t.Fatalf("expected exactly 1 deduplicated canonical endpoint, got %d", inv.TotalEndpoints)
	}

	ep := inv.Endpoints[0]
	if len(ep.Provenance) != 3 {
		t.Fatalf("expected 3 distinct provenance records from 3 sources, got %d", len(ep.Provenance))
	}

	typesSeen := make(map[string]bool)
	for _, p := range ep.Provenance {
		typesSeen[p.ArtifactType] = true
		if p.APKSHA256 != "sha-provenance-audit-12345" {
			t.Errorf("APK SHA256 lost in provenance: %s", p.APKSHA256)
		}
	}

	if !typesSeen["dex"] || !typesSeen["resource"] || !typesSeen["manifest"] {
		t.Errorf("expected dex, resource, and manifest provenance types: %+v", typesSeen)
	}

	// Verify that sensitive value redaction cannot cause unrelated endpoints to be merged silently
	// Endpoint A: action=create (different non-sensitive parameter)
	// Endpoint B: action=delete
	normA, err := NormalizeEndpoint("https://api.mycorp.com/v1/items?action=create&apiKey=SECRET_A")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	normB, err := NormalizeEndpoint("https://api.mycorp.com/v1/items?action=delete&apiKey=SECRET_B")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if normA.NormalizedURL == normB.NormalizedURL {
		t.Fatalf("SECURITY/SEMANTIC DEFECT: Unrelated endpoints were merged due to sensitive value redaction! Both got %q", normA.NormalizedURL)
	}
	if !strings.Contains(normA.NormalizedURL, "action=create") || !strings.Contains(normB.NormalizedURL, "action=delete") {
		t.Errorf("non-sensitive query parameters were lost: %s vs %s", normA.NormalizedURL, normB.NormalizedURL)
	}
	if !strings.Contains(normA.NormalizedURL, "apiKey=[REDACTED]") || !strings.Contains(normB.NormalizedURL, "apiKey=[REDACTED]") {
		t.Errorf("sensitive apiKey was not redacted properly: %s vs %s", normA.NormalizedURL, normB.NormalizedURL)
	}
}
