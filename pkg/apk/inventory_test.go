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
