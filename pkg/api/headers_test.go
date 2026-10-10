package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSecurityHeaders_GoogleLikeFixture verifies behavior when a target serves
// Content-Security-Policy-Report-Only and X-Frame-Options without an enforcing CSP.
func TestSecurityHeaders_GoogleLikeFixture(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy-Report-Only", "script-src 'nonce-abc123' 'strict-dynamic'; report-uri /csp-report")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<!doctype html><html><body>Google-like Test</body></html>"))
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{HTTPClient: ts.Client()})
	findings := AuditSecurityHeaders(context.Background(), client, ts.URL)

	var cspFinding *APIFinding
	var xfoFinding *APIFinding
	for i := range findings {
		f := &findings[i]
		if f.Category == CategoryMissingCSP {
			cspFinding = f
		}
		if f.Category == CategoryMissingXFrameOptions {
			xfoFinding = f
		}
	}

	// 1. Missing CSP finding must be present because enforcing CSP is absent
	if cspFinding == nil {
		t.Fatalf("expected CategoryMissingCSP finding for report-only target")
	}

	// 2. But evidence and description must explicitly acknowledge that Report-Only CSP was observed
	if !strings.Contains(cspFinding.Description, "Report-Only CSP detected") {
		t.Errorf("description should state Report-Only CSP detected, got: %q", cspFinding.Description)
	}
	if !strings.Contains(cspFinding.Evidence, "Content-Security-Policy-Report-Only observed") {
		t.Errorf("evidence should acknowledge Report-Only policy, got: %q", cspFinding.Evidence)
	}
	if cspFinding.Details["report_only"] != "present" || cspFinding.Details["enforcing"] != "absent" {
		t.Errorf("expected details to report report_only: present, enforcing: absent; got: %+v", cspFinding.Details)
	}

	// 3. XFO was present so missing-x-frame-options must NOT be flagged
	if xfoFinding != nil {
		t.Errorf("X-Frame-Options was present on target; must NOT flag CategoryMissingXFrameOptions")
	}
}

// TestSecurityHeaders_CSPVariants verifies all four matrix combinations of enforcing and report-only CSP.
func TestSecurityHeaders_CSPVariants(t *testing.T) {
	cases := []struct {
		name                 string
		headers              map[string]string
		expectMissingCSP     bool
		expectReportOnlyNote bool
		expectWeakCSP        bool
	}{
		{
			name: "Enforcing secure CSP only",
			headers: map[string]string{
				"Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-123'",
			},
			expectMissingCSP:     false,
			expectReportOnlyNote: false,
			expectWeakCSP:        false,
		},
		{
			name: "Enforcing weak CSP (unsafe-inline)",
			headers: map[string]string{
				"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
			},
			expectMissingCSP:     false,
			expectReportOnlyNote: false,
			expectWeakCSP:        true,
		},
		{
			name: "Both Enforcing and Report-Only CSP",
			headers: map[string]string{
				"Content-Security-Policy":             "default-src 'self'",
				"Content-Security-Policy-Report-Only": "default-src 'none'",
			},
			expectMissingCSP:     false,
			expectReportOnlyNote: false,
			expectWeakCSP:        false,
		},
		{
			name: "Report-Only CSP only",
			headers: map[string]string{
				"Content-Security-Policy-Report-Only": "default-src 'none'",
			},
			expectMissingCSP:     true,
			expectReportOnlyNote: true,
			expectWeakCSP:        false,
		},
		{
			name:                 "Neither Enforcing nor Report-Only CSP",
			headers:              map[string]string{},
			expectMissingCSP:     true,
			expectReportOnlyNote: false,
			expectWeakCSP:        false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tc.headers {
					w.Header().Set(k, v)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer ts.Close()

			client := NewClient(ClientOptions{HTTPClient: ts.Client()})
			findings := AuditSecurityHeaders(context.Background(), client, ts.URL)

			var hasMissingCSP, hasReportOnlyNote, hasWeakCSP bool
			for _, f := range findings {
				if f.Category == CategoryMissingCSP {
					hasMissingCSP = true
					if strings.Contains(f.Evidence, "Content-Security-Policy-Report-Only observed") {
						hasReportOnlyNote = true
					}
				}
				if f.Category == CategoryWeakCSP {
					hasWeakCSP = true
				}
			}

			if hasMissingCSP != tc.expectMissingCSP {
				t.Errorf("hasMissingCSP = %v, expected %v", hasMissingCSP, tc.expectMissingCSP)
			}
			if hasReportOnlyNote != tc.expectReportOnlyNote {
				t.Errorf("hasReportOnlyNote = %v, expected %v", hasReportOnlyNote, tc.expectReportOnlyNote)
			}
			if hasWeakCSP != tc.expectWeakCSP {
				t.Errorf("hasWeakCSP = %v, expected %v", hasWeakCSP, tc.expectWeakCSP)
			}
		})
	}
}

// TestSecurityHeaders_CaseInsensitivityAndMultiHeaders verifies case insensitivity and multiple headers.
func TestSecurityHeaders_CaseInsensitivityAndMultiHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Non-canonical header casing
		w.Header()["x-content-type-options"] = []string{"nosniff, nosniff"}
		w.Header()["referrer-policy"] = []string{"unsafe-url"}
		w.Header()["permissions-policy"] = []string{"camera=(), geolocation=()"}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{HTTPClient: ts.Client()})
	findings := AuditSecurityHeaders(context.Background(), client, ts.URL)

	var hasMissingXCTO, hasWeakReferrer, hasMissingPerm bool
	for _, f := range findings {
		if f.Category == CategoryMissingXContentType {
			hasMissingXCTO = true
		}
		if f.Category == CategoryWeakReferrerPolicy {
			hasWeakReferrer = true
		}
		if f.Category == CategoryMissingPermissions {
			hasMissingPerm = true
		}
	}

	// Since "nosniff" is present (even with multiple values and lowercase), it should NOT be flagged as missing
	if hasMissingXCTO {
		t.Errorf("X-Content-Type-Options: nosniff was present; should not be reported missing")
	}

	// "unsafe-url" should be flagged as weak referrer policy
	if !hasWeakReferrer {
		t.Errorf("expected CategoryWeakReferrerPolicy for unsafe-url")
	}

	// permissions policy was provided; should not be flagged as missing
	if hasMissingPerm {
		t.Errorf("Permissions-Policy was present; should not be reported missing")
	}
}
