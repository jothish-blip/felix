package assessment

import "testing"

func TestPhase9_ScopeValidator_NormalizationAndSchemePort(t *testing.T) {
	sv := NewScopeValidator(
		"EXPLICIT_ALLOWLIST_WITH_EXCLUSIONS",
		[]string{"https://app.authorized.example:8443"},
		nil,
		[]Exclusion{
			{ExclusionType: "PATH_PREFIX", Pattern: "/admin/reset", Reason: "destructive"},
			{ExclusionType: "EXACT_URL", Pattern: "https://app.authorized.example:8443/api/danger", Reason: "dangerous"},
		},
	)

	// Path normalization bypass attempts against PATH_PREFIX exclusion
	excludedCases := []string{
		"https://app.authorized.example:8443/admin/reset",
		"https://app.authorized.example:8443/%61dmin/reset",
		"https://app.authorized.example:8443/foo/../admin/reset",
		"https://app.authorized.example:8443//admin//reset",
		`https://app.authorized.example:8443/\admin\reset`,
		"https://app.authorized.example:8443/api/foo/../danger",
	}
	for _, raw := range excludedCases {
		if excluded, _ := sv.IsExcluded(raw); !excluded {
			t.Errorf("expected IsExcluded=true for bypass candidate %q", raw)
		}
		if sv.IsAllowed(raw) {
			t.Errorf("expected IsAllowed=false for excluded bypass candidate %q", raw)
		}
	}

	// Valid in-scope path
	if !sv.IsAllowed("https://app.authorized.example:8443/api/items") {
		t.Errorf("expected in-scope origin+port URL to be allowed")
	}

	// Scheme/port mismatch must be refused in EXPLICIT_ALLOWLIST_WITH_EXCLUSIONS
	outOfScopeCases := []string{
		"http://app.authorized.example:8443/api/items",
		"https://app.authorized.example:9443/api/items",
		"https://app.authorized.example/api/items", // port 443 != 8443
		"https://other.authorized.example:8443/api/items",
	}
	for _, raw := range outOfScopeCases {
		if sv.IsAllowed(raw) {
			t.Errorf("expected out-of-scope scheme/port/host %q to be denied", raw)
		}
	}
}
