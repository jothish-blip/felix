package compliance

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 1. A valid minimal catalog is accepted.
func TestCatalogValidation_1_ValidMinimal(t *testing.T) {
	cat := &ControlCatalog{
		SchemaVersion: SchemaVersion1_0,
		ID:            "felix-baseline-minimal",
		Title:         "Minimal Baseline Catalog",
		Version:       "1.0.0",
		Controls: []Control{
			{
				ID:          "CTRL-001",
				Title:       "Access Control Policy",
				Description: "The organization must maintain an explicit access control policy.",
			},
		},
	}

	if err := ValidateCatalog(cat); err != nil {
		t.Fatalf("expected valid minimal catalog to pass validation, got: %v", err)
	}
	if cat.Identity() != "felix-baseline-minimal:1.0.0" {
		t.Errorf("unexpected identity: %s", cat.Identity())
	}
}

// 2. A valid catalog with multiple controls is accepted.
func TestCatalogValidation_2_ValidMultipleControls(t *testing.T) {
	cat := &ControlCatalog{
		SchemaVersion: SchemaVersion1_0,
		ID:            "owasp-asvs-4.0",
		Title:         "OWASP Application Security Verification Standard",
		Version:       "4.0.3",
		Framework:     "OWASP",
		Description:   "Comprehensive web application security requirements",
		Source: &CatalogSource{
			Name:            "OWASP Foundation",
			URL:             "https://owasp.org/www-project-application-security-verification-standard/",
			IsAuthoritative: false,
			Limitations:     "Standard definition catalog only; audit certification required separately.",
		},
		Controls: []Control{
			{
				ID:          "V1.1.1",
				Title:       "Architecture Verification",
				Description: "Verify that all user stories and features specify security requirements.",
				Status:      StatusActive,
				Category:    "Architecture",
				Severity:    "HIGH",
				References: []ControlReference{
					{
						Source:  "OWASP",
						URI:     "https://owasp.org/asvs",
						Section: "1.1.1",
					},
				},
				RelatedControls: []string{"V1.1.2"},
			},
			{
				ID:          "V1.1.2",
				Title:       "Security Architecture Documentation",
				Description: "Verify the availability of a high-level architecture diagram and documentation.",
				Status:      StatusActive,
				Category:    "Architecture",
				Severity:    "MEDIUM",
			},
		},
	}

	if err := ValidateCatalog(cat); err != nil {
		t.Fatalf("expected valid multi-control catalog to pass, got: %v", err)
	}
}

// 3. Missing catalog identifiers are rejected.
func TestCatalogValidation_3_MissingCatalogID(t *testing.T) {
	cat := &ControlCatalog{
		SchemaVersion: SchemaVersion1_0,
		ID:            "", // Missing
		Title:         "Untitled Catalog",
		Version:       "1.0.0",
		Controls: []Control{
			{ID: "C1", Title: "Control 1", Description: "Description 1"},
		},
	}

	err := ValidateCatalog(cat)
	if err == nil {
		t.Fatal("expected error for missing catalog ID, got nil")
	}
	if !strings.Contains(err.Error(), "catalog identifier 'id' is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// 4. Missing catalog titles are rejected.
func TestCatalogValidation_4_MissingCatalogTitle(t *testing.T) {
	cat := &ControlCatalog{
		SchemaVersion: SchemaVersion1_0,
		ID:            "cat-test",
		Title:         "   ", // Whitespace/empty
		Version:       "1.0.0",
		Controls: []Control{
			{ID: "C1", Title: "Control 1", Description: "Description 1"},
		},
	}

	err := ValidateCatalog(cat)
	if err == nil {
		t.Fatal("expected error for missing catalog title, got nil")
	}
	if !strings.Contains(err.Error(), "catalog 'title' is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// 5. Unsupported schema versions are rejected.
func TestCatalogValidation_5_UnsupportedSchemaVersion(t *testing.T) {
	unsupportedVersions := []string{"2.0", "0.9", "v1", "custom-schema"}
	for _, v := range unsupportedVersions {
		cat := &ControlCatalog{
			SchemaVersion: v,
			ID:            "cat-test",
			Title:         "Test Catalog",
			Version:       "1.0.0",
			Controls: []Control{
				{ID: "C1", Title: "Control 1", Description: "Description 1"},
			},
		}

		err := ValidateCatalog(cat)
		if err == nil {
			t.Fatalf("expected rejection for unsupported schema_version %q, got nil", v)
		}
		if !strings.Contains(err.Error(), "unsupported schema_version") {
			t.Errorf("expected unsupported schema_version error for %q, got: %v", v, err)
		}
	}
}

// 6. Malformed JSON is rejected.
func TestCatalogValidation_6_MalformedJSON(t *testing.T) {
	malformedInputs := [][]byte{
		[]byte(`{ "schema_version": "1.0", "id": "unclosed"`),
		[]byte(`{ "schema_version": "1.0", "id": "test",, "title": "bad commas" }`),
		[]byte(`not json at all`),
	}

	for i, raw := range malformedInputs {
		_, err := LoadCatalogFromBytes(raw)
		if err == nil {
			t.Fatalf("case %d: expected error on malformed JSON, got nil", i)
		}
		if !strings.Contains(err.Error(), "malformed") && !strings.Contains(err.Error(), "JSON") {
			t.Errorf("case %d: unexpected error message: %v", i, err)
		}
	}
}

// 7. Missing control IDs are rejected.
func TestCatalogValidation_7_MissingControlID(t *testing.T) {
	cat := &ControlCatalog{
		SchemaVersion: SchemaVersion1_0,
		ID:            "cat-test",
		Title:         "Test Catalog",
		Version:       "1.0.0",
		Controls: []Control{
			{ID: "", Title: "Control Without ID", Description: "Some description"},
		},
	}

	err := ValidateCatalog(cat)
	if err == nil {
		t.Fatal("expected error on missing control ID, got nil")
	}
	if !strings.Contains(err.Error(), "control 'id' is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// 8. Duplicate control IDs are rejected deterministically.
func TestCatalogValidation_8_DuplicateControlID(t *testing.T) {
	cat := &ControlCatalog{
		SchemaVersion: SchemaVersion1_0,
		ID:            "cat-duplicate-test",
		Title:         "Duplicate Test Catalog",
		Version:       "1.0.0",
		Controls: []Control{
			{ID: "AC-1", Title: "Access Control Policy", Description: "Policy statement"},
			{ID: "AC-2", Title: "Account Management", Description: "Account statement"},
			{ID: "ac-1", Title: "Duplicate of AC-1", Description: "Conflicting statement"},
		},
	}

	err := ValidateCatalog(cat)
	if err == nil {
		t.Fatal("expected error for duplicate control ID, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate control identifier") {
		t.Errorf("expected duplicate identifier error, got: %v", err)
	}
}

// 9. Missing required control titles are rejected.
func TestCatalogValidation_9_MissingControlTitle(t *testing.T) {
	cat := &ControlCatalog{
		SchemaVersion: SchemaVersion1_0,
		ID:            "cat-test",
		Title:         "Test Catalog",
		Version:       "1.0.0",
		Controls: []Control{
			{ID: "C1", Title: "   ", Description: "Valid description"},
		},
	}

	err := ValidateCatalog(cat)
	if err == nil {
		t.Fatal("expected error on missing control title, got nil")
	}
	if !strings.Contains(err.Error(), "control 'title' is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// 10. Missing required requirement descriptions are rejected.
func TestCatalogValidation_10_MissingControlDescription(t *testing.T) {
	cat := &ControlCatalog{
		SchemaVersion: SchemaVersion1_0,
		ID:            "cat-test",
		Title:         "Test Catalog",
		Version:       "1.0.0",
		Controls: []Control{
			{ID: "C1", Title: "Valid Title", Description: ""},
		},
	}

	err := ValidateCatalog(cat)
	if err == nil {
		t.Fatal("expected error on missing control description, got nil")
	}
	if !strings.Contains(err.Error(), "control 'description' is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// 11. Invalid references are rejected where reference validation applies.
func TestCatalogValidation_11_InvalidReferences(t *testing.T) {
	// a. Invalid URI
	catBadURI := &ControlCatalog{
		SchemaVersion: SchemaVersion1_0,
		ID:            "cat-ref-test",
		Title:         "Reference Test",
		Version:       "1.0.0",
		Controls: []Control{
			{
				ID:          "C1",
				Title:       "Control 1",
				Description: "Desc",
				References: []ControlReference{
					{Source: "Ref", URI: "://invalid uri with spaces"},
				},
			},
		},
	}
	errURI := ValidateCatalog(catBadURI)
	if errURI == nil {
		t.Fatal("expected error on invalid reference URI, got nil")
	}
	if !strings.Contains(errURI.Error(), "invalid reference URI") {
		t.Errorf("expected invalid reference URI error, got: %v", errURI)
	}

	// b. Unresolved related control
	catBadRel := &ControlCatalog{
		SchemaVersion: SchemaVersion1_0,
		ID:            "cat-rel-test",
		Title:         "Relational Test",
		Version:       "1.0.0",
		Controls: []Control{
			{
				ID:              "C1",
				Title:           "Control 1",
				Description:     "Desc",
				RelatedControls: []string{"NON-EXISTENT-ID"},
			},
		},
	}
	errRel := ValidateCatalog(catBadRel)
	if errRel == nil {
		t.Fatal("expected error on unresolved related control, got nil")
	}
	if !strings.Contains(errRel.Error(), "references non-existent related control") {
		t.Errorf("expected unresolved related control error, got: %v", errRel)
	}

	// c. Self-referential related control
	catSelfRel := &ControlCatalog{
		SchemaVersion: SchemaVersion1_0,
		ID:            "cat-self-test",
		Title:         "Self Relational Test",
		Version:       "1.0.0",
		Controls: []Control{
			{
				ID:              "C1",
				Title:           "Control 1",
				Description:     "Desc",
				RelatedControls: []string{"C1"},
			},
		},
	}
	errSelf := ValidateCatalog(catSelfRel)
	if errSelf == nil {
		t.Fatal("expected error on self-referential related control, got nil")
	}
	if !strings.Contains(errSelf.Error(), "cannot reference itself in related_controls") {
		t.Errorf("expected self reference error, got: %v", errSelf)
	}
}

// 12. Unknown security-relevant fields are handled according to documented compatibility policy.
func TestCatalogValidation_12_UnknownSecurityFields(t *testing.T) {
	// Unknown security field directly on Control object (e.g. misspelled 'securty_level')
	jsonWithUnknown := []byte(`{
		"schema_version": "1.0",
		"id": "cat-unknown-field",
		"title": "Catalog with Unknown Field",
		"version": "1.0.0",
		"controls": [
			{
				"id": "C1",
				"title": "Control 1",
				"description": "Desc 1",
				"securty_level": "critical"
			}
		]
	}`)

	_, err := LoadCatalogFromBytes(jsonWithUnknown)
	if err == nil {
		t.Fatal("expected strict decoder to reject unknown security field on control, got nil")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("expected unknown field error, got: %v", err)
	}

	// Contrast with supported metadata object: custom attributes in "metadata" MUST be accepted
	jsonWithMetadata := []byte(`{
		"schema_version": "1.0",
		"id": "cat-custom-metadata",
		"title": "Catalog with Metadata",
		"version": "1.0.0",
		"controls": [
			{
				"id": "C1",
				"title": "Control 1",
				"description": "Desc 1",
				"metadata": {
					"custom_score": 9.5,
					"audit_tier": "gold"
				}
			}
		]
	}`)
	catMeta, errMeta := LoadCatalogFromBytes(jsonWithMetadata)
	if errMeta != nil {
		t.Fatalf("expected metadata object to be accepted, got: %v", errMeta)
	}
	if catMeta.Controls[0].Metadata["audit_tier"] != "gold" {
		t.Errorf("expected metadata attribute preserved, got: %v", catMeta.Controls[0].Metadata["audit_tier"])
	}
}

// 13. Empty catalogs follow the explicitly chosen validation rule (rejected).
func TestCatalogValidation_13_EmptyCatalog(t *testing.T) {
	cat := &ControlCatalog{
		SchemaVersion: SchemaVersion1_0,
		ID:            "cat-empty",
		Title:         "Empty Catalog",
		Version:       "1.0.0",
		Controls:      []Control{}, // Zero controls
	}

	err := ValidateCatalog(cat)
	if err == nil {
		t.Fatal("expected error for empty catalog controls, got nil")
	}
	if !strings.Contains(err.Error(), "catalog must contain at least one control definition") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// 14. Unsupported lifecycle states are rejected if lifecycle states are implemented.
func TestCatalogValidation_14_UnsupportedLifecycleStates(t *testing.T) {
	invalidStates := []ControlStatus{"retired", "archived", "pending", "unknown", "experimental"}

	for _, state := range invalidStates {
		cat := &ControlCatalog{
			SchemaVersion: SchemaVersion1_0,
			ID:            "cat-test",
			Title:         "Test Catalog",
			Version:       "1.0.0",
			Controls: []Control{
				{
					ID:          "C1",
					Title:       "Control 1",
					Description: "Desc 1",
					Status:      state,
				},
			},
		}

		err := ValidateCatalog(cat)
		if err == nil {
			t.Fatalf("expected error for invalid lifecycle status %q, got nil", state)
		}
		if !strings.Contains(err.Error(), "unsupported control status") {
			t.Errorf("expected unsupported control status error for %q, got: %v", state, err)
		}
	}

	// Valid lifecycle states MUST succeed
	validStates := []ControlStatus{StatusActive, StatusDeprecated, StatusDraft, ""}
	for _, state := range validStates {
		cat := &ControlCatalog{
			SchemaVersion: SchemaVersion1_0,
			ID:            "cat-test",
			Title:         "Test Catalog",
			Version:       "1.0.0",
			Controls: []Control{
				{
					ID:          "C1",
					Title:       "Control 1",
					Description: "Desc 1",
					Status:      state,
				},
			},
		}

		if err := ValidateCatalog(cat); err != nil {
			t.Errorf("valid lifecycle status %q failed validation: %v", state, err)
		}
	}
}

// 15. Catalog identity remains stable across repeated validation.
func TestCatalogValidation_15_StableIdentity(t *testing.T) {
	cat := &ControlCatalog{
		SchemaVersion: SchemaVersion1_0,
		ID:            "nist-sp800-53",
		Title:         "NIST SP 800-53",
		Version:       "Rev5",
		Controls: []Control{
			{ID: "AC-1", Title: "Access Control", Description: "Policy requirement"},
		},
	}

	for i := 0; i < 5; i++ {
		if err := ValidateCatalog(cat); err != nil {
			t.Fatalf("validation failed on iteration %d: %v", i, err)
		}
		if cat.Identity() != "nist-sp800-53:Rev5" {
			t.Fatalf("identity shifted on iteration %d: got %s", i, cat.Identity())
		}
	}
}

// 16. Canonical content digests remain stable for equivalent inputs.
func TestCatalogValidation_16_CanonicalDigestDeterminism(t *testing.T) {
	// Catalog A: controls in order C2, C1
	catA := &ControlCatalog{
		SchemaVersion: SchemaVersion1_0,
		ID:            "cis-v8",
		Title:         "CIS Critical Security Controls",
		Version:       "8.0",
		Controls: []Control{
			{ID: "CIS-2", Title: "Inventory and Control of Software", Description: "Software inventory desc"},
			{ID: "CIS-1", Title: "Inventory and Control of Hardware", Description: "Hardware inventory desc"},
		},
		Metadata: map[string]any{"tier": "enterprise", "scope": "it"},
	}

	// Catalog B: identical content, but controls in reverse order (C1, C2) and metadata keys created in different order
	catB := &ControlCatalog{
		SchemaVersion: SchemaVersion1_0,
		ID:            "cis-v8",
		Title:         "CIS Critical Security Controls",
		Version:       "8.0",
		Controls: []Control{
			{ID: "CIS-1", Title: "Inventory and Control of Hardware", Description: "Hardware inventory desc"},
			{ID: "CIS-2", Title: "Inventory and Control of Software", Description: "Software inventory desc"},
		},
		Metadata: map[string]any{"scope": "it", "tier": "enterprise"},
	}

	digestA := catA.Digest()
	digestB := catB.Digest()

	if digestA == "" || digestB == "" {
		t.Fatal("expected non-empty digests")
	}
	if !strings.HasPrefix(digestA, "sha256:") {
		t.Fatalf("expected sha256: prefix, got: %s", digestA)
	}
	if digestA != digestB {
		t.Fatalf("digest mismatch for equivalent catalogs:\n  A: %s\n  B: %s", digestA, digestB)
	}
}

// 17. Changes to security-relevant content change the digest.
func TestCatalogValidation_17_DigestSensitivity(t *testing.T) {
	base := &ControlCatalog{
		SchemaVersion: SchemaVersion1_0,
		ID:            "pci-dss-4.0",
		Title:         "PCI DSS",
		Version:       "4.0",
		Controls: []Control{
			{
				ID:          "Req-1.1",
				Title:       "Network Security Controls",
				Description: "Install and maintain network security controls.",
				Status:      StatusActive,
				Severity:    "HIGH",
			},
		},
	}
	baseDigest := base.Digest()

	// Sub-case 1: Changed description
	mutatedDesc := *base
	mutatedDesc.Controls = []Control{
		{
			ID:          "Req-1.1",
			Title:       "Network Security Controls",
			Description: "Install, configure, and actively audit firewall rules.", // modified statement
			Status:      StatusActive,
			Severity:    "HIGH",
		},
	}
	if mutatedDesc.Digest() == baseDigest {
		t.Error("digest failed to change when requirement description was modified")
	}

	// Sub-case 2: Changed lifecycle status
	mutatedStatus := *base
	mutatedStatus.Controls = []Control{
		{
			ID:          "Req-1.1",
			Title:       "Network Security Controls",
			Description: "Install and maintain network security controls.",
			Status:      StatusDeprecated, // deprecated
			Severity:    "HIGH",
		},
	}
	if mutatedStatus.Digest() == baseDigest {
		t.Error("digest failed to change when control status was modified")
	}

	// Sub-case 3: Changed severity
	mutatedSev := *base
	mutatedSev.Controls = []Control{
		{
			ID:          "Req-1.1",
			Title:       "Network Security Controls",
			Description: "Install and maintain network security controls.",
			Status:      StatusActive,
			Severity:    "CRITICAL", // changed from HIGH to CRITICAL
		},
	}
	if mutatedSev.Digest() == baseDigest {
		t.Error("digest failed to change when severity was modified")
	}
}

// 18. Invalid inputs never cause panics.
func TestCatalogValidation_18_PanicSafety(t *testing.T) {
	invalidCases := [][]byte{
		nil,
		{},
		[]byte(""),
		[]byte("{"),
		[]byte("}"),
		[]byte("null"),
		[]byte("12345"),
		[]byte(`{"schema_version": null}`),
		[]byte(`{"controls": [null, {}]}`),
		[]byte(`{"controls": [{"id": null}]}`),
	}

	for i, c := range invalidCases {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("case %d panicked: %v", i, r)
			}
		}()

		_, _ = LoadCatalogFromBytes(c)
	}

	// Nil catalog validation must not panic
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil catalog validation panicked: %v", r)
		}
	}()
	_ = ValidateCatalog(nil)
}

// 19. Oversized or excessively nested inputs are rejected where limits are implemented.
func TestCatalogValidation_19_OversizedAndDeeplyNested(t *testing.T) {
	// a. Oversized payload (> 10MB)
	oversized := make([]byte, MaxCatalogSizeBytes+1024)
	copy(oversized, []byte(`{"schema_version":"1.0","id":"big","title":"Big","version":"1","controls":[{"id":"C1","title":"T","description":"`))
	oversized[len(oversized)-2] = '"'
	oversized[len(oversized)-1] = '}'

	_, errLarge := LoadCatalogFromBytes(oversized)
	if errLarge == nil {
		t.Fatal("expected error on oversized catalog payload, got nil")
	}
	if !strings.Contains(errLarge.Error(), "exceeds maximum") {
		t.Errorf("expected maximum size error, got: %v", errLarge)
	}

	// b. Deeply nested JSON (> MaxNestingDepth of 32)
	var nestedBuf bytes.Buffer
	for i := 0; i < 40; i++ {
		nestedBuf.WriteString(`{"nested":`)
	}
	nestedBuf.WriteString(`"deep"`)
	for i := 0; i < 40; i++ {
		nestedBuf.WriteString(`}`)
	}

	_, errDeep := LoadCatalogFromBytes(nestedBuf.Bytes())
	if errDeep == nil {
		t.Fatal("expected error on deeply nested JSON, got nil")
	}
	if !strings.Contains(errDeep.Error(), "maximum allowed nesting depth") {
		t.Errorf("expected nesting depth error, got: %v", errDeep)
	}
}

// 20. Older supported catalog versions remain compatible according to the chosen schema policy.
func TestCatalogValidation_20_BackwardCompatibility(t *testing.T) {
	supportedVersions := []string{SchemaVersion1_0, SchemaVersion1_0_0, SchemaVersion1}

	for _, v := range supportedVersions {
		jsonPayload := fmt.Sprintf(`{
			"schema_version": %q,
			"id": "felix-compat-catalog",
			"title": "Compatibility Verification Catalog",
			"version": "1.0.0",
			"controls": [
				{
					"id": "COMPAT-1",
					"title": "Backward Compatibility Check",
					"description": "Verifies that schema version %s is fully accepted."
				}
			]
		}`, v, v)

		cat, err := LoadCatalogFromBytes([]byte(jsonPayload))
		if err != nil {
			t.Errorf("failed to load catalog with supported version %q: %v", v, err)
			continue
		}
		if cat.SchemaVersion != v {
			t.Errorf("expected schema_version %q, got: %q", v, cat.SchemaVersion)
		}
	}
}

// Supplementary: Test file loading and duplicate object keys
func TestCatalogValidation_DuplicateObjectKeys(t *testing.T) {
	jsonDup := []byte(`{
		"schema_version": "1.0",
		"id": "cat-dup-key",
		"title": "First Title",
		"title": "Second Title",
		"version": "1.0.0",
		"controls": [
			{"id": "C1", "title": "T1", "description": "D1"}
		]
	}`)

	_, err := LoadCatalogFromBytes(jsonDup)
	if err == nil {
		t.Fatal("expected error on duplicate JSON key 'title', got nil")
	}
	if !strings.Contains(err.Error(), "ambiguous duplicate object key") {
		t.Errorf("expected duplicate object key error, got: %v", err)
	}
}

func TestCatalogValidation_FileLoading(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "catalog.json")

	validJSON := `{
		"schema_version": "1.0",
		"id": "file-catalog",
		"title": "File Loaded Catalog",
		"version": "1.2.0",
		"controls": [
			{
				"id": "FILE-01",
				"title": "File Loading Test",
				"description": "Tests loading directly from a file path."
			}
		]
	}`

	if err := os.WriteFile(filePath, []byte(validJSON), 0644); err != nil {
		t.Fatalf("failed writing test catalog file: %v", err)
	}

	cat, err := LoadCatalog(filePath)
	if err != nil {
		t.Fatalf("LoadCatalog failed: %v", err)
	}
	if cat.ID != "file-catalog" || cat.Version != "1.2.0" {
		t.Errorf("unexpected catalog loaded from file: %+v", cat)
	}

	// Test non-existent file
	_, errMissing := LoadCatalog(filepath.Join(tmpDir, "non_existent.json"))
	if errMissing == nil {
		t.Fatal("expected error for non-existent file path, got nil")
	}
}
