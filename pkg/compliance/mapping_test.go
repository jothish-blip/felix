package compliance

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"felix/pkg/report"
)

func sampleValidCatalog() *ControlCatalog {
	return &ControlCatalog{
		SchemaVersion: SchemaVersion1_0,
		ID:            "nist-sp800-53-r5",
		Title:         "NIST SP 800-53 Rev 5",
		Version:       "5.1.1",
		Framework:     "NIST",
		Controls: []Control{
			{
				ID:          "AC-1",
				Title:       "Policy and Procedures",
				Description: "Access control policy and procedures.",
				Status:      StatusActive,
				Category:    "Access Control",
				Severity:    "HIGH",
			},
			{
				ID:          "AC-3",
				Title:       "Access Enforcement",
				Description: "Enforce approved authorizations for logical access.",
				Status:      StatusActive,
				Category:    "Access Control",
				Severity:    "HIGH",
			},
			{
				ID:          "SI-10",
				Title:       "Information Input Validation",
				Description: "Check input for validity.",
				Status:      StatusActive,
				Category:    "System and Information Integrity",
				Severity:    "CRITICAL",
			},
			{
				ID:          "SC-7",
				Title:       "Boundary Protection",
				Description: "Monitor and control communications at external boundary.",
				Status:      StatusActive,
				Category:    "System and Communications Protection",
				Severity:    "MEDIUM",
			},
			{
				ID:          "IA-2",
				Title:       "Identification and Authentication",
				Description: "Uniquely identify and authenticate organizational users.",
				Status:      StatusActive,
				Category:    "Identification and Authentication",
				Severity:    "HIGH",
			},
		},
	}
}

func sampleValidRuleSet() *MappingRuleSet {
	return &MappingRuleSet{
		SchemaVersion:        SchemaVersion1_0,
		ID:                   "felix-to-nist-sp800-53",
		Title:                "FELIX to NIST SP 800-53 Mappings",
		Version:              "1.0.0",
		TargetCatalogID:      "nist-sp800-53-r5",
		TargetCatalogVersion: "5.1.1",
		Rules: []MappingRule{
			{
				ID:              "RULE-SQLI-SI10",
				SourceRuleID:    "WEB_SQL_INJECTION",
				SourceCategory:  "injection",
				TargetControlID: "SI-10",
				Relationship:    RelationshipDirect,
				Rationale:       "SQL injection directly indicates a failure to validate structured information inputs.",
				Confidence:      1.0,
			},
			{
				ID:              "RULE-SQLI-AC3",
				SourceRuleID:    "WEB_SQL_INJECTION",
				TargetControlID: "AC-3",
				Relationship:    RelationshipPartialEvidence,
				Rationale:       "SQL injection bypasses access control mechanisms by manipulating query logic.",
				Confidence:      0.8,
			},
			{
				ID:              "RULE-AUTH-IA2",
				SourceRuleID:    "APISPEC_NO_AUTH",
				TargetControlID: "IA-2",
				Relationship:    RelationshipDirect,
				Rationale:       "Unauthenticated API endpoints demonstrate missing user identification and authentication.",
				Confidence:      0.95,
			},
			{
				ID:              "RULE-CLOUD-AC3",
				SourceRuleID:    "AWS_S3_PUBLIC_READ",
				TargetControlID: "AC-3",
				Relationship:    RelationshipDirect,
				Rationale:       "Publicly accessible storage buckets violate mandatory access enforcement.",
				Confidence:      0.9,
			},
			{
				ID:              "RULE-CLOUD-SC7",
				SourceRuleID:    "AWS_S3_PUBLIC_READ",
				TargetControlID: "SC-7",
				Relationship:    RelationshipPartialEvidence,
				Rationale:       "Unprotected storage buckets bypass boundary protection controls.",
				Confidence:      0.85,
			},
		},
	}
}

// 1. Valid finding maps to valid control
func TestScenario1_ValidFindingMapsToValidControl(t *testing.T) {
	cat := sampleValidCatalog()
	rs := sampleValidRuleSet()

	findings := []report.Finding{
		{
			ID:          "F-001",
			RuleID:      "APISPEC_NO_AUTH",
			Category:    "auth",
			Title:       "Missing Endpoint Authentication",
			Severity:    "HIGH",
			Evidence:    "HTTP 200 OK without Authorization header",
			Endpoint:    "/api/v1/admin/users",
			Fingerprint: "fp-auth-001",
		},
	}

	res, err := MapFindings(cat, rs, findings)
	if err != nil {
		t.Fatalf("unexpected mapping error: %v", err)
	}

	if len(res.Mappings) != 1 {
		t.Fatalf("expected 1 mapping, got %d", len(res.Mappings))
	}

	m := res.Mappings[0]
	if m.FindingID != "F-001" {
		t.Errorf("expected FindingID 'F-001', got %q", m.FindingID)
	}
	if m.ControlID != "IA-2" {
		t.Errorf("expected ControlID 'IA-2', got %q", m.ControlID)
	}
	if m.CatalogID != "nist-sp800-53-r5" {
		t.Errorf("expected CatalogID 'nist-sp800-53-r5', got %q", m.CatalogID)
	}
	if m.Relationship != RelationshipDirect {
		t.Errorf("expected Relationship 'direct', got %q", m.Relationship)
	}
	if m.Confidence != 0.95 {
		t.Errorf("expected Confidence 0.95, got %v", m.Confidence)
	}
	if !m.HasEvidence {
		t.Errorf("expected HasEvidence true")
	}
	if m.EvidenceLocation != "/api/v1/admin/users" {
		t.Errorf("expected EvidenceLocation '/api/v1/admin/users', got %q", m.EvidenceLocation)
	}
	if len(res.Unmapped) != 0 {
		t.Errorf("expected 0 unmapped findings, got %d", len(res.Unmapped))
	}
}

// 2. One finding maps to multiple controls
func TestScenario2_OneFindingMapsToMultipleControls(t *testing.T) {
	cat := sampleValidCatalog()
	rs := sampleValidRuleSet()

	findings := []report.Finding{
		{
			ID:       "F-SQLI-001",
			RuleID:   "WEB_SQL_INJECTION",
			Category: "injection",
			Title:    "SQL Injection in Search Parameter",
			Severity: "CRITICAL",
			Evidence: "syntax error at or near 'admin'",
			Endpoint: "/api/search",
		},
	}

	res, err := MapFindings(cat, rs, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(res.Mappings) != 2 {
		t.Fatalf("expected 2 mappings for 1 finding, got %d", len(res.Mappings))
	}

	controls := []string{res.Mappings[0].ControlID, res.Mappings[1].ControlID}
	if !((controls[0] == "AC-3" && controls[1] == "SI-10") || (controls[0] == "SI-10" && controls[1] == "AC-3")) {
		t.Errorf("unexpected mapped controls: %v", controls)
	}

	cov := res.Coverage
	if cov.TotalFindings != 1 {
		t.Errorf("expected TotalFindings 1, got %d", cov.TotalFindings)
	}
	if cov.MappedFindings != 1 {
		t.Errorf("expected MappedFindings 1, got %d", cov.MappedFindings)
	}
	if cov.TotalMappings != 2 {
		t.Errorf("expected TotalMappings 2, got %d", cov.TotalMappings)
	}
	if cov.MultiMappedFindings != 1 {
		t.Errorf("expected MultiMappedFindings 1, got %d", cov.MultiMappedFindings)
	}
	if len(cov.ReferencedControls) != 2 {
		t.Errorf("expected 2 referenced controls, got %d", len(cov.ReferencedControls))
	}
}

// 3. Multiple findings map to one control
func TestScenario3_MultipleFindingsMapToOneControl(t *testing.T) {
	cat := sampleValidCatalog()
	rs := sampleValidRuleSet()

	findings := []report.Finding{
		{
			ID:       "F-1",
			RuleID:   "WEB_SQL_INJECTION",
			Category: "injection",
			Title:    "SQLi vulnerability",
		},
		{
			ID:       "F-2",
			RuleID:   "AWS_S3_PUBLIC_READ",
			Category: "cloud",
			Title:    "S3 Bucket World-Readable",
		},
	}

	res, err := MapFindings(cat, rs, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// F-1 maps to SI-10 & AC-3. F-2 maps to AC-3 & SC-7.
	// Both findings have a mapping to AC-3.
	ac3Mappings := 0
	for _, m := range res.Mappings {
		if m.ControlID == "AC-3" {
			ac3Mappings++
		}
	}
	if ac3Mappings != 2 {
		t.Errorf("expected 2 mappings to control AC-3, got %d", ac3Mappings)
	}
	if res.Coverage.MappedFindings != 2 {
		t.Errorf("expected MappedFindings 2, got %d", res.Coverage.MappedFindings)
	}
	if res.Coverage.UnmappedFindings != 0 {
		t.Errorf("expected UnmappedFindings 0, got %d", res.Coverage.UnmappedFindings)
	}
}

// 4. Findings from different engines (apisec, webvuln, cloudsec) use correct identifiers
func TestScenario4_FindingsFromDifferentEngines(t *testing.T) {
	cat := sampleValidCatalog()
	rs := sampleValidRuleSet()

	findings := []report.Finding{
		{
			ID:       "F-WEB",
			Source:   "webvuln",
			RuleID:   "WEB_SQL_INJECTION",
			Category: "injection",
			Severity: "CRITICAL",
			Endpoint: "https://example.com/login",
		},
		{
			ID:       "F-API",
			Source:   "apisec",
			RuleID:   "APISPEC_NO_AUTH",
			Category: "auth",
			Severity: "HIGH",
			Endpoint: "https://api.example.com/v2/orders",
		},
		{
			ID:       "F-CLOUD",
			Source:   "cloudsec",
			RuleID:   "AWS_S3_PUBLIC_READ",
			Category: "cloud",
			Severity: "MEDIUM",
			Endpoint: "s3://corp-backups",
		},
	}

	res, err := MapFindings(cat, rs, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	findingSourcesMapped := make(map[string]bool)
	for _, m := range res.Mappings {
		findingSourcesMapped[m.FindingID] = true
		if m.FindingID == "F-WEB" && m.FindingLocation != "https://example.com/login" {
			t.Errorf("expected web finding location retained, got %q", m.FindingLocation)
		}
		if m.FindingID == "F-API" && m.FindingLocation != "https://api.example.com/v2/orders" {
			t.Errorf("expected api finding location retained, got %q", m.FindingLocation)
		}
		if m.FindingID == "F-CLOUD" && m.FindingLocation != "s3://corp-backups" {
			t.Errorf("expected cloud finding location retained, got %q", m.FindingLocation)
		}
	}

	if !findingSourcesMapped["F-WEB"] || !findingSourcesMapped["F-API"] || !findingSourcesMapped["F-CLOUD"] {
		t.Errorf("expected all 3 engine finding IDs to be mapped, got %v", findingSourcesMapped)
	}
}

// 5. Unknown finding identifiers remain unmapped
func TestScenario5_UnknownFindingIdentifiersRemainUnmapped(t *testing.T) {
	cat := sampleValidCatalog()
	rs := sampleValidRuleSet()

	findings := []report.Finding{
		{
			ID:       "F-UNKNOWN-999",
			RuleID:   "ZERO_DAY_CUSTOM_CHECK",
			Category: "experimental",
			Title:    "Custom internal finding",
			Severity: "LOW",
		},
	}

	res, err := MapFindings(cat, rs, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(res.Mappings) != 0 {
		t.Errorf("expected 0 mappings for unknown finding, got %d", len(res.Mappings))
	}
	if len(res.Unmapped) != 1 {
		t.Fatalf("expected 1 unmapped finding, got %d", len(res.Unmapped))
	}

	u := res.Unmapped[0]
	if u.FindingID != "F-UNKNOWN-999" {
		t.Errorf("expected unmapped FindingID 'F-UNKNOWN-999', got %q", u.FindingID)
	}
	if u.RuleID != "ZERO_DAY_CUSTOM_CHECK" {
		t.Errorf("expected RuleID 'ZERO_DAY_CUSTOM_CHECK', got %q", u.RuleID)
	}
	if u.Reason == "" {
		t.Errorf("expected non-empty reason for unmapped finding")
	}

	if res.Coverage.TotalFindings != 1 || res.Coverage.MappedFindings != 0 || res.Coverage.UnmappedFindings != 1 {
		t.Errorf("coverage mismatch: %+v", res.Coverage)
	}
}

// 6. Unknown catalog IDs and nonexistent control IDs rejected
func TestScenario6_UnknownCatalogIDsAndNonexistentControlsRejected(t *testing.T) {
	cat := sampleValidCatalog()

	// Catalog ID mismatch
	rsMismatch := sampleValidRuleSet()
	rsMismatch.TargetCatalogID = "iso-27001-2022"
	err := ValidateMappingRuleSet(rsMismatch, cat)
	if err == nil || !strings.Contains(err.Error(), "does not match catalog ID") {
		t.Errorf("expected catalog mismatch error, got: %v", err)
	}

	// Nonexistent Control ID
	rsInvalidControl := sampleValidRuleSet()
	rsInvalidControl.Rules = append(rsInvalidControl.Rules, MappingRule{
		ID:              "RULE-INVALID-CTRL",
		SourceRuleID:    "SOME_RULE",
		TargetControlID: "ZZ-9999", // not in catalog
		Relationship:    RelationshipDirect,
		Rationale:       "Testing nonexistent control",
	})
	err = ValidateMappingRuleSet(rsInvalidControl, cat)
	if err == nil || !strings.Contains(err.Error(), "unknown target control ID") {
		t.Errorf("expected unknown target control error, got: %v", err)
	}
}

// 7. Duplicate mapping rules detected
func TestScenario7_DuplicateMappingRulesDetected(t *testing.T) {
	cat := sampleValidCatalog()

	// Duplicate Rule ID
	rsDupID := sampleValidRuleSet()
	rsDupID.Rules = append(rsDupID.Rules, MappingRule{
		ID:              "RULE-SQLI-SI10", // already exists
		SourceRuleID:    "ANOTHER_RULE",
		TargetControlID: "SI-10",
		Relationship:    RelationshipDirect,
		Rationale:       "Testing duplicate ID",
	})
	err := ValidateMappingRuleSet(rsDupID, cat)
	if err == nil || !strings.Contains(err.Error(), "duplicate rule ID") {
		t.Errorf("expected duplicate rule ID error, got: %v", err)
	}

	// Duplicate Mapping Definition (same source, target control, and relationship)
	rsDupDef := sampleValidRuleSet()
	rsDupDef.Rules = append(rsDupDef.Rules, MappingRule{
		ID:              "RULE-SQLI-SI10-ALIAS",
		SourceRuleID:    "WEB_SQL_INJECTION",
		SourceCategory:  "injection",
		TargetControlID: "SI-10",
		Relationship:    RelationshipDirect,
		Rationale:       "Identical mapping definition with another ID",
	})
	err = ValidateMappingRuleSet(rsDupDef, cat)
	if err == nil || !strings.Contains(err.Error(), "duplicate mapping rule") {
		t.Errorf("expected duplicate mapping rule error, got: %v", err)
	}
}

// 8. Conflicting rules produce deterministic outcomes
func TestScenario8_ConflictingRulesProduceDeterministicOutcome(t *testing.T) {
	cat := sampleValidCatalog()

	// Rule 1: High confidence, direct relationship
	rule1 := MappingRule{
		ID:              "RULE-A-DIRECT",
		SourceRuleID:    "WEB_SQL_INJECTION",
		TargetControlID: "SI-10",
		Relationship:    RelationshipDirect,
		Rationale:       "Direct SQLi relationship",
		Confidence:      1.0,
	}

	// Rule 2: Lower confidence, indirect relationship
	rule2 := MappingRule{
		ID:              "RULE-B-INDIRECT",
		SourceCategory:  "injection",
		TargetControlID: "SI-10",
		Relationship:    RelationshipIndirect,
		Rationale:       "Indirect SQLi relationship",
		Confidence:      0.5,
	}

	// RuleSet 1: [rule1, rule2]
	rs1 := &MappingRuleSet{
		SchemaVersion:        SchemaVersion1_0,
		ID:                   "ruleset-conflict-test",
		Title:                "Conflict Test",
		Version:              "1.0.0",
		TargetCatalogID:      cat.ID,
		TargetCatalogVersion: cat.Version,
		Rules:                []MappingRule{rule1, rule2},
	}

	// RuleSet 2: [rule2, rule1] (reversed order)
	rs2 := &MappingRuleSet{
		SchemaVersion:        SchemaVersion1_0,
		ID:                   "ruleset-conflict-test",
		Title:                "Conflict Test",
		Version:              "1.0.0",
		TargetCatalogID:      cat.ID,
		TargetCatalogVersion: cat.Version,
		Rules:                []MappingRule{rule2, rule1},
	}

	finding := []report.Finding{
		{
			ID:       "F-SQLI",
			RuleID:   "WEB_SQL_INJECTION",
			Category: "injection",
			Title:    "SQL Injection",
		},
	}

	fixedClock := func() time.Time { return time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC) }

	res1, err1 := NewMappingEngine().WithClock(fixedClock).MapFindings(cat, rs1, finding)
	if err1 != nil {
		t.Fatalf("unexpected error 1: %v", err1)
	}

	res2, err2 := NewMappingEngine().WithClock(fixedClock).MapFindings(cat, rs2, finding)
	if err2 != nil {
		t.Fatalf("unexpected error 2: %v", err2)
	}

	if len(res1.Mappings) != 1 || len(res2.Mappings) != 1 {
		t.Fatalf("expected 1 winning mapping per run, got %d and %d", len(res1.Mappings), len(res2.Mappings))
	}

	// Winning rule must be rule1 (RelationshipDirect, Confidence 1.0) in both cases
	if res1.Mappings[0].RuleID != "RULE-A-DIRECT" || res1.Mappings[0].Relationship != RelationshipDirect {
		t.Errorf("res1 did not select direct rule: %+v", res1.Mappings[0])
	}
	if res2.Mappings[0].RuleID != "RULE-A-DIRECT" || res2.Mappings[0].Relationship != RelationshipDirect {
		t.Errorf("res2 did not select direct rule: %+v", res2.Mappings[0])
	}

	// Ambiguous findings must be recorded
	if res1.Coverage.AmbiguousFindings != 1 || res2.Coverage.AmbiguousFindings != 1 {
		t.Errorf("expected ambiguous findings count 1, got %d and %d",
			res1.Coverage.AmbiguousFindings, res2.Coverage.AmbiguousFindings)
	}

	// Entire outputs must be strictly equal
	if !reflect.DeepEqual(res1.Mappings, res2.Mappings) {
		t.Errorf("mappings differ under rule reordering!")
	}
}

// 9. Unsupported relationship types rejected
func TestScenario9_UnsupportedRelationshipTypesRejected(t *testing.T) {
	cat := sampleValidCatalog()

	unsupported := []string{
		"compliant",
		"non_compliant",
		"partially_compliant",
		"passed",
		"failed",
		"full",
		"correlated",
	}

	for _, badRel := range unsupported {
		rs := sampleValidRuleSet()
		rs.Rules[0].Relationship = MappingRelationship(badRel)
		err := ValidateMappingRuleSet(rs, cat)
		if err == nil || !strings.Contains(err.Error(), "unsupported relationship") {
			t.Errorf("expected unsupported relationship error for %q, got: %v", badRel, err)
		}
	}
}

// 10. Invalid confidence values rejected
func TestScenario10_InvalidConfidenceValuesRejected(t *testing.T) {
	cat := sampleValidCatalog()

	invalidConfidences := []float64{-0.5, -0.001, 1.001, 2.0, 100.0}
	for _, conf := range invalidConfidences {
		rs := sampleValidRuleSet()
		rs.Rules[0].Confidence = conf
		err := ValidateMappingRuleSet(rs, cat)
		if err == nil || !strings.Contains(err.Error(), "confidence must be between 0.0 and 1.0") {
			t.Errorf("expected invalid confidence error for %v, got: %v", conf, err)
		}
	}

	// Valid confidences must pass
	validConfidences := []float64{0.0, 0.1, 0.5, 0.99, 1.0}
	for _, conf := range validConfidences {
		rs := sampleValidRuleSet()
		rs.Rules[0].Confidence = conf
		if err := ValidateMappingRuleSet(rs, cat); err != nil {
			t.Errorf("expected confidence %v to pass, got error: %v", conf, err)
		}
	}
}

// 11. Missing finding data does not cause panic
func TestScenario11_MissingFindingDataDoesNotCausePanic(t *testing.T) {
	cat := sampleValidCatalog()
	rs := sampleValidRuleSet()

	// Completely empty finding struct
	findings := []report.Finding{
		{},
		{
			ID: "", // empty ID
		},
		{
			ID:          "F-EMPTY-EVIDENCE",
			RuleID:      "WEB_SQL_INJECTION",
			Evidence:    "",
			Endpoint:    "",
			Target:      "",
			Description: "",
		},
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic handling empty finding data: %v", r)
		}
	}()

	res, err := MapFindings(cat, rs, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res == nil {
		t.Fatal("expected non-nil result")
	}
	if res.Coverage.TotalFindings != 3 {
		t.Errorf("expected 3 total findings, got %d", res.Coverage.TotalFindings)
	}
}

// 12. Nil, empty, malformed inputs handled safely
func TestScenario12_NilEmptyMalformedInputsHandledSafely(t *testing.T) {
	cat := sampleValidCatalog()
	rs := sampleValidRuleSet()

	// Nil inputs to MapFindings
	if _, err := MapFindings(nil, rs, nil); err == nil {
		t.Errorf("expected error for nil catalog")
	}
	if _, err := MapFindings(cat, nil, nil); err == nil {
		t.Errorf("expected error for nil ruleset")
	}

	// Empty findings slice
	res, err := MapFindings(cat, rs, []report.Finding{})
	if err != nil {
		t.Errorf("unexpected error for empty findings slice: %v", err)
	}
	if res == nil || len(res.Mappings) != 0 || res.Coverage.TotalFindings != 0 {
		t.Errorf("unexpected result for empty findings: %+v", res)
	}

	// Nil to ValidateMappingRuleSet
	if err := ValidateMappingRuleSet(nil, cat); err == nil {
		t.Errorf("expected error for nil ruleset in validator")
	}

	// Empty and malformed loader bytes
	if _, err := LoadMappingRuleSetFromBytes(nil); err != ErrEmptyRuleSetPayload {
		t.Errorf("expected ErrEmptyRuleSetPayload for nil bytes, got %v", err)
	}
	if _, err := LoadMappingRuleSetFromBytes([]byte("   ")); err != ErrEmptyRuleSetPayload {
		t.Errorf("expected ErrEmptyRuleSetPayload for whitespace bytes, got %v", err)
	}
	if _, err := LoadMappingRuleSetFromBytes([]byte("{invalid json")); err == nil {
		t.Errorf("expected syntax error for malformed json")
	}
}

// 13. Output stable under reordered findings or rules
func TestScenario13_OutputStableUnderReorderedFindingsOrRules(t *testing.T) {
	cat := sampleValidCatalog()
	rs1 := sampleValidRuleSet()

	// Reverse rules array in rs2
	rs2 := sampleValidRuleSet()
	for i, j := 0, len(rs2.Rules)-1; i < j; i, j = i+1, j-1 {
		rs2.Rules[i], rs2.Rules[j] = rs2.Rules[j], rs2.Rules[i]
	}

	f1 := report.Finding{ID: "F-1", RuleID: "WEB_SQL_INJECTION", Category: "injection"}
	f2 := report.Finding{ID: "F-2", RuleID: "APISPEC_NO_AUTH", Category: "auth"}
	f3 := report.Finding{ID: "F-3", RuleID: "AWS_S3_PUBLIC_READ", Category: "cloud"}

	findingsOrderA := []report.Finding{f1, f2, f3}
	findingsOrderB := []report.Finding{f3, f1, f2}

	fixedClock := func() time.Time { return time.Date(2026, 10, 21, 14, 0, 0, 0, time.UTC) }

	resA, errA := NewMappingEngine().WithClock(fixedClock).MapFindings(cat, rs1, findingsOrderA)
	if errA != nil {
		t.Fatalf("unexpected error A: %v", errA)
	}

	resB, errB := NewMappingEngine().WithClock(fixedClock).MapFindings(cat, rs2, findingsOrderB)
	if errB != nil {
		t.Fatalf("unexpected error B: %v", errB)
	}

	if !reflect.DeepEqual(resA.Mappings, resB.Mappings) {
		t.Errorf("mappings differ under reordering!")
	}
	if !reflect.DeepEqual(resA.Coverage, resB.Coverage) {
		t.Errorf("coverage differs under reordering!")
	}
}

// 14. Equivalent inputs produce equivalent results
func TestScenario14_EquivalentInputsProduceEquivalentResults(t *testing.T) {
	cat := sampleValidCatalog()
	rs := sampleValidRuleSet()

	findings := []report.Finding{
		{ID: "F-1", RuleID: "WEB_SQL_INJECTION", Category: "injection"},
		{ID: "F-2", RuleID: "UNKNOWN", Category: "unknown"},
	}

	fixedClock := func() time.Time { return time.Date(2026, 10, 21, 15, 0, 0, 0, time.UTC) }

	res1, _ := NewMappingEngine().WithClock(fixedClock).MapFindings(cat, rs, findings)
	res2, _ := NewMappingEngine().WithClock(fixedClock).MapFindings(cat, rs, findings)

	data1, _ := json.Marshal(res1)
	data2, _ := json.Marshal(res2)

	if string(data1) != string(data2) {
		t.Errorf("equivalent inputs did not produce byte-identical JSON: \n%s\nvs\n%s", string(data1), string(data2))
	}
}

// 15. Changing catalog/ruleset version reflected in provenance
func TestScenario15_ChangingCatalogRulesetVersionReflectedInProvenance(t *testing.T) {
	catV1 := sampleValidCatalog()
	catV1.Version = "5.1.1"

	catV2 := sampleValidCatalog()
	catV2.Version = "5.2.0"

	rsV1 := sampleValidRuleSet()
	rsV1.Version = "1.0.0"
	rsV1.TargetCatalogVersion = "*" // accept any version

	rsV2 := sampleValidRuleSet()
	rsV2.Version = "2.0.0"
	rsV2.TargetCatalogVersion = "*"

	findings := []report.Finding{
		{ID: "F-1", RuleID: "WEB_SQL_INJECTION", Category: "injection"},
	}

	resCat1, _ := MapFindings(catV1, rsV1, findings)
	resCat2, _ := MapFindings(catV2, rsV1, findings)

	if resCat1.CatalogIdentity == resCat2.CatalogIdentity {
		t.Errorf("expected different CatalogIdentity for different catalog versions, got %q", resCat1.CatalogIdentity)
	}
	if resCat1.CatalogDigest == resCat2.CatalogDigest {
		t.Errorf("expected different CatalogDigest for different catalog versions")
	}

	resRs1, _ := MapFindings(catV1, rsV1, findings)
	resRs2, _ := MapFindings(catV1, rsV2, findings)

	if resRs1.MappingRuleSetIdentity == resRs2.MappingRuleSetIdentity {
		t.Errorf("expected different MappingRuleSetIdentity for different ruleset versions, got %q", resRs1.MappingRuleSetIdentity)
	}
	if resRs1.MappingRuleSetDigest == resRs2.MappingRuleSetDigest {
		t.Errorf("expected different MappingRuleSetDigest for different ruleset versions")
	}
	if resRs1.Mappings[0].MappingVersion != "1.0.0" || resRs2.Mappings[0].MappingVersion != "2.0.0" {
		t.Errorf("mapping entries did not reflect ruleset version in provenance")
	}
}

// 16. Findings without evidence not falsely represented as evidence-backed
func TestScenario16_FindingsWithoutEvidenceNotFalselyRepresented(t *testing.T) {
	cat := sampleValidCatalog()
	rs := sampleValidRuleSet()

	findings := []report.Finding{
		{
			ID:          "F-WITH-EVIDENCE",
			RuleID:      "WEB_SQL_INJECTION",
			Category:    "injection",
			Evidence:    "differential response observed with sleep(5)",
			Endpoint:    "/api/query",
			Description: "Active SQL injection",
		},
		{
			ID:          "F-NO-EVIDENCE",
			RuleID:      "WEB_SQL_INJECTION",
			Category:    "injection",
			Title:       "Potential SQL injection from header review",
			Endpoint:    "/api/query", // location present, but NO observation, evidence, or verification
			Description: "Heuristic inspection",
		},
	}

	res, err := MapFindings(cat, rs, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var withEv, withoutEv []FindingControlMapping
	for _, m := range res.Mappings {
		if m.FindingID == "F-WITH-EVIDENCE" {
			withEv = append(withEv, m)
		} else if m.FindingID == "F-NO-EVIDENCE" {
			withoutEv = append(withoutEv, m)
		}
	}

	if len(withEv) == 0 || len(withoutEv) == 0 {
		t.Fatalf("missing mappings for evidence test findings")
	}

	for _, m := range withEv {
		if !m.HasEvidence {
			t.Errorf("expected HasEvidence=true for finding with evidence, got false")
		}
		if m.EvidenceLocation == "" {
			t.Errorf("expected non-empty EvidenceLocation for finding with evidence")
		}
	}

	for _, m := range withoutEv {
		if m.HasEvidence {
			t.Errorf("finding without concrete evidence was falsely represented as evidence-backed!")
		}
		if m.EvidenceLocation != "" {
			t.Errorf("expected empty EvidenceLocation when HasEvidence is false, got %q", m.EvidenceLocation)
		}
	}
}

// 17. Multiple mappings do not inflate unique-finding coverage counts
func TestScenario17_MultipleMappingsDoNotInflateCoverage(t *testing.T) {
	cat := sampleValidCatalog()
	rs := sampleValidRuleSet()

	// Finding 1: maps to 2 controls (SI-10, AC-3)
	// Finding 2: maps to 2 controls (AC-3, SC-7)
	// Finding 3: maps to 1 control (IA-2)
	// Finding 4: maps to 0 controls (unmapped)
	findings := []report.Finding{
		{ID: "F-1", RuleID: "WEB_SQL_INJECTION", Category: "injection"},
		{ID: "F-2", RuleID: "AWS_S3_PUBLIC_READ", Category: "cloud"},
		{ID: "F-3", RuleID: "APISPEC_NO_AUTH", Category: "auth"},
		{ID: "F-4", RuleID: "UNMAPPED_RULE", Category: "unknown"},
	}

	res, err := MapFindings(cat, rs, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cov := res.Coverage
	if cov.TotalFindings != 4 {
		t.Errorf("expected TotalFindings 4, got %d", cov.TotalFindings)
	}
	if cov.MappedFindings != 3 {
		t.Errorf("expected MappedFindings 3 (unique findings), got %d", cov.MappedFindings)
	}
	if cov.UnmappedFindings != 1 {
		t.Errorf("expected UnmappedFindings 1, got %d", cov.UnmappedFindings)
	}
	if cov.TotalMappings != 5 { // 2 + 2 + 1 = 5 mappings
		t.Errorf("expected TotalMappings 5, got %d", cov.TotalMappings)
	}
	if cov.MultiMappedFindings != 2 { // F-1 and F-2
		t.Errorf("expected MultiMappedFindings 2, got %d", cov.MultiMappedFindings)
	}
}

// 18. Mapping never produces compliance evaluation states
func TestScenario18_MappingNeverProducesComplianceEvaluationStates(t *testing.T) {
	cat := sampleValidCatalog()
	rs := sampleValidRuleSet()

	findings := []report.Finding{
		{
			ID:       "F-1",
			RuleID:   "WEB_SQL_INJECTION",
			Category: "injection",
			Evidence: "vulnerability proof",
		},
	}

	res, err := MapFindings(cat, rs, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify Limitations Notice explicitly clarifies that mapping != compliance evaluation
	if !strings.Contains(res.LimitationsNotice, "NOT constitute a compliance evaluation") {
		t.Errorf("LimitationsNotice missing required disclaimer: %q", res.LimitationsNotice)
	}

	// Serialize result to JSON and verify forbidden compliance evaluation state strings are absent from keys
	data, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("failed marshaling result: %v", err)
	}

	var genericMap map[string]any
	if err := json.Unmarshal(data, &genericMap); err != nil {
		t.Fatalf("failed unmarshaling generic map: %v", err)
	}

	forbiddenKeys := []string{"compliant", "non_compliant", "partially_compliant", "passed", "failed", "evaluation_status", "audit_result"}
	for _, key := range forbiddenKeys {
		if _, exists := genericMap[key]; exists {
			t.Errorf("forbidden compliance evaluation state key %q found in MappingResult", key)
		}
	}

	// Verify inside mappings as well
	mappingsArr, ok := genericMap["mappings"].([]any)
	if !ok || len(mappingsArr) == 0 {
		t.Fatalf("expected mappings array in JSON")
	}

	for _, item := range mappingsArr {
		mMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for _, key := range forbiddenKeys {
			if _, exists := mMap[key]; exists {
				t.Errorf("forbidden evaluation state key %q found in FindingControlMapping", key)
			}
		}
		// Check that relationship is strictly a relevance relationship, not a compliance verdict
		rel, _ := mMap["relationship"].(string)
		if rel != "direct" && rel != "partial_evidence" && rel != "indirect" {
			t.Errorf("invalid relationship value %q in mapping", rel)
		}
	}
}

// 19. Loader limits and validation enforcement
func TestMappingLoader_SecurityAndLimits(t *testing.T) {
	// 1. Unknown fields rejected
	jsonWithUnknown := `{
		"schema_version": "1.0",
		"id": "ruleset-test",
		"title": "Ruleset Test",
		"version": "1.0.0",
		"unexpected_field": "hacker_payload",
		"rules": []
	}`
	_, err := LoadMappingRuleSetFromBytes([]byte(jsonWithUnknown))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("expected unknown field error, got: %v", err)
	}

	// 2. Duplicate keys rejected
	jsonWithDupKey := `{
		"schema_version": "1.0",
		"id": "ruleset-test",
		"id": "ruleset-duplicate",
		"title": "Ruleset Test",
		"version": "1.0.0",
		"rules": []
	}`
	_, err = LoadMappingRuleSetFromBytes([]byte(jsonWithDupKey))
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("expected duplicate key error, got: %v", err)
	}

	// 3. Deeply nested payload rejected
	var deepJSON strings.Builder
	for i := 0; i < 40; i++ {
		deepJSON.WriteString(`{"nested":`)
	}
	deepJSON.WriteString(`"value"`)
	for i := 0; i < 40; i++ {
		deepJSON.WriteString(`}`)
	}
	_, err = LoadMappingRuleSetFromBytes([]byte(deepJSON.String()))
	if err != ErrNestingTooDeep {
		t.Errorf("expected ErrNestingTooDeep, got: %v", err)
	}
}
