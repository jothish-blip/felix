package compliance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/report"
)

// Helper to generate a trusted test key pair
func generateTestSigner(keyID, authority string) (ed25519.PublicKey, ed25519.PrivateKey, assessment.TrustedKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, assessment.TrustedKey{}, err
	}
	tk := assessment.TrustedKey{
		KeyID:       keyID,
		PublicKey:   pub,
		Authority:   authority,
		Description: "Test Key",
	}
	return pub, priv, tk, nil
}

// Helper to create a valid signed attestation letter
func createValidAttestationLetter(t *testing.T, asmID, clientName, keyID string, priv ed25519.PrivateKey) assessment.AttestationLetter {
	snapshot := assessment.AttestationSnapshot{
		AssessmentID:       asmID,
		AssessmentRef:      "ASM-2026-TEST",
		AssessmentName:     "Test Assessment",
		AssessmentType:     "FULL",
		ClientID:           "client-01",
		ClientName:         clientName,
		ClientOrganization: clientName,
		ScopeMode:          "IN_SCOPE",
		SigningKeyID:       keyID,
		StartedAt:          time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		CompletedAt:        time.Now().UTC().Format(time.RFC3339),
		DurationMs:         3600000,
		TestingMethodology: []string{"OWASP ASVS v4.0.3 Level 2", "PTES Technical Guidelines"},
		TotalFindingsCount: 2,
		ConfirmedFindings:  1,
	}

	canonicalDigest, digestBytes, err := assessment.ComputeCanonicalSnapshotDigest(snapshot)
	if err != nil {
		t.Fatalf("failed computing canonical snapshot digest: %v", err)
	}

	sig := ed25519.Sign(priv, digestBytes)
	pub := priv.Public().(ed25519.PublicKey)

	return assessment.AttestationLetter{
		LetterID:        fmt.Sprintf("ATT-%s-001", asmID),
		LetterVersion:   "1.0.0",
		IssuedAt:        time.Now().UTC(),
		Issuer:          "FELIX Automated Security Assessment Authority",
		CanonicalDigest: canonicalDigest,
		Signature: assessment.AttestationSignature{
			Algorithm:      "Ed25519",
			KeyID:          keyID,
			PublicKeyHex:   hex.EncodeToString(pub),
			SignatureHex:   hex.EncodeToString(sig),
			SignedAt:       time.Now().UTC(),
			SignerIdentity: "FELIX Cryptographic Attestation Engine v3.0",
		},
		Snapshot:             snapshot,
		ExecutiveStatement:   "This certifies that an automated penetration test was performed.",
		RegulatoryDisclaimer: "Certified assessment results.",
	}
}

// -----------------------------------------------------------------------------
// Test 1: Vanta Successful Pen Test Sync & JSON Schema Validation
// -----------------------------------------------------------------------------
func TestComplianceSync_01_VantaSuccessfulSyncAndSchemaValidation(t *testing.T) {
	var receivedPayload []byte
	var receivedAuth string
	var receivedIdempotency string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/audits/penetration-tests" && r.Method == http.MethodPost {
			receivedAuth = r.Header.Get("Authorization")
			receivedIdempotency = r.Header.Get("Idempotency-Key")
			receivedPayload, _ = io.ReadAll(r.Body)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"id": "vanta-audit-rec-101",
				"status": "INGESTED",
				"url": "https://app.vanta.com/audits/vanta-audit-rec-101",
				"findings_ingested": 2
			}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	pub, priv, tk, _ := generateTestSigner("KEY-FELIX-VANTA-01", "Vanta Authority")
	_ = pub
	reg := assessment.MapKeyRegistry{tk.KeyID: tk}

	att := createValidAttestationLetter(t, "asm-vanta-01", "Acme Corporation", tk.KeyID, priv)
	store, err := NewSQLiteComplianceStore(":memory:")
	if err != nil {
		t.Fatalf("failed creating store: %v", err)
	}
	defer store.Close()

	engine := NewAuditorSyncEngine(store, reg)

	cfg := ComplianceSyncConfig{
		Platform:            PlatformVanta,
		BaseURL:             server.URL,
		Token:               "vanta_secret_bearer_token_xyz999",
		Timeout:             5 * time.Second,
		SSRF:                SSRFConfig{AllowLoopback: true, AllowPrivateIPs: true, EnforceHTTPS: false},
		ValidateVantaSchema: true,
	}

	req := &SyncAssessmentRequest{
		Assessment: assessment.Assessment{
			ID:         "asm-vanta-01",
			Ref:        "ASM-2026-VANTA01",
			Name:       "Acme Corporation",
			CreatedAt:  time.Now().UTC().Add(-2 * time.Hour),
		},
		Attestation: &att,
		Findings: []assessment.AssessmentFinding{
			{
				ID:                 "FND-SQLI-01",
				Title:              "SQL Injection in Search",
				Severity:           "CRITICAL",
				Status:             "REMEDIATED_VERIFIED",
				VerificationStatus: report.VerificationVerified,
				Endpoint:           "/api/v1/search",
			},
			{
				ID:                 "FND-BOLA-01",
				Title:              "BOLA in Users API",
				Severity:           "HIGH",
				Status:             assessment.FindingStatusVerifiedDefect,
				VerificationStatus: report.VerificationVerified,
				Endpoint:           "/api/v1/users/1",
			},
		},
	}

	res, err := engine.SyncAssessment(context.Background(), PlatformVanta, req, cfg)
	if err != nil {
		t.Fatalf("SyncAssessment failed: %v", err)
	}

	if res.Status != SyncStatusSuccess {
		t.Errorf("expected status SUCCESS, got %s", res.Status)
	}
	if res.ExternalID != "vanta-audit-rec-101" {
		t.Errorf("expected external ID 'vanta-audit-rec-101', got %s", res.ExternalID)
	}
	if !res.AttestationAccepted {
		t.Errorf("expected attestation to be accepted")
	}
	if res.RemediatedCount != 1 || res.UnresolvedCount != 1 {
		t.Errorf("expected 1 remediated and 1 unresolved, got %d rem, %d unres", res.RemediatedCount, res.UnresolvedCount)
	}

	// Verify headers
	if receivedAuth != "Bearer vanta_secret_bearer_token_xyz999" {
		t.Errorf("expected valid auth header, got %q", receivedAuth)
	}
	if receivedIdempotency == "" {
		t.Errorf("expected idempotency header to be set")
	}

	// Verify that received payload cleanly validates against the formal Vanta schema
	if err := ValidateVantaPayloadSchema(receivedPayload); err != nil {
		t.Errorf("outbound payload failed Vanta JSON schema validation: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Test 2: Vanta Schema Rejection (Malformed / Missing Fields)
// -----------------------------------------------------------------------------
func TestComplianceSync_02_VantaSchemaRejection(t *testing.T) {
	// 1. Missing client_organization
	badPayload1 := []byte(`{
		"assessment_id": "asm-01",
		"assessment_ref": "REF-01",
		"audit_type": "PENETRATION_TEST",
		"methodology": ["OWASP"],
		"testing_window": {"started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T01:00:00Z"},
		"attestation": {"letter_id":"L1"},
		"retest_summary": {"total_findings": 0},
		"findings": []
	}`)
	err1 := ValidateVantaPayloadSchema(badPayload1)
	if err1 == nil || !strings.Contains(err1.Error(), "client_organization") {
		t.Errorf("expected schema error for missing client_organization, got %v", err1)
	}

	// 2. Invalid audit_type enum
	badPayload2 := []byte(`{
		"client_organization": "Acme",
		"assessment_id": "asm-01",
		"assessment_ref": "REF-01",
		"audit_type": "INVALID_AUDIT_TYPE",
		"methodology": ["OWASP"],
		"testing_window": {"started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T01:00:00Z"},
		"attestation": {"letter_id":"L1"},
		"retest_summary": {"total_findings": 0},
		"findings": []
	}`)
	err2 := ValidateVantaPayloadSchema(badPayload2)
	if err2 == nil || !strings.Contains(err2.Error(), "audit_type") {
		t.Errorf("expected schema error for invalid audit_type, got %v", err2)
	}

	// 3. Empty methodology array
	badPayload3 := []byte(`{
		"client_organization": "Acme",
		"assessment_id": "asm-01",
		"assessment_ref": "REF-01",
		"audit_type": "PENETRATION_TEST",
		"methodology": [],
		"testing_window": {"started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T01:00:00Z"},
		"attestation": {"letter_id":"L1"},
		"retest_summary": {"total_findings": 0},
		"findings": []
	}`)
	err3 := ValidateVantaPayloadSchema(badPayload3)
	if err3 == nil || !strings.Contains(err3.Error(), "methodology") {
		t.Errorf("expected schema error for empty methodology, got %v", err3)
	}
}

// -----------------------------------------------------------------------------
// Test 3: Drata Evidence Upload & SOC 2 CC7.1 / CC6.8 Control Mapping
// -----------------------------------------------------------------------------
func TestComplianceSync_03_DrataEvidenceUploadAndSOC2Mapping(t *testing.T) {
	var drataReceived []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/public/v1/evidence/upload" && r.Method == http.MethodPost {
			drataReceived, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{
				"evidence_id": "drata-ev-777",
				"status": "UPLOADED",
				"url": "https://app.drata.com/evidence/drata-ev-777",
				"controls_linked": ["CC7.1", "CC6.8", "CC6.6"]
			}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	store, err := NewSQLiteComplianceStore(":memory:")
	if err != nil {
		t.Fatalf("failed creating store: %v", err)
	}
	defer store.Close()

	engine := NewAuditorSyncEngine(store)
	cfg := ComplianceSyncConfig{
		Platform: PlatformDrata,
		BaseURL:  server.URL,
		Token:    "drata_api_key_secret_888",
		Timeout:  5 * time.Second,
		SSRF:     SSRFConfig{AllowLoopback: true, AllowPrivateIPs: true, EnforceHTTPS: false},
	}

	req := &SyncAssessmentRequest{
		Assessment: assessment.Assessment{
			ID:   "asm-drata-01",
			Ref:  "ASM-2026-DRATA01",
			Name: "SaaS Corp",
		},
		Findings: []assessment.AssessmentFinding{
			{
				ID:       "FND-SQLI-01",
				RuleID:   "RULE-SQLI",
				Category: "A03:2021-Injection",
				Title:    "SQL Injection",
				Severity: "CRITICAL",
				Status:   "REMEDIATED_VERIFIED",
			},
			{
				ID:       "FND-BOLA-01",
				RuleID:   "RULE-BOLA",
				Category: "API1:2023-BOLA",
				Title:    "Broken Object Level Authorization",
				Severity: "HIGH",
				Status:   assessment.FindingStatusVerifiedDefect,
			},
			{
				ID:       "FND-HSTS-01",
				RuleID:   "RULE-HSTS",
				Category: "A05:2021-Security-Misconfiguration",
				Title:    "Missing HSTS Header",
				Severity: "MEDIUM",
				Status:   assessment.FindingStatusVerifiedDefect,
			},
		},
	}

	res, err := engine.SyncAssessment(context.Background(), PlatformDrata, req, cfg)
	if err != nil {
		t.Fatalf("Drata sync failed: %v", err)
	}

	if res.Status != SyncStatusSuccess {
		t.Errorf("expected SUCCESS, got %s", res.Status)
	}
	if res.ExternalID != "drata-ev-777" {
		t.Errorf("expected external ID 'drata-ev-777', got %s", res.ExternalID)
	}

	// Verify mapped controls in payload
	var payload DrataEvidencePayload
	if err := json.Unmarshal(drataReceived, &payload); err != nil {
		t.Fatalf("failed unmarshaling payload: %v", err)
	}

	if payload.ComplianceFramework != "SOC_2_TYPE_II" {
		t.Errorf("expected SOC_2_TYPE_II, got %s", payload.ComplianceFramework)
	}

	// Verify automatic finding to control mapping
	foundCC71 := false
	foundCC68 := false
	foundCC66 := false
	for _, m := range payload.FindingMappings {
		if m.FindingID == "FND-SQLI-01" && m.ControlID == "CC7.1" {
			foundCC71 = true
		}
		if m.FindingID == "FND-BOLA-01" && m.ControlID == "CC6.8" {
			foundCC68 = true
		}
		if m.FindingID == "FND-HSTS-01" && m.ControlID == "CC6.6" {
			foundCC66 = true
		}
	}

	if !foundCC71 || !foundCC68 || !foundCC66 {
		t.Errorf("SOC 2 mappings incomplete: CC7.1=%v, CC6.8=%v, CC6.6=%v", foundCC71, foundCC68, foundCC66)
	}
}

// -----------------------------------------------------------------------------
// Test 4: Secureframe Pen Test Timestamps & SLA Sync
// -----------------------------------------------------------------------------
func TestComplianceSync_04_SecureframeTestAndSLASync(t *testing.T) {
	var sfReceived []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/tests/penetration-test" && r.Method == http.MethodPost {
			sfReceived, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"test_id": "sf-test-999",
				"status": "RECORDED",
				"url": "https://app.secureframe.com/tests/sf-test-999",
				"slas_synced": 2
			}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	store, err := NewSQLiteComplianceStore(":memory:")
	if err != nil {
		t.Fatalf("failed creating store: %v", err)
	}
	defer store.Close()

	engine := NewAuditorSyncEngine(store)
	cfg := ComplianceSyncConfig{
		Platform: PlatformSecureframe,
		BaseURL:  server.URL,
		Token:    "sf_token_secret_123",
		Timeout:  5 * time.Second,
		SSRF:     SSRFConfig{AllowLoopback: true, AllowPrivateIPs: true, EnforceHTTPS: false},
	}

	now := time.Now().UTC()
	req := &SyncAssessmentRequest{
		Assessment: assessment.Assessment{
			ID:        "asm-sf-01",
			Ref:       "ASM-2026-SF01",
			Name:      "FinTech Labs",
			CreatedAt: now.Add(-24 * time.Hour),
		},
		Execution: &assessment.AssessmentExecution{
			ID:          "exec-sf-01",
			StartedAt:   now.Add(-2 * time.Hour),
			CompletedAt: &now,
		},
		Findings: []assessment.AssessmentFinding{
			{
				ID:       "FND-AUTH-01",
				Title:    "Authentication Bypass",
				Severity: "CRITICAL",
				Status:   "REMAINING_UNRESOLVED",
			},
		},
		RemediationSLAs: []RemediationRecord{
			{
				ID:        "rem-01",
				FindingID: "FND-AUTH-01",
				Status:    RemediationStatusOpen,
				Deadline:  now.Add(48 * time.Hour), // Within SLA
			},
		},
	}

	res, err := engine.SyncAssessment(context.Background(), PlatformSecureframe, req, cfg)
	if err != nil {
		t.Fatalf("Secureframe sync failed: %v", err)
	}

	if res.Status != SyncStatusSuccess {
		t.Errorf("expected SUCCESS, got %s", res.Status)
	}
	if res.ExternalID != "sf-test-999" {
		t.Errorf("expected external ID 'sf-test-999', got %s", res.ExternalID)
	}

	var payload SecureframeTestPayload
	if err := json.Unmarshal(sfReceived, &payload); err != nil {
		t.Fatalf("failed unmarshaling payload: %v", err)
	}

	if payload.Vendor != "FELIX" {
		t.Errorf("expected Vendor 'FELIX', got %s", payload.Vendor)
	}
	if payload.Pass != false {
		t.Errorf("expected Pass=false because finding is unresolved")
	}
	if payload.RemediationSLASummary.WithinSLA != 1 {
		t.Errorf("expected 1 WithinSLA, got %d", payload.RemediationSLASummary.WithinSLA)
	}
}

// -----------------------------------------------------------------------------
// Test 5: Multi-Platform Orchestration (SyncAllPlatforms)
// -----------------------------------------------------------------------------
func TestComplianceSync_05_MultiPlatformOrchestration(t *testing.T) {
	vantaHit := false
	drataHit := false
	sfHit := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/audits/penetration-tests":
			vantaHit = true
			_, _ = w.Write([]byte(`{"id":"vanta-1","status":"INGESTED"}`))
		case "/public/v1/evidence/upload":
			drataHit = true
			_, _ = w.Write([]byte(`{"evidence_id":"drata-1","status":"UPLOADED"}`))
		case "/v1/tests/penetration-test":
			sfHit = true
			_, _ = w.Write([]byte(`{"test_id":"sf-1","status":"RECORDED"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	store, _ := NewSQLiteComplianceStore(":memory:")
	defer store.Close()

	engine := NewAuditorSyncEngine(store)

	configs := map[CompliancePlatform]ComplianceSyncConfig{
		PlatformVanta: {
			Platform: PlatformVanta,
			BaseURL:  server.URL,
			Token:    "v-tok",
			SSRF:     SSRFConfig{AllowLoopback: true, AllowPrivateIPs: true, EnforceHTTPS: false},
		},
		PlatformDrata: {
			Platform: PlatformDrata,
			BaseURL:  server.URL,
			Token:    "d-tok",
			SSRF:     SSRFConfig{AllowLoopback: true, AllowPrivateIPs: true, EnforceHTTPS: false},
		},
		PlatformSecureframe: {
			Platform: PlatformSecureframe,
			BaseURL:  server.URL,
			Token:    "sf-tok",
			SSRF:     SSRFConfig{AllowLoopback: true, AllowPrivateIPs: true, EnforceHTTPS: false},
		},
	}

	req := &SyncAssessmentRequest{
		Assessment: assessment.Assessment{
			ID:   "asm-multi-01",
			Ref:  "ASM-2026-MULTI01",
			Name: "Omni Corp",
		},
		Findings: []assessment.AssessmentFinding{
			{
				ID:       "FND-01",
				Title:    "Test Defect",
				Severity: "MEDIUM",
				Status:   "REMEDIATED_VERIFIED",
			},
		},
	}

	results, err := engine.SyncAllPlatforms(context.Background(), req, configs)
	if err != nil {
		t.Fatalf("SyncAllPlatforms failed: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("expected 3 results, got %d", len(results))
	}
	if !vantaHit || !drataHit || !sfHit {
		t.Errorf("not all platforms hit: vanta=%v, drata=%v, sf=%v", vantaHit, drataHit, sfHit)
	}
}

// -----------------------------------------------------------------------------
// Test 6: Authentication Failure (HTTP 401 Unauthorized)
// -----------------------------------------------------------------------------
func TestComplianceSync_06_AuthenticationFailure401(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Invalid or expired API token"}`))
	}))
	defer server.Close()

	store, _ := NewSQLiteComplianceStore(":memory:")
	defer store.Close()

	engine := NewAuditorSyncEngine(store)
	cfg := ComplianceSyncConfig{
		Platform: PlatformVanta,
		BaseURL:  server.URL,
		Token:    "expired_token_123",
		Timeout:  2 * time.Second,
		SSRF:     SSRFConfig{AllowLoopback: true, AllowPrivateIPs: true, EnforceHTTPS: false},
	}

	req := &SyncAssessmentRequest{
		Assessment: assessment.Assessment{ID: "asm-401"},
	}

	res, err := engine.SyncAssessment(context.Background(), PlatformVanta, req, cfg)
	if err == nil {
		t.Fatalf("expected error for 401 Unauthorized, got nil")
	}
	if res.Status != SyncStatusFailed {
		t.Errorf("expected status FAILED, got %s", res.Status)
	}
}

// -----------------------------------------------------------------------------
// Test 7: Missing Credentials Rejection
// -----------------------------------------------------------------------------
func TestComplianceSync_07_MissingCredentialsRejection(t *testing.T) {
	store, _ := NewSQLiteComplianceStore(":memory:")
	defer store.Close()

	engine := NewAuditorSyncEngine(store)
	cfg := ComplianceSyncConfig{
		Platform: PlatformVanta,
		BaseURL:  "https://api.vanta.com",
		Token:    "", // Empty
		APIKey:   "", // Empty
		SSRF:     SSRFConfig{AllowLoopback: true, AllowPrivateIPs: true, EnforceHTTPS: true},
	}

	req := &SyncAssessmentRequest{Assessment: assessment.Assessment{ID: "asm-nocreds"}}
	res, err := engine.SyncAssessment(context.Background(), PlatformVanta, req, cfg)
	if err == nil || !errors.Is(err, ErrMissingCredentials) {
		t.Errorf("expected ErrMissingCredentials, got %v", err)
	}
	if res.Status != SyncStatusRejected {
		t.Errorf("expected status REJECTED, got %s", res.Status)
	}
}

// -----------------------------------------------------------------------------
// Test 8: Rate Limiting (HTTP 429 with Retry-After) and Bounded Retries
// -----------------------------------------------------------------------------
func TestComplianceSync_08_RateLimitingAndRetryAfter(t *testing.T) {
	var callCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&callCount, 1)
		if count == 1 {
			// First call: 429 Too Many Requests with 1 second Retry-After
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"Rate limit exceeded"}`))
			return
		}

		// Second call: 200 OK
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"vanta-rate-ok","status":"INGESTED"}`))
	}))
	defer server.Close()

	store, _ := NewSQLiteComplianceStore(":memory:")
	defer store.Close()

	engine := NewAuditorSyncEngine(store)
	cfg := ComplianceSyncConfig{
		Platform:    PlatformVanta,
		BaseURL:     server.URL,
		Token:       "tok",
		MaxRetries:  2,
		BackoffBase: 10 * time.Millisecond,
		Timeout:     5 * time.Second,
		SSRF:        SSRFConfig{AllowLoopback: true, AllowPrivateIPs: true, EnforceHTTPS: false},
	}

	req := &SyncAssessmentRequest{
		Assessment: assessment.Assessment{ID: "asm-rate-01"},
		Findings:   []assessment.AssessmentFinding{{ID: "F1", Title: "X", Severity: "LOW", Status: "REMEDIATED_VERIFIED"}},
	}

	res, err := engine.SyncAssessment(context.Background(), PlatformVanta, req, cfg)
	if err != nil {
		t.Fatalf("expected retry to succeed, got %v", err)
	}
	if res.Status != SyncStatusSuccess {
		t.Errorf("expected status SUCCESS after retry, got %s", res.Status)
	}
	if atomic.LoadInt32(&callCount) != 2 {
		t.Errorf("expected exactly 2 calls, got %d", callCount)
	}
}

// -----------------------------------------------------------------------------
// Test 9: Idempotency & Duplicate Prevention
// -----------------------------------------------------------------------------
func TestComplianceSync_09_IdempotencyDuplicatePrevention(t *testing.T) {
	var networkCalls int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&networkCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"vanta-idemp-01","status":"INGESTED"}`))
	}))
	defer server.Close()

	store, _ := NewSQLiteComplianceStore(":memory:")
	defer store.Close()

	engine := NewAuditorSyncEngine(store)
	cfg := ComplianceSyncConfig{
		Platform: PlatformVanta,
		BaseURL:  server.URL,
		Token:    "tok",
		Timeout:  5 * time.Second,
		SSRF:     SSRFConfig{AllowLoopback: true, AllowPrivateIPs: true, EnforceHTTPS: false},
	}

	req := &SyncAssessmentRequest{
		Assessment:     assessment.Assessment{ID: "asm-idemp-01", Ref: "REF-01"},
		IdempotencyKey: "fixed-deterministic-idempotency-key-001",
		Findings:       []assessment.AssessmentFinding{{ID: "F1", Title: "T", Severity: "INFO", Status: "REMEDIATED_VERIFIED"}},
	}

	// 1st sync -> reaches network
	res1, err1 := engine.SyncAssessment(context.Background(), PlatformVanta, req, cfg)
	if err1 != nil {
		t.Fatalf("first sync failed: %v", err1)
	}
	if res1.Status != SyncStatusSuccess {
		t.Errorf("expected SUCCESS for first sync, got %s", res1.Status)
	}
	if atomic.LoadInt32(&networkCalls) != 1 {
		t.Errorf("expected 1 network call, got %d", networkCalls)
	}

	// 2nd sync with same idempotency key -> cached, 0 new network calls
	res2, err2 := engine.SyncAssessment(context.Background(), PlatformVanta, req, cfg)
	if err2 != nil {
		t.Fatalf("second sync failed: %v", err2)
	}
	if res2.Status != SyncStatusSuccess {
		t.Errorf("expected SUCCESS for second sync, got %s", res2.Status)
	}
	if atomic.LoadInt32(&networkCalls) != 1 {
		t.Errorf("expected duplicate sync to be served from store without network call; got %d calls", networkCalls)
	}
}

// -----------------------------------------------------------------------------
// Test 10: Partial Failure Handling (HTTP 207 Multi-Status)
// -----------------------------------------------------------------------------
func TestComplianceSync_10_PartialFailureHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMultiStatus) // 207 Multi-Status
		_, _ = w.Write([]byte(`{
			"id": "vanta-partial-01",
			"status": "PARTIAL",
			"findings_ingested": 1,
			"findings_failed": 1,
			"errors": ["Finding FND-02 rejected: invalid endpoint format"]
		}`))
	}))
	defer server.Close()

	store, _ := NewSQLiteComplianceStore(":memory:")
	defer store.Close()

	engine := NewAuditorSyncEngine(store)
	cfg := ComplianceSyncConfig{
		Platform: PlatformVanta,
		BaseURL:  server.URL,
		Token:    "tok",
		SSRF:     SSRFConfig{AllowLoopback: true, AllowPrivateIPs: true, EnforceHTTPS: false},
	}

	req := &SyncAssessmentRequest{
		Assessment: assessment.Assessment{ID: "asm-part-01"},
		Findings: []assessment.AssessmentFinding{
			{ID: "F1", Title: "F1", Severity: "LOW", Status: "REMEDIATED_VERIFIED"},
			{ID: "F2", Title: "F2", Severity: "HIGH", Status: "REMAINING_UNRESOLVED"},
		},
	}

	res, err := engine.SyncAssessment(context.Background(), PlatformVanta, req, cfg)
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if res.Status != SyncStatusPartial {
		t.Errorf("expected PARTIAL status, got %s", res.Status)
	}
}

// -----------------------------------------------------------------------------
// Test 11: SSRF Prevention: Cloud Metadata (169.254.169.254) Refusal
// -----------------------------------------------------------------------------
func TestComplianceSync_11_SSRFCloudMetadataRefusal(t *testing.T) {
	store, _ := NewSQLiteComplianceStore(":memory:")
	defer store.Close()

	engine := NewAuditorSyncEngine(store)

	prohibitedTargets := []string{
		"http://169.254.169.254/v1/audits",
		"http://169.254.169.254:8080/v1/audits",
		"http://metadata.google.internal/computeMetadata/v1/",
	}

	for _, target := range prohibitedTargets {
		cfg := ComplianceSyncConfig{
			Platform: PlatformVanta,
			BaseURL:  target,
			Token:    "tok",
			SSRF:     SSRFConfig{AllowLoopback: true, AllowPrivateIPs: true, EnforceHTTPS: false},
		}

		req := &SyncAssessmentRequest{Assessment: assessment.Assessment{ID: "asm-meta"}}
		_, err := engine.SyncAssessment(context.Background(), PlatformVanta, req, cfg)
		if err == nil || !strings.Contains(err.Error(), "SSRF") && !errors.Is(err, ErrSSRFRefusal) {
			t.Errorf("expected SSRF refusal for cloud metadata target %q, got %v", target, err)
		}
	}
}

// -----------------------------------------------------------------------------
// Test 12: SSRF Prevention: Loopback Prohibited When AllowLoopback=false
// -----------------------------------------------------------------------------
func TestComplianceSync_12_SSRFLoopbackProhibited(t *testing.T) {
	store, _ := NewSQLiteComplianceStore(":memory:")
	defer store.Close()

	engine := NewAuditorSyncEngine(store)
	cfg := ComplianceSyncConfig{
		Platform: PlatformVanta,
		BaseURL:  "https://127.0.0.1:8443",
		Token:    "tok",
		SSRF:     SSRFConfig{AllowLoopback: false, AllowPrivateIPs: false, EnforceHTTPS: true},
	}

	req := &SyncAssessmentRequest{Assessment: assessment.Assessment{ID: "asm-loopback"}}
	_, err := engine.SyncAssessment(context.Background(), PlatformVanta, req, cfg)
	if err == nil || !strings.Contains(err.Error(), "prohibited IP") {
		t.Errorf("expected loopback prohibited error, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Test 13: SSRF Prevention: Redirect Hop to Prohibited IP Blocked
// -----------------------------------------------------------------------------
func TestComplianceSync_13_SSRFRedirectHopBlocked(t *testing.T) {
	// Server redirects to cloud metadata IP
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer server.Close()

	store, _ := NewSQLiteComplianceStore(":memory:")
	defer store.Close()

	engine := NewAuditorSyncEngine(store)
	cfg := ComplianceSyncConfig{
		Platform: PlatformVanta,
		BaseURL:  server.URL,
		Token:    "tok",
		Timeout:  3 * time.Second,
		SSRF:     SSRFConfig{AllowLoopback: true, AllowPrivateIPs: true, EnforceHTTPS: false},
	}

	req := &SyncAssessmentRequest{
		Assessment: assessment.Assessment{ID: "asm-redir"},
		Findings:   []assessment.AssessmentFinding{{ID: "F1", Title: "T", Severity: "LOW", Status: "REMEDIATED_VERIFIED"}},
	}

	_, err := engine.SyncAssessment(context.Background(), PlatformVanta, req, cfg)
	if err == nil || !strings.Contains(err.Error(), "redirect blocked") {
		t.Errorf("expected redirect blocked error for hop to 169.254.169.254, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Test 14: Secret Redaction (Zero Leakage in Errors, Logs, and Responses)
// -----------------------------------------------------------------------------
func TestComplianceSync_14_SecretRedaction(t *testing.T) {
	secretToken := "secret_vanta_token_super_confidential_99999"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		// Leaky server attempts to echo back the token in its error body
		_, _ = w.Write([]byte(fmt.Sprintf(`{"error":"Bearer token %s was rejected by policy"}`, secretToken)))
	}))
	defer server.Close()

	store, _ := NewSQLiteComplianceStore(":memory:")
	defer store.Close()

	engine := NewAuditorSyncEngine(store)
	cfg := ComplianceSyncConfig{
		Platform: PlatformVanta,
		BaseURL:  server.URL,
		Token:    secretToken,
		Timeout:  2 * time.Second,
		SSRF:     SSRFConfig{AllowLoopback: true, AllowPrivateIPs: true, EnforceHTTPS: false},
	}

	req := &SyncAssessmentRequest{
		Assessment: assessment.Assessment{ID: "asm-secret-leak"},
		Findings:   []assessment.AssessmentFinding{{ID: "F1", Title: "T", Severity: "INFO", Status: "REMEDIATED_VERIFIED"}},
	}

	res, err := engine.SyncAssessment(context.Background(), PlatformVanta, req, cfg)
	if err == nil {
		t.Fatalf("expected error from 400 Bad Request, got nil")
	}

	errStr := err.Error()
	if strings.Contains(errStr, secretToken) {
		t.Errorf("SECURITY LEAK: secret token leaked in error string: %s", errStr)
	}

	for _, eMsg := range res.Errors {
		if strings.Contains(eMsg, secretToken) {
			t.Errorf("SECURITY LEAK: secret token leaked in response errors: %s", eMsg)
		}
	}
}

// -----------------------------------------------------------------------------
// Test 15: Cryptographic Attestation Verification (Tampered Letter Rejection)
// -----------------------------------------------------------------------------
func TestComplianceSync_15_TamperedAttestationRejection(t *testing.T) {
	pub, priv, tk, _ := generateTestSigner("KEY-FELIX-TEST-15", "Tamper Test Auth")
	_ = pub
	reg := assessment.MapKeyRegistry{tk.KeyID: tk}

	att := createValidAttestationLetter(t, "asm-tamper-01", "Client", tk.KeyID, priv)
	// Tamper with the snapshot after signing
	att.Snapshot.TotalFindingsCount = 9999

	store, _ := NewSQLiteComplianceStore(":memory:")
	defer store.Close()

	engine := NewAuditorSyncEngine(store, reg)
	cfg := ComplianceSyncConfig{
		Platform: PlatformVanta,
		BaseURL:  "https://api.vanta.com",
		Token:    "tok",
		SSRF:     SSRFConfig{AllowLoopback: true, AllowPrivateIPs: true, EnforceHTTPS: false},
	}

	req := &SyncAssessmentRequest{
		Assessment:  assessment.Assessment{ID: "asm-tamper-01"},
		Attestation: &att,
	}

	res, err := engine.SyncAssessment(context.Background(), PlatformVanta, req, cfg)
	if err == nil || !errors.Is(err, ErrAttestationTampered) {
		t.Errorf("expected ErrAttestationTampered for tampered letter, got %v", err)
	}
	if res.AttestationVerificationStatus != "INVALID_SIGNATURE" {
		t.Errorf("expected INVALID_SIGNATURE status, got %s", res.AttestationVerificationStatus)
	}
}

// -----------------------------------------------------------------------------
// Test 16: Untrusted Signing Key Detection
// -----------------------------------------------------------------------------
func TestComplianceSync_16_UntrustedSigningKeyDetection(t *testing.T) {
	// Sign with Key B
	_, privB, _, _ := generateTestSigner("KEY-UNTRUSTED-B", "Rogue Signer")
	att := createValidAttestationLetter(t, "asm-untrusted-01", "Client", "KEY-UNTRUSTED-B", privB)

	// Registry only trusts Key A
	_, _, tkA, _ := generateTestSigner("KEY-TRUSTED-A", "Authoritative Signer")
	reg := assessment.MapKeyRegistry{tkA.KeyID: tkA}

	store, _ := NewSQLiteComplianceStore(":memory:")
	defer store.Close()

	engine := NewAuditorSyncEngine(store, reg)
	cfg := ComplianceSyncConfig{
		Platform: PlatformVanta,
		BaseURL:  "https://api.vanta.com",
		Token:    "tok",
		SSRF:     SSRFConfig{AllowLoopback: true, AllowPrivateIPs: true, EnforceHTTPS: false},
	}

	req := &SyncAssessmentRequest{
		Assessment:  assessment.Assessment{ID: "asm-untrusted-01"},
		Attestation: &att,
	}

	res, err := engine.SyncAssessment(context.Background(), PlatformVanta, req, cfg)
	if err == nil || !errors.Is(err, ErrAttestationTampered) {
		t.Errorf("expected ErrAttestationTampered for untrusted key, got %v", err)
	}
	if res.Status != SyncStatusRejected {
		t.Errorf("expected status REJECTED, got %s", res.Status)
	}
}

// -----------------------------------------------------------------------------
// Test 17: Retest State Preservation (Exact 6-State Transitions Preserved)
// -----------------------------------------------------------------------------
func TestComplianceSync_17_RetestStatePreservation(t *testing.T) {
	var vantaReceived []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vantaReceived, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"vanta-retest-ok","status":"INGESTED"}`))
	}))
	defer server.Close()

	store, _ := NewSQLiteComplianceStore(":memory:")
	defer store.Close()

	engine := NewAuditorSyncEngine(store)
	cfg := ComplianceSyncConfig{
		Platform: PlatformVanta,
		BaseURL:  server.URL,
		Token:    "tok",
		SSRF:     SSRFConfig{AllowLoopback: true, AllowPrivateIPs: true, EnforceHTTPS: false},
	}

	req := &SyncAssessmentRequest{
		Assessment: assessment.Assessment{ID: "asm-retest-01"},
		RetestResult: &assessment.RetestResult{
			Comparison: &assessment.FullAssessmentComparison{
				RetestMode:               assessment.RetestModeFull,
				OriginalFindingCount:     4,
				RemediatedVerifiedCount:  1,
				SimulatedRemediatedCount: 0,
			},
		},
		Findings: []assessment.AssessmentFinding{
			{ID: "F1", Title: "Remediated Defect", Status: "REMEDIATED_VERIFIED", Severity: "HIGH"},
			{ID: "F2", Title: "Unresolved Defect", Status: "REMAINING_UNRESOLVED", Severity: "CRITICAL"},
			{ID: "F3", Title: "Inconclusive Probe", Status: "INCONCLUSIVE", Severity: "MEDIUM"},
			{ID: "F4", Title: "Out of Scope Route", Status: "OUT_OF_SCOPE_OR_ASSET_UNAVAILABLE", Severity: "LOW"},
		},
	}

	res, err := engine.SyncAssessment(context.Background(), PlatformVanta, req, cfg)
	if err != nil {
		t.Fatalf("SyncAssessment failed: %v", err)
	}

	if res.RemediatedCount != 1 {
		t.Errorf("expected exactly 1 RemediatedCount, got %d", res.RemediatedCount)
	}
	if res.UnresolvedCount != 3 {
		t.Errorf("expected 3 UnresolvedCount (unresolved + inconclusive + out of scope), got %d", res.UnresolvedCount)
	}

	var payload VantaPenTestPayload
	_ = json.Unmarshal(vantaReceived, &payload)
	for _, f := range payload.Findings {
		switch f.FindingID {
		case "F1":
			if f.Status != "resolved" || f.RemediationStatus != "REMEDIATED_VERIFIED" {
				t.Errorf("F1 transition corrupted: status=%s, remStatus=%s", f.Status, f.RemediationStatus)
			}
		case "F2":
			if f.Status != "open" || f.RemediationStatus != "REMAINING_UNRESOLVED" {
				t.Errorf("F2 transition corrupted: status=%s, remStatus=%s", f.Status, f.RemediationStatus)
			}
		case "F3":
			if f.Status != "open" || f.RemediationStatus != "INCONCLUSIVE" {
				t.Errorf("F3 transition corrupted: status=%s, remStatus=%s", f.Status, f.RemediationStatus)
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Test 18: Simulated Fixture Segregation
// -----------------------------------------------------------------------------
func TestComplianceSync_18_SimulatedFixtureSegregation(t *testing.T) {
	var drataReceived []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		drataReceived, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"evidence_id":"drata-sim-ok","status":"UPLOADED"}`))
	}))
	defer server.Close()

	store, _ := NewSQLiteComplianceStore(":memory:")
	defer store.Close()

	engine := NewAuditorSyncEngine(store)
	cfg := ComplianceSyncConfig{
		Platform: PlatformDrata,
		BaseURL:  server.URL,
		Token:    "tok",
		SSRF:     SSRFConfig{AllowLoopback: true, AllowPrivateIPs: true, EnforceHTTPS: false},
	}

	req := &SyncAssessmentRequest{
		Assessment: assessment.Assessment{ID: "asm-sim-01"},
		Findings: []assessment.AssessmentFinding{
			{
				ID:       "FND-LIVE-01",
				Title:    "Live Remediated Defect",
				Severity: "HIGH",
				Status:   "REMEDIATED_VERIFIED",
				VerificationRecord: report.VerificationRecord{
					SyntheticFixture: false,
				},
			},
			{
				ID:       "FND-SIM-01",
				Title:    "Simulated Fixture Defect",
				Severity: "HIGH",
				Status:   "REMEDIATED_VERIFIED",
				VerificationRecord: report.VerificationRecord{
					SyntheticFixture: true, // Marked as synthetic fixture!
				},
			},
		},
	}

	res, err := engine.SyncAssessment(context.Background(), PlatformDrata, req, cfg)
	if err != nil {
		t.Fatalf("Drata sync failed: %v", err)
	}

	// Verify that simulated finding is segregated from real verified remediation count
	if res.RemediatedCount != 1 {
		t.Errorf("expected RemediatedCount=1 (only live finding), got %d", res.RemediatedCount)
	}
	if res.SimulatedFindingsCount != 1 {
		t.Errorf("expected SimulatedFindingsCount=1, got %d", res.SimulatedFindingsCount)
	}

	var payload DrataEvidencePayload
	_ = json.Unmarshal(drataReceived, &payload)
	for _, m := range payload.FindingMappings {
		if m.FindingID == "FND-SIM-01" && !m.IsSimulated {
			t.Errorf("expected FND-SIM-01 to have IsSimulated=true in payload")
		}
		if m.FindingID == "FND-LIVE-01" && m.IsSimulated {
			t.Errorf("expected FND-LIVE-01 to have IsSimulated=false in payload")
		}
	}
}

// -----------------------------------------------------------------------------
// Test 19: Inbound Status Non-Trust
// -----------------------------------------------------------------------------
func TestComplianceSync_19_InboundStatusNonTrust(t *testing.T) {
	// External platform claims the audit is closed / completed
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"id": "vanta-audit-closed-99",
			"status": "COMPLETED_RESOLVED",
			"remediated": true
		}`))
	}))
	defer server.Close()

	adapter, _ := NewVantaAdapter(ComplianceSyncConfig{
		Platform: PlatformVanta,
		BaseURL:  server.URL,
		Token:    "tok",
		SSRF:     SSRFConfig{AllowLoopback: true, AllowPrivateIPs: true, EnforceHTTPS: false},
	})

	extStatus, err := adapter.GetSyncStatus(context.Background(), "vanta-audit-closed-99")
	if err != nil {
		t.Fatalf("GetSyncStatus failed: %v", err)
	}

	// Invariant: External closure does NOT prove remediation!
	if extStatus.RemediationProofAcknowledged {
		t.Errorf("TRUTH IN ENGINEERING VIOLATION: external platform status claimed remediation proof acknowledged")
	}
}

// -----------------------------------------------------------------------------
// Test 20: Persistence & Recovery (SQLite Store Round-Trip)
// -----------------------------------------------------------------------------
func TestComplianceSync_20_PersistenceAndRecoveryRoundTrip(t *testing.T) {
	dbPath := t.TempDir() + "/compliance_test.db"

	store1, err := NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("failed creating store1: %v", err)
	}

	now := time.Now().UTC()
	rec := &PlatformSyncRecord{
		SyncID:              "sync-rec-roundtrip-01",
		Platform:            PlatformVanta,
		AssessmentID:        "asm-rt-01",
		ExecutionID:         "exec-rt-01",
		AttestationLetterID: "ATT-RT-01",
		ExternalRecordID:    "vanta-ext-999",
		ExternalURL:         "https://app.vanta.com/audits/vanta-ext-999",
		Status:              SyncStatusSuccess,
		IdempotencyKey:      "idemp-rt-key-123",
		PayloadDigest:       "sha256:abc1234567890",
		RecordsSynced:       5,
		RecordsFailed:       0,
		SyncedAt:            now,
		CreatedAt:           now,
	}

	if err := store1.SavePlatformSyncRecord(rec); err != nil {
		t.Fatalf("SavePlatformSyncRecord failed: %v", err)
	}
	_ = store1.Close()

	// Reopen store from disk and assert recovery
	store2, err := NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("failed reopening store2: %v", err)
	}
	defer store2.Close()

	recovered, err := store2.GetPlatformSyncRecord("sync-rec-roundtrip-01")
	if err != nil {
		t.Fatalf("GetPlatformSyncRecord failed: %v", err)
	}

	if recovered.Platform != PlatformVanta {
		t.Errorf("expected platform Vanta, got %s", recovered.Platform)
	}
	if recovered.ExternalRecordID != "vanta-ext-999" {
		t.Errorf("expected external record ID 'vanta-ext-999', got %s", recovered.ExternalRecordID)
	}
	if recovered.Status != SyncStatusSuccess {
		t.Errorf("expected status SUCCESS, got %s", recovered.Status)
	}
	if recovered.RecordsSynced != 5 {
		t.Errorf("expected 5 records synced, got %d", recovered.RecordsSynced)
	}

	// Query by idempotency key
	byKey, err := store2.GetPlatformSyncRecordByIdempotencyKey("idemp-rt-key-123")
	if err != nil {
		t.Fatalf("GetPlatformSyncRecordByIdempotencyKey failed: %v", err)
	}
	if byKey.SyncID != "sync-rec-roundtrip-01" {
		t.Errorf("expected sync ID 'sync-rec-roundtrip-01', got %s", byKey.SyncID)
	}
}

// -----------------------------------------------------------------------------
// Test 21: DNS Rebinding and Resolved-IP Validation
// -----------------------------------------------------------------------------
type mockRebindingResolver struct {
	resolvedIPs []net.IPAddr
	err         error
}

func (m *mockRebindingResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.resolvedIPs, nil
}

func TestComplianceSync_21_DNSRebindingAndResolvedIPValidation(t *testing.T) {
	store, _ := NewSQLiteComplianceStore(":memory:")
	defer store.Close()

	engine := NewAuditorSyncEngine(store)

	// Resolver resolves an innocent-looking domain to a private RFC 1918 address (10.0.0.99)
	mockResolver := &mockRebindingResolver{
		resolvedIPs: []net.IPAddr{{IP: net.ParseIP("10.0.0.99")}},
	}

	cfg := ComplianceSyncConfig{
		Platform: PlatformVanta,
		BaseURL:  "https://innocent-vanta-sync.example.com",
		Token:    "tok",
		SSRF: SSRFConfig{
			AllowLoopback:   false,
			AllowPrivateIPs: false,
			EnforceHTTPS:    true,
			Resolver:        mockResolver,
		},
	}

	req := &SyncAssessmentRequest{
		Assessment: assessment.Assessment{ID: "asm-dns-rebind-01"},
		Findings:   []assessment.AssessmentFinding{{ID: "F1", Title: "T", Severity: "LOW", Status: "REMEDIATED_VERIFIED"}},
	}

	_, err := engine.SyncAssessment(context.Background(), PlatformVanta, req, cfg)
	if err == nil {
		t.Fatal("expected DNS rebinding / resolved-IP validation rejection, got nil")
	}
	if !errors.Is(err, ErrSSRFRefusal) && !strings.Contains(err.Error(), "prohibited IP") {
		t.Errorf("expected SSRF refusal for resolved private IP, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Test 22: Request Timeout and Bounded Execution Handling
// -----------------------------------------------------------------------------
func TestComplianceSync_22_RequestTimeoutHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"vanta-t1"}`))
	}))
	defer server.Close()

	store, _ := NewSQLiteComplianceStore(":memory:")
	defer store.Close()

	engine := NewAuditorSyncEngine(store)
	cfg := ComplianceSyncConfig{
		Platform:   PlatformVanta,
		BaseURL:    server.URL,
		Token:      "tok",
		Timeout:    50 * time.Millisecond,
		MaxRetries: 0,
		SSRF:       SSRFConfig{AllowLoopback: true, AllowPrivateIPs: true, EnforceHTTPS: false},
	}

	req := &SyncAssessmentRequest{
		Assessment: assessment.Assessment{ID: "asm-timeout-01"},
		Findings:   []assessment.AssessmentFinding{{ID: "F1", Title: "T", Severity: "LOW", Status: "REMEDIATED_VERIFIED"}},
	}

	_, err := engine.SyncAssessment(context.Background(), PlatformVanta, req, cfg)
	if err == nil {
		t.Fatal("expected request timeout error, got nil")
	}
}

// -----------------------------------------------------------------------------
// Test 23: Pagination Support (ListPlatformSyncRecordsPaged)
// -----------------------------------------------------------------------------
func TestComplianceSync_23_PaginationSupport(t *testing.T) {
	store, err := NewSQLiteComplianceStore(":memory:")
	if err != nil {
		t.Fatalf("failed creating store: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	for i := 1; i <= 5; i++ {
		rec := &PlatformSyncRecord{
			SyncID:         fmt.Sprintf("sync-page-%02d", i),
			Platform:       PlatformVanta,
			AssessmentID:   "asm-paged-01",
			Status:         SyncStatusSuccess,
			IdempotencyKey: fmt.Sprintf("idemp-page-%02d", i),
			SyncedAt:       now.Add(time.Duration(i) * time.Minute),
			CreatedAt:      now.Add(time.Duration(i) * time.Minute),
		}
		if err := store.SavePlatformSyncRecord(rec); err != nil {
			t.Fatalf("SavePlatformSyncRecord failed: %v", err)
		}
	}

	// Page 1: limit 2, offset 0 -> newest 2 (sync-page-05, sync-page-04)
	page1, err := store.ListPlatformSyncRecordsPaged("", "asm-paged-01", 2, 0)
	if err != nil {
		t.Fatalf("ListPlatformSyncRecordsPaged page 1 failed: %v", err)
	}
	if len(page1) != 2 {
		t.Fatalf("expected 2 records on page 1, got %d", len(page1))
	}
	if page1[0].SyncID != "sync-page-05" || page1[1].SyncID != "sync-page-04" {
		t.Errorf("unexpected page 1 items: %s, %s", page1[0].SyncID, page1[1].SyncID)
	}

	// Page 2: limit 2, offset 2 -> next 2 (sync-page-03, sync-page-02)
	page2, err := store.ListPlatformSyncRecordsPaged("", "asm-paged-01", 2, 2)
	if err != nil {
		t.Fatalf("ListPlatformSyncRecordsPaged page 2 failed: %v", err)
	}
	if len(page2) != 2 {
		t.Fatalf("expected 2 records on page 2, got %d", len(page2))
	}
	if page2[0].SyncID != "sync-page-03" || page2[1].SyncID != "sync-page-02" {
		t.Errorf("unexpected page 2 items: %s, %s", page2[0].SyncID, page2[1].SyncID)
	}

	// Page 3: limit 2, offset 4 -> remaining 1 (sync-page-01)
	page3, err := store.ListPlatformSyncRecordsPaged("", "asm-paged-01", 2, 4)
	if err != nil {
		t.Fatalf("ListPlatformSyncRecordsPaged page 3 failed: %v", err)
	}
	if len(page3) != 1 {
		t.Fatalf("expected 1 record on page 3, got %d", len(page3))
	}
	if page3[0].SyncID != "sync-page-01" {
		t.Errorf("unexpected page 3 item: %s", page3[0].SyncID)
	}
}

// -----------------------------------------------------------------------------
// Test 24: Malformed and Hostile Vendor API Responses
// -----------------------------------------------------------------------------
func TestComplianceSync_24_MalformedHostileVendorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><title>502 Bad Gateway</title></head><body>Hostile WAF Interception</body></html>`))
	}))
	defer server.Close()

	store, _ := NewSQLiteComplianceStore(":memory:")
	defer store.Close()

	engine := NewAuditorSyncEngine(store)
	cfg := ComplianceSyncConfig{
		Platform: PlatformVanta,
		BaseURL:  server.URL,
		Token:    "tok",
		SSRF:     SSRFConfig{AllowLoopback: true, AllowPrivateIPs: true, EnforceHTTPS: false},
	}

	req := &SyncAssessmentRequest{
		Assessment: assessment.Assessment{ID: "asm-malformed-01"},
		Findings:   []assessment.AssessmentFinding{{ID: "F1", Title: "T", Severity: "LOW", Status: "REMEDIATED_VERIFIED"}},
	}

	res, err := engine.SyncAssessment(context.Background(), PlatformVanta, req, cfg)
	if err == nil {
		t.Fatal("expected error on malformed vendor HTML response, got nil")
	}
	if res.Status != SyncStatusFailed {
		t.Errorf("expected SyncStatusFailed, got %s", res.Status)
	}
	if !strings.Contains(err.Error(), "malformed vendor JSON response") {
		t.Errorf("expected malformed vendor error, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Test 25: Conflicting Sync Record Rejection
// -----------------------------------------------------------------------------
func TestComplianceSync_25_ConflictingSyncRecordRejection(t *testing.T) {
	store, _ := NewSQLiteComplianceStore(":memory:")
	defer store.Close()

	now := time.Now().UTC()
	// Pre-populate store with an existing sync for ASM-01 with fixed idempotency key
	existing := &PlatformSyncRecord{
		SyncID:         "sync-orig-01",
		Platform:       PlatformVanta,
		AssessmentID:   "ASM-ORIGINAL-01",
		Status:         SyncStatusSuccess,
		IdempotencyKey: "idemp-shared-key-999",
		SyncedAt:       now,
		CreatedAt:      now,
	}
	if err := store.SavePlatformSyncRecord(existing); err != nil {
		t.Fatalf("SavePlatformSyncRecord failed: %v", err)
	}

	engine := NewAuditorSyncEngine(store)
	cfg := ComplianceSyncConfig{
		Platform: PlatformVanta,
		BaseURL:  "https://api.vanta.com",
		Token:    "tok",
	}

	// Mismatched assessment using the same idempotency key
	req := &SyncAssessmentRequest{
		Assessment:     assessment.Assessment{ID: "ASM-ATTACKER-COLLISION-02"},
		IdempotencyKey: "idemp-shared-key-999",
		Findings:       []assessment.AssessmentFinding{{ID: "F1", Title: "T", Severity: "LOW", Status: "REMEDIATED_VERIFIED"}},
	}

	_, err := engine.SyncAssessment(context.Background(), PlatformVanta, req, cfg)
	if err == nil {
		t.Fatal("expected conflict error for mismatched assessment ID with identical idempotency key, got nil")
	}
	if !strings.Contains(err.Error(), "conflicting sync record") {
		t.Errorf("expected conflict error, got %v", err)
	}
}

// -----------------------------------------------------------------------------
// Test 26: Unsupported Platform Rejection
// -----------------------------------------------------------------------------
func TestComplianceSync_26_UnsupportedPlatformRejection(t *testing.T) {
	store, _ := NewSQLiteComplianceStore(":memory:")
	defer store.Close()

	engine := NewAuditorSyncEngine(store)
	cfg := ComplianceSyncConfig{
		Platform: CompliancePlatform("UNSUPPORTED_VENDOR_XYZ"),
		BaseURL:  "https://api.unsupported.com",
		Token:    "tok",
	}

	req := &SyncAssessmentRequest{
		Assessment: assessment.Assessment{ID: "asm-unsupported-01"},
		Findings:   []assessment.AssessmentFinding{{ID: "F1", Title: "T", Severity: "LOW", Status: "REMEDIATED_VERIFIED"}},
	}

	_, err := engine.SyncAssessment(context.Background(), CompliancePlatform("UNSUPPORTED_VENDOR_XYZ"), req, cfg)
	if err == nil {
		t.Fatal("expected unsupported platform error, got nil")
	}
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("expected ErrUnsupportedPlatform, got %v", err)
	}
}
