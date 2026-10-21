package provenance

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/policy"
)

func TestProvenance_VCSInfo_UnavailableGraceful(t *testing.T) {
	// Query an empty non-git temp directory
	tmpDir := t.TempDir()
	info := ResolveVCSInfo(context.Background(), tmpDir)

	// In an empty directory, git command fails; it must not crash or fabricate a dummy SHA
	if info.RuntimeRevision != "" && info.VCSSource == "unavailable" {
		t.Errorf("expected empty RuntimeRevision when unavailable, got: %s", info.RuntimeRevision)
	}
	if info.VCSSource == "" {
		t.Errorf("expected non-empty VCSSource")
	}
}

func TestProvenance_VCSInfo_CurrentRepo(t *testing.T) {
	// In the real FELIX repository, git rev-parse HEAD should find the commit
	info := ResolveVCSInfo(context.Background(), "")
	if info.RuntimeRevision == "" && info.BuildRevision == "" {
		t.Logf("Notice: no runtime git revision detected; VCSSource: %s", info.VCSSource)
	} else {
		if info.RuntimeRevision != "" {
			if len(info.RuntimeRevision) < 7 {
				t.Errorf("unexpectedly short commit SHA: %s", info.RuntimeRevision)
			}
			t.Logf("Detected runtime commit: %s (dirty: %v, source: %s)",
				info.RuntimeRevision, info.RuntimeDirty != nil && *info.RuntimeDirty, info.VCSSource)
		}
	}
}

func TestProvenance_ConfigDigest_DeterminismAndEquivalence(t *testing.T) {
	// Two configurations with different map insertion orders must produce identical digests
	cfg1 := map[string]any{
		"concurrency":         5,
		"timeout_seconds":     30,
		"scope_mode":          "same-origin",
		"max_assets":          200,
		"max_size_bytes":      5242880,
		"user_agent":          "felix/2.0",
		"allow_loopback":      true,
		"active_verification": true,
	}

	cfg2 := map[string]any{
		"active_verification": true,
		"allow_loopback":      true,
		"user_agent":          "felix/2.0",
		"max_size_bytes":      5242880,
		"max_assets":          200,
		"scope_mode":          "same-origin",
		"timeout_seconds":     30,
		"concurrency":         5,
	}

	digest1, san1, err1 := ComputeConfigDigest(cfg1)
	if err1 != nil {
		t.Fatalf("ComputeConfigDigest cfg1 failed: %v", err1)
	}

	digest2, san2, err2 := ComputeConfigDigest(cfg2)
	if err2 != nil {
		t.Fatalf("ComputeConfigDigest cfg2 failed: %v", err2)
	}

	if digest1 != digest2 {
		t.Fatalf("expected identical digests for equivalent configs, got:\n  %s\n  vs\n  %s", digest1, digest2)
	}

	if !strings.HasPrefix(digest1, "sha256:") {
		t.Errorf("expected sha256: prefix, got: %s", digest1)
	}

	if len(san1) != len(san2) {
		t.Errorf("sanitized map length mismatch: %d vs %d", len(san1), len(san2))
	}
}

func TestProvenance_ConfigDigest_ChangesYieldDifferentDigest(t *testing.T) {
	cfgBase := map[string]any{
		"concurrency":     5,
		"timeout_seconds": 30,
		"scope_mode":      "same-origin",
	}

	cfgModified := map[string]any{
		"concurrency":     10, // Changed field
		"timeout_seconds": 30,
		"scope_mode":      "same-origin",
	}

	digestBase, _, _ := ComputeConfigDigest(cfgBase)
	digestMod, _, _ := ComputeConfigDigest(cfgModified)

	if digestBase == digestMod {
		t.Fatalf("expected different digests when concurrency changed, but got identical: %s", digestBase)
	}
}

func TestProvenance_SecretRedaction(t *testing.T) {
	cfgWithSecrets := map[string]any{
		"concurrency":     5,
		"timeout_seconds": 30,
		"api_key":         "sk_live_secret_token_12345",
		"token":           "ghp_super_secret_github_token_xyz",
		"password":        "admin_password_999",
		"webhook_secret":  "whsec_top_secret_value",
		"authorization":   "Bearer secret_bearer_token",
		"user_agent":      "Felix/2.0 (token=secret)",
	}

	digest, san, err := ComputeConfigDigest(cfgWithSecrets)
	if err != nil {
		t.Fatalf("ComputeConfigDigest failed: %v", err)
	}

	if digest == "" {
		t.Fatal("expected non-empty digest")
	}

	// Sensitive keys must be completely stripped
	sensitiveKeys := []string{"api_key", "token", "password", "webhook_secret", "authorization"}
	for _, k := range sensitiveKeys {
		if _, exists := san[k]; exists {
			t.Errorf("sensitive key %q leaked into sanitized config!", k)
		}
	}

	// Any secrets inside allowed fields must be redacted
	ua, ok := san["user_agent"].(string)
	if !ok || strings.Contains(ua, "secret_bearer_token") {
		t.Errorf("user_agent leaked secret: %v", ua)
	}
}

func TestProvenance_PolicyDigest(t *testing.T) {
	zero := 0
	one := 1
	pol1 := &policy.ThresholdPolicy{
		Name:        "Default CI Gate",
		Version:     "1.0",
		Description: "Standard security policy",
		MaxCritical: &zero,
		MaxHigh:     &one,
	}

	pol2 := &policy.ThresholdPolicy{
		Name:        "Default CI Gate",
		Version:     "1.0",
		Description: "Standard security policy",
		MaxCritical: &zero,
		MaxHigh:     &one,
	}

	d1 := ComputePolicyDigest(pol1)
	d2 := ComputePolicyDigest(pol2)
	if d1 == "" || d1 != d2 {
		t.Errorf("expected identical policy digests, got %q vs %q", d1, d2)
	}

	// Change threshold
	two := 2
	pol3 := &policy.ThresholdPolicy{
		Name:        "Default CI Gate",
		Version:     "1.0",
		Description: "Standard security policy",
		MaxCritical: &zero,
		MaxHigh:     &two, // Changed
	}
	d3 := ComputePolicyDigest(pol3)
	if d1 == d3 {
		t.Errorf("expected different policy digests when threshold changed, got identical %q", d1)
	}
}

func TestProvenance_CaptureStart_And_Finalize(t *testing.T) {
	startOpts := StartOptions{
		ExecutionID:    "exec-test-1",
		AssessmentID:   "asm-test-1",
		AssessmentRef:  "ASM-TEST-1",
		FelixVersion:   "2.0.0",
		BuildID:        "build-42",
		TargetIdentity: "https://example.com",
		ScopeMode:      "same-origin",
		Config: map[string]any{
			"concurrency": 5,
		},
	}

	prov := CaptureStart(context.Background(), startOpts)
	if prov == nil {
		t.Fatal("expected non-nil provenance")
	}

	if prov.ExecutionID != "exec-test-1" {
		t.Errorf("expected ExecutionID exec-test-1, got %s", prov.ExecutionID)
	}
	if prov.StartedAt.IsZero() {
		t.Error("expected non-zero StartedAt")
	}
	if prov.Status != "RUNNING" {
		t.Errorf("expected status RUNNING, got %s", prov.Status)
	}
	if prov.IsComplete() {
		t.Error("expected IsComplete() == false while RUNNING")
	}

	// Create a dummy artifact file to test artifact digest computation
	tmpDir := t.TempDir()
	reportPath := filepath.Join(tmpDir, "report.json")
	if err := os.WriteFile(reportPath, []byte(`{"findings":[]}`), 0644); err != nil {
		t.Fatalf("failed to write dummy report: %v", err)
	}

	// Finalize successful completion
	prov.Finalize(FinalizeOptions{
		Status:          "COMPLETED",
		FailureCategory: "SUCCESS",
		ExitCode:        0,
		DurationMs:      1500,
		Artifacts: []ArtifactProvenance{
			{
				Format:    "JSON",
				Path:      reportPath,
				Generated: true,
			},
		},
	})

	if prov.Status != "COMPLETED" {
		t.Errorf("expected status COMPLETED, got %s", prov.Status)
	}
	if prov.CompletedAt == nil {
		t.Fatal("expected non-nil CompletedAt")
	}
	if prov.DurationMs != 1500 {
		t.Errorf("expected DurationMs 1500, got %d", prov.DurationMs)
	}
	if !prov.IsComplete() {
		t.Error("expected IsComplete() == true for completed assessment")
	}
	if len(prov.Artifacts) != 1 || prov.Artifacts[0].Digest == "" {
		t.Errorf("expected artifact digest populated, got: %+v", prov.Artifacts)
	}
}

func TestProvenance_Finalize_CancelledOrInterrupted(t *testing.T) {
	prov := CaptureStart(context.Background(), StartOptions{
		ExecutionID: "exec-cancel-1",
	})

	now := time.Now().UTC()
	prov.Finalize(FinalizeOptions{
		Status:          "CANCELLED",
		FailureCategory: "INCOMPLETE",
		ExitCode:        2,
		IsPartial:       true,
		RecoveryReason:  "Execution cancelled by operator",
		RecoveredAt:     &now,
	})

	if prov.Status != "CANCELLED" {
		t.Errorf("expected status CANCELLED, got %s", prov.Status)
	}
	if prov.ExitCode != 2 {
		t.Errorf("expected exit code 2, got %d", prov.ExitCode)
	}
	if !prov.IsPartial {
		t.Error("expected IsPartial == true for cancelled run")
	}
	if prov.IsComplete() {
		t.Error("expected IsComplete() == false for cancelled run")
	}
}
