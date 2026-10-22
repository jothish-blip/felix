package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"felix/pkg/report"
)

func TestSeverityRankAndThresholds(t *testing.T) {
	if SeverityRank(SeverityCritical) != 5 {
		t.Errorf("expected 5 for CRITICAL")
	}
	if SeverityRank(SeverityHigh) != 4 {
		t.Errorf("expected 4 for HIGH")
	}
	if SeverityRank(SeverityMedium) != 3 {
		t.Errorf("expected 3 for MEDIUM")
	}
	if SeverityRank(SeverityLow) != 2 {
		t.Errorf("expected 2 for LOW")
	}
	if SeverityRank(SeverityInfo) != 1 {
		t.Errorf("expected 1 for INFO")
	}

	if !MeetsSeverityThreshold("CRITICAL", "LOW") {
		t.Errorf("CRITICAL should exceed LOW")
	}
	if MeetsSeverityThreshold("LOW", "HIGH") {
		t.Errorf("LOW should not meet HIGH")
	}
	if !MeetsSeverityThreshold("HIGH", "") {
		t.Errorf("empty threshold should pass all")
	}
}

func TestSSRFProhibitedRanges(t *testing.T) {
	if err := CheckSafeDestination("127.0.0.1", time.Second); err == nil {
		t.Errorf("expected 127.0.0.1 to be prohibited")
	}
	if err := CheckSafeDestination("10.1.2.3", time.Second); err == nil {
		t.Errorf("expected 10.1.2.3 to be prohibited")
	}
	if err := CheckSafeDestination("192.168.1.1", time.Second); err == nil {
		t.Errorf("expected 192.168.1.1 to be prohibited")
	}
	if err := CheckSafeDestination("169.254.169.254", time.Second); err == nil {
		t.Errorf("expected 169.254.169.254 to be prohibited")
	}
}

func TestWebhookSignatureGeneration(t *testing.T) {
	secret := "test-secret-key-123"
	payload := []byte(`{"title":"hello"}`)
	sig := ComputeWebhookSignature(secret, payload)
	if sig == "" {
		t.Fatalf("expected non-empty HMAC signature")
	}

	// Verify exact reproducibility
	sig2 := ComputeWebhookSignature(secret, payload)
	if sig != sig2 {
		t.Errorf("expected deterministic signature: %s != %s", sig, sig2)
	}
}

func TestWebhookProviderDelivery(t *testing.T) {
	var receivedEvent, receivedDelivery, receivedSig string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedEvent = r.Header.Get("X-Felix-Event")
		receivedDelivery = r.Header.Get("X-Felix-Delivery")
		receivedSig = r.Header.Get("X-Felix-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	prov, err := NewWebhookProvider(WebhookConfig{
		URL:               server.URL,
		Secret:            "my-hmac-secret",
		AllowInsecureHTTP: true,
		AllowPrivateIPs:   true,
		AllowLoopback:     true,
	})
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}

	now := time.Now().UTC()
	n := BuildLifecycleNotification("t-1", "acc-1", "asm-1", "ASM-1", "exec-1", "COMPLETED", 2, time.Second, "", now)
	receipt, err := prov.Send(context.Background(), n)
	if err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if receipt.StatusCode != 200 {
		t.Errorf("expected 200 status, got %d", receipt.StatusCode)
	}

	if receivedEvent != EventAssessmentCompleted {
		t.Errorf("expected event %s, got %s", EventAssessmentCompleted, receivedEvent)
	}
	if receivedDelivery != n.ID {
		t.Errorf("expected delivery ID %s, got %s", n.ID, receivedDelivery)
	}
	if !strings.HasPrefix(receivedSig, "v1=") && !strings.HasPrefix(receivedSig, "sha256=") {
		t.Errorf("expected v1= or sha256= prefix in signature, got %s", receivedSig)
	}
}

func TestDispatcherBackoffCalculation(t *testing.T) {
	d := NewOutboxDispatcher(nil, nil, DispatcherConfig{
		InitialRetryDelay: 1 * time.Second,
		MaxRetryDelay:     60 * time.Second,
	})

	b1 := d.calculateBackoff(1)
	if b1 < 1*time.Second || b1 > 2*time.Second {
		t.Errorf("backoff 1 out of expected range: %v", b1)
	}

	b3 := d.calculateBackoff(3)
	if b3 < 4*time.Second || b3 > 6*time.Second {
		t.Errorf("backoff 3 out of expected range: %v", b3)
	}

	bLarge := d.calculateBackoff(10)
	if bLarge > 75*time.Second {
		t.Errorf("backoff capped improperly: %v", bLarge)
	}
}

func TestModelFindingIDsJSON(t *testing.T) {
	n := &Notification{
		FindingIDs: []string{"fnd-1", "fnd-2"},
	}
	raw := n.FindingIDsJSON()
	if !strings.Contains(raw, "fnd-1") || !strings.Contains(raw, "fnd-2") {
		t.Errorf("unexpected json: %s", raw)
	}

	n2 := &Notification{}
	n2.SetFindingIDsFromJSON(raw)
	if len(n2.FindingIDs) != 2 || n2.FindingIDs[0] != "fnd-1" || n2.FindingIDs[1] != "fnd-2" {
		t.Errorf("deserialization mismatch: %+v", n2.FindingIDs)
	}
}

func TestBuildDeltaNotificationVariants(t *testing.T) {
	now := time.Now().UTC()
	item := report.ChangeFindingItem{
		FindingID:   "fnd-test",
		Fingerprint: "fp-test",
		Title:       "Test Issue",
		Severity:    "HIGH",
		Reason:      "Reappeared issue",
	}

	regNotif := BuildDeltaNotification("t-1", "", "asm-1", "ASM-1", "exec-1", "base-1", "REGRESSED", item, now)
	if regNotif.EventType != EventSecurityFindingRegressed {
		t.Errorf("expected EventSecurityFindingRegressed, got %s", regNotif.EventType)
	}
	if !strings.Contains(regNotif.Title, "REGRESSION") {
		t.Errorf("expected title to mention regression, got %s", regNotif.Title)
	}

	resNotif := BuildDeltaNotification("t-1", "", "asm-1", "ASM-1", "exec-1", "base-1", "RESOLVED", item, now)
	if resNotif.EventType != EventSecurityFindingResolved {
		t.Errorf("expected EventSecurityFindingResolved, got %s", resNotif.EventType)
	}
}
