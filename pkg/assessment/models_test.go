package assessment

import (
	"testing"
	"time"
)

func TestAssessmentStatusTransitions(t *testing.T) {
	// Valid transitions
	validCases := [][2]AssessmentStatus{
		{StatusDraft, StatusReady},
		{StatusDraft, StatusCancelled},
		{StatusReady, StatusRunning},
		{StatusReady, StatusDraft},
		{StatusReady, StatusCancelled},
		{StatusRunning, StatusCompleted},
		{StatusRunning, StatusCompletedWithErrors},
		{StatusRunning, StatusFailed},
		{StatusRunning, StatusCancelled},
		{StatusCompleted, StatusReady},
		{StatusCompleted, StatusRunning},
		{StatusFailed, StatusReady},
	}

	for _, tc := range validCases {
		if !IsValidTransition(tc[0], tc[1]) {
			t.Errorf("expected valid transition from %s to %s, got false", tc[0], tc[1])
		}
	}

	// Invalid transitions
	invalidCases := [][2]AssessmentStatus{
		{StatusDraft, StatusCompleted},
		{StatusDraft, StatusRunning},
		{StatusDraft, StatusFailed},
		{StatusCompleted, StatusDraft},
		{StatusCancelled, StatusDraft},
	}

	for _, tc := range invalidCases {
		if IsValidTransition(tc[0], tc[1]) {
			t.Errorf("expected invalid transition from %s to %s, got true", tc[0], tc[1])
		}
	}
}

func TestAuthorizationValidity(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-48 * time.Hour)
	yesterday := now.Add(-24 * time.Hour)
	tomorrow := now.Add(24 * time.Hour)
	future := now.Add(48 * time.Hour)

	// 1. Nil authorization
	var nilAuth *AuthorizationRecord
	valid, reason := nilAuth.IsCurrentlyValid(now)
	if valid || reason == "" {
		t.Errorf("nil authorization should be invalid")
	}

	// 2. Pending authorization
	pendingAuth := &AuthorizationRecord{
		Status: AuthPending,
	}
	valid, reason = pendingAuth.IsCurrentlyValid(now)
	if valid || reason == "" {
		t.Errorf("pending authorization should be invalid")
	}

	// 3. Approved authorization with no window restrictions
	approvedAuth := &AuthorizationRecord{
		Status: AuthApproved,
	}
	valid, _ = approvedAuth.IsCurrentlyValid(now)
	if !valid {
		t.Errorf("approved authorization without window should be valid")
	}

	// 4. Approved authorization with active window
	activeAuth := &AuthorizationRecord{
		Status:     AuthApproved,
		ValidFrom:  &yesterday,
		ValidUntil: &tomorrow,
	}
	valid, _ = activeAuth.IsCurrentlyValid(now)
	if !valid {
		t.Errorf("active window authorization should be valid")
	}

	// 5. Future authorization (not yet active)
	futureAuth := &AuthorizationRecord{
		Status:     AuthApproved,
		ValidFrom:  &tomorrow,
		ValidUntil: &future,
	}
	valid, reason = futureAuth.IsCurrentlyValid(now)
	if valid || reason == "" {
		t.Errorf("future authorization should be invalid, got valid=true")
	}

	// 6. Expired authorization
	expiredAuth := &AuthorizationRecord{
		Status:     AuthApproved,
		ValidFrom:  &past,
		ValidUntil: &yesterday,
	}
	valid, reason = expiredAuth.IsCurrentlyValid(now)
	if valid || reason == "" {
		t.Errorf("expired authorization should be invalid, got valid=true")
	}
}

func TestGenerateAssessmentRef(t *testing.T) {
	ref1 := GenerateAssessmentRef()
	ref2 := GenerateAssessmentRef()

	if len(ref1) < 10 || len(ref2) < 10 {
		t.Fatalf("unexpected ref length: %s, %s", ref1, ref2)
	}

	currentYear := time.Now().Year()
	prefix := "ASM-"
	if ref1[:4] != prefix {
		t.Errorf("expected ref to start with ASM-, got %s", ref1)
	}
	yearStr := ref1[4:8]
	if yearStr != time.Now().Format("2006") {
		t.Errorf("expected year %d in ref, got %s", currentYear, yearStr)
	}
}
