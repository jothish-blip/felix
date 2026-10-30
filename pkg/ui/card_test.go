package ui

import (
	"strings"
	"testing"
)

func TestSeverityBadges(t *testing.T) {
	tests := []struct {
		sev      string
		colored  bool
		contains string
	}{
		{"CRITICAL", false, "[CRIT]"},
		{"critical", false, "[CRIT]"},
		{"HIGH", false, "[HIGH]"},
		{"high", false, "[HIGH]"},
		{"MEDIUM", false, "[MED]"},
		{"medium", false, "[MED]"},
		{"LOW", false, "[LOW]"},
		{"low", false, "[LOW]"},
		{"INFORMATIONAL", false, "[INFO]"},
		{"info", false, "[INFO]"},
		{"CRITICAL", true, "\033[1;31m[CRIT]\033[0m"},
		{"HIGH", true, "\033[38;5;208m[HIGH]\033[0m"},
		{"MEDIUM", true, "\033[1;33m[MED]\033[0m"},
		{"LOW", true, "\033[34m[LOW]\033[0m"},
		{"INFO", true, "\033[90m[INFO]\033[0m"},
	}

	for _, tc := range tests {
		got := SeverityBadge(tc.sev, tc.colored)
		if !strings.Contains(got, tc.contains) {
			t.Errorf("SeverityBadge(%q, %v) = %q; expected to contain %q", tc.sev, tc.colored, got, tc.contains)
		}
	}
}

func TestVerificationBadges(t *testing.T) {
	tests := []struct {
		status   string
		colored  bool
		expected string
	}{
		{"VERIFIED", false, "[VERIFIED]"},
		{"DETECTED", false, "[DETECTED]"},
		{"OBSERVED", false, "[OBSERVED]"},
		{"NOT_EXPOSED", false, "[DEFENDED]"},
		{"BLOCKED", false, "[BLOCKED]"},
		{"INCONCLUSIVE", false, "[INCONCLUSIVE]"},
	}

	for _, tc := range tests {
		got := VerificationBadge(tc.status, tc.colored)
		if got != tc.expected {
			t.Errorf("VerificationBadge(%q, false) = %q; want %q", tc.status, got, tc.expected)
		}
	}
}

func TestRenderBoxUnicodeAndASCII(t *testing.T) {
	lines := []string{
		"Target:     https://example.com",
		"Status:     COMPLETED",
		"---",
		"Findings:   2 verified, 1 detected",
	}

	uBox := RenderBox("ASSESSMENT SUMMARY", lines, CardConfig{Width: 50, ASCII: false, NoColor: true})
	if !strings.Contains(uBox, "┌") || !strings.Contains(uBox, "┐") || !strings.Contains(uBox, "┴") && !strings.Contains(uBox, "└") {
		t.Errorf("expected Unicode box borders, got:\n%s", uBox)
	}
	if !strings.Contains(uBox, "ASSESSMENT SUMMARY") {
		t.Errorf("expected title in box, got:\n%s", uBox)
	}
	if !strings.Contains(uBox, "├") || !strings.Contains(uBox, "┤") {
		t.Errorf("expected divider in Unicode box, got:\n%s", uBox)
	}

	aBox := RenderBox("ASSESSMENT SUMMARY", lines, CardConfig{Width: 50, ASCII: true, NoColor: true})
	if !strings.Contains(aBox, "+") || !strings.Contains(aBox, "|") {
		t.Errorf("expected ASCII box borders, got:\n%s", aBox)
	}
	if strings.Contains(aBox, "┌") {
		t.Errorf("ASCII box should not contain unicode chars, got:\n%s", aBox)
	}
}

func TestStageOutput(t *testing.T) {
	var buf strings.Builder
	p := New(Options{
		Writer:   &buf,
		Quiet:    false,
		JSONMode: false,
	})
	p.Stage(1, 4, "Discovery")
	if !strings.Contains(buf.String(), "[*] [1/4] Discovery\n") {
		t.Errorf("expected stage output, got: %q", buf.String())
	}
}

func TestRenderExecutiveSummaryCard(t *testing.T) {
	data := SummaryCardData{
		Target:            "https://target.local",
		CompletionStatus:  "COMPLETED",
		Timestamp:         "2026-10-22 14:00:00 UTC",
		Duration:          "1.42s",
		RiskScore:         82,
		RiskLevel:         "CRITICAL",
		ScoreAvailable:    true,
		CriticalCount:     1,
		HighCount:         2,
		MediumCount:       0,
		LowCount:          1,
		InfoCount:         3,
		VerifiedCount:     1,
		DetectedCount:     2,
		NotExposedCount:   1,
	}

	cfg := DefaultCardConfig(false)
	card := RenderExecutiveSummaryCard(data, cfg)

	if !strings.Contains(card, "FELIX :: EXECUTIVE SECURITY POSTURE") {
		t.Errorf("card missing title, got:\n%s", card)
	}
	if !strings.Contains(card, "https://target.local") {
		t.Errorf("card missing target, got:\n%s", card)
	}
	if !strings.Contains(card, "82/100") {
		t.Errorf("card missing risk score, got:\n%s", card)
	}
	if !strings.Contains(card, "[CRIT]") {
		t.Errorf("card missing [CRIT] badge, got:\n%s", card)
	}
	if !strings.Contains(card, "1 verified exposure(s)") {
		t.Errorf("card missing verified exposure count, got:\n%s", card)
	}
}

func TestRenderCommercialSummaryCard(t *testing.T) {
	data := CommercialSummaryCardData{
		ReportID:        "cr_rep_test",
		Target:          "https://example.com",
		GeneratedAt:     "2026-10-22",
		CompletionState: "COMPLETED",
		RiskScore:       65,
		RiskLevel:       "HIGH",
		ScoreAvailable:  true,
		AssetsCount:     12,
		VerifiedCount:   2,
		DetectedCount:   1,
		ObservedCount:   4,
		NegativeProbes:  1,
	}

	cfg := DefaultCardConfig(false)
	card := RenderCommercialSummaryCard(data, cfg)

	if !strings.Contains(card, "COMMERCIAL SECURITY DOSSIER") {
		t.Errorf("card missing commercial title, got:\n%s", card)
	}
	if !strings.Contains(card, "cr_rep_test") {
		t.Errorf("card missing report ref, got:\n%s", card)
	}
	if !strings.Contains(card, "65/100") {
		t.Errorf("card missing score, got:\n%s", card)
	}
	if !strings.Contains(card, "12 cataloged asset(s)") {
		t.Errorf("card missing assets, got:\n%s", card)
	}
}
