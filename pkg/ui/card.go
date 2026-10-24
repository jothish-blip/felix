package ui

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

// ANSI color escape constants
const (
	ansiReset      = "\033[0m"
	ansiBold       = "\033[1m"
	ansiDim        = "\033[2m"
	ansiRedBold    = "\033[1;31m"
	ansiYellowBold = "\033[1;33m"
	ansiAmberBold  = "\033[38;5;208m"
	ansiYellow     = "\033[33m"
	ansiBlue       = "\033[34m"
	ansiCyan       = "\033[36m"
	ansiGreenBold  = "\033[1;32m"
	ansiGreen      = "\033[32m"
	ansiGray       = "\033[90m"
	ansiMagenta    = "\033[35m"
)

// SeverityBadge returns a standardized 6-character bracketed badge for terminal output:
// [CRIT], [HIGH], [MED], [LOW], [INFO].
// If colored is true, appropriate ANSI styling is applied.
func SeverityBadge(severity string, colored bool) string {
	sev := strings.ToUpper(strings.TrimSpace(severity))
	var badge, color string

	switch sev {
	case "CRITICAL", "CRIT":
		badge = "[CRIT]"
		color = ansiRedBold
	case "HIGH":
		badge = "[HIGH]"
		color = ansiAmberBold
	case "MEDIUM", "MED":
		badge = "[MED]"
		color = ansiYellowBold
	case "LOW":
		badge = "[LOW]"
		color = ansiBlue
	case "INFORMATIONAL", "INFO":
		badge = "[INFO]"
		color = ansiGray
	default:
		badge = fmt.Sprintf("[%s]", sev)
		color = ansiReset
	}

	if colored && color != "" {
		return color + badge + ansiReset
	}
	return badge
}

// VerificationBadge returns a bracketed badge for verification status.
func VerificationBadge(status string, colored bool) string {
	st := strings.ToUpper(strings.TrimSpace(status))
	var badge, color string

	switch st {
	case "VERIFIED":
		badge = "[VERIFIED]"
		color = ansiGreenBold
	case "DETECTED":
		badge = "[DETECTED]"
		color = ansiYellow
	case "OBSERVED":
		badge = "[OBSERVED]"
		color = ansiCyan
	case "NOT_EXPOSED", "DEFENDED":
		badge = "[DEFENDED]"
		color = ansiGreen
	case "BLOCKED":
		badge = "[BLOCKED]"
		color = ansiMagenta
	case "INCONCLUSIVE":
		badge = "[INCONCLUSIVE]"
		color = ansiGray
	default:
		badge = fmt.Sprintf("[%s]", st)
		color = ansiReset
	}

	if colored && color != "" {
		return color + badge + ansiReset
	}
	return badge
}

// BoxStyle defines the characters used for framing cards.
type BoxStyle struct {
	TopLeft      string
	TopRight     string
	BottomLeft   string
	BottomRight  string
	Horizontal   string
	Vertical     string
	DividerLeft  string
	DividerRight string
	Cross        string
}

// UnicodeBoxStyle uses modern Unicode box-drawing characters.
var UnicodeBoxStyle = BoxStyle{
	TopLeft:      "┌",
	TopRight:     "┐",
	BottomLeft:   "└",
	BottomRight:  "┘",
	Horizontal:   "─",
	Vertical:     "│",
	DividerLeft:  "├",
	DividerRight: "┤",
	Cross:        "┼",
}

// ASCIIBoxStyle uses standard ASCII fallback characters.
var ASCIIBoxStyle = BoxStyle{
	TopLeft:      "+",
	TopRight:     "+",
	BottomLeft:   "+",
	BottomRight:  "+",
	Horizontal:   "-",
	Vertical:     "|",
	DividerLeft:  "+",
	DividerRight: "+",
	Cross:        "+",
}

// CardConfig specifies rendering options for terminal cards.
type CardConfig struct {
	Width   int
	ASCII   bool
	NoColor bool
}

// DefaultCardConfig returns a sensible default configuration (width 62).
func DefaultCardConfig(interactive bool) CardConfig {
	noColor := !interactive || os.Getenv("NO_COLOR") != ""
	return CardConfig{
		Width:   62,
		ASCII:   false,
		NoColor: noColor,
	}
}

// stripANSI removes ANSI escape sequences to compute visual character length.
func stripANSI(s string) string {
	var b strings.Builder
	inSeq := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0x1b { // ESC
			inSeq = true
			continue
		}
		if inSeq {
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
				inSeq = false
			}
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// visualLen returns the visual rune width of a string ignoring ANSI escapes.
func visualLen(s string) int {
	return utf8.RuneCountInString(stripANSI(s))
}

// RenderBox wraps lines inside a styled terminal box card.
func RenderBox(title string, lines []string, cfg CardConfig) string {
	width := cfg.Width
	if width < 40 {
		width = 62
	}
	innerWidth := width - 2

	style := UnicodeBoxStyle
	if cfg.ASCII {
		style = ASCIIBoxStyle
	}

	var sb strings.Builder

	// Top border
	sb.WriteString(style.TopLeft)
	if title != "" {
		cleanTitle := " " + strings.TrimSpace(title) + " "
		tLen := utf8.RuneCountInString(cleanTitle)
		if tLen > innerWidth-4 {
			cleanTitle = cleanTitle[:innerWidth-4] + "... "
			tLen = utf8.RuneCountInString(cleanTitle)
		}
		sb.WriteString(cleanTitle)
		sb.WriteString(strings.Repeat(style.Horizontal, innerWidth-tLen))
	} else {
		sb.WriteString(strings.Repeat(style.Horizontal, innerWidth))
	}
	sb.WriteString(style.TopRight + "\n")

	// Content lines
	for _, line := range lines {
		if line == "---" {
			// Divider
			sb.WriteString(style.DividerLeft)
			sb.WriteString(strings.Repeat(style.Horizontal, innerWidth))
			sb.WriteString(style.DividerRight + "\n")
			continue
		}

		vLen := visualLen(line)
		padding := innerWidth - vLen - 2 // 1 space padding on left and right
		if padding < 0 {
			// Truncate if too long
			raw := stripANSI(line)
			if utf8.RuneCountInString(raw) > innerWidth-2 {
				line = string([]rune(raw)[:innerWidth-5]) + "..."
				vLen = visualLen(line)
				padding = innerWidth - vLen - 2
			}
			if padding < 0 {
				padding = 0
			}
		}

		sb.WriteString(style.Vertical)
		sb.WriteString(" ")
		sb.WriteString(line)
		sb.WriteString(strings.Repeat(" ", padding))
		sb.WriteString(" ")
		sb.WriteString(style.Vertical + "\n")
	}

	// Bottom border
	sb.WriteString(style.BottomLeft)
	sb.WriteString(strings.Repeat(style.Horizontal, innerWidth))
	sb.WriteString(style.BottomRight + "\n")

	return sb.String()
}

// SummaryCardData holds metrics to format an executive terminal summary card.
type SummaryCardData struct {
	Target            string
	CompletionStatus  string
	Timestamp         string
	Duration          string
	RiskScore         int
	RiskLevel         string
	ScoreAvailable    bool
	CriticalCount     int
	HighCount         int
	MediumCount       int
	LowCount          int
	InfoCount         int
	VerifiedCount     int
	DetectedCount     int
	ObservedCount     int
	NotExposedCount   int
	BlockedCount      int
	InconclusiveCount int
	TotalAssets       int
}

// padBadge pads a badge with trailing spaces to match the visual width.
func padBadge(b string, targetLen int) string {
	vLen := visualLen(b)
	if vLen < targetLen {
		return b + strings.Repeat(" ", targetLen-vLen)
	}
	return b
}

// RenderExecutiveSummaryCard renders an executive terminal summary card.
func RenderExecutiveSummaryCard(data SummaryCardData, cfg CardConfig) string {
	colored := !cfg.NoColor

	var verdict string
	if !data.ScoreAvailable || data.RiskLevel == "UNAVAILABLE" || data.CompletionStatus == "BLOCKED" || data.CompletionStatus == "FAILED" {
		verdict = fmt.Sprintf("N/A (%s)", data.RiskLevel)
	} else {
		badgeSev := data.RiskLevel
		verdict = fmt.Sprintf("%s %d/100 (%s RISK)", SeverityBadge(badgeSev, colored), data.RiskScore, data.RiskLevel)
	}

	status := data.CompletionStatus
	if status == "" {
		status = "COMPLETED"
	}

	lines := []string{
		fmt.Sprintf("Target:          %s", data.Target),
		fmt.Sprintf("Status:          %s", status),
	}
	if data.Timestamp != "" {
		lines = append(lines, fmt.Sprintf("Timestamp:       %s", data.Timestamp))
	}
	if data.Duration != "" {
		lines = append(lines, fmt.Sprintf("Duration:        %s", data.Duration))
	}
	lines = append(lines, fmt.Sprintf("Posture Verdict: %s", verdict))
	lines = append(lines, "---")

	critB := padBadge(SeverityBadge("CRIT", colored), 6)
	highB := padBadge(SeverityBadge("HIGH", colored), 6)
	medB := padBadge(SeverityBadge("MED", colored), 6)
	lowB := padBadge(SeverityBadge("LOW", colored), 6)
	infoB := padBadge(SeverityBadge("INFO", colored), 6)

	lines = append(lines, "Findings Breakdown:")
	lines = append(lines, fmt.Sprintf("  %s %-4d  %s %-4d  %s %-4d",
		critB, data.CriticalCount,
		highB, data.HighCount,
		medB, data.MediumCount,
	))
	lines = append(lines, fmt.Sprintf("  %s %-4d  %s %-4d",
		lowB, data.LowCount,
		infoB, data.InfoCount,
	))
	lines = append(lines, "---")

	lines = append(lines, "Empirical Verification:")
	lines = append(lines, fmt.Sprintf("  Confirmed:   %d verified exposure(s)", data.VerifiedCount))
	lines = append(lines, fmt.Sprintf("  Candidates:  %d unverified candidate(s)", data.DetectedCount))
	if data.NotExposedCount > 0 {
		lines = append(lines, fmt.Sprintf("  Defended:    %d verified non-exposed control(s)", data.NotExposedCount))
	}
	if data.BlockedCount > 0 {
		lines = append(lines, fmt.Sprintf("  Blocked:     %d (safety boundary reached)", data.BlockedCount))
	}

	return RenderBox("FELIX :: EXECUTIVE SECURITY POSTURE", lines, cfg)
}

// CommercialSummaryCardData holds metrics for commercial executive card rendering.
type CommercialSummaryCardData struct {
	ReportID        string
	Target          string
	GeneratedAt     string
	CompletionState string
	RiskScore       int
	RiskLevel       string
	ScoreAvailable  bool
	AssetsCount     int
	VerifiedCount   int
	DetectedCount   int
	ObservedCount   int
	NegativeProbes  int
}

// RenderCommercialSummaryCard renders an executive commercial report terminal card.
func RenderCommercialSummaryCard(data CommercialSummaryCardData, cfg CardConfig) string {
	colored := !cfg.NoColor

	var verdict string
	if !data.ScoreAvailable || data.RiskLevel == "UNAVAILABLE" {
		verdict = fmt.Sprintf("N/A (%s)", data.RiskLevel)
	} else {
		verdict = fmt.Sprintf("%s %d/100 (%s RISK)", SeverityBadge(data.RiskLevel, colored), data.RiskScore, data.RiskLevel)
	}

	lines := []string{
		fmt.Sprintf("Report Ref:      %s", data.ReportID),
		fmt.Sprintf("Target:          %s", data.Target),
		fmt.Sprintf("Generated:       %s", data.GeneratedAt),
		fmt.Sprintf("Posture Verdict: %s", verdict),
		"---",
		fmt.Sprintf("Attack Surface:  %d cataloged asset(s)", data.AssetsCount),
		fmt.Sprintf("Verified Exposures:  %d confirmed", data.VerifiedCount),
		fmt.Sprintf("Detected Candidates: %d unverified", data.DetectedCount),
		fmt.Sprintf("Observations:        %d informational", data.ObservedCount),
	}
	if data.NegativeProbes > 0 {
		lines = append(lines, fmt.Sprintf("Defensive Proofs:    %d non-exposed controls", data.NegativeProbes))
	}

	return RenderBox("FELIX :: COMMERCIAL SECURITY DOSSIER 2.0", lines, cfg)
}
