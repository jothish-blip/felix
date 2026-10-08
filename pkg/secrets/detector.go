package secrets

import (
	"encoding/json"
	"regexp"
	"strings"
	"sync"

	"felix/pkg/crawler"
)

// Detector orchestrates pattern matching, entropy analysis, and context evaluation.
type Detector struct {
	patterns []Pattern
	mu       sync.RWMutex
}

// NewDetector initializes a Detector with default pattern signatures.
func NewDetector() *Detector {
	return &Detector{
		patterns: DefaultPatterns(),
	}
}

// NewDetectorWithPatterns allows custom pattern registration.
func NewDetectorWithPatterns(patterns []Pattern) *Detector {
	return &Detector{
		patterns: patterns,
	}
}

// sourceMapJSON represents the structural format of source maps with embedded source code.
type sourceMapJSON struct {
	Version        int      `json:"version"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

// ScanAssets inspects a slice of crawled assets and extracts secret findings.
func (d *Detector) ScanAssets(assets []crawler.Asset) []SecretFinding {
	var (
		allFindings []SecretFinding
		seen        = make(map[string]struct{})
	)

	for _, a := range assets {
		if len(a.Content) == 0 {
			continue
		}

		var fileFindings []SecretFinding

		// Check if asset is a source map with embedded sourcesContent
		if a.IsSourceMap || a.Type == crawler.AssetSourceMap || strings.HasSuffix(a.URL, ".map") {
			fileFindings = d.scanSourceMap(a.URL, a.Content)
		} else {
			fileFindings = d.ScanContent(a.URL, a.Content)
		}

		// Deduplicate findings across files by fingerprint
		for _, f := range fileFindings {
			if _, exists := seen[f.Fingerprint]; !exists {
				seen[f.Fingerprint] = struct{}{}
				allFindings = append(allFindings, f)
			}
		}
	}

	return allFindings
}

// scanSourceMap attempts to parse sourcesContent and scan embedded original sources.
func (d *Detector) scanSourceMap(originURL string, content []byte) []SecretFinding {
	var sm sourceMapJSON
	if err := json.Unmarshal(content, &sm); err == nil && len(sm.SourcesContent) > 0 {
		var findings []SecretFinding
		for i, srcText := range sm.SourcesContent {
			if strings.TrimSpace(srcText) == "" {
				continue
			}
			srcName := "embedded-source"
			if i < len(sm.Sources) && sm.Sources[i] != "" {
				srcName = sm.Sources[i]
			}
			fileOrigin := srcName

			subFindings := d.ScanContent(fileOrigin, []byte(srcText))
			findings = append(findings, subFindings...)
		}
		return findings
	}

	// Fallback to scanning raw source map content if JSON extraction fails or has no sourcesContent
	return d.ScanContent(originURL, content)
}

// Regex for extracting quoted candidate strings for high-entropy analysis
var quotedStringRegex = regexp.MustCompile(`["']([a-zA-Z0-9_\-\+/=]{20,100})["']`)

// ScanContent scans a single buffer of text/code for secrets.
func (d *Detector) ScanContent(fileOrigin string, content []byte) []SecretFinding {
	d.mu.RLock()
	patterns := d.patterns
	d.mu.RUnlock()

	var findings []SecretFinding
	contentStr := string(content)
	matchedFingerprints := make(map[string]struct{})

	// 1. Regular expression signatures
	for _, p := range patterns {
		matches := p.Regex.FindAllStringIndex(contentStr, -1)
		for _, loc := range matches {
			start, end := loc[0], loc[1]
			val := contentStr[start:end]

			// Determine matched type, title, severity, confidence
			sType := p.Type
			title := p.Name
			severity := p.Severity
			confidence := p.Confidence

			if p.Validator != nil {
				keep, valType, valTitle, valSev, valConf := p.Validator(val)
				if !keep {
					continue
				}
				if valType != "" {
					sType = valType
				}
				if valTitle != "" {
					title = valTitle
				}
				if valSev != "" {
					severity = valSev
				}
				if valConf != "" {
					confidence = valConf
				}
			}

			// Context extraction (up to 80 chars before and after)
			ctxStart := start - 80
			if ctxStart < 0 {
				ctxStart = 0
			}
			ctxEnd := end + 80
			if ctxEnd > len(contentStr) {
				ctxEnd = len(contentStr)
			}
			surroundingCtx := contentStr[ctxStart:ctxEnd]

			// False positive check
			if IsFalsePositive(val, sType, surroundingCtx) {
				continue
			}

			// Context analysis & confidence boosting
			boostedConf := evaluateContextConfidence(surroundingCtx, confidence)

			// Line number calculation
			lineNo := LineNumberAtOffset(content, start)

			// Evidence extraction (redacted snippet)
			evidence := extractEvidenceLine(contentStr, start, end, val)

			fp := GenerateFingerprint(sType, val)
			if _, exists := matchedFingerprints[fp]; !exists {
				matchedFingerprints[fp] = struct{}{}
				findings = append(findings, SecretFinding{
					Type:        sType,
					Title:       title,
					Value:       val,
					Redacted:    RedactSecret(val),
					FileOrigin:  fileOrigin,
					LineNumber:  lineNo,
					Severity:    severity,
					Confidence:  boostedConf,
					Evidence:    evidence,
					Fingerprint: fp,
				})
			}
		}
	}

	// 2. High-Entropy Candidate Analysis (Candidate -> Context analysis -> Finding)
	entropyMatches := quotedStringRegex.FindAllStringSubmatchIndex(contentStr, -1)
	for _, loc := range entropyMatches {
		if len(loc) < 4 {
			continue
		}
		start, end := loc[2], loc[3]
		candidate := contentStr[start:end]

		// Skip if already captured by a known signature
		fp := GenerateFingerprint(SecretHighEntropy, candidate)
		if _, exists := matchedFingerprints[fp]; exists {
			continue
		}

		// Calculate Shannon entropy
		entropy := ShannonEntropy(candidate)
		if entropy < 4.5 {
			continue
		}

		// Context analysis: Must have secret-like identifier nearby
		ctxStart := start - 80
		if ctxStart < 0 {
			ctxStart = 0
		}
		ctxEnd := end + 80
		if ctxEnd > len(contentStr) {
			ctxEnd = len(contentStr)
		}
		surroundingCtx := contentStr[ctxStart:ctxEnd]

		if !hasSecretContextKeywords(surroundingCtx) {
			continue
		}

		if IsFalsePositive(candidate, SecretHighEntropy, surroundingCtx) {
			continue
		}

		lineNo := LineNumberAtOffset(content, start)
		evidence := extractEvidenceLine(contentStr, start, end, candidate)

		matchedFingerprints[fp] = struct{}{}
		findings = append(findings, SecretFinding{
			Type:        SecretHighEntropy,
			Title:       "High-Entropy Suspicious Secret String",
			Value:       candidate,
			Redacted:    RedactSecret(candidate),
			FileOrigin:  fileOrigin,
			LineNumber:  lineNo,
			Severity:    SeverityLow,
			Confidence:  ConfidenceLow,
			Evidence:    evidence,
			Fingerprint: fp,
		})
	}

	return findings
}

// LineNumberAtOffset calculates the 1-based line number for a byte offset in content.
func LineNumberAtOffset(content []byte, offset int) int {
	if offset < 0 {
		return 1
	}
	if offset > len(content) {
		offset = len(content)
	}
	line := 1
	for i := 0; i < offset; i++ {
		if content[i] == '\n' {
			line++
		}
	}
	return line
}

var sensitiveKeywords = []string{
	"secret",
	"key",
	"token",
	"password",
	"passwd",
	"credential",
	"auth",
	"api_key",
	"apikey",
	"private",
	"bearer",
	"stripe",
	"access_token",
}

func hasSecretContextKeywords(ctx string) bool {
	lower := strings.ToLower(ctx)
	for _, kw := range sensitiveKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func evaluateContextConfidence(ctx string, baseConfidence string) string {
	if hasSecretContextKeywords(ctx) {
		if baseConfidence == ConfidenceMedium {
			return ConfidenceHigh
		}
		if baseConfidence == ConfidenceLow {
			return ConfidenceMedium
		}
	}
	return baseConfidence
}

// extractEvidenceLine retrieves the line containing the match and redacts the secret.
func extractEvidenceLine(contentStr string, start, end int, rawSecret string) string {
	lineStart := strings.LastIndex(contentStr[:start], "\n")
	if lineStart == -1 {
		lineStart = 0
	} else {
		lineStart++ // Skip the newline character
	}

	lineEnd := strings.Index(contentStr[end:], "\n")
	if lineEnd == -1 {
		lineEnd = len(contentStr)
	} else {
		lineEnd = end + lineEnd
	}

	lineText := strings.TrimSpace(contentStr[lineStart:lineEnd])
	if len(lineText) > 160 {
		// Truncate overly long minified lines
		lineText = lineText[:160] + "..."
	}

	// Always mask the raw secret inside the evidence
	redactedVal := RedactSecret(rawSecret)
	return strings.ReplaceAll(lineText, rawSecret, redactedVal)
}
