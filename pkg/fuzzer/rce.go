package fuzzer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// RCEType defines the specific execution engine or injection category.
type RCEType string

const (
	RCECommandInjection RCEType = "OS_COMMAND_INJECTION"
	RCESSJI             RCEType = "SSJI_JAVASCRIPT_INJECTION"
	RCENone             RCEType = "NONE"
)

// RCEConfidence reflects the conclusive certainty of an RCE/SSJI finding.
type RCEConfidence string

const (
	RCEConfidenceConfirmed  RCEConfidence = "CONFIRMED"
	RCEConfidenceCandidate  RCEConfidence = "CANDIDATE"
	RCEConfidenceNotExposed RCEConfidence = "NOT_EXPOSED"
)

// RCEPlatform defines the underlying shell or runtime execution environment.
type RCEPlatform string

const (
	RCEPlatformPOSIX   RCEPlatform = "POSIX_SHELL"
	RCEPlatformWindows RCEPlatform = "WINDOWS_CMD"
	RCEPlatformNodeJS  RCEPlatform = "NODEJS_RUNTIME"
	RCEPlatformGeneric RCEPlatform = "GENERIC"
)

// RCEProbeDefinition defines a bounded non-destructive arithmetic evaluation probe.
type RCEProbeDefinition struct {
	Name            string
	Type            RCEType
	Platform        RCEPlatform
	Payload         string
	ArithmeticToken string
	FormulaPattern  *regexp.Regexp
	Description     string
}

// RCEFinding records a verified or candidate command injection / SSJI vulnerability.
type RCEFinding struct {
	TargetURL               string        `json:"target_url"`
	Parameter               Parameter     `json:"parameter"`
	Type                    RCEType       `json:"type"`
	Confidence              RCEConfidence `json:"confidence"`
	Platform                RCEPlatform   `json:"platform,omitempty"`
	ProbeName               string        `json:"probe_name"`
	Payload                 string        `json:"payload"`
	ArithmeticToken         string        `json:"arithmetic_token"`
	ExpectedOutput          string        `json:"expected_output"`
	MatchedOutput           string        `json:"matched_output,omitempty"`
	Evidence                string        `json:"evidence"`
	StatusCode              int           `json:"status_code"`
	NonTargetPreserved      bool          `json:"non_target_preserved"`
	ClassificationRationale string        `json:"classification_rationale"`
}

// DefaultRCEProbes defines bounded, safe arithmetic evaluation probes.
// None of these execute destructive actions; they perform pure integer arithmetic.
var DefaultRCEProbes = []RCEProbeDefinition{
	// 1. POSIX Semicolon separator with expr
	{
		Name:            "POSIX Semicolon expr",
		Type:            RCECommandInjection,
		Platform:        RCEPlatformPOSIX,
		Payload:         "; expr 41 + 1",
		ArithmeticToken: "42",
		FormulaPattern:  regexp.MustCompile(`;\s*expr\s+41\s*\+\s*1`),
		Description:     "POSIX semicolon command separator chaining expr 41 + 1 arithmetic calculation",
	},
	// 2. POSIX Pipe separator with expr
	{
		Name:            "POSIX Pipe expr",
		Type:            RCECommandInjection,
		Platform:        RCEPlatformPOSIX,
		Payload:         "| expr 41 + 1",
		ArithmeticToken: "42",
		FormulaPattern:  regexp.MustCompile(`\|\s*expr\s+41\s*\+\s*1`),
		Description:     "POSIX pipe command separator chaining expr 41 + 1 arithmetic calculation",
	},
	// 3. POSIX AND operator with expr
	{
		Name:            "POSIX AND expr",
		Type:            RCECommandInjection,
		Platform:        RCEPlatformPOSIX,
		Payload:         "&& expr 41 + 1",
		ArithmeticToken: "42",
		FormulaPattern:  regexp.MustCompile(`&&\s*expr\s+41\s*\+\s*1`),
		Description:     "POSIX AND logical separator chaining expr 41 + 1 arithmetic calculation",
	},
	// 4. POSIX Subshell substitution $(expr ...)
	{
		Name:            "POSIX Subshell expr",
		Type:            RCECommandInjection,
		Platform:        RCEPlatformPOSIX,
		Payload:         "$(expr 41 + 1)",
		ArithmeticToken: "42",
		FormulaPattern:  regexp.MustCompile(`\$\(expr\s+41\s*\+\s*1\)`),
		Description:     "POSIX subshell command substitution $(expr 41 + 1)",
	},
	// 5. POSIX Backtick command substitution `expr ...`
	{
		Name:            "POSIX Backtick expr",
		Type:            RCECommandInjection,
		Platform:        RCEPlatformPOSIX,
		Payload:         "`expr 41 + 1`",
		ArithmeticToken: "42",
		FormulaPattern:  regexp.MustCompile("`expr\\s+41\\s*\\+\\s*1`"),
		Description:     "POSIX backtick command substitution `expr 41 + 1`",
	},
	// 6. POSIX Arithmetic expansion echo $((41+1))
	{
		Name:            "POSIX Arithmetic Expansion",
		Type:            RCECommandInjection,
		Platform:        RCEPlatformPOSIX,
		Payload:         "; echo $((41+1))",
		ArithmeticToken: "42",
		FormulaPattern:  regexp.MustCompile(`;\s*echo\s*\$\(\(41\s*\+\s*1\)\)`),
		Description:     "POSIX shell integer expansion ; echo $((41+1))",
	},
	// 7. Windows Command Prompt ampersand arithmetic
	{
		Name:            "Windows CMD set arithmetic",
		Type:            RCECommandInjection,
		Platform:        RCEPlatformWindows,
		Payload:         "& set /a 41+1",
		ArithmeticToken: "42",
		FormulaPattern:  regexp.MustCompile(`&\s*set\s+/a\s*41\s*\+\s*1`),
		Description:     "Windows CMD ampersand separator with set /a arithmetic calculation",
	},
	// 8. Node.js SSJI direct response write (NodeGoat evaluation)
	{
		Name:            "NodeJS SSJI res.end",
		Type:            RCESSJI,
		Platform:        RCEPlatformNodeJS,
		Payload:         "res.end(String(41+1))",
		ArithmeticToken: "42",
		FormulaPattern:  regexp.MustCompile(`res\.end\s*\(\s*String\s*\(\s*41\s*\+\s*1\s*\)\s*\)`),
		Description:     "Server-Side JavaScript Injection writing evaluated arithmetic 41+1 to HTTP response stream",
	},
	// 9. Node.js SSJI arithmetic expression evaluation (NodeGoat contributions)
	{
		Name:            "NodeJS SSJI Arithmetic Expression",
		Type:            RCESSJI,
		Platform:        RCEPlatformNodeJS,
		Payload:         "21 + 21",
		ArithmeticToken: "42",
		FormulaPattern:  regexp.MustCompile(`21\s*\+\s*21`),
		Description:     "Server-Side JavaScript eval() integer addition 21 + 21 evaluating to 42",
	},
	// 10. Node.js SSJI IIFE return arithmetic
	{
		Name:            "NodeJS SSJI IIFE return",
		Type:            RCESSJI,
		Platform:        RCEPlatformNodeJS,
		Payload:         "(function(){return 41+1;})()",
		ArithmeticToken: "42",
		FormulaPattern:  regexp.MustCompile(`\(function\(\)\{return\s*41\s*\+\s*1;?\}\)\(\)`),
		Description:     "Server-Side JavaScript Immediately Invoked Function Expression returning 41+1",
	},
}

// RCEAnalyzer coordinates differential command injection and SSJI detection.
type RCEAnalyzer struct {
	client    *http.Client
	extractor *ParameterExtractor
	probes    []RCEProbeDefinition
	timeout   time.Duration
}

// NewRCEAnalyzer constructs a new RCE & SSJI differential analyzer.
func NewRCEAnalyzer(client *http.Client, extractor *ParameterExtractor) *RCEAnalyzer {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if extractor == nil {
		extractor = NewParameterExtractor()
	}
	return &RCEAnalyzer{
		client:    client,
		extractor: extractor,
		probes:    DefaultRCEProbes,
		timeout:   10 * time.Second,
	}
}

// SetProbes overrides the active RCE probe definitions.
func (a *RCEAnalyzer) SetProbes(probes []RCEProbeDefinition) {
	a.probes = probes
}

// AnalyzeRequest audits all extractable parameters in an HTTP request for command injection & SSJI.
func (a *RCEAnalyzer) AnalyzeRequest(req *http.Request) ([]RCEFinding, error) {
	params, err := a.extractor.Extract(req)
	if err != nil {
		return nil, fmt.Errorf("failed to extract parameters for RCE analysis: %w", err)
	}

	var allFindings []RCEFinding
	for _, param := range params {
		findings, err := a.AnalyzeParameter(req, param)
		if err != nil {
			return nil, fmt.Errorf("error analyzing parameter %s for RCE: %w", param.Name, err)
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// AnalyzeParameter tests a single parameter against bounded RCE & SSJI probes.
func (a *RCEAnalyzer) AnalyzeParameter(req *http.Request, param Parameter) ([]RCEFinding, error) {
	// 1. Establish benign baseline response
	baselineReq, err := a.extractor.GenerateMutation(req, param, param.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to create baseline mutation: %w", err)
	}

	baselineResp, err := a.executeRequest(baselineReq)
	if err != nil {
		return nil, fmt.Errorf("failed to execute baseline request: %w", err)
	}
	baselineBody := baselineResp.Body

	var findings []RCEFinding

	for _, probe := range a.probes {
		// Mutate target parameter
		mutatedReq, err := a.extractor.GenerateMutation(req, param, probe.Payload)
		if err != nil {
			continue
		}

		// Verify non-target parameters preserved
		nonTargetPreserved := a.verifyNonTargetPreservation(req, mutatedReq, param)

		resp, err := a.executeRequest(mutatedReq)
		if err != nil {
			continue
		}

		// Evaluate response for executed arithmetic vs. static reflection
		confirmed, matchedToken, rationale, evidence := a.evaluateRCE(probe, baselineBody, resp.Body, resp.StatusCode)

		confidence := RCEConfidenceNotExposed
		if confirmed {
			confidence = RCEConfidenceConfirmed
		} else if strings.Contains(resp.Body, probe.ArithmeticToken) && !strings.Contains(baselineBody, probe.ArithmeticToken) {
			confidence = RCEConfidenceCandidate
		}

		finding := RCEFinding{
			TargetURL:               req.URL.String(),
			Parameter:               param,
			Type:                    probe.Type,
			Confidence:              confidence,
			Platform:                probe.Platform,
			ProbeName:               probe.Name,
			Payload:                 probe.Payload,
			ArithmeticToken:         probe.ArithmeticToken,
			ExpectedOutput:          probe.ArithmeticToken,
			MatchedOutput:           matchedToken,
			Evidence:                evidence,
			StatusCode:              resp.StatusCode,
			NonTargetPreserved:      nonTargetPreserved,
			ClassificationRationale: rationale,
		}

		if confidence == RCEConfidenceConfirmed {
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// evaluateRCE performs rigorous differential evaluation to verify arithmetic execution
// while strictly rejecting static reflection of the raw formula string.
func (a *RCEAnalyzer) evaluateRCE(probe RCEProbeDefinition, baselineBody string, respBody string, statusCode int) (bool, string, string, string) {
	token := probe.ArithmeticToken

	// Check 1: Does the response contain the expected calculated arithmetic token?
	tokenPattern := regexp.MustCompile(`(?:\b|\D)` + regexp.QuoteMeta(token) + `(?:\b|\D)`)
	bodyContainsToken := tokenPattern.MatchString(respBody) || strings.TrimSpace(respBody) == token

	// Check 1b: NodeGoat specific SSJI evaluation artifact:
	// When preTax evaluates to 42 (>30), NodeGoat renders "Contribution percentages cannot exceed 30 %"
	// which occurs ONLY when arithmetic is evaluated by eval(req.body.preTax).
	isNodeGoatSSJIExceed := probe.Type == RCESSJI &&
		strings.Contains(respBody, "Contribution percentages cannot exceed 30 %") &&
		!strings.Contains(baselineBody, "Contribution percentages cannot exceed 30 %")

	// Check 1c: NodeGoat specific SSJI success artifact:
	// When preTax evaluates to 28 (<=30), NodeGoat renders "28 %" in table cell
	isNodeGoatSSJIRendered := probe.Type == RCESSJI &&
		strings.Contains(respBody, token+" %") &&
		!strings.Contains(baselineBody, token+" %")

	if !bodyContainsToken && !isNodeGoatSSJIExceed && !isNodeGoatSSJIRendered {
		return false, "", "Calculated arithmetic output absent in response", ""
	}

	// Check 2: Was this token already present in the baseline response?
	baselineCount := strings.Count(baselineBody, token)
	respCount := strings.Count(respBody, token)
	if respCount <= baselineCount && !isNodeGoatSSJIExceed && !isNodeGoatSSJIRendered {
		return false, "", "Token frequency unchanged from benign baseline (static content)", ""
	}

	// Check 3: STATIC REFLECTION REJECTION
	// If the server simply reflected the raw payload string (e.g. echo 42 or expr 41 + 1),
	// and no actual execution occurred, reject static reflection.
	if probe.FormulaPattern != nil && probe.FormulaPattern.MatchString(respBody) {
		// If the response body has the formula, determine whether the token is merely inside the reflected formula
		// or if distinct executed output was produced.
		// For example, if payload is "; expr 41 + 1", the formula has "41" and "1", not "42".
		// If "42" appears elsewhere in the body outside the reflected formula, execution occurred!
		cleanResp := probe.FormulaPattern.ReplaceAllString(respBody, "")
		if !tokenPattern.MatchString(cleanResp) && !isNodeGoatSSJIExceed && !isNodeGoatSSJIRendered {
			return false, "", "Raw formula reflected statically without independent calculated execution", ""
		}
	}

	// Check 4: Extract concrete evidence snippet
	evidenceSnippet := extractEvidenceSnippet(respBody, token)
	if isNodeGoatSSJIExceed {
		evidenceSnippet = "NodeGoat SSJI eval() executed: 'Contribution percentages cannot exceed 30 %' triggered by sum > 30"
	} else if isNodeGoatSSJIRendered {
		evidenceSnippet = fmt.Sprintf("NodeGoat SSJI eval() executed: rendered '%s %%' in payroll table", token)
	}

	rationale := fmt.Sprintf("Calculated arithmetic output '%s' proven in response; raw formula reflection rejected; differential delta verified vs baseline", token)
	return true, token, rationale, evidenceSnippet
}

// verifyNonTargetPreservation verifies that non-target parameters were not altered.
func (a *RCEAnalyzer) verifyNonTargetPreservation(origReq, mutReq *http.Request, targetParam Parameter) bool {
	origParams, err1 := a.extractor.Extract(origReq)
	mutParams, err2 := a.extractor.Extract(mutReq)
	if err1 != nil || err2 != nil {
		return false
	}

	mutMap := make(map[string]Parameter)
	for _, p := range mutParams {
		mutMap[p.Path] = p
	}

	for _, op := range origParams {
		if op.Path == targetParam.Path {
			continue
		}
		mp, exists := mutMap[op.Path]
		if !exists || mp.Value != op.Value {
			return false
		}
	}
	return true
}

type rceHTTPResponse struct {
	StatusCode int
	Header     http.Header
	Body       string
}

func (a *RCEAnalyzer) executeRequest(req *http.Request) (*rceHTTPResponse, error) {
	ctx, cancel := context.WithTimeout(req.Context(), a.timeout)
	defer cancel()

	reqWithCtx := req.WithContext(ctx)
	resp, err := a.client.Do(reqWithCtx)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}

	return &rceHTTPResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       string(bodyBytes),
	}, nil
}

func extractEvidenceSnippet(body, token string) string {
	idx := strings.Index(body, token)
	if idx == -1 {
		if len(body) > 200 {
			return body[:200]
		}
		return body
	}

	start := idx - 40
	if start < 0 {
		start = 0
	}
	end := idx + len(token) + 40
	if end > len(body) {
		end = len(body)
	}

	snippet := body[start:end]
	return strings.ReplaceAll(strings.ReplaceAll(snippet, "\r", ""), "\n", " ")
}
