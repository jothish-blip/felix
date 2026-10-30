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

// SSTIType defines the server-side template engine family.
type SSTIType string

const (
	SSTIJinja2Twig SSTIType = "SSTI_JINJA2_TWIG"
	SSTIFreemarker SSTIType = "SSTI_FREEMARKER"
	SSTIErb        SSTIType = "SSTI_RUBY_ERB"
	SSTISmarty     SSTIType = "SSTI_SMARTY"
	SSTISpringEL   SSTIType = "SSTI_SPRING_EL"
	SSTINone       SSTIType = "NONE"
)

// SSTIConfidence reflects the conclusive certainty of an SSTI finding.
type SSTIConfidence string

const (
	SSTIConfidenceConfirmed  SSTIConfidence = "CONFIRMED"
	SSTIConfidenceCandidate  SSTIConfidence = "CANDIDATE"
	SSTIConfidenceNotExposed SSTIConfidence = "NOT_EXPOSED"
)

// SSTIProbeDefinition defines a bounded non-destructive template expression probe.
type SSTIProbeDefinition struct {
	Name            string
	Type            SSTIType
	Engine          string
	Payload         string
	ArithmeticToken string
	FormulaPattern  *regexp.Regexp
	Description     string
}

// SSTIFinding records a verified or candidate server-side template injection vulnerability.
type SSTIFinding struct {
	TargetURL               string         `json:"target_url"`
	Parameter               Parameter      `json:"parameter"`
	Type                    SSTIType       `json:"type"`
	Confidence              SSTIConfidence `json:"confidence"`
	TemplateEngine          string         `json:"template_engine,omitempty"`
	ProbeName               string         `json:"probe_name"`
	Payload                 string         `json:"payload"`
	ArithmeticToken         string         `json:"arithmetic_token"`
	ExpectedOutput          string         `json:"expected_output"`
	MatchedOutput           string         `json:"matched_output,omitempty"`
	Evidence                string         `json:"evidence"`
	StatusCode              int            `json:"status_code"`
	NonTargetPreserved      bool           `json:"non_target_preserved"`
	ClassificationRationale string         `json:"classification_rationale"`
}

// DefaultSSTIProbes defines harmless template arithmetic expressions across major engines.
var DefaultSSTIProbes = []SSTIProbeDefinition{
	// 1. Jinja2 / Twig arithmetic: {{7*7}} -> 49
	{
		Name:            "Jinja2/Twig Math Expression",
		Type:            SSTIJinja2Twig,
		Engine:          "Jinja2 / Twig / Nunjucks",
		Payload:         "{{7*7}}",
		ArithmeticToken: "49",
		FormulaPattern:  regexp.MustCompile(`\{\{\s*7\s*\*\s*7\s*\}\}`),
		Description:     "Jinja2/Twig double-curly arithmetic expression {{7*7}} evaluating to 49",
	},
	// 2. Jinja2 string multiplication: {{7*'7'}} -> 7777777
	{
		Name:            "Jinja2 String Multiplication",
		Type:            SSTIJinja2Twig,
		Engine:          "Jinja2 / Python",
		Payload:         "{{7*'7'}}",
		ArithmeticToken: "7777777",
		FormulaPattern:  regexp.MustCompile(`\{\{\s*7\s*\*\s*['"]7['"]\s*\}\}`),
		Description:     "Python Jinja2 string repetition expression {{7*'7'}} evaluating to 7777777",
	},
	// 3. Freemarker / SpEL: ${7*7} -> 49
	{
		Name:            "Freemarker/SpEL Dollar Expression",
		Type:            SSTIFreemarker,
		Engine:          "Freemarker / Spring EL / MVEL",
		Payload:         "${7*7}",
		ArithmeticToken: "49",
		FormulaPattern:  regexp.MustCompile(`\$\{\s*7\s*\*\s*7\s*\}`),
		Description:     "Freemarker and Spring Expression Language dollar expression ${7*7} evaluating to 49",
	},
	// 4. Spring EL / MVEL Hash Expression: #{7*7} -> 49
	{
		Name:            "Spring EL Hash Expression",
		Type:            SSTISpringEL,
		Engine:          "Spring Expression Language / MVEL",
		Payload:         "#{7*7}",
		ArithmeticToken: "49",
		FormulaPattern:  regexp.MustCompile(`\#\{\s*7\s*\*\s*7\s*\}`),
		Description:     "Spring EL pound expression #{7*7} evaluating to 49",
	},
	// 5. Ruby ERB / EJS: <%= 7*7 %> -> 49
	{
		Name:            "Ruby ERB / EJS Tag Expression",
		Type:            SSTIErb,
		Engine:          "Ruby ERB / Node.js EJS",
		Payload:         "<%= 7*7 %>",
		ArithmeticToken: "49",
		FormulaPattern:  regexp.MustCompile(`<%\s*=\s*7\s*\*\s*7\s*%>`),
		Description:     "Ruby ERB / EJS evaluation tag <%= 7*7 %> evaluating to 49",
	},
	// 6. Smarty / Angular Tag: {7*7} -> 49
	{
		Name:            "Smarty Single Curly Expression",
		Type:            SSTISmarty,
		Engine:          "Smarty / PHP",
		Payload:         "{7*7}",
		ArithmeticToken: "49",
		FormulaPattern:  regexp.MustCompile(`\{\s*7\s*\*\s*7\s*\}`),
		Description:     "Smarty template engine single curly expression {7*7} evaluating to 49",
	},
	// 7. Nested syntax ${{7*7}} -> 49
	{
		Name:            "Nested Dollar-Curly Expression",
		Type:            SSTIJinja2Twig,
		Engine:          "Template Expression",
		Payload:         "${{7*7}}",
		ArithmeticToken: "49",
		FormulaPattern:  regexp.MustCompile(`\$\{\{\s*7\s*\*\s*7\s*\}\}`),
		Description:     "Nested dollar double-curly expression ${{7*7}} evaluating to 49",
	},
}

// SSTIAnalyzer coordinates server-side template injection detection.
type SSTIAnalyzer struct {
	client    *http.Client
	extractor *ParameterExtractor
	probes    []SSTIProbeDefinition
	timeout   time.Duration
}

// NewSSTIAnalyzer constructs a new SSTI analyzer.
func NewSSTIAnalyzer(client *http.Client, extractor *ParameterExtractor) *SSTIAnalyzer {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if extractor == nil {
		extractor = NewParameterExtractor()
	}
	return &SSTIAnalyzer{
		client:    client,
		extractor: extractor,
		probes:    DefaultSSTIProbes,
		timeout:   10 * time.Second,
	}
}

// SetProbes overrides the active SSTI probe definitions.
func (a *SSTIAnalyzer) SetProbes(probes []SSTIProbeDefinition) {
	a.probes = probes
}

// AnalyzeRequest audits all extractable parameters in an HTTP request for SSTI.
func (a *SSTIAnalyzer) AnalyzeRequest(req *http.Request) ([]SSTIFinding, error) {
	params, err := a.extractor.Extract(req)
	if err != nil {
		return nil, fmt.Errorf("failed to extract parameters for SSTI analysis: %w", err)
	}

	var allFindings []SSTIFinding
	for _, param := range params {
		findings, err := a.AnalyzeParameter(req, param)
		if err != nil {
			return nil, fmt.Errorf("error analyzing parameter %s for SSTI: %w", param.Name, err)
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// AnalyzeParameter tests a single parameter against bounded SSTI probes.
func (a *SSTIAnalyzer) AnalyzeParameter(req *http.Request, param Parameter) ([]SSTIFinding, error) {
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

	var findings []SSTIFinding

	for _, probe := range a.probes {
		// Mutate target parameter
		mutatedReq, err := a.extractor.GenerateMutation(req, param, probe.Payload)
		if err != nil {
			continue
		}

		// Verify non-target preservation
		nonTargetPreserved := a.verifyNonTargetPreservation(req, mutatedReq, param)

		resp, err := a.executeRequest(mutatedReq)
		if err != nil {
			continue
		}

		// Evaluate response for calculated arithmetic vs. static reflection
		confirmed, matchedToken, rationale, evidence := a.evaluateSSTI(probe, baselineBody, resp.Body, resp.StatusCode)

		confidence := SSTIConfidenceNotExposed
		if confirmed {
			confidence = SSTIConfidenceConfirmed
		} else if strings.Contains(resp.Body, probe.ArithmeticToken) && !strings.Contains(baselineBody, probe.ArithmeticToken) {
			confidence = SSTIConfidenceCandidate
		}

		finding := SSTIFinding{
			TargetURL:               req.URL.String(),
			Parameter:               param,
			Type:                    probe.Type,
			Confidence:              confidence,
			TemplateEngine:          probe.Engine,
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

		if confidence == SSTIConfidenceConfirmed {
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// evaluateSSTI rigorously validates template arithmetic evaluation while rejecting static reflection.
func (a *SSTIAnalyzer) evaluateSSTI(probe SSTIProbeDefinition, baselineBody string, respBody string, statusCode int) (bool, string, string, string) {
	token := probe.ArithmeticToken

	// Check 1: Does the response contain the evaluated output token (e.g. "49" or "7777777")?
	tokenPattern := regexp.MustCompile(`(?:\b|\D)` + regexp.QuoteMeta(token) + `(?:\b|\D)`)
	if !tokenPattern.MatchString(respBody) && strings.TrimSpace(respBody) != token {
		return false, "", "Calculated template arithmetic output absent in response", ""
	}

	// Check 2: Was this token already present in benign baseline response?
	baselineCount := strings.Count(baselineBody, token)
	respCount := strings.Count(respBody, token)
	if respCount <= baselineCount {
		return false, "", "Token frequency unchanged from benign baseline (static content)", ""
	}

	// Check 3: STATIC RAW REFLECTION REJECTION
	// If the server simply reflected the raw template tag without evaluating it (e.g. {{7*7}} in an HTML attribute),
	// this is static reflection, NOT SSTI!
	if probe.FormulaPattern != nil && probe.FormulaPattern.MatchString(respBody) {
		cleanResp := probe.FormulaPattern.ReplaceAllString(respBody, "")
		if !tokenPattern.MatchString(cleanResp) {
			return false, "", "Raw template expression reflected statically without evaluation", ""
		}
	}

	// Check 4: Extract evidence snippet
	evidenceSnippet := extractSSTIEvidenceSnippet(respBody, token)
	rationale := fmt.Sprintf("Template arithmetic evaluated: '%s' produced calculated output '%s' in %s engine; static raw string reflection rejected", probe.Payload, token, probe.Engine)

	return true, token, rationale, evidenceSnippet
}

// verifyNonTargetPreservation verifies that non-target parameters were not altered.
func (a *SSTIAnalyzer) verifyNonTargetPreservation(origReq, mutReq *http.Request, targetParam Parameter) bool {
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

type sstiHTTPResponse struct {
	StatusCode int
	Header     http.Header
	Body       string
}

func (a *SSTIAnalyzer) executeRequest(req *http.Request) (*sstiHTTPResponse, error) {
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

	return &sstiHTTPResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       string(bodyBytes),
	}, nil
}

func extractSSTIEvidenceSnippet(body, token string) string {
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
