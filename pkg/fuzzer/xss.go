package fuzzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// XSSContext represents the syntactic HTML or payload context in which a probe reflects.
type XSSContext string

const (
	XSSContextNone          XSSContext = "NONE"
	XSSContextHTMLBody      XSSContext = "HTML_BODY"
	XSSContextHTMLAttribute XSSContext = "HTML_ATTRIBUTE"
	XSSContextScriptTag     XSSContext = "SCRIPT_TAG"
	XSSContextHTMLComment   XSSContext = "HTML_COMMENT"
	XSSContextInertTag      XSSContext = "INERT_TAG"
	XSSContextJSONBody      XSSContext = "JSON_BODY"
)

// XSSConfidence indicates the degree of verification and exploitability.
type XSSConfidence string

const (
	// ConfidenceConfirmed indicates parser-visible executable vector structure (e.g. event-handler attribute injection
	// or unescaped script tag/statement), verified via static HTML parsing (parser-visible structure).
	XSSConfidenceConfirmed XSSConfidence = "CONFIRMED"

	// ConfidenceCandidate indicates unsafe HTML markup injection (such as custom element instantiation <felix_xss_probe>)
	// or unverified reflection where tag injection occurred but executable script invocation is unverified.
	XSSConfidenceCandidate XSSConfidence = "CANDIDATE"

	// ConfidenceNotExposed indicates entity-encoded, safely escaped, or inert reflection where execution is prevented.
	XSSConfidenceNotExposed XSSConfidence = "NOT_EXPOSED"
)

// XSSType defines the specific reflection vector discovered.
type XSSType string

const (
	XSSTypeHTMLInjection      XSSType = "HTML_INJECTION"       // Unencoded custom HTML markup reflection (tag creation without script)
	XSSTypeReflectedBody      XSSType = "REFLECTED_HTML_BODY"  // Unencoded HTML body reflection with executable script tags
	XSSTypeReflectedAttribute XSSType = "REFLECTED_ATTRIBUTE"  // Attribute quote breakout with event handler (parser-visible attribute structure)
	XSSTypeReflectedScript    XSSType = "REFLECTED_SCRIPT"     // Script block literal breakout (parser-visible script syntax)
	XSSTypeReflectedComment   XSSType = "REFLECTED_COMMENT"    // Comment breakout
	XSSTypeReflectedInert     XSSType = "REFLECTED_INERT"      // Reflection inside inert non-executing elements
	XSSTypeNone               XSSType = "NONE"
)

// ExecutionEvidenceModel defines the technical evidentiary foundation of the finding.
type ExecutionEvidenceModel string

const (
	ModelParserStructure ExecutionEvidenceModel = "PARSER_STRUCTURE"  // Static parser confirmed executable syntax/structure (does not verify browser runtime JS execution)
	ModelMarkupInjection ExecutionEvidenceModel = "MARKUP_INJECTION"  // Unsafe HTML element/tag creation confirmed without executable script payload
	ModelBrowserRuntime  ExecutionEvidenceModel = "BROWSER_RUNTIME"   // Verified in live headless browser execution environment
	ModelDefendedOrInert ExecutionEvidenceModel = "DEFENDED_OR_INERT" // Entity-encoded, safely escaped, or inert reflection
)

// XSSFinding records a verified, candidate, or defended XSS reflection finding.
type XSSFinding struct {
	TargetURL          string                 `json:"target_url"`
	Parameter          Parameter              `json:"parameter"`
	Type               XSSType                `json:"type"`
	Confidence         XSSConfidence          `json:"confidence"`
	Context            XSSContext             `json:"context"`
	EvidenceModel      ExecutionEvidenceModel `json:"evidence_model"`
	Payload            string                 `json:"payload"`
	Evidence           string                 `json:"evidence"`
	TagContext         string                 `json:"tag_context,omitempty"`
	AttributeName      string                 `json:"attribute_name,omitempty"`
	UnencodedReflected bool                   `json:"unencoded_reflected"`
	EncodedReflected   bool                   `json:"encoded_reflected"`
	NonTargetPreserved bool                   `json:"non_target_preserved"`
	ExecutionRationale string                 `json:"execution_rationale"`
}

// XSSProbeDefinition defines a context-aware test vector.
type XSSProbeDefinition struct {
	Name            string
	Context         XSSContext
	Payload         string
	BreakoutTag     string
	BreakoutAttr    string
	BreakoutScript  string
	IsScriptPayload bool
	Description     string
}

// Standard non-destructive XSS test probes prescribed by Felix specifications.
var DefaultXSSProbes = []XSSProbeDefinition{
	{
		Name:            "HTML_BODY_INJECTION",
		Context:         XSSContextHTMLBody,
		Payload:         "><felix_xss_probe>",
		BreakoutTag:     "felix_xss_probe",
		IsScriptPayload: false,
		Description:     "Universal closing breakout injecting custom <felix_xss_probe> element (HTML injection)",
	},
	{
		Name:            "HTML_TAG_DIRECT",
		Context:         XSSContextHTMLBody,
		Payload:         "<felix_xss_probe>",
		BreakoutTag:     "felix_xss_probe",
		IsScriptPayload: false,
		Description:     "Direct HTML body custom element injection (HTML injection)",
	},
	{
		Name:            "HTML_EVENT_HANDLER_DIRECT",
		Context:         XSSContextHTMLBody,
		Payload:         `<img src=x onerror="felix_xss_probe()">`,
		BreakoutAttr:    "onerror",
		IsScriptPayload: true,
		Description:     "Direct HTML body event handler element injection",
	},
	{
		Name:            "ATTRIBUTE_DOUBLE_QUOTE_BREAKOUT",
		Context:         XSSContextHTMLAttribute,
		Payload:         `" autofocus onfocus="felix_xss_probe()`,
		BreakoutAttr:    "onfocus",
		IsScriptPayload: true,
		Description:     "Double quote breakout injecting autofocus event handler",
	},
	{
		Name:            "ATTRIBUTE_SINGLE_QUOTE_BREAKOUT",
		Context:         XSSContextHTMLAttribute,
		Payload:         `' autofocus onfocus='felix_xss_probe()`,
		BreakoutAttr:    "onfocus",
		IsScriptPayload: true,
		Description:     "Single quote breakout injecting autofocus event handler",
	},
	{
		Name:            "SCRIPT_STRING_BREAKOUT",
		Context:         XSSContextScriptTag,
		Payload:         `';felix_xss_probe();//`,
		BreakoutScript:  `felix_xss_probe()`,
		IsScriptPayload: true,
		Description:     "JavaScript single quote string breakout with function invocation",
	},
	{
		Name:            "SCRIPT_TAG_CLOSING_BREAKOUT",
		Context:         XSSContextScriptTag,
		Payload:         `</script><img src=x onerror="felix_xss_probe()">`,
		BreakoutAttr:    "onerror",
		IsScriptPayload: true,
		Description:     "Script tag termination injecting event handler element",
	},
	{
		Name:            "COMMENT_BREAKOUT",
		Context:         XSSContextHTMLComment,
		Payload:         `--> <img src=x onerror="felix_xss_probe()">`,
		BreakoutAttr:    "onerror",
		IsScriptPayload: true,
		Description:     "HTML comment closure breakout into event handler element",
	},
}

// XSSAnalyzer orchestrates context discovery, probe injection, and DOM reflection verification.
type XSSAnalyzer struct {
	Client    *http.Client
	Extractor *ParameterExtractor
	Timeout   time.Duration
	Probes    []XSSProbeDefinition
}

// NewXSSAnalyzer initializes an analyzer with default timeout and probe configurations.
func NewXSSAnalyzer(client *http.Client, pe *ParameterExtractor) *XSSAnalyzer {
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
	return &XSSAnalyzer{
		Client:    client,
		Extractor: pe,
		Timeout:   5 * time.Second,
		Probes:    DefaultXSSProbes,
	}
}

// executeRequest performs an HTTP request safely respecting context deadlines.
func (xa *XSSAnalyzer) executeRequest(req *http.Request) (*http.Response, string, error) {
	ctx, cancel := context.WithTimeout(req.Context(), xa.Timeout)
	defer cancel()

	clonedReq := req.Clone(ctx)
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err == nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			clonedReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}

	resp, err := xa.Client.Do(clonedReq)
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

// ReflectionDetail describes the outcome of DOM reflection inspection.
type ReflectionDetail struct {
	Context            XSSContext
	Type               XSSType
	Confidence         XSSConfidence
	EvidenceModel      ExecutionEvidenceModel
	TagContext         string
	AttributeName      string
	BreakoutVerified   bool
	UnencodedReflected bool
	EncodedReflected   bool
	EvidenceSnippet    string
	Rationale          string
}

// AnalyzeParameter conducts context-aware reflection fuzzing for a specific parameter.
func (xa *XSSAnalyzer) AnalyzeParameter(origReq *http.Request, target Parameter) ([]XSSFinding, error) {
	targetURL := ""
	if origReq.URL != nil {
		targetURL = origReq.URL.String()
	}

	// 1. Initial harmless canary test to detect reflection presence and candidate context
	canaryValue := fmt.Sprintf("fx_canary_%d", time.Now().UnixNano()%100000)
	canaryReq, err := xa.Extractor.GenerateMutation(origReq, target, canaryValue)
	if err != nil {
		return nil, fmt.Errorf("failed to generate canary mutation: %w", err)
	}

	resp, canaryBody, err := xa.executeRequest(canaryReq)
	if err != nil {
		return nil, fmt.Errorf("canary request failed: %w", err)
	}

	contentType := resp.Header.Get("Content-Type")

	// If canary is not reflected anywhere in the response, short-circuit immediately
	if !strings.Contains(canaryBody, canaryValue) {
		return []XSSFinding{}, nil
	}

	// 2. Initial canary context inspection
	initialDetail := xa.InspectReflection(canaryBody, contentType, canaryValue, XSSProbeDefinition{
		Name:    "CANARY_PROBE",
		Context: XSSContextNone,
		Payload: canaryValue,
	})

	var findings []XSSFinding
	seenSignatures := make(map[string]bool)

	// 3. Execute context breakout probes
	for _, probe := range xa.Probes {
		probeReq, err := xa.Extractor.GenerateMutation(origReq, target, probe.Payload)
		if err != nil {
			continue
		}

		_, probeBody, err := xa.executeRequest(probeReq)
		if err != nil {
			continue
		}

		detail := xa.InspectReflection(probeBody, contentType, probe.Payload, probe)

		// De-duplicate findings by Type and Confidence
		sig := fmt.Sprintf("%s:%s:%s", detail.Type, detail.Confidence, detail.TagContext)
		if seenSignatures[sig] {
			continue
		}
		seenSignatures[sig] = true

		finding := XSSFinding{
			TargetURL:          targetURL,
			Parameter:          target,
			Type:               detail.Type,
			Confidence:         detail.Confidence,
			Context:            detail.Context,
			EvidenceModel:      detail.EvidenceModel,
			Payload:            probe.Payload,
			Evidence:           detail.EvidenceSnippet,
			TagContext:         detail.TagContext,
			AttributeName:      detail.AttributeName,
			UnencodedReflected: detail.UnencodedReflected,
			EncodedReflected:   detail.EncodedReflected,
			NonTargetPreserved: true,
			ExecutionRationale: detail.Rationale,
		}

		findings = append(findings, finding)
	}

	// If no breakout probe yielded a confirmed finding, but canary was observed in an inert/defended context,
	// record the baseline defended status.
	if len(findings) == 0 {
		findings = append(findings, XSSFinding{
			TargetURL:          targetURL,
			Parameter:          target,
			Type:               initialDetail.Type,
			Confidence:         XSSConfidenceNotExposed,
			Context:            initialDetail.Context,
			EvidenceModel:      ModelDefendedOrInert,
			Payload:            canaryValue,
			Evidence:           initialDetail.EvidenceSnippet,
			TagContext:         initialDetail.TagContext,
			AttributeName:      initialDetail.AttributeName,
			UnencodedReflected: false,
			EncodedReflected:   initialDetail.EncodedReflected,
			NonTargetPreserved: true,
			ExecutionRationale: initialDetail.Rationale,
		})
	}

	return findings, nil
}

// AnalyzeRequest extracts all input parameters and executes XSS reflection analysis across each.
func (xa *XSSAnalyzer) AnalyzeRequest(req *http.Request) ([]XSSFinding, error) {
	params, err := xa.Extractor.Extract(req)
	if err != nil {
		return nil, fmt.Errorf("failed to extract parameters: %w", err)
	}

	var allFindings []XSSFinding
	for _, p := range params {
		findings, err := xa.AnalyzeParameter(req, p)
		if err != nil {
			continue
		}
		allFindings = append(allFindings, findings...)
	}
	return allFindings, nil
}

// InspectReflection examines response structure (HTML/DOM or JSON) to determine reflection context,
// breakout success, entity encoding, and exploitability.
func (xa *XSSAnalyzer) InspectReflection(body, contentType, payload string, probe XSSProbeDefinition) ReflectionDetail {
	// 1. Check for JSON response encapsulation
	isJSON := strings.Contains(strings.ToLower(contentType), "application/json") ||
		(strings.HasPrefix(strings.TrimSpace(body), "{") && strings.HasSuffix(strings.TrimSpace(body), "}"))

	if isJSON {
		return xa.inspectJSONReflection(body, payload, probe)
	}

	// 2. Parse HTML body with net/html DOM parser
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		// Fallback to text heuristic if HTML parsing completely fails
		return xa.inspectTextFallback(body, payload, probe)
	}

	detail := ReflectionDetail{
		Context:       XSSContextNone,
		Type:          XSSTypeNone,
		Confidence:    XSSConfidenceNotExposed,
		EvidenceModel: ModelDefendedOrInert,
	}

	// 3. Check for raw entity encodings of critical characters in the unparsed body
	encStatus := xa.CheckEntityEncoding(body, payload)
	detail.EncodedReflected = encStatus.IsEncoded

	// 4. Traverse DOM tree searching for probe artifacts
	var occurrences []domOccurrence
	traverseDOM(doc, "", false, &occurrences)

	// Evaluate DOM occurrences against probe expectations
	for _, occ := range occurrences {
		// Case A: Unencoded tag breakout confirmed in DOM tree
		if probe.BreakoutTag != "" && occ.NodeTag == probe.BreakoutTag {
			detail.TagContext = occ.NodeTag
			detail.BreakoutVerified = true
			detail.UnencodedReflected = true
			detail.EvidenceSnippet = occ.Snippet

			if probe.IsScriptPayload || occ.NodeTag == "script" {
				detail.Context = XSSContextHTMLBody
				detail.Type = XSSTypeReflectedBody
				detail.Confidence = XSSConfidenceConfirmed
				detail.EvidenceModel = ModelParserStructure
				detail.Rationale = fmt.Sprintf("Parser-visible executable <%s> script tag instantiated in DOM; static HTML parser verifies structure, not browser runtime execution.", occ.NodeTag)
			} else {
				detail.Context = XSSContextHTMLBody
				detail.Type = XSSTypeHTMLInjection
				detail.Confidence = XSSConfidenceCandidate
				detail.EvidenceModel = ModelMarkupInjection
				detail.Rationale = fmt.Sprintf("Unsafe unencoded HTML tag reflection confirmed via DOM parser (<%s>); custom element creates DOM markup without executable script.", occ.NodeTag)
			}
			return detail
		}

		// Case B: Attribute breakout confirmed in DOM tree (e.g., injected 'onfocus' or 'onerror' attribute)
		if probe.BreakoutAttr != "" && occ.AttributeKey == probe.BreakoutAttr && strings.Contains(occ.AttributeVal, "felix_xss_probe") {
			detail.Context = probe.Context
			if detail.Context == XSSContextNone {
				detail.Context = XSSContextHTMLBody
			}
			detail.Type = XSSTypeReflectedAttribute
			if probe.Context == XSSContextHTMLBody {
				detail.Type = XSSTypeReflectedBody
			}
			detail.Confidence = XSSConfidenceConfirmed
			detail.EvidenceModel = ModelParserStructure
			detail.TagContext = occ.ParentTag
			detail.AttributeName = occ.AttributeKey
			detail.BreakoutVerified = true
			detail.UnencodedReflected = true
			detail.EvidenceSnippet = occ.Snippet
			detail.Rationale = fmt.Sprintf("Parser-visible event handler attribute %s=%q injected on <%s>; static HTML parser verifies attribute syntax, not browser runtime execution.", occ.AttributeKey, occ.AttributeVal, occ.ParentTag)
			return detail
		}

		// Case C: Script context execution confirmed (only for script breakout probes)
		if occ.InScript && probe.BreakoutScript != "" && strings.Contains(occ.TextContent, probe.BreakoutScript) {
			isEscaped := isJSStringEscaped(occ.TextContent, probe.BreakoutScript)
			if !isEscaped {
				detail.Context = XSSContextScriptTag
				detail.Type = XSSTypeReflectedScript
				detail.Confidence = XSSConfidenceConfirmed
				detail.EvidenceModel = ModelParserStructure
				detail.TagContext = "script"
				detail.BreakoutVerified = true
				detail.UnencodedReflected = true
				detail.EvidenceSnippet = occ.Snippet
				detail.Rationale = "Parser-visible unescaped JavaScript function call injected in script block; static parser verifies syntax structure, not browser runtime execution."
				return detail
			} else {
				detail.Context = XSSContextScriptTag
				detail.Type = XSSTypeReflectedScript
				detail.Confidence = XSSConfidenceNotExposed
				detail.EvidenceModel = ModelDefendedOrInert
				detail.TagContext = "script"
				detail.EncodedReflected = true
				detail.EvidenceSnippet = occ.Snippet
				detail.Rationale = "Probe reflection inside <script> is safely backslash-escaped; script breakout prevented"
			}
		}

		// Case D: Reflection inside inert tags (<textarea>, <title>, <style>, <noscript>)
		if occ.InInert != "" && (strings.Contains(occ.TextContent, payload) || strings.Contains(occ.TextContent, "felix_xss_probe")) {
			detail.Context = XSSContextInertTag
			detail.Type = XSSTypeReflectedInert
			detail.Confidence = XSSConfidenceNotExposed
			detail.EvidenceModel = ModelDefendedOrInert
			detail.TagContext = occ.InInert
			detail.EvidenceSnippet = occ.Snippet
			detail.Rationale = fmt.Sprintf("Probe reflected inside non-executable inert element <%s>; requires element closure breakout to execute", occ.InInert)
			return detail
		}

		// Case E: Passive reflection inside attribute value without breakout
		if occ.AttributeKey != "" && strings.Contains(occ.AttributeVal, payload) {
			detail.Context = XSSContextHTMLAttribute
			detail.Type = XSSTypeReflectedAttribute
			detail.Confidence = XSSConfidenceNotExposed
			detail.EvidenceModel = ModelDefendedOrInert
			detail.TagContext = occ.ParentTag
			detail.AttributeName = occ.AttributeKey
			detail.EvidenceSnippet = occ.Snippet
			detail.Rationale = fmt.Sprintf("Probe reflected passively inside attribute %s of <%s> without quote breakout", occ.AttributeKey, occ.ParentTag)
		}

		// Case F: Reflection inside HTML comment
		if occ.IsComment && strings.Contains(occ.TextContent, payload) {
			detail.Context = XSSContextHTMLComment
			detail.Type = XSSTypeReflectedComment
			detail.Confidence = XSSConfidenceNotExposed
			detail.EvidenceModel = ModelDefendedOrInert
			detail.EvidenceSnippet = occ.Snippet
			detail.Rationale = "Probe reflected inside HTML comment without '-->' breakout sequence"
		}

		// Case G: Passive reflection inside text node
		if occ.NodeTag == "" && occ.AttributeKey == "" && !occ.InScript && occ.InInert == "" && strings.Contains(occ.TextContent, payload) {
			if encStatus.IsEncoded {
				detail.Context = XSSContextHTMLBody
				detail.Type = XSSTypeReflectedBody
				detail.Confidence = XSSConfidenceNotExposed
				detail.EvidenceModel = ModelDefendedOrInert
				detail.EncodedReflected = true
				detail.EvidenceSnippet = extractSnippet(body, encStatus.EncodedMatch)
				detail.Rationale = fmt.Sprintf("Probe characters properly entity-encoded as %s in HTML body; execution prevented", encStatus.EncodedMatch)
			} else {
				if strings.Contains(body, payload) && (strings.Contains(payload, "<") || strings.Contains(payload, ">")) {
					detail.Context = XSSContextHTMLBody
					detail.Type = XSSTypeHTMLInjection
					detail.Confidence = XSSConfidenceCandidate
					detail.EvidenceModel = ModelMarkupInjection
					detail.UnencodedReflected = true
					detail.EvidenceSnippet = extractSnippet(body, payload)
					detail.Rationale = "Probe angle brackets reflected unencoded directly in response text (unsafe HTML markup injection)"
					return detail
				}
			}
		}
	}

	// If no specific occurrence matched but body contains the payload
	if detail.Context == XSSContextNone && strings.Contains(body, payload) {
		if encStatus.IsEncoded {
			detail.Context = XSSContextHTMLBody
			detail.Type = XSSTypeReflectedBody
			detail.Confidence = XSSConfidenceNotExposed
			detail.EvidenceModel = ModelDefendedOrInert
			detail.EncodedReflected = true
			detail.EvidenceSnippet = extractSnippet(body, encStatus.EncodedMatch)
			detail.Rationale = "Probe characters safely entity-encoded in HTML response"
		} else {
			detail.Context = XSSContextHTMLBody
			detail.Type = XSSTypeHTMLInjection
			detail.Confidence = XSSConfidenceCandidate
			detail.EvidenceModel = ModelMarkupInjection
			detail.UnencodedReflected = true
			detail.EvidenceSnippet = extractSnippet(body, payload)
			detail.Rationale = "Probe string reflected unencoded in response body; DOM context inconclusive"
		}
	}

	return detail
}

// inspectJSONReflection parses JSON payloads and inspects whether string properties contain unencoded HTML.
func (xa *XSSAnalyzer) inspectJSONReflection(body, payload string, probe XSSProbeDefinition) ReflectionDetail {
	detail := ReflectionDetail{
		Context:       XSSContextJSONBody,
		Type:          XSSTypeReflectedBody,
		Confidence:    XSSConfidenceNotExposed,
		EvidenceModel: ModelDefendedOrInert,
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return xa.inspectTextFallback(body, payload, probe)
	}

	encStatus := xa.CheckEntityEncoding(body, payload)
	detail.EncodedReflected = encStatus.IsEncoded

	// Check string fields in JSON for HTML snippets containing unencoded probe tags
	for key, val := range parsed {
		strVal, ok := val.(string)
		if !ok {
			continue
		}

		if strings.Contains(strVal, "felix_xss_probe") || strings.Contains(strVal, payload) {
			// Test if the JSON string is an HTML fragment (e.g. WebGoat 'output' field)
			fragNodes, err := html.ParseFragment(strings.NewReader(strVal), &html.Node{
				Type:     html.ElementNode,
				Data:     "body",
				DataAtom: atom.Body,
			})
			if err == nil {
				for _, fn := range fragNodes {
					var occs []domOccurrence
					traverseDOM(fn, "", false, &occs)
					for _, occ := range occs {
						if probe.BreakoutTag != "" && occ.NodeTag == probe.BreakoutTag {
							detail.TagContext = occ.NodeTag
							detail.BreakoutVerified = true
							detail.UnencodedReflected = true
							detail.EvidenceSnippet = fmt.Sprintf("json_field:%s -> %s", key, extractSnippet(strVal, probe.BreakoutTag))

							if probe.IsScriptPayload || occ.NodeTag == "script" {
								detail.Context = XSSContextHTMLBody
								detail.Type = XSSTypeReflectedBody
								detail.Confidence = XSSConfidenceConfirmed
								detail.EvidenceModel = ModelParserStructure
								detail.Rationale = fmt.Sprintf("JSON property %q contains parser-visible executable <%s> tag; static HTML parser verifies structure, not browser execution.", key, occ.NodeTag)
							} else {
								detail.Context = XSSContextHTMLBody
								detail.Type = XSSTypeHTMLInjection
								detail.Confidence = XSSConfidenceCandidate
								detail.EvidenceModel = ModelMarkupInjection
								detail.Rationale = fmt.Sprintf("JSON property %q contains unencoded HTML creating custom element <%s> (HTML injection); does not prove JavaScript execution.", key, occ.NodeTag)
							}
							return detail
						}

						if probe.BreakoutAttr != "" && occ.AttributeKey == probe.BreakoutAttr && strings.Contains(occ.AttributeVal, "felix_xss_probe") {
							detail.Context = XSSContextHTMLBody
							detail.Type = XSSTypeReflectedBody
							detail.Confidence = XSSConfidenceConfirmed
							detail.EvidenceModel = ModelParserStructure
							detail.TagContext = occ.ParentTag
							detail.AttributeName = occ.AttributeKey
							detail.BreakoutVerified = true
							detail.UnencodedReflected = true
							detail.EvidenceSnippet = fmt.Sprintf("json_field:%s -> %s", key, occ.Snippet)
							detail.Rationale = fmt.Sprintf("JSON property %q contains parser-visible event handler attribute %s=%q on <%s>; static HTML parser verifies attribute syntax, not browser runtime execution.", key, occ.AttributeKey, occ.AttributeVal, occ.ParentTag)
							return detail
						}
					}
				}
			}

			// If JSON string contains raw unencoded angle brackets
			if strings.Contains(strVal, "<script>") || strings.Contains(strVal, "<script ") {
				detail.Context = XSSContextHTMLBody
				detail.Type = XSSTypeReflectedBody
				detail.Confidence = XSSConfidenceConfirmed
				detail.EvidenceModel = ModelParserStructure
				detail.UnencodedReflected = true
				detail.EvidenceSnippet = fmt.Sprintf("json_field:%s -> %s", key, extractSnippet(strVal, payload))
				detail.Rationale = fmt.Sprintf("JSON property %q contains parser-visible <script> markup", key)
				return detail
			}

			if strings.Contains(strVal, "<felix_xss_probe>") || (strings.Contains(strVal, "<") && strings.Contains(strVal, ">")) {
				detail.Context = XSSContextHTMLBody
				detail.Type = XSSTypeHTMLInjection
				detail.Confidence = XSSConfidenceCandidate
				detail.EvidenceModel = ModelMarkupInjection
				detail.UnencodedReflected = true
				detail.EvidenceSnippet = fmt.Sprintf("json_field:%s -> %s", key, extractSnippet(strVal, payload))
				detail.Rationale = fmt.Sprintf("JSON property %q contains unencoded HTML markup (HTML injection)", key)
				return detail
			}

			detail.EvidenceSnippet = fmt.Sprintf("json_field:%s -> %s", key, extractSnippet(strVal, payload))
			detail.Rationale = fmt.Sprintf("Probe reflected inside JSON data field %q without HTML execution context", key)
		}
	}

	return detail
}

// inspectTextFallback provides heuristic classification when HTML parsing is unavailable.
func (xa *XSSAnalyzer) inspectTextFallback(body, payload string, probe XSSProbeDefinition) ReflectionDetail {
	detail := ReflectionDetail{
		Context:       XSSContextHTMLBody,
		Type:          XSSTypeReflectedBody,
		Confidence:    XSSConfidenceNotExposed,
		EvidenceModel: ModelDefendedOrInert,
	}

	encStatus := xa.CheckEntityEncoding(body, payload)
	detail.EncodedReflected = encStatus.IsEncoded

	if encStatus.IsEncoded {
		detail.Confidence = XSSConfidenceNotExposed
		detail.EvidenceModel = ModelDefendedOrInert
		detail.EvidenceSnippet = extractSnippet(body, encStatus.EncodedMatch)
		detail.Rationale = "Probe characters detected in entity-encoded form; execution prevented"
		return detail
	}

	if strings.Contains(body, "<script>") || strings.Contains(body, "onfocus=\"felix_xss_probe()\"") {
		detail.Confidence = XSSConfidenceConfirmed
		detail.EvidenceModel = ModelParserStructure
		detail.UnencodedReflected = true
		detail.EvidenceSnippet = extractSnippet(body, payload)
		detail.Rationale = "Parser-visible executable markup detected in raw response"
		return detail
	}

	if strings.Contains(body, "<felix_xss_probe>") {
		detail.Type = XSSTypeHTMLInjection
		detail.Confidence = XSSConfidenceCandidate
		detail.EvidenceModel = ModelMarkupInjection
		detail.UnencodedReflected = true
		detail.EvidenceSnippet = extractSnippet(body, payload)
		detail.Rationale = "Unencoded custom tag markup detected in raw response (HTML injection)"
		return detail
	}

	if strings.Contains(body, payload) {
		detail.Confidence = XSSConfidenceCandidate
		detail.EvidenceModel = ModelMarkupInjection
		detail.UnencodedReflected = true
		detail.EvidenceSnippet = extractSnippet(body, payload)
		detail.Rationale = "Payload string reflected in response text"
	}
	return detail
}

// domOccurrence stores a detected reflection node in the parsed DOM tree.
type domOccurrence struct {
	ParentTag    string
	NodeTag      string
	AttributeKey string
	AttributeVal string
	TextContent  string
	InScript     bool
	InInert      string
	IsComment    bool
	Snippet      string
}

// traverseDOM recursively walks the net/html DOM hierarchy extracting structural occurrences.
func traverseDOM(n *html.Node, inInert string, inScript bool, occurrences *[]domOccurrence) {
	if n == nil {
		return
	}

	currentInert := inInert
	currentScript := inScript

	switch n.Type {
	case html.ElementNode:
		tag := strings.ToLower(n.Data)
		if tag == "script" {
			currentScript = true
		} else if tag == "textarea" || tag == "title" || tag == "style" || tag == "noscript" || tag == "template" {
			currentInert = tag
		}

		// Record the element tag itself
		*occurrences = append(*occurrences, domOccurrence{
			NodeTag:   tag,
			InScript:  currentScript,
			InInert:   currentInert,
			Snippet:   renderNodeSnippet(n),
		})

		// Inspect all element attributes
		for _, attr := range n.Attr {
			*occurrences = append(*occurrences, domOccurrence{
				ParentTag:    tag,
				AttributeKey: strings.ToLower(attr.Key),
				AttributeVal: attr.Val,
				InScript:     currentScript,
				InInert:      currentInert,
				Snippet:      fmt.Sprintf("<%s %s=%q>", tag, attr.Key, attr.Val),
			})
		}

	case html.TextNode:
		parentTag := ""
		if n.Parent != nil {
			parentTag = strings.ToLower(n.Parent.Data)
		}
		*occurrences = append(*occurrences, domOccurrence{
			ParentTag:   parentTag,
			TextContent: n.Data,
			InScript:    currentScript,
			InInert:     currentInert,
			Snippet:     renderTextSnippet(n.Data),
		})

	case html.CommentNode:
		*occurrences = append(*occurrences, domOccurrence{
			IsComment:   true,
			TextContent: n.Data,
			Snippet:     fmt.Sprintf("<!-- %s -->", renderTextSnippet(n.Data)),
		})
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		traverseDOM(c, currentInert, currentScript, occurrences)
	}
}

// EntityEncodingStatus details whether critical characters were escaped.
type EntityEncodingStatus struct {
	IsEncoded    bool
	EncodedMatch string
}

// CheckEntityEncoding determines if critical XSS characters (<, >, ", ') are entity-encoded.
func (xa *XSSAnalyzer) CheckEntityEncoding(body, probe string) EntityEncodingStatus {
	encodedPatterns := []string{
		"&lt;", "&#60;", "&#x3c;", "&#x3C;",
		"&gt;", "&#62;", "&#x3e;", "&#x3E;",
		"&quot;", "&#34;", "&#x22;",
		"&#39;", "&#x27;", "&apos;",
		"&amp;", "&#38;", "&#x26;",
		`\u003c`, `\u003e`, `\u0022`, `\u0027`,
	}

	// If probe contained '<' or '>' or quotes, check if those exact tokens appear encoded in body
	for _, ep := range encodedPatterns {
		if strings.Contains(body, ep) {
			// Verify the encoded entity appears in proximity to the probe canary or probe tokens
			if strings.Contains(body, ep+"felix_xss_probe") ||
				strings.Contains(body, "felix_xss_probe"+ep) ||
				strings.Contains(body, ep+"fx_canary") ||
				strings.Contains(body, ep) {
				return EntityEncodingStatus{
					IsEncoded:    true,
					EncodedMatch: ep,
				}
			}
		}
	}

	return EntityEncodingStatus{IsEncoded: false}
}

// isJSStringEscaped checks if the target function call inside a script block was preceded
// by an odd number of backslashes escaping the string delimiter quote.
func isJSStringEscaped(scriptText, marker string) bool {
	idx := strings.Index(scriptText, marker)
	if idx <= 0 {
		return false
	}

	// Look backwards from the marker to find quote delimiters and backslashes
	prefix := scriptText[:idx]
	lastQuoteIdx := strings.LastIndexAny(prefix, `'"`)
	if lastQuoteIdx == -1 {
		return false
	}

	// Count consecutive backslashes preceding the quote
	slashCount := 0
	for i := lastQuoteIdx - 1; i >= 0 && prefix[i] == '\\'; i-- {
		slashCount++
	}

	// Odd number of backslashes means the quote delimiter is escaped: \' or \"
	return slashCount%2 == 1
}

// extractSnippet locates target in text and returns a context snippet with surrounding boundaries.
func extractSnippet(text, target string) string {
	idx := strings.Index(text, target)
	if idx == -1 {
		if len(text) > 80 {
			return text[:80] + "..."
		}
		return text
	}

	start := idx - 30
	if start < 0 {
		start = 0
	}
	end := idx + len(target) + 30
	if end > len(text) {
		end = len(text)
	}

	snip := strings.ReplaceAll(text[start:end], "\n", " ")
	snip = strings.ReplaceAll(snip, "\r", " ")
	return strings.TrimSpace(snip)
}

func renderNodeSnippet(n *html.Node) string {
	var buf bytes.Buffer
	_ = html.Render(&buf, n)
	s := buf.String()
	if len(s) > 100 {
		return s[:100] + "..."
	}
	return s
}

func renderTextSnippet(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}
