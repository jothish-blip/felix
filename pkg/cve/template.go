package cve

import (
	"bytes"
	"context"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"felix/pkg/crawler"
	"felix/pkg/oast"
	"gopkg.in/yaml.v3"
)

//go:embed templates/*.yaml
var BuiltinTemplatesFS embed.FS

// Standard severity levels for vulnerability templates.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Template represents the parsed declarative Nuclei-compatible YAML vulnerability template.
type Template struct {
	ID         string                 `yaml:"id"`
	Info       TemplateInfo           `yaml:"info"`
	HTTP       []HTTPRequestConfig    `yaml:"http,omitempty"`
	Requests   []HTTPRequestConfig    `yaml:"requests,omitempty"` // Alias for community compatibility
	TCP        any                    `yaml:"tcp,omitempty"`
	DNS        any                    `yaml:"dns,omitempty"`
	SSL        any                    `yaml:"ssl,omitempty"`
	Headless   any                    `yaml:"headless,omitempty"`
	Websocket  any                    `yaml:"websocket,omitempty"`
	RawYAML    string                 `yaml:"-"`
	SourcePath string                 `yaml:"-"`
}

// TemplateInfo contains comprehensive vulnerability metadata and classification.
type TemplateInfo struct {
	Name           string                 `yaml:"name"`
	Author         string                 `yaml:"author"`
	Severity       string                 `yaml:"severity"`
	Description    string                 `yaml:"description"`
	Reference      any                    `yaml:"reference,omitempty"` // string or []any
	Tags           string                 `yaml:"tags,omitempty"`
	Classification map[string]any         `yaml:"classification,omitempty"`
	Metadata       map[string]any         `yaml:"metadata,omitempty"`
}

// HTTPRequestConfig defines the HTTP probing request and matching specifications.
type HTTPRequestConfig struct {
	Method            string            `yaml:"method"`
	Path              any               `yaml:"path"` // string or []any
	Headers           map[string]string `yaml:"headers,omitempty"`
	Body              string            `yaml:"body,omitempty"`
	MatchersCondition string            `yaml:"matchers-condition,omitempty"` // "and" | "or"
	Matchers          []MatcherConfig   `yaml:"matchers,omitempty"`
	Extractors        []ExtractorConfig `yaml:"extractors,omitempty"`
	MaxRedirects      int               `yaml:"max-redirects,omitempty"`
	Timeout           int               `yaml:"timeout,omitempty"` // seconds
}

// MatcherConfig specifies matching rules across response status, words, regex, or binary hex.
type MatcherConfig struct {
	Type            string   `yaml:"type"` // "status", "word", "words", "regex", "binary", "hex"
	Name            string   `yaml:"name,omitempty"`
	Status          []int    `yaml:"status,omitempty"`
	Words           []string `yaml:"words,omitempty"`
	Regex           []string `yaml:"regex,omitempty"`
	Binary          []string `yaml:"binary,omitempty"`
	Part            string   `yaml:"part,omitempty"`      // "body" (default), "header", "all"
	Condition       string   `yaml:"condition,omitempty"` // "and" | "or"
	CaseInsensitive bool     `yaml:"case-insensitive,omitempty"`
	Negative        bool     `yaml:"negative,omitempty"`
}

// ExtractorConfig specifies dynamic extraction of parameters or versions from responses.
type ExtractorConfig struct {
	Type  string   `yaml:"type"` // "regex"
	Name  string   `yaml:"name,omitempty"`
	Part  string   `yaml:"part,omitempty"` // "body", "header"
	Regex []string `yaml:"regex,omitempty"`
	Group int      `yaml:"group,omitempty"`
}

// ResponseContext encapsulates the HTTP response payload for compiled matcher evaluation.
type ResponseContext struct {
	StatusCode    int
	HeaderBytes   []byte
	HeaderString  string
	BodyBytes     []byte
	BodyString    string
	LowerBody     string
	RequestURL    string
	RequestMethod string
	Duration      time.Duration
}

// CompiledMatcher is a high-performance in-memory closure evaluating response criteria.
type CompiledMatcher func(resp *ResponseContext) (matched bool, evidence string)

// CompiledExtractor is an in-memory closure extracting tokens or version strings.
type CompiledExtractor func(resp *ResponseContext) map[string]string

// CompiledHTTPRequest encapsulates compiled execution closures for a single probe.
type CompiledHTTPRequest struct {
	Method            string
	Paths             []string
	Headers           map[string]string
	Body              string
	MatchersCondition string // "and" | "or"
	Matchers          []CompiledMatcher
	Extractors        []CompiledExtractor
	MaxRedirects      int
	Timeout           time.Duration
}

// TemplateFinding records a verified or refuted vulnerability match outcome.
type TemplateFinding struct {
	TemplateID       string             `json:"template_id"`
	CVEID            string             `json:"cve_id,omitempty"`
	Name             string             `json:"name"`
	Severity         string             `json:"severity"`
	CVSSScore        float64            `json:"cvss_score,omitempty"`
	TargetURL        string             `json:"target_url"`
	MatchedURL       string             `json:"matched_url,omitempty"`
	Matched          bool               `json:"matched"`
	Evidence         []string           `json:"evidence,omitempty"`
	ExtractedData    map[string]string  `json:"extracted_data,omitempty"`
	Duration         time.Duration      `json:"duration"`
	Error            string             `json:"error,omitempty"`
	Timestamp        time.Time          `json:"timestamp"`
	OASTInteractions []oast.Interaction `json:"oast_interactions,omitempty"`
}

// ExecutionOptions defines network authorization and execution boundaries for template probes.
type ExecutionOptions struct {
	Client          *http.Client
	AllowLoopback   bool
	AllowPrivateIPs bool
	OASTCorrelator  *oast.Correlator
	OASTDomain      string
	OASTTimeout     time.Duration
}

// CompiledTemplate holds the pre-compiled, allocation-minimized execution pipeline.
type CompiledTemplate struct {
	ID        string
	Info      TemplateInfo
	CVEID     string
	Severity  string
	CVSSScore float64
	Requests  []CompiledHTTPRequest

	// Execute runs this template against the authorized target URL using safe networking.
	Execute func(ctx context.Context, targetURL string, client *http.Client) (*TemplateFinding, error)

	// ExecuteWithOptions runs this template with explicit network permissions and configuration.
	ExecuteWithOptions func(ctx context.Context, targetURL string, opts ExecutionOptions) (*TemplateFinding, error)
}

// ParseTemplate parses raw YAML bytes into a Template struct without compiling.
func ParseTemplate(yamlBytes []byte, sourcePath string) (*Template, error) {
	if len(yamlBytes) == 0 {
		return nil, errors.New("empty template source")
	}

	var tmpl Template
	decoder := yaml.NewDecoder(bytes.NewReader(yamlBytes))
	if err := decoder.Decode(&tmpl); err != nil {
		return nil, fmt.Errorf("YAML syntax error: %w", err)
	}

	tmpl.RawYAML = string(yamlBytes)
	tmpl.SourcePath = sourcePath

	if err := ValidateTemplate(&tmpl); err != nil {
		return nil, err
	}

	return &tmpl, nil
}

// ValidateTemplate verifies mandatory metadata, severities, and request structures.
func ValidateTemplate(t *Template) error {
	if t.TCP != nil || t.DNS != nil || t.SSL != nil || t.Headless != nil || t.Websocket != nil {
		return fmt.Errorf("template %q specifies unsupported protocol engine (only HTTP is supported in Subphase 4.3)", t.ID)
	}

	if strings.TrimSpace(t.ID) == "" {
		return errors.New("template missing required 'id'")
	}
	if strings.TrimSpace(t.Info.Name) == "" {
		return fmt.Errorf("template %q missing required 'info.name'", t.ID)
	}
	if strings.TrimSpace(t.Info.Author) == "" {
		return fmt.Errorf("template %q missing required 'info.author'", t.ID)
	}

	sev := strings.ToLower(strings.TrimSpace(t.Info.Severity))
	switch sev {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo, "":
		// Valid
	default:
		return fmt.Errorf("template %q has invalid severity %q (expected critical, high, medium, low, info)", t.ID, t.Info.Severity)
	}

	// Merge HTTP and Requests aliases
	reqs := t.HTTP
	if len(reqs) == 0 {
		reqs = t.Requests
	}
	if len(reqs) == 0 {
		return fmt.Errorf("template %q contains zero HTTP requests", t.ID)
	}

	for i, r := range reqs {
		if strings.TrimSpace(r.Method) == "" {
			return fmt.Errorf("template %q request [%d] missing 'method'", t.ID, i)
		}
		paths := extractStringSlice(r.Path)
		if len(paths) == 0 {
			return fmt.Errorf("template %q request [%d] missing 'path'", t.ID, i)
		}

		matchersCond := strings.ToLower(strings.TrimSpace(r.MatchersCondition))
		if matchersCond != "" && matchersCond != "and" && matchersCond != "or" {
			return fmt.Errorf("template %q request [%d] has invalid matchers-condition %q (expected 'and' or 'or')", t.ID, i, r.MatchersCondition)
		}

		for mIdx, m := range r.Matchers {
			mType := strings.ToLower(strings.TrimSpace(m.Type))
			switch mType {
			case "status", "word", "words", "regex", "binary", "hex":
				// Supported
			default:
				return fmt.Errorf("template %q request [%d] matcher [%d] has unsupported type %q", t.ID, i, mIdx, m.Type)
			}

			mPart := strings.ToLower(strings.TrimSpace(m.Part))
			switch mPart {
			case "", "body", "header", "headers", "all":
				// Supported
			default:
				return fmt.Errorf("template %q request [%d] matcher [%d] has unsupported part %q", t.ID, i, mIdx, m.Part)
			}

			mCond := strings.ToLower(strings.TrimSpace(m.Condition))
			if mCond != "" && mCond != "and" && mCond != "or" {
				return fmt.Errorf("template %q request [%d] matcher [%d] has invalid condition %q", t.ID, i, mIdx, m.Condition)
			}
		}

		for eIdx, e := range r.Extractors {
			eType := strings.ToLower(strings.TrimSpace(e.Type))
			if eType != "regex" && eType != "" {
				return fmt.Errorf("template %q request [%d] extractor [%d] has unsupported type %q (only 'regex' is supported)", t.ID, i, eIdx, e.Type)
			}
		}
	}

	return nil
}

// effectivePort returns the canonical normalized port for a URL ("80" for http, "443" for https if omitted).
func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	return "80"
}

// CompileTemplate transforms a validated Template into an optimized CompiledTemplate.
// Compiles regular expressions, binary hex patterns, and word matching logic once into Go closures.
func CompileTemplate(t *Template) (*CompiledTemplate, error) {
	if err := ValidateTemplate(t); err != nil {
		return nil, err
	}

	cveID := ""
	if t.Info.Classification != nil {
		if c, ok := t.Info.Classification["cve-id"]; ok {
			cveID = fmt.Sprintf("%v", c)
		}
	}
	if cveID == "" && strings.HasPrefix(strings.ToLower(t.ID), "cve-") {
		cveID = strings.ToUpper(t.ID)
	}

	var cvssScore float64
	if t.Info.Classification != nil {
		if s, ok := t.Info.Classification["cvss-score"]; ok {
			switch val := s.(type) {
			case float64:
				cvssScore = val
			case int:
				cvssScore = float64(val)
			case string:
				cvssScore, _ = strconv.ParseFloat(val, 64)
			}
		}
	}

	reqConfigs := t.HTTP
	if len(reqConfigs) == 0 {
		reqConfigs = t.Requests
	}

	compiledReqs := make([]CompiledHTTPRequest, 0, len(reqConfigs))
	for rIdx, r := range reqConfigs {
		paths := extractStringSlice(r.Path)

		// Compile matchers
		matchersCondition := strings.ToLower(strings.TrimSpace(r.MatchersCondition))
		if matchersCondition == "" {
			matchersCondition = "and"
		}

		compiledMatchers := make([]CompiledMatcher, 0, len(r.Matchers))
		for mIdx, m := range r.Matchers {
			cm, err := compileMatcher(m)
			if err != nil {
				return nil, fmt.Errorf("template %q req[%d] matcher[%d] compilation error: %w", t.ID, rIdx, mIdx, err)
			}
			compiledMatchers = append(compiledMatchers, cm)
		}

		// Compile extractors
		compiledExtractors := make([]CompiledExtractor, 0, len(r.Extractors))
		for eIdx, e := range r.Extractors {
			ce, err := compileExtractor(e)
			if err != nil {
				return nil, fmt.Errorf("template %q req[%d] extractor[%d] compilation error: %w", t.ID, rIdx, eIdx, err)
			}
			compiledExtractors = append(compiledExtractors, ce)
		}

		reqTimeout := time.Duration(r.Timeout) * time.Second
		if reqTimeout <= 0 {
			reqTimeout = 10 * time.Second
		}

		maxRedir := r.MaxRedirects
		if maxRedir <= 0 {
			maxRedir = 3
		}

		compiledReqs = append(compiledReqs, CompiledHTTPRequest{
			Method:            strings.ToUpper(strings.TrimSpace(r.Method)),
			Paths:             paths,
			Headers:           r.Headers,
			Body:              r.Body,
			MatchersCondition: matchersCondition,
			Matchers:          compiledMatchers,
			Extractors:        compiledExtractors,
			MaxRedirects:      maxRedir,
			Timeout:           reqTimeout,
		})
	}

	ct := &CompiledTemplate{
		ID:        t.ID,
		Info:      t.Info,
		CVEID:     cveID,
		Severity:  strings.ToLower(strings.TrimSpace(t.Info.Severity)),
		CVSSScore: cvssScore,
		Requests:  compiledReqs,
	}

	// Build the optimized template execution closure with explicit network options
	ct.ExecuteWithOptions = func(ctx context.Context, targetURL string, opts ExecutionOptions) (*TemplateFinding, error) {
		start := time.Now()

		parsedTarget, err := url.Parse(targetURL)
		if err != nil {
			return nil, fmt.Errorf("invalid target URL %q: %w", targetURL, err)
		}
		if parsedTarget.Scheme != "http" && parsedTarget.Scheme != "https" {
			return nil, fmt.Errorf("unsupported URL scheme %q for %s", parsedTarget.Scheme, targetURL)
		}
		if parsedTarget.Hostname() == "" {
			return nil, fmt.Errorf("invalid target URL %q: missing host", targetURL)
		}
		if parsedTarget.User != nil {
			return nil, fmt.Errorf("target URL %q contains disallowed embedded credentials", targetURL)
		}

		targetEffectivePort := effectivePort(parsedTarget)
		initialIsHTTPS := strings.EqualFold(parsedTarget.Scheme, "https")

		finding := &TemplateFinding{
			TemplateID:    ct.ID,
			CVEID:         ct.CVEID,
			Name:          ct.Info.Name,
			Severity:      ct.Severity,
			CVSSScore:     ct.CVSSScore,
			TargetURL:     targetURL,
			Matched:       false,
			Evidence:      make([]string, 0, 4),
			ExtractedData: make(map[string]string),
			Timestamp:     time.Now().UTC(),
		}

		// Ensure safe client
		activeClient := opts.Client
		if activeClient == nil {
			activeClient = &http.Client{
				Timeout: 10 * time.Second,
				Transport: crawler.NewSafeTransport(crawler.SafeTransportOptions{
					AllowLoopback:   opts.AllowLoopback,
					AllowPrivateIPs: opts.AllowPrivateIPs,
					Timeout:         10 * time.Second,
				}),
			}
		}

		// Clone and enforce strict scope and SSRF-safe redirect boundary
		clientCopy := *activeClient
		origCheckRedirect := clientCopy.CheckRedirect
		clientCopy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after %d redirects", 10)
			}
			scheme := strings.ToLower(req.URL.Scheme)
			if scheme != "http" && scheme != "https" {
				return fmt.Errorf("redirect to unsupported scheme %q blocked", req.URL.Scheme)
			}

			// Prevent HTTPS -> HTTP scheme downgrade redirects
			if initialIsHTTPS && scheme == "http" {
				return fmt.Errorf("insecure redirect downgrade from HTTPS to HTTP blocked for %s", req.URL.String())
			}

			if req.URL.User != nil {
				return errors.New("redirect with embedded credentials blocked")
			}
			destHost := req.URL.Hostname()
			if !strings.EqualFold(destHost, parsedTarget.Hostname()) {
				return fmt.Errorf("redirect to out-of-scope host %q blocked", destHost)
			}

			// Enforce target port confinement on redirects
			if effectivePort(req.URL) != targetEffectivePort {
				return fmt.Errorf("redirect to out-of-scope port %q blocked (expected %s)", effectivePort(req.URL), targetEffectivePort)
			}

			if ip := net.ParseIP(destHost); ip != nil {
				allowLB := opts.AllowLoopback || (opts.Client != nil && ip.IsLoopback())
				allowPriv := opts.AllowPrivateIPs || (opts.Client != nil && ip.IsPrivate())
				if prohibited, reason := crawler.ProhibitedIPReason(ip, allowLB, allowPriv); prohibited {
					return &crawler.SSRFError{Host: destHost, IP: ip, Reason: reason}
				}
			}
			if origCheckRedirect != nil {
				return origCheckRedirect(req, via)
			}
			return nil
		}
		activeClient = &clientCopy

		// Register OAST probe if correlator is configured and template uses OAST variables
		var activeOASTProbe *oast.Probe
		var oastVars map[string]string
		if opts.OASTCorrelator != nil {
			needsOAST := false
			for _, req := range ct.Requests {
				for _, p := range req.Paths {
					if strings.Contains(p, "{{OAST_") {
						needsOAST = true
						break
					}
				}
				if strings.Contains(req.Body, "{{OAST_") {
					needsOAST = true
				}
				for _, hv := range req.Headers {
					if strings.Contains(hv, "{{OAST_") {
						needsOAST = true
					}
				}
				if needsOAST {
					break
				}
			}

			if needsOAST {
				p, err := opts.OASTCorrelator.RegisterProbe(oast.ProbeOptions{
					FindingID:  fmt.Sprintf("finding-%s-%d", ct.ID, time.Now().UnixNano()),
					TemplateID: ct.ID,
					TargetURL:  targetURL,
					ProbeType:  "oast_template",
					OASTDomain: opts.OASTDomain,
					TTL:        30 * time.Second,
				})
				if err == nil && p != nil {
					activeOASTProbe = p
					oastVars = map[string]string{
						"{{OAST_DOMAIN}}": p.CallbackDomain,
						"{{OAST_HOST}}":   p.CallbackDomain,
						"{{OAST_TOKEN}}":  p.Token,
						"{{OAST_URL}}":    p.CallbackURL,
					}
				}
			}
		}

		allReqsMatched := true

		for _, req := range ct.Requests {
			reqMatched := false

			for _, pathTmpl := range req.Paths {
				// Evaluate context cancellation
				select {
				case <-ctx.Done():
					finding.Error = ctx.Err().Error()
					finding.Duration = time.Since(start)
					return finding, ctx.Err()
				default:
				}

				resolvedURL := substituteTemplateVariables(pathTmpl, parsedTarget, oastVars)
				resolvedParsed, err := url.Parse(resolvedURL)
				if err != nil {
					finding.Error = fmt.Sprintf("invalid resolved URL: %v", err)
					continue
				}
				if !strings.EqualFold(resolvedParsed.Hostname(), parsedTarget.Hostname()) {
					finding.Error = fmt.Sprintf("resolved URL %q attempts to escape target scope %q", resolvedURL, parsedTarget.Hostname())
					continue
				}

				// Enforce target port confinement on template requests
				if effectivePort(resolvedParsed) != targetEffectivePort {
					finding.Error = fmt.Sprintf("resolved URL %q attempts to escape target port %s (effective port: %s)", resolvedURL, targetEffectivePort, effectivePort(resolvedParsed))
					continue
				}

				if resolvedParsed.Scheme != "http" && resolvedParsed.Scheme != "https" {
					finding.Error = fmt.Sprintf("resolved URL %q has disallowed scheme %q", resolvedURL, resolvedParsed.Scheme)
					continue
				}
				if resolvedParsed.User != nil {
					finding.Error = fmt.Sprintf("resolved URL %q contains disallowed embedded credentials", resolvedURL)
					continue
				}

				// Construct HTTP Request
				var bodyReader io.Reader
				if req.Body != "" {
					resolvedBody := substituteTemplateVariables(req.Body, parsedTarget, oastVars)
					bodyReader = strings.NewReader(resolvedBody)
				}

				httpReq, err := http.NewRequestWithContext(ctx, req.Method, resolvedURL, bodyReader)
				if err != nil {
					finding.Error = fmt.Sprintf("failed creating request: %v", err)
					finding.Duration = time.Since(start)
					return finding, err
				}

				// Populate Headers
				for k, v := range req.Headers {
					httpReq.Header.Set(k, substituteTemplateVariables(v, parsedTarget, oastVars))
				}
				if httpReq.Header.Get("User-Agent") == "" {
					httpReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) FELIX/3.0 Security Assessor")
				}

				reqStart := time.Now()
				resp, err := activeClient.Do(httpReq)
				if err != nil {
					finding.Error = fmt.Sprintf("request dispatch failed: %v", err)
					continue
				}

				// Enforce safe response body cap (max 2 MB)
				const maxRespBytes = 2 * 1024 * 1024
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
				resp.Body.Close()

				// Build Header bytes
				var headerBuf bytes.Buffer
				_ = resp.Header.Write(&headerBuf)
				headerBytes := headerBuf.Bytes()

				bodyStr := string(bodyBytes)
				respCtx := &ResponseContext{
					StatusCode:    resp.StatusCode,
					HeaderBytes:   headerBytes,
					HeaderString:  string(headerBytes),
					BodyBytes:     bodyBytes,
					BodyString:    bodyStr,
					LowerBody:     strings.ToLower(bodyStr),
					RequestURL:    resolvedURL,
					RequestMethod: req.Method,
					Duration:      time.Since(reqStart),
				}

				// Evaluate Matchers
				var matchedCount int
				matchedEvidences := make([]string, 0, len(req.Matchers))

				for _, m := range req.Matchers {
					isM, ev := m(respCtx)
					if isM {
						matchedCount++
						if ev != "" {
							matchedEvidences = append(matchedEvidences, ev)
						}
					}
				}

				var thisPathMatched bool
				if len(req.Matchers) == 0 {
					thisPathMatched = true
				} else if req.MatchersCondition == "and" {
					thisPathMatched = (matchedCount == len(req.Matchers))
				} else { // "or" condition
					thisPathMatched = (matchedCount > 0)
				}

				if thisPathMatched {
					reqMatched = true
					finding.MatchedURL = resolvedURL
					finding.Evidence = append(finding.Evidence, matchedEvidences...)

					// Execute Extractors
					for _, ext := range req.Extractors {
						extData := ext(respCtx)
						for k, v := range extData {
							finding.ExtractedData[k] = v
						}
					}
					break // Successfully matched on this path
				}
			}

			if !reqMatched {
				allReqsMatched = false
				break
			}
		}

		if activeOASTProbe != nil {
			waitTimeout := opts.OASTTimeout
			if waitTimeout <= 0 {
				waitTimeout = 100 * time.Millisecond
			}
			inter, err := opts.OASTCorrelator.WaitForInteraction(ctx, activeOASTProbe.Token, waitTimeout)
			if err == nil && inter != nil {
				finding.Evidence = append(finding.Evidence, fmt.Sprintf("OAST interaction confirmed: protocol=%s client_ip=%s token=%s (out-of-band callback observed; does not prove code execution or data exfiltration)", inter.Protocol, inter.ClientIP, inter.Token))
				finding.OASTInteractions = append(finding.OASTInteractions, *inter)
			}
		}

		finding.Matched = allReqsMatched || len(finding.OASTInteractions) > 0
		finding.Duration = time.Since(start)
		return finding, nil
	}

	// Build the standard Execute closure (inherits system/environment authorization)
	ct.Execute = func(ctx context.Context, targetURL string, client *http.Client) (*TemplateFinding, error) {
		allowLoopback := os.Getenv("FELIX_ALLOW_LOOPBACK") == "true" || os.Getenv("FELIX_ALLOW_LOOPBACK") == "1"
		allowPrivate := os.Getenv("FELIX_ALLOW_PRIVATE") == "true" || os.Getenv("FELIX_ALLOW_PRIVATE") == "1"
		return ct.ExecuteWithOptions(ctx, targetURL, ExecutionOptions{
			Client:          client,
			AllowLoopback:   allowLoopback,
			AllowPrivateIPs: allowPrivate,
		})
	}

	return ct, nil
}

// compileMatcher compiles a single declarative MatcherConfig into a reusable CompiledMatcher closure.
func compileMatcher(m MatcherConfig) (CompiledMatcher, error) {
	mType := strings.ToLower(strings.TrimSpace(m.Type))
	part := strings.ToLower(strings.TrimSpace(m.Part))
	if part == "" {
		part = "body"
	}
	cond := strings.ToLower(strings.TrimSpace(m.Condition))
	if cond == "" {
		cond = "or"
	}
	isNegative := m.Negative

	switch mType {
	case "status":
		if len(m.Status) == 0 {
			return nil, errors.New("status matcher must specify at least one HTTP status code")
		}
		statusSet := make(map[int]bool, len(m.Status))
		for _, s := range m.Status {
			statusSet[s] = true
		}
		return func(resp *ResponseContext) (bool, string) {
			matched := statusSet[resp.StatusCode]
			if isNegative {
				matched = !matched
			}
			if matched {
				return true, fmt.Sprintf("Status code %d matched expectation %v", resp.StatusCode, m.Status)
			}
			return false, ""
		}, nil

	case "word", "words":
		if len(m.Words) == 0 {
			return nil, errors.New("word matcher must specify at least one word")
		}
		words := make([]string, len(m.Words))
		caseInsensitive := m.CaseInsensitive
		for i, w := range m.Words {
			if caseInsensitive {
				words[i] = strings.ToLower(w)
			} else {
				words[i] = w
			}
		}

		return func(resp *ResponseContext) (bool, string) {
			targetStr := getTargetPartString(resp, part, caseInsensitive)
			var hits []string
			for _, w := range words {
				if strings.Contains(targetStr, w) {
					hits = append(hits, w)
				}
			}

			var matched bool
			if cond == "and" {
				matched = (len(hits) == len(words))
			} else { // "or"
				matched = (len(hits) > 0)
			}

			if isNegative {
				matched = !matched
			}

			if matched {
				return true, fmt.Sprintf("Word match on %s (words: %v, hits: %v)", part, words, hits)
			}
			return false, ""
		}, nil

	case "regex":
		if len(m.Regex) == 0 {
			return nil, errors.New("regex matcher must specify at least one regex pattern")
		}
		compiledRegexes := make([]*regexp.Regexp, len(m.Regex))
		for i, p := range m.Regex {
			rx, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("invalid regular expression %q: %w", p, err)
			}
			compiledRegexes[i] = rx
		}

		return func(resp *ResponseContext) (bool, string) {
			targetBytes := getTargetPartBytes(resp, part)
			var hits []string

			for _, rx := range compiledRegexes {
				if loc := rx.Find(targetBytes); loc != nil {
					hits = append(hits, string(loc))
				}
			}

			var matched bool
			if cond == "and" {
				matched = (len(hits) == len(compiledRegexes))
			} else { // "or"
				matched = (len(hits) > 0)
			}

			if isNegative {
				matched = !matched
			}

			if matched {
				return true, fmt.Sprintf("Regex match on %s (patterns: %d, hits: %v)", part, len(compiledRegexes), hits)
			}
			return false, ""
		}, nil

	case "binary", "hex":
		if len(m.Binary) == 0 {
			return nil, errors.New("binary hex matcher must specify at least one hexadecimal pattern")
		}
		bytePatterns := make([][]byte, len(m.Binary))
		for i, h := range m.Binary {
			cleanHex := strings.ReplaceAll(strings.ReplaceAll(h, " ", ""), "0x", "")
			decoded, err := hex.DecodeString(cleanHex)
			if err != nil {
				return nil, fmt.Errorf("invalid hexadecimal pattern %q: %w", h, err)
			}
			bytePatterns[i] = decoded
		}

		return func(resp *ResponseContext) (bool, string) {
			targetBytes := getTargetPartBytes(resp, part)
			var hits int

			for _, pattern := range bytePatterns {
				if bytes.Contains(targetBytes, pattern) {
					hits++
				}
			}

			var matched bool
			if cond == "and" {
				matched = (hits == len(bytePatterns))
			} else { // "or"
				matched = (hits > 0)
			}

			if isNegative {
				matched = !matched
			}

			if matched {
				return true, fmt.Sprintf("Binary hex match on %s (patterns: %d, hits: %d)", part, len(bytePatterns), hits)
			}
			return false, ""
		}, nil

	default:
		return nil, fmt.Errorf("unrecognized matcher type %q", m.Type)
	}
}

// compileExtractor compiles a single ExtractorConfig into a CompiledExtractor closure.
func compileExtractor(e ExtractorConfig) (CompiledExtractor, error) {
	part := strings.ToLower(strings.TrimSpace(e.Part))
	if part == "" {
		part = "body"
	}
	group := e.Group
	if group <= 0 {
		group = 1
	}

	compiledRegexes := make([]*regexp.Regexp, len(e.Regex))
	for i, r := range e.Regex {
		rx, err := regexp.Compile(r)
		if err != nil {
			return nil, fmt.Errorf("invalid extractor regex %q: %w", r, err)
		}
		compiledRegexes[i] = rx
	}

	name := e.Name
	if name == "" {
		name = "extracted"
	}

	return func(resp *ResponseContext) map[string]string {
		out := make(map[string]string)
		targetStr := getTargetPartString(resp, part, false)

		for i, rx := range compiledRegexes {
			sub := rx.FindStringSubmatch(targetStr)
			if len(sub) > group && sub[group] != "" {
				key := name
				if len(compiledRegexes) > 1 {
					key = fmt.Sprintf("%s_%d", name, i)
				}
				out[key] = sub[group]
			}
		}
		return out
	}, nil
}

// getTargetPartString retrieves the appropriate response section as a string.
func getTargetPartString(resp *ResponseContext, part string, caseInsensitive bool) string {
	switch part {
	case "header", "headers":
		if caseInsensitive {
			return strings.ToLower(resp.HeaderString)
		}
		return resp.HeaderString
	case "all":
		combined := resp.HeaderString + "\r\n\r\n" + resp.BodyString
		if caseInsensitive {
			return strings.ToLower(combined)
		}
		return combined
	case "body":
		fallthrough
	default:
		if caseInsensitive {
			return resp.LowerBody
		}
		return resp.BodyString
	}
}

// getTargetPartBytes retrieves the appropriate response section as raw bytes.
func getTargetPartBytes(resp *ResponseContext, part string) []byte {
	switch part {
	case "header", "headers":
		return resp.HeaderBytes
	case "all":
		return append(append(resp.HeaderBytes, []byte("\r\n\r\n")...), resp.BodyBytes...)
	case "body":
		fallthrough
	default:
		return resp.BodyBytes
	}
}

// substituteTemplateVariables performs variable substitution ({{BaseURL}}, {{RootURL}}, {{Hostname}}, etc.)
func substituteTemplateVariables(input string, target *url.URL, extraVars ...map[string]string) string {
	baseURL := strings.TrimRight(target.String(), "/")
	rootURL := fmt.Sprintf("%s://%s", target.Scheme, target.Host)
	hostname := target.Hostname()
	port := target.Port()
	if port == "" {
		if target.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	path := target.Path
	if path == "" {
		path = "/"
	}

	res := input
	if strings.Contains(res, "{{") {
		res = strings.ReplaceAll(res, "{{BaseURL}}", baseURL)
		res = strings.ReplaceAll(res, "{{RootURL}}", rootURL)
		res = strings.ReplaceAll(res, "{{Hostname}}", hostname)
		res = strings.ReplaceAll(res, "{{Host}}", target.Host)
		res = strings.ReplaceAll(res, "{{Port}}", port)
		res = strings.ReplaceAll(res, "{{Path}}", path)
		res = strings.ReplaceAll(res, "{{Scheme}}", target.Scheme)

		for _, ev := range extraVars {
			for k, v := range ev {
				res = strings.ReplaceAll(res, k, v)
			}
		}
	}

	if !strings.Contains(res, "://") && (strings.HasPrefix(res, "/") || strings.HasPrefix(res, "?")) {
		if strings.HasPrefix(res, "/") {
			res = baseURL + res
		} else {
			res = baseURL + "/" + res
		}
	}
	return res
}

// extractStringSlice safely extracts string or []any into []string.
func extractStringSlice(val any) []string {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case string:
		if strings.TrimSpace(v) != "" {
			return []string{v}
		}
		return nil
	case []string:
		return v
	case []any:
		res := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				res = append(res, s)
			}
		}
		return res
	default:
		return nil
	}
}

// TemplateRegistry maintains loaded and compiled templates indexed by ID and CVE.
type TemplateRegistry struct {
	mu          sync.RWMutex
	templates   map[string]*CompiledTemplate
	byCVE       map[string][]*CompiledTemplate
	byTag       map[string][]*CompiledTemplate
	metadata    map[string]TemplateMeta
	coordinator *PublicationCoordinator
}

// NewTemplateRegistry initializes an empty thread-safe template registry.
func NewTemplateRegistry() *TemplateRegistry {
	return &TemplateRegistry{
		templates:   make(map[string]*CompiledTemplate),
		byCVE:       make(map[string][]*CompiledTemplate),
		byTag:       make(map[string][]*CompiledTemplate),
		metadata:    make(map[string]TemplateMeta),
		coordinator: NewPublicationCoordinator(),
	}
}

// SetCoordinator sets the shared publication coordinator for cross-component atomicity.
func (r *TemplateRegistry) SetCoordinator(c *PublicationCoordinator) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.coordinator = c
}

// Coordinator returns the assigned publication coordinator without blocking.
func (r *TemplateRegistry) Coordinator() *PublicationCoordinator {
	return r.coordinator
}

// Generation returns the current published generation for the registry.
func (r *TemplateRegistry) Generation() uint64 {
	c := r.coordinator
	if c != nil {
		return c.Generation()
	}
	return 1
}

// BindStore binds a store to this registry using a shared publication coordinator.
func (r *TemplateRegistry) BindStore(store *Store) *PublicationCoordinator {
	return BindCoordinated(store, r)
}

// Register compiles and indexes a template into the registry.
func (r *TemplateRegistry) Register(tmpl *Template) (*CompiledTemplate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.templates[tmpl.ID]; exists {
		return nil, fmt.Errorf("duplicate template ID %q already registered", tmpl.ID)
	}

	ct, err := CompileTemplate(tmpl)
	if err != nil {
		return nil, err
	}

	r.templates[ct.ID] = ct
	if r.metadata == nil {
		r.metadata = make(map[string]TemplateMeta)
	}
	r.metadata[ct.ID] = TemplateMeta{
		ID:       ct.ID,
		Source:   tmpl.SourcePath,
		Severity: ct.Info.Severity,
		CVE:      ct.CVEID,
		LoadedAt: time.Now(),
	}

	if ct.CVEID != "" {
		cveKey := strings.ToUpper(ct.CVEID)
		r.byCVE[cveKey] = append(r.byCVE[cveKey], ct)
	}

	if ct.Info.Tags != "" {
		for _, tag := range strings.Split(ct.Info.Tags, ",") {
			tClean := strings.ToLower(strings.TrimSpace(tag))
			if tClean != "" {
				r.byTag[tClean] = append(r.byTag[tClean], ct)
			}
		}
	}

	return ct, nil
}

// Get returns a compiled template by its ID.
func (r *TemplateRegistry) Get(id string) (*CompiledTemplate, bool) {
	coord := r.Coordinator()
	if coord != nil {
		coord.mu.RLock()
		defer coord.mu.RUnlock()
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	ct, ok := r.templates[id]
	return ct, ok
}

// GetByCVE returns all compiled templates mapped to a specific CVE identifier.
func (r *TemplateRegistry) GetByCVE(cveID string) []*CompiledTemplate {
	coord := r.Coordinator()
	if coord != nil {
		coord.mu.RLock()
		defer coord.mu.RUnlock()
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byCVE[strings.ToUpper(strings.TrimSpace(cveID))]
}

// All returns a slice of all registered compiled templates.
func (r *TemplateRegistry) All() []*CompiledTemplate {
	coord := r.Coordinator()
	if coord != nil {
		coord.mu.RLock()
		defer coord.mu.RUnlock()
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*CompiledTemplate, 0, len(r.templates))
	for _, ct := range r.templates {
		out = append(out, ct)
	}
	return out
}

// Count returns the number of registered templates.
func (r *TemplateRegistry) Count() int {
	coord := r.Coordinator()
	if coord != nil {
		coord.mu.RLock()
		defer coord.mu.RUnlock()
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.templates)
}

// RegistrySnapshot represents an immutable point-in-time snapshot of the template registry state.
type RegistrySnapshot struct {
	templates map[string]*CompiledTemplate
	byCVE     map[string][]*CompiledTemplate
	byTag     map[string][]*CompiledTemplate
	metadata  map[string]TemplateMeta
}

// Snapshot creates an in-memory snapshot for coordinated atomicity and rollback safety.
func (r *TemplateRegistry) Snapshot() *RegistrySnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()

	snap := &RegistrySnapshot{
		templates: make(map[string]*CompiledTemplate, len(r.templates)),
		byCVE:     make(map[string][]*CompiledTemplate, len(r.byCVE)),
		byTag:     make(map[string][]*CompiledTemplate, len(r.byTag)),
		metadata:  make(map[string]TemplateMeta, len(r.metadata)),
	}

	for k, v := range r.templates {
		snap.templates[k] = v
	}
	for k, slice := range r.byCVE {
		sCopy := make([]*CompiledTemplate, len(slice))
		copy(sCopy, slice)
		snap.byCVE[k] = sCopy
	}
	for k, slice := range r.byTag {
		sCopy := make([]*CompiledTemplate, len(slice))
		copy(sCopy, slice)
		snap.byTag[k] = sCopy
	}
	for k, v := range r.metadata {
		snap.metadata[k] = v
	}
	return snap
}

// Restore reverts the template registry to an earlier snapshot state upon transaction failure.
func (r *TemplateRegistry) Restore(snap *RegistrySnapshot) {
	if snap == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	r.templates = make(map[string]*CompiledTemplate, len(snap.templates))
	for k, v := range snap.templates {
		r.templates[k] = v
	}
	r.byCVE = make(map[string][]*CompiledTemplate, len(snap.byCVE))
	for k, slice := range snap.byCVE {
		sCopy := make([]*CompiledTemplate, len(slice))
		copy(sCopy, slice)
		r.byCVE[k] = sCopy
	}
	r.byTag = make(map[string][]*CompiledTemplate, len(snap.byTag))
	for k, slice := range snap.byTag {
		sCopy := make([]*CompiledTemplate, len(slice))
		copy(sCopy, slice)
		r.byTag[k] = sCopy
	}
	r.metadata = make(map[string]TemplateMeta, len(snap.metadata))
	for k, v := range snap.metadata {
		r.metadata[k] = v
	}
}

// ApplySnapshot atomically updates the live template registry to the provided snapshot state.
func (r *TemplateRegistry) ApplySnapshot(snap *RegistrySnapshot) {
	r.Restore(snap)
}

// StageTemplates takes the current registry snapshot and stages the provided templates into a new snapshot
// without modifying the live template registry.
func (r *TemplateRegistry) StageTemplates(templates []*Template, metas ...TemplateMeta) (*RegistrySnapshot, error) {
	snap := r.Snapshot()
	return snap.Stage(templates, metas...)
}

// Stage compiles and stages templates into an isolated snapshot copy without modifying any parent registry.
func (snap *RegistrySnapshot) Stage(templates []*Template, metas ...TemplateMeta) (*RegistrySnapshot, error) {
	if snap == nil {
		snap = &RegistrySnapshot{
			templates: make(map[string]*CompiledTemplate),
			byCVE:     make(map[string][]*CompiledTemplate),
			byTag:     make(map[string][]*CompiledTemplate),
			metadata:  make(map[string]TemplateMeta),
		}
	}

	staged := &RegistrySnapshot{
		templates: make(map[string]*CompiledTemplate, len(snap.templates)+len(templates)),
		byCVE:     make(map[string][]*CompiledTemplate, len(snap.byCVE)),
		byTag:     make(map[string][]*CompiledTemplate, len(snap.byTag)),
		metadata:  make(map[string]TemplateMeta, len(snap.metadata)+len(templates)),
	}

	for k, v := range snap.templates {
		staged.templates[k] = v
	}
	for k, slice := range snap.byCVE {
		sCopy := make([]*CompiledTemplate, len(slice))
		copy(sCopy, slice)
		staged.byCVE[k] = sCopy
	}
	for k, slice := range snap.byTag {
		sCopy := make([]*CompiledTemplate, len(slice))
		copy(sCopy, slice)
		staged.byTag[k] = sCopy
	}
	for k, v := range snap.metadata {
		staged.metadata[k] = v
	}

	metaMap := make(map[string]TemplateMeta)
	for _, m := range metas {
		metaMap[m.ID] = m
	}

	for _, tmpl := range templates {
		if tmpl == nil {
			return nil, errors.New("cannot stage nil template")
		}
		ct, err := CompileTemplate(tmpl)
		if err != nil {
			return nil, fmt.Errorf("failed compiling template %s: %w", tmpl.ID, err)
		}

		if oldCT, exists := staged.templates[tmpl.ID]; exists {
			if oldCT.CVEID != "" {
				cveKey := strings.ToUpper(oldCT.CVEID)
				filtered := make([]*CompiledTemplate, 0, len(staged.byCVE[cveKey]))
				for _, item := range staged.byCVE[cveKey] {
					if item.ID != tmpl.ID {
						filtered = append(filtered, item)
					}
				}
				if len(filtered) > 0 {
					staged.byCVE[cveKey] = filtered
				} else {
					delete(staged.byCVE, cveKey)
				}
			}

			if oldCT.Info.Tags != "" {
				for _, tag := range strings.Split(oldCT.Info.Tags, ",") {
					tClean := strings.ToLower(strings.TrimSpace(tag))
					if tClean != "" {
						filtered := make([]*CompiledTemplate, 0, len(staged.byTag[tClean]))
						for _, item := range staged.byTag[tClean] {
							if item.ID != tmpl.ID {
								filtered = append(filtered, item)
							}
						}
						if len(filtered) > 0 {
							staged.byTag[tClean] = filtered
						} else {
							delete(staged.byTag, tClean)
						}
					}
				}
			}
		}

		staged.templates[ct.ID] = ct
		if m, ok := metaMap[ct.ID]; ok {
			staged.metadata[ct.ID] = m
		} else {
			staged.metadata[ct.ID] = TemplateMeta{
				ID:       ct.ID,
				Source:   tmpl.SourcePath,
				Severity: ct.Info.Severity,
				CVE:      ct.CVEID,
				LoadedAt: time.Now(),
			}
		}

		if ct.CVEID != "" {
			cveKey := strings.ToUpper(ct.CVEID)
			staged.byCVE[cveKey] = append(staged.byCVE[cveKey], ct)
		}

		if ct.Info.Tags != "" {
			for _, tag := range strings.Split(ct.Info.Tags, ",") {
				tClean := strings.ToLower(strings.TrimSpace(tag))
				if tClean != "" {
					staged.byTag[tClean] = append(staged.byTag[tClean], ct)
				}
			}
		}
	}

	return staged, nil
}

// LoadStats records metrics from directory scanning and parsing.
type LoadStats struct {
	TotalFiles     int
	LoadedCount    int
	CompiledCount  int
	SkippedCount   int
	Errors         []string
	LoadDuration   time.Duration
	CompileDuration time.Duration
}

// LoadTemplatesFromDir recursively discovers and compiles all .yaml and .yml templates from dir.
func (r *TemplateRegistry) LoadTemplatesFromDir(dir string) (LoadStats, error) {
	start := time.Now()
	var stats LoadStats

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return stats, fmt.Errorf("directory %s does not exist", dir)
	}

	var yamlFiles []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".yaml" || ext == ".yml" {
				yamlFiles = append(yamlFiles, path)
			}
		}
		return nil
	})
	if err != nil {
		return stats, fmt.Errorf("error walking template dir: %w", err)
	}

	stats.TotalFiles = len(yamlFiles)
	compileStart := time.Now()

	for _, path := range yamlFiles {
		bytes, err := os.ReadFile(path)
		if err != nil {
			stats.SkippedCount++
			stats.Errors = append(stats.Errors, fmt.Sprintf("%s: read error: %v", path, err))
			continue
		}

		tmpl, err := ParseTemplate(bytes, path)
		if err != nil {
			stats.SkippedCount++
			stats.Errors = append(stats.Errors, fmt.Sprintf("%s: parse error: %v", path, err))
			continue
		}
		stats.LoadedCount++

		if _, err := r.Register(tmpl); err != nil {
			stats.SkippedCount++
			stats.Errors = append(stats.Errors, fmt.Sprintf("%s: register error: %v", path, err))
			continue
		}
		stats.CompiledCount++
	}

	stats.CompileDuration = time.Since(compileStart)
	stats.LoadDuration = time.Since(start)
	return stats, nil
}

// LoadBuiltinTemplates compiles and loads all embedded core templates into the registry.
func (r *TemplateRegistry) LoadBuiltinTemplates() (int, error) {
	entries, err := BuiltinTemplatesFS.ReadDir("templates")
	if err != nil {
		return 0, fmt.Errorf("failed reading embedded templates dir: %w", err)
	}

	loaded := 0
	for _, e := range entries {
		if !e.IsDir() {
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if ext == ".yaml" || ext == ".yml" {
				b, err := BuiltinTemplatesFS.ReadFile("templates/" + e.Name())
				if err != nil {
					continue
				}
				tmpl, err := ParseTemplate(b, e.Name())
				if err != nil {
					continue
				}
				if _, err := r.Register(tmpl); err == nil {
					loaded++
				}
			}
		}
	}
	return loaded, nil
}

// DefaultTemplatesDir returns the canonical location of vulnerability templates (~/.felix/templates).
func DefaultTemplatesDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("unable to resolve user home directory: %w", err)
	}
	return filepath.Join(home, ".felix", "templates"), nil
}
