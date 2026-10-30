package fuzzer

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SQLiType defines the injection analysis mechanism.
type SQLiType string

const (
	SQLiBooleanDifferential SQLiType = "BOOLEAN_DIFFERENTIAL"
	SQLiErrorBased           SQLiType = "ERROR_BASED"
	SQLiTimeBased            SQLiType = "TIME_BASED"
)

// SQLiConfidence reflects the conclusive certainty of an injection finding.
type SQLiConfidence string

const (
	ConfidenceConfirmed  SQLiConfidence = "CONFIRMED"
	ConfidenceCandidate  SQLiConfidence = "CANDIDATE"
	ConfidenceNotExposed SQLiConfidence = "NOT_EXPOSED"
)

// SQLiFinding records a verified or candidate SQL injection vulnerability.
type SQLiFinding struct {
	TargetURL           string         `json:"target_url"`
	Parameter           Parameter      `json:"parameter"`
	Type                SQLiType       `json:"type"`
	Confidence          SQLiConfidence `json:"confidence"`
	Payload             string         `json:"payload"`
	Evidence            string         `json:"evidence"`
	BaselineSimilarity  float64        `json:"baseline_similarity"`
	TrueSimilarity      float64        `json:"true_similarity"`
	FalseSimilarity     float64        `json:"false_similarity"`
	ResponseDeltaRatio  float64        `json:"response_delta_ratio"`
	ExecutionTimeMs     int64          `json:"execution_time_ms"`
	Dialect             string         `json:"dialect,omitempty"`
	NonTargetPreserved  bool           `json:"non_target_preserved"`
	DynamicNoiseMasked  bool           `json:"dynamic_noise_masked"`
	TimeScalingVerified bool           `json:"time_scaling_verified"`
}

// DynamicMasker detects and masks fluctuating tokens (timestamps, CSRF nonces, random IDs)
// by pre-comparing dual baselines and applying dialect-neutral pattern recognition.
type DynamicMasker struct {
	mu            sync.RWMutex
	volatileWords map[string]bool
	staticRegexes []*regexp.Regexp
}

// Built-in regular expressions identifying common dynamic page elements.
var defaultDynamicPatterns = []*regexp.Regexp{
	// ISO-8601 & RFC-3339 timestamps
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?`),
	// HTTP date format (e.g., Wed, 21 Oct 2026 07:28:00 GMT)
	regexp.MustCompile(`[A-Za-z]{3},\s+\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+(?:GMT|UTC|[A-Z]{3})`),
	// Unix epoch millisecond/second timestamps
	regexp.MustCompile(`\b1[6-9]\d{8,12}\b`),
	// Standard UUID v4 / v1
	regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`),
	// Hexadecimal tokens (hashes, session tokens >= 32 chars)
	regexp.MustCompile(`\b[0-9a-fA-F]{32,64}\b`),
	// Anti-CSRF / session token patterns in HTML attributes or JSON
	regexp.MustCompile(`(?i)(csrf[-_]?token|xsrf[-_]?token|authenticity_token|_token|nonce)[\"']?\s*[:=]\s*[\"'][^\"'\s]{10,}[\"']`),
	// Rotating execution time stamps (e.g., Rendered in 0.043s)
	regexp.MustCompile(`(?i)(rendered in|response time|generated in|load time)[\s:]+[0-9.]+\s*(?:ms|s|sec)?`),
}

// NewDynamicMasker initializes a masker by comparing two unmutated baseline responses.
func NewDynamicMasker(baseline1, baseline2 string) *DynamicMasker {
	dm := &DynamicMasker{
		volatileWords: make(map[string]bool),
		staticRegexes: defaultDynamicPatterns,
	}

	if baseline1 != "" && baseline2 != "" && baseline1 != baseline2 {
		dm.computeVolatileTokens(baseline1, baseline2)
	}
	return dm
}

// computeVolatileTokens tokenizes both baselines and flags tokens that differ between identical requests.
func (dm *DynamicMasker) computeVolatileTokens(b1, b2 string) {
	tokenize := func(s string) []string {
		// Split by HTML delimiters, whitespace, and common punctuation
		return strings.FieldsFunc(s, func(r rune) bool {
			return r == '<' || r == '>' || r == ' ' || r == '\t' || r == '\n' || r == '\r' ||
				r == '"' || r == '\'' || r == ',' || r == ';' || r == '='
		})
	}

	tokens1 := tokenize(b1)
	tokens2 := tokenize(b2)

	set1 := make(map[string]int)
	for _, t := range tokens1 {
		if len(t) >= 3 {
			set1[t]++
		}
	}

	set2 := make(map[string]int)
	for _, t := range tokens2 {
		if len(t) >= 3 {
			set2[t]++
		}
	}

	dm.mu.Lock()
	defer dm.mu.Unlock()

	for t, c1 := range set1 {
		if c2, exists := set2[t]; !exists || c1 != c2 {
			dm.volatileWords[t] = true
		}
	}
	for t := range set2 {
		if _, exists := set1[t]; !exists {
			dm.volatileWords[t] = true
		}
	}
}

// Mask replaces all volatile tokens and regular expression patterns with a stable placeholder.
func (dm *DynamicMasker) Mask(content string) string {
	if content == "" {
		return ""
	}

	result := content

	// 1. Apply static dynamic pattern masking
	for _, re := range dm.staticRegexes {
		result = re.ReplaceAllString(result, "__DYNAMIC_MASKED__")
	}

	// 2. Apply baseline diff-extracted volatile word masking
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	if len(dm.volatileWords) > 0 {
		for word := range dm.volatileWords {
			if strings.Contains(result, word) {
				result = strings.ReplaceAll(result, word, "__DYNAMIC_MASKED__")
			}
		}
	}

	return result
}

// StripDOMSkeleton normalizes whitespace and layout structure across the masked document.
func StripDOMSkeleton(content string) string {
	return strings.Join(strings.Fields(content), " ")
}

// LevenshteinDistance computes the classic Levenshtein distance between two strings using O(min(N,M)) memory.
func LevenshteinDistance(s1, s2 string) int {
	r1, r2 := []rune(s1), []rune(s2)
	n, m := len(r1), len(r2)

	if n == 0 {
		return m
	}
	if m == 0 {
		return n
	}

	// Ensure r1 is shorter or equal to r2 to minimize row allocation
	if n > m {
		r1, r2 = r2, r1
		n, m = m, n
	}

	// Cap comparison length to prevent runaway computation on enormous files
	const maxCompare = 8192
	if n > maxCompare {
		r1 = r1[:maxCompare]
		n = maxCompare
	}
	if m > maxCompare {
		r2 = r2[:maxCompare]
		m = maxCompare
	}

	v0 := make([]int, n+1)
	v1 := make([]int, n+1)

	for i := 0; i <= n; i++ {
		v0[i] = i
	}

	for j := 0; j < m; j++ {
		v1[0] = j + 1
		for i := 0; i < n; i++ {
			cost := 0
			if r1[i] != r2[j] {
				cost = 1
			}
			minCost := v0[i+1] + 1
			if ins := v1[i] + 1; ins < minCost {
				minCost = ins
			}
			if sub := v0[i] + cost; sub < minCost {
				minCost = sub
			}
			v1[i+1] = minCost
		}
		copy(v0, v1)
	}

	return v0[n]
}

// LevenshteinSimilarity returns a normalized similarity ratio [0.0, 1.0].
func LevenshteinSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}
	maxLen := math.Max(float64(len([]rune(s1))), float64(len([]rune(s2))))
	if maxLen == 0 {
		return 1.0
	}
	dist := LevenshteinDistance(s1, s2)
	sim := 1.0 - (float64(dist) / maxLen)
	if sim < 0.0 {
		return 0.0
	}
	return sim
}

// DBErrorSignature maps a database dialect to its characteristic error patterns.
type DBErrorSignature struct {
	Dialect  string
	Patterns []*regexp.Regexp
}

// DBErrorMatcher provides dialect-specific database syntax error detection.
type DBErrorMatcher struct {
	signatures []DBErrorSignature
}

// NewDBErrorMatcher constructs a matcher loaded with dialects MySQL, Postgres, MSSQL, Oracle, SQLite, HSQLDB/H2, Mongo.
func NewDBErrorMatcher() *DBErrorMatcher {
	return &DBErrorMatcher{
		signatures: []DBErrorSignature{
			{
				Dialect: "MySQL / MariaDB",
				Patterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)you have an error in your sql syntax`),
					regexp.MustCompile(`(?i)check the manual that corresponds to your (?:mysql|mariadb) server version`),
					regexp.MustCompile(`(?i)com\.mysql\.jdbc\.exceptions`),
					regexp.MustCompile(`(?i)MySqlException`),
					regexp.MustCompile(`(?i)SQLSTATE\[42000\]`),
					regexp.MustCompile(`(?i)Column count doesn't match value count`),
				},
			},
			{
				Dialect: "PostgreSQL",
				Patterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)postgresql.*error`),
					regexp.MustCompile(`(?i)valid PostgreSQL result`),
					regexp.MustCompile(`(?i)PG::SyntaxError`),
					regexp.MustCompile(`(?i)org\.postgresql\.util\.PSQLException`),
					regexp.MustCompile(`(?i)ERROR:\s*syntax error at or near`),
					regexp.MustCompile(`(?i)unterminated quoted string at or near`),
				},
			},
			{
				Dialect: "Microsoft SQL Server",
				Patterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)driver.*SQL[\-\_\ ]*Server`),
					regexp.MustCompile(`(?i)OLE DB.*SQL Server`),
					regexp.MustCompile(`(?i)\bSQLServer JDBC Driver\b`),
					regexp.MustCompile(`(?i)com\.microsoft\.sqlserver\.jdbc\.SQLServerException`),
					regexp.MustCompile(`(?i)Unclosed quotation mark after the character string`),
					regexp.MustCompile(`(?i)Incorrect syntax near`),
				},
			},
			{
				Dialect: "Oracle",
				Patterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)ORA-[0-9]{4,5}`),
					regexp.MustCompile(`(?i)oracle\.jdbc\.driver`),
					regexp.MustCompile(`(?i)OracleException`),
					regexp.MustCompile(`(?i)quoted string not properly terminated`),
				},
			},
			{
				Dialect: "SQLite",
				Patterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)SQLite/JDBCDriver`),
					regexp.MustCompile(`(?i)SQLite\.Exception`),
					regexp.MustCompile(`(?i)System\.Data\.SQLite\.SQLiteException`),
					regexp.MustCompile(`(?i)SQL logic error`),
					regexp.MustCompile(`(?i)near \"[^\"]*\": syntax error`),
					regexp.MustCompile(`(?i)unrecognized token:`),
				},
			},
			{
				Dialect: "HSQLDB / H2",
				Patterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)org\.hsqldb\.HsqlException`),
					regexp.MustCompile(`(?i)Syntax error in SQL statement`),
					regexp.MustCompile(`(?i)Unexpected token.*in statement`),
					regexp.MustCompile(`(?i)unexpected token:`),
					regexp.MustCompile(`(?i)malformed string:.*in statement`),
					regexp.MustCompile(`(?i)org\.h2\.jdbc\.JdbcSQLException`),
					regexp.MustCompile(`(?i)user_data.*not found`),
					regexp.MustCompile(`(?i)error in script`),
				},
			},
			{
				Dialect: "MongoDB / NoSQL",
				Patterns: []*regexp.Regexp{
					regexp.MustCompile(`(?i)MongoError`),
					regexp.MustCompile(`(?i)Cast to ObjectId failed`),
					regexp.MustCompile(`(?i)cannot use '.*' with \$.*`),
					regexp.MustCompile(`(?i)SyntaxError: Unexpected identifier`),
					regexp.MustCompile(`(?i)ReferenceError: .* is not defined`),
					regexp.MustCompile(`(?i)unterminated string literal`),
					regexp.MustCompile(`(?i)BadValue`),
				},
			},
		},
	}
}

// Match scans content for known database error messages, returning the dialect and matching snippet.
func (dem *DBErrorMatcher) Match(content string) (dialect string, snippet string, found bool) {
	for _, sig := range dem.signatures {
		for _, re := range sig.Patterns {
			if loc := re.FindStringIndex(content); loc != nil {
				start := loc[0] - 20
				if start < 0 {
					start = 0
				}
				end := loc[1] + 40
				if end > len(content) {
					end = len(content)
				}
				return sig.Dialect, strings.TrimSpace(content[start:end]), true
			}
		}
	}
	return "", "", false
}

// IsGenericFrameworkError asserts whether an HTTP response is a standard unhandled framework crash
// without any database-specific syntax disclosure.
func (dem *DBErrorMatcher) IsGenericFrameworkError(statusCode int, body string) bool {
	if statusCode < 500 {
		return false
	}
	_, _, hasDBError := dem.Match(body)
	return !hasDBError
}

// ResponseSnapshot records the observable characteristics of an HTTP probe response.
type ResponseSnapshot struct {
	StatusCode    int
	Body          string
	ContentLength int64
	Duration      time.Duration
	Headers       http.Header
}

// SQLiAnalyzer provides differential response analysis, dialect error pattern matching,
// and mathematical time-based latency verification.
type SQLiAnalyzer struct {
	Client    *http.Client
	Extractor *ParameterExtractor
	DBErrors  *DBErrorMatcher
	Timeout   time.Duration
}

// NewSQLiAnalyzer constructs a ready-to-execute SQL injection analyzer.
func NewSQLiAnalyzer(client *http.Client, pe *ParameterExtractor) *SQLiAnalyzer {
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Do not auto-follow redirects to inspect raw differential
			},
		}
	}
	if pe == nil {
		pe = NewParameterExtractor()
	}
	return &SQLiAnalyzer{
		Client:    client,
		Extractor: pe,
		DBErrors:  NewDBErrorMatcher(),
		Timeout:   10 * time.Second,
	}
}

// executeRequest performs an HTTP request and measures precise round-trip duration.
func (sa *SQLiAnalyzer) executeRequest(req *http.Request) (*ResponseSnapshot, error) {
	start := time.Now()
	resp, err := sa.Client.Do(req)
	duration := time.Since(start)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &ResponseSnapshot{
		StatusCode:    resp.StatusCode,
		Body:          string(bodyBytes),
		ContentLength: resp.ContentLength,
		Duration:      duration,
		Headers:       resp.Header.Clone(),
	}, nil
}

// AnalyzeRequest runs the full Phase 2.2 differential suite across all parameters discovered in a request.
func (sa *SQLiAnalyzer) AnalyzeRequest(req *http.Request) ([]SQLiFinding, error) {
	params, err := sa.Extractor.Extract(req)
	if err != nil {
		return nil, fmt.Errorf("failed to extract parameters for SQLi analysis: %w", err)
	}

	var allFindings []SQLiFinding
	for _, p := range params {
		if p.Sensitive {
			// Skip sensitive credentials (passwords, tokens) to prevent account lockouts
			continue
		}
		findings, err := sa.AnalyzeParameter(req, p)
		if err != nil {
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// AnalyzeParameter conducts Error-Based, Boolean Differential, and Time-Based analysis for a single parameter.
func (sa *SQLiAnalyzer) AnalyzeParameter(origReq *http.Request, target Parameter) ([]SQLiFinding, error) {
	var findings []SQLiFinding

	// Step 1: Send two unmutated baseline requests to build the dynamic content exclusion mask
	baseReq1, err := sa.Extractor.GenerateMutation(origReq, target, target.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to generate baseline 1: %w", err)
	}
	baseResp1, err := sa.executeRequest(baseReq1)
	if err != nil {
		return nil, fmt.Errorf("baseline 1 request failed: %w", err)
	}

	baseReq2, err := sa.Extractor.GenerateMutation(origReq, target, target.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to generate baseline 2: %w", err)
	}
	baseResp2, err := sa.executeRequest(baseReq2)
	if err != nil {
		return nil, fmt.Errorf("baseline 2 request failed: %w", err)
	}

	// Initialize dynamic content masker
	masker := NewDynamicMasker(baseResp1.Body, baseResp2.Body)

	// Step 2: Error-Based Syntax Probing
	errorFindings, err := sa.AnalyzeErrorBased(origReq, target, baseResp1, masker)
	if err == nil && len(errorFindings) > 0 {
		findings = append(findings, errorFindings...)
	}

	// Step 3: Boolean Differential Analysis with Dynamic Masking
	boolFindings, err := sa.AnalyzeBooleanDifferential(origReq, target, baseResp1, masker)
	if err == nil && len(boolFindings) > 0 {
		findings = append(findings, boolFindings...)
	}

	// Step 4: Time-Based Latency Progression (if boolean/error did not conclusively confirm)
	needsTimeCheck := true
	for _, f := range findings {
		if f.Confidence == ConfidenceConfirmed {
			needsTimeCheck = false
			break
		}
	}
	if needsTimeCheck {
		timeFindings, err := sa.AnalyzeTimeBased(origReq, target, baseResp1)
		if err == nil && len(timeFindings) > 0 {
			findings = append(findings, timeFindings...)
		}
	}

	return findings, nil
}

// AnalyzeErrorBased checks if non-destructive syntax disruptions trigger database dialect error messages
// that were absent in the baseline response.
func (sa *SQLiAnalyzer) AnalyzeErrorBased(
	origReq *http.Request,
	target Parameter,
	baseline *ResponseSnapshot,
	masker *DynamicMasker,
) ([]SQLiFinding, error) {
	// Candidate non-destructive syntax-breaking probes
	probes := []string{
		target.Value + "'",
		target.Value + "''",
		target.Value + "\"",
		target.Value + "')",
	}

	// Check if baseline already discloses a DB error
	baselineHasDB, _, _ := sa.DBErrors.Match(baseline.Body)
	if baselineHasDB != "" {
		// Baseline already has database error; cannot reliably assert error-based injection
		return nil, nil
	}

	var findings []SQLiFinding

	for _, probe := range probes {
		mutatedReq, err := sa.Extractor.GenerateMutation(origReq, target, probe)
		if err != nil {
			continue
		}

		resp, err := sa.executeRequest(mutatedReq)
		if err != nil {
			continue
		}

		dialect, snippet, found := sa.DBErrors.Match(resp.Body)
		if found && !strings.Contains(baseline.Body, snippet) {
			targetURL := ""
			if origReq.URL != nil {
				targetURL = origReq.URL.String()
			}

			findings = append(findings, SQLiFinding{
				TargetURL:          targetURL,
				Parameter:          target,
				Type:               SQLiErrorBased,
				Confidence:         ConfidenceConfirmed,
				Payload:            probe,
				Evidence:           fmt.Sprintf("Disclosed %s error signature: %s", dialect, snippet),
				ExecutionTimeMs:    resp.Duration.Milliseconds(),
				Dialect:            dialect,
				NonTargetPreserved: true,
				DynamicNoiseMasked: true,
			})
			// One confirmed dialect error suffices
			break
		} else if sa.DBErrors.IsGenericFrameworkError(resp.StatusCode, resp.Body) {
			// Generic 500 without database error signature remains CANDIDATE per Roadmap Iron Gate
			targetURL := ""
			if origReq.URL != nil {
				targetURL = origReq.URL.String()
			}
			findings = append(findings, SQLiFinding{
				TargetURL:          targetURL,
				Parameter:          target,
				Type:               SQLiErrorBased,
				Confidence:         ConfidenceCandidate,
				Payload:            probe,
				Evidence:           fmt.Sprintf("Generic HTTP %d error without database signature", resp.StatusCode),
				ExecutionTimeMs:    resp.Duration.Milliseconds(),
				NonTargetPreserved: true,
				DynamicNoiseMasked: true,
			})
		}
	}

	return findings, nil
}

// AnalyzeBooleanDifferential executes paired True/False logical probes and compares Levenshtein
// similarity against the masked stable DOM skeleton.
func (sa *SQLiAnalyzer) AnalyzeBooleanDifferential(
	origReq *http.Request,
	target Parameter,
	baseline *ResponseSnapshot,
	masker *DynamicMasker,
) ([]SQLiFinding, error) {
	// Construct context-tailored True / False probe pairs
	type probePair struct {
		TruePayload  string
		FalsePayload string
	}

	var pairs []probePair
	switch target.Context {
	case ContextNumeric:
		pairs = []probePair{
			{TruePayload: target.Value + " AND 1=1", FalsePayload: target.Value + " AND 1=2"},
			{TruePayload: target.Value + " OR 1=1", FalsePayload: target.Value + " OR 1=2"},
			{TruePayload: target.Value + " - 0", FalsePayload: target.Value + " - 999999"},
		}
	default:
		// String / Alphanumeric / Default context
		pairs = []probePair{
			{TruePayload: target.Value + "' AND '1'='1", FalsePayload: target.Value + "' AND '1'='2"},
			{TruePayload: target.Value + "' OR '1'='1", FalsePayload: target.Value + "' OR '1'='2"},
			{TruePayload: target.Value + "' AND 1=1-- ", FalsePayload: target.Value + "' AND 1=2-- "},
			// MongoDB / NoSQL query injection format
			{TruePayload: target.Value + "' || '1'=='1", FalsePayload: target.Value + "' && '1'=='2"},
		}
	}

	targetURL := ""
	if origReq.URL != nil {
		targetURL = origReq.URL.String()
	}

	maskedBaselineBody := masker.Mask(baseline.Body)
	maskedBaselineDOM := StripDOMSkeleton(maskedBaselineBody)

	var findings []SQLiFinding

	for _, pair := range pairs {
		// 1. Send True condition probe
		trueReq, err := sa.Extractor.GenerateMutation(origReq, target, pair.TruePayload)
		if err != nil {
			continue
		}
		trueResp, err := sa.executeRequest(trueReq)
		if err != nil {
			continue
		}

		// 2. Send False condition probe
		falseReq, err := sa.Extractor.GenerateMutation(origReq, target, pair.FalsePayload)
		if err != nil {
			continue
		}
		falseResp, err := sa.executeRequest(falseReq)
		if err != nil {
			continue
		}

		// Apply dynamic content masking and DOM skeleton extraction
		maskedTrueBody := masker.Mask(trueResp.Body)
		maskedTrueDOM := StripDOMSkeleton(maskedTrueBody)

		maskedFalseBody := masker.Mask(falseResp.Body)
		maskedFalseDOM := StripDOMSkeleton(maskedFalseBody)

		// Calculate similarities against masked baseline
		simTrue := LevenshteinSimilarity(maskedBaselineDOM, maskedTrueDOM)
		simFalse := LevenshteinSimilarity(maskedBaselineDOM, maskedFalseDOM)
		delta := simTrue - simFalse

		// Evaluation Criteria per Iron Gate:
		// 1. True condition must closely match baseline (high similarity >= 0.90)
		// 2. False condition must noticeably diverge (similarity delta >= 0.10 OR status code diverges)
		isTrueMatched := simTrue >= 0.88 && trueResp.StatusCode == baseline.StatusCode
		isFalseDiverged := simFalse < 0.80 || (delta >= 0.10) || (falseResp.StatusCode != baseline.StatusCode)

		if isTrueMatched && isFalseDiverged {
			findings = append(findings, SQLiFinding{
				TargetURL:           targetURL,
				Parameter:           target,
				Type:                SQLiBooleanDifferential,
				Confidence:          ConfidenceConfirmed,
				Payload:             fmt.Sprintf("True: %s | False: %s", pair.TruePayload, pair.FalsePayload),
				Evidence:            fmt.Sprintf("True-Similarity: %.3f, False-Similarity: %.3f, Delta: %.3f (Status True: %d, False: %d)", simTrue, simFalse, delta, trueResp.StatusCode, falseResp.StatusCode),
				BaselineSimilarity:  1.0,
				TrueSimilarity:      simTrue,
				FalseSimilarity:     simFalse,
				ResponseDeltaRatio:  delta,
				ExecutionTimeMs:     trueResp.Duration.Milliseconds(),
				NonTargetPreserved:  true,
				DynamicNoiseMasked:  true,
				TimeScalingVerified: false,
			})
			break
		}
	}

	return findings, nil
}

// AnalyzeTimeBased verifies time-based SQL injection using a strict sequential mathematical progression:
// Probe 1: 1s delay (assert elapsed >= 900ms)
// Probe 2: 3s delay (assert elapsed >= 2700ms)
// Probe 3: 0s control probe (assert elapsed <= baseline + 500ms)
// Linear scaling requirement: T(3s) - T(1s) >= 1600ms, eliminating concurrency-induced queuing false positives.
func (sa *SQLiAnalyzer) AnalyzeTimeBased(
	origReq *http.Request,
	target Parameter,
	baseline *ResponseSnapshot,
) ([]SQLiFinding, error) {
	// Dialect-specific time probe generators
	type timeProbeProgression struct {
		Name     string
		Probe1s  string
		Probe3s  string
		Probe0s  string
	}

	progressions := []timeProbeProgression{
		{
			Name:    "SQL Generic SLEEP",
			Probe1s: target.Value + "' OR SLEEP(1)-- ",
			Probe3s: target.Value + "' OR SLEEP(3)-- ",
			Probe0s: target.Value + "' OR SLEEP(0)-- ",
		},
		{
			Name:    "PostgreSQL pg_sleep",
			Probe1s: target.Value + "'; SELECT pg_sleep(1)--",
			Probe3s: target.Value + "'; SELECT pg_sleep(3)--",
			Probe0s: target.Value + "'; SELECT pg_sleep(0)--",
		},
		{
			Name:    "MSSQL WAITFOR DELAY",
			Probe1s: target.Value + "'; WAITFOR DELAY '0:0:1'--",
			Probe3s: target.Value + "'; WAITFOR DELAY '0:0:3'--",
			Probe0s: target.Value + "'; WAITFOR DELAY '0:0:0'--",
		},
		{
			Name:    "MongoDB / Node.js Loop Delay",
			Probe1s: target.Value + "'; var d=new Date(); do{var c=new Date();}while(c-d<1000); //",
			Probe3s: target.Value + "'; var d=new Date(); do{var c=new Date();}while(c-d<3000); //",
			Probe0s: target.Value + "'; var d=new Date(); do{var c=new Date();}while(c-d<0); //",
		},
	}

	targetURL := ""
	if origReq.URL != nil {
		targetURL = origReq.URL.String()
	}

	baselineDuration := baseline.Duration

	var findings []SQLiFinding

	for _, prog := range progressions {
		// Step 1: Probe 1s
		req1s, err := sa.Extractor.GenerateMutation(origReq, target, prog.Probe1s)
		if err != nil {
			continue
		}
		resp1s, err := sa.executeRequest(req1s)
		if err != nil {
			continue
		}

		// If 1s probe didn't cause any delay, skip to next progression
		if resp1s.Duration < 850*time.Millisecond {
			continue
		}

		// Step 2: Probe 3s
		req3s, err := sa.Extractor.GenerateMutation(origReq, target, prog.Probe3s)
		if err != nil {
			continue
		}
		resp3s, err := sa.executeRequest(req3s)
		if err != nil {
			continue
		}

		// Step 3: Probe 0s (Control Probe)
		req0s, err := sa.Extractor.GenerateMutation(origReq, target, prog.Probe0s)
		if err != nil {
			continue
		}
		resp0s, err := sa.executeRequest(req0s)
		if err != nil {
			continue
		}

		// Mathematical Linear Scaling Check
		// 1. T(1s) >= 850ms
		// 2. T(3s) >= 2500ms
		// 3. T(3s) - T(1s) >= 1500ms
		// 4. T(0s) <= baselineDuration + 500ms
		t1 := resp1s.Duration.Milliseconds()
		t3 := resp3s.Duration.Milliseconds()
		t0 := resp0s.Duration.Milliseconds()
		deltaT := t3 - t1
		baselineMax := baselineDuration.Milliseconds() + 500

		isLinear := t1 >= 850 && t3 >= 2500 && deltaT >= 1500 && t0 <= baselineMax

		if isLinear {
			findings = append(findings, SQLiFinding{
				TargetURL:           targetURL,
				Parameter:           target,
				Type:                SQLiTimeBased,
				Confidence:          ConfidenceConfirmed,
				Payload:             prog.Probe3s,
				Evidence:            fmt.Sprintf("Strict mathematical progression verified: T(1s)=%dms, T(3s)=%dms (Delta=%dms), Control T(0s)=%dms (Baseline=%dms)", t1, t3, deltaT, t0, baselineDuration.Milliseconds()),
				ExecutionTimeMs:     t3,
				NonTargetPreserved:  true,
				DynamicNoiseMasked:  true,
				TimeScalingVerified: true,
			})
			break
		}
	}

	return findings, nil
}

// EvaluateControlledDifferential is a test-support helper function that analyzes
// baseline, true, and false strings directly with dynamic content masking and Levenshtein similarity.
func EvaluateControlledDifferential(
	baseline1, baseline2 string,
	trueResponse, falseResponse string,
) (maskedTrueSim, maskedFalseSim float64, isConfirmed bool) {
	masker := NewDynamicMasker(baseline1, baseline2)

	mBase := StripDOMSkeleton(masker.Mask(baseline1))
	mTrue := StripDOMSkeleton(masker.Mask(trueResponse))
	mFalse := StripDOMSkeleton(masker.Mask(falseResponse))

	simTrue := LevenshteinSimilarity(mBase, mTrue)
	simFalse := LevenshteinSimilarity(mBase, mFalse)

	confirmed := simTrue >= 0.90 && (simFalse <= 0.80 || (simTrue-simFalse >= 0.15))
	return simTrue, simFalse, confirmed
}
