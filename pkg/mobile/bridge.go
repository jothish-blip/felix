package mobile

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"felix/pkg/bola"
	"felix/pkg/correlation"
	"felix/pkg/fuzzer"
	"felix/pkg/report"
)

// CorrelationSummary aggregates high-level metrics for the mobile-to-backend analysis.
type CorrelationSummary struct {
	TotalEndpointsDiscovered int `json:"total_endpoints_discovered"`
	StaticEndpointsCount     int `json:"static_endpoints_count"`
	RuntimeEndpointsCount    int `json:"runtime_endpoints_count"`
	MatchedEndpointsCount    int `json:"matched_endpoints_count"`
	RuntimeOnlyCount         int `json:"runtime_only_count"`
	StaticOnlyCount          int `json:"static_only_count"`
	TotalCorrelatedFindings  int `json:"total_correlated_findings"`
	ConfirmedFindingsCount   int `json:"confirmed_findings_count"`
	PotentialFindingsCount   int `json:"potential_findings_count"`
	HighCriticalFindings     int `json:"high_critical_findings"`
	GraphNodeCount           int `json:"graph_node_count"`
	GraphEdgeCount           int `json:"graph_edge_count"`
}

// MobileBackendCorrelationResult encapsulates the complete intelligence output
// linking mobile static/runtime behavior with backend infrastructure findings.
type MobileBackendCorrelationResult struct {
	PackageName        string                    `json:"package_name"`
	AnalyzedAt         time.Time                 `json:"analyzed_at"`
	Endpoints          []CorrelatedEndpoint      `json:"endpoints"`
	CorrelatedFindings []CorrelatedFinding       `json:"correlated_findings"`
	BackendFindings    []correlation.NormalizedFinding `json:"backend_findings,omitempty"`
	Graph              *MobileBackendGraph       `json:"graph,omitempty"`
	AttackGraph        *correlation.AttackGraph  `json:"attack_graph,omitempty"`
	Summary            CorrelationSummary        `json:"summary"`
}

// MobileBackendBridge orchestrates the extraction, normalization, static-to-runtime matching,
// and backend finding correlation for mobile application audits.
type MobileBackendBridge struct {
	mu sync.RWMutex
}

// NewMobileBackendBridge initializes a new mobile-to-backend correlation bridge.
func NewMobileBackendBridge() *MobileBackendBridge {
	return &MobileBackendBridge{}
}

// Correlate conducts full multi-layer correlation across static manifest analysis,
// DEX bytecode string pools, runtime instrumentation events, and backend assessment findings.
func (b *MobileBackendBridge) Correlate(
	pkgResult *PackageInspectionResult,
	dynamicResult *DynamicExecutionResult,
	dexResult *DEXAnalysisResult,
	backendFindings []correlation.NormalizedFinding,
) (*MobileBackendCorrelationResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	pkgName := "unknown"
	var manifest *AndroidMetadata
	var staticFindings []MobileFinding

	if pkgResult != nil {
		if pkgResult.Android != nil {
			pkgName = pkgResult.Android.PackageName
			manifest = pkgResult.Android
		}
		staticFindings = append(staticFindings, pkgResult.Findings...)
	}

	if pkgName == "unknown" && dynamicResult != nil && dynamicResult.TargetPackage != "" {
		pkgName = dynamicResult.TargetPackage
	}

	// 1. Static endpoint harvesting
	staticEndpoints := ExtractStaticEndpoints(manifest, dexResult)

	// 2. Runtime endpoint ingestion
	var runtimeEndpoints []BackendEndpoint
	if dynamicResult != nil && len(dynamicResult.Events) > 0 {
		runtimeEndpoints = IngestRuntimeEndpoints(dynamicResult.Events)
	}

	// 3. Static-to-Runtime matching
	correlatedEndpoints := CorrelateEndpoints(pkgName, staticEndpoints, runtimeEndpoints)

	// Include DEX secret findings if present
	if dexResult != nil && len(dexResult.Findings) > 0 {
		staticFindings = append(staticFindings, dexResult.Findings...)
	}

	// 4. Backend finding correlation
	findings := CorrelateWithBackendFindings(pkgName, correlatedEndpoints, backendFindings, staticFindings)

	// 5. Build unified security graph
	graph := BuildMobileBackendGraph(pkgName, correlatedEndpoints, findings, backendFindings)
	attackGraph := graph.ToAttackGraph()

	// 6. Compute summary statistics
	summary := CorrelationSummary{
		TotalEndpointsDiscovered: len(correlatedEndpoints),
		GraphNodeCount:           len(graph.Nodes),
		GraphEdgeCount:           len(graph.Edges),
	}

	for _, ep := range correlatedEndpoints {
		if ep.IsStaticExtracted && ep.IsObservedRuntime {
			summary.MatchedEndpointsCount++
			summary.StaticEndpointsCount++
			summary.RuntimeEndpointsCount++
		} else if ep.IsObservedRuntime {
			summary.RuntimeOnlyCount++
			summary.RuntimeEndpointsCount++
		} else if ep.IsStaticExtracted {
			summary.StaticOnlyCount++
			summary.StaticEndpointsCount++
		}
	}

	summary.TotalCorrelatedFindings = len(findings)
	for _, f := range findings {
		if f.VerificationState == ClassificationConfirmed {
			summary.ConfirmedFindingsCount++
		} else {
			summary.PotentialFindingsCount++
		}
		upperSev := strings.ToUpper(f.Severity)
		if upperSev == "CRITICAL" || upperSev == "HIGH" {
			summary.HighCriticalFindings++
		}
	}

	return &MobileBackendCorrelationResult{
		PackageName:        pkgName,
		AnalyzedAt:         time.Now().UTC(),
		Endpoints:          correlatedEndpoints,
		CorrelatedFindings: findings,
		BackendFindings:    backendFindings,
		Graph:              graph,
		AttackGraph:        attackGraph,
		Summary:            summary,
	}, nil
}

// ExportEndpointsForDAST extracts endpoints discovered from mobile operations into target descriptors
// formatted for automated fuzzer and BOLA vulnerability probe execution.
func (r *MobileBackendCorrelationResult) ExportEndpointsForDAST() []map[string]any {
	if r == nil {
		return nil
	}
	var targets []map[string]any
	for _, ep := range r.Endpoints {
		if ep.Host == "" || ep.Host == "*" {
			continue
		}
		target := map[string]any{
			"host":        ep.Host,
			"port":        ep.Port,
			"scheme":      ep.Scheme,
			"path":        ep.Path,
			"method":      ep.Method,
			"canonical":   ep.CanonicalKey,
			"confidence":  string(ep.Confidence),
			"is_runtime":  ep.IsObservedRuntime,
			"is_cleartext": ep.RuntimeEndpoint != nil && ep.RuntimeEndpoint.IsCleartext,
		}
		targets = append(targets, target)
	}

	sort.Slice(targets, func(i, j int) bool {
		h1 := targets[i]["host"].(string)
		h2 := targets[j]["host"].(string)
		if h1 != h2 {
			return h1 < h2
		}
		return targets[i]["path"].(string) < targets[j]["path"].(string)
	})

	return targets
}

// ToReportFindings converts all correlated findings into standardized report.Finding instances.
func (r *MobileBackendCorrelationResult) ToReportFindings() []report.Finding {
	if r == nil {
		return nil
	}
	var reportFindings []report.Finding
	for _, cf := range r.CorrelatedFindings {
		if rf := cf.ToFinding(); rf != nil {
			reportFindings = append(reportFindings, *rf)
		}
	}
	return reportFindings
}

// MobileFuzzExecutionRecord records the per-endpoint execution telemetry from Engine 2 (Fuzzer).
type MobileFuzzExecutionRecord struct {
	TargetURL       string             `json:"target_url"`
	EndpointPath    string             `json:"endpoint_path"`
	Method          string             `json:"method"`
	TaskID          string             `json:"task_id"`
	Parameters      []fuzzer.Parameter `json:"parameters,omitempty"`
	StatusCode      int                `json:"status_code,omitempty"`
	DurationMs      int64              `json:"duration_ms,omitempty"`
	RetriesExecuted int                `json:"retries_executed,omitempty"`
	Executed        bool               `json:"executed"`
	Error           string             `json:"error,omitempty"`
}

// FuzzerHandoffResult records the result of transferring exported mobile targets to Engine 2 (Fuzzer).
type FuzzerHandoffResult struct {
	TotalTargetsConsumed int                         `json:"total_targets_consumed"`
	AuthorizedTargets    int                         `json:"authorized_targets"`
	ParametersExtracted  int                         `json:"parameters_extracted"`
	TasksCreated         int                         `json:"tasks_created"`
	TargetEndpoints      []string                    `json:"target_endpoints"`
	DispatchedResults    []fuzzer.FuzzResult         `json:"dispatched_results,omitempty"`
	ExecutionRecords     []MobileFuzzExecutionRecord `json:"execution_records,omitempty"`
}

// MobileBOLAExecutionRecord records the per-endpoint execution telemetry from Engine 3 (BOLA).
type MobileBOLAExecutionRecord struct {
	EndpointPath      string                 `json:"endpoint_path"`
	Method            string                 `json:"method"`
	Category          string                 `json:"category"`
	TestID            string                 `json:"test_id"`
	ObjectID          string                 `json:"object_id,omitempty"`
	OwnerAlias        string                 `json:"owner_alias,omitempty"`
	AccessorAlias     string                 `json:"accessor_alias,omitempty"`
	VerificationState bola.VerificationState `json:"verification_state"`
	ObservedStatus    int                    `json:"observed_status,omitempty"`
	EvidenceSummary   string                 `json:"evidence_summary"`
	FindingID         string                 `json:"finding_id,omitempty"`
	Executed          bool                   `json:"executed"`
}

// BOLAHandoffResult records the result of transferring exported mobile targets to Engine 3 (BOLA Engine).
type BOLAHandoffResult struct {
	TotalTargetsConsumed int                         `json:"total_targets_consumed"`
	TemplatesMapped      int                         `json:"templates_mapped"`
	Templates            []bola.EndpointTemplate     `json:"templates"`
	Plan                 *bola.TestPlan              `json:"plan,omitempty"`
	Results              []bola.Result               `json:"results,omitempty"`
	Summary              *bola.Summary               `json:"summary,omitempty"`
	ExecutionRecords     []MobileBOLAExecutionRecord `json:"execution_records,omitempty"`
}

// BuildHTTPRequestFromTarget builds a valid http.Request from an exported DAST target descriptor.
func BuildHTTPRequestFromTarget(target map[string]any) (*http.Request, error) {
	scheme, _ := target["scheme"].(string)
	if scheme == "" {
		scheme = "http"
	}
	host, _ := target["host"].(string)
	if host == "" {
		return nil, fmt.Errorf("target missing host")
	}
	port, _ := target["port"].(int)
	path, _ := target["path"].(string)
	if path == "" {
		path = "/"
	}
	method, _ := target["method"].(string)

	cleanPath := strings.ToLower(path)
	// Recognize typical mutation or authentication routes and ensure POST semantics
	if (method == "" || method == http.MethodGet) &&
		(strings.Contains(cleanPath, "login") ||
			strings.Contains(cleanPath, "password") ||
			strings.Contains(cleanPath, "transfer") ||
			strings.Contains(cleanPath, "account") ||
			strings.Contains(cleanPath, "auth") ||
			strings.Contains(cleanPath, "token") ||
			strings.Contains(cleanPath, "post") ||
			strings.Contains(cleanPath, "submit") ||
			strings.Contains(cleanPath, "create") ||
			strings.Contains(cleanPath, "update")) {
		method = http.MethodPost
	}
	if method == "" {
		method = http.MethodGet
	}

	hostPort := host
	if port > 0 && port != 80 && port != 443 {
		hostPort = fmt.Sprintf("%s:%d", host, port)
	}

	rawURL := fmt.Sprintf("%s://%s%s", scheme, hostPort, path)
	reqURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	var body io.Reader
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
		switch cleanPath {
		case "/login":
			body = strings.NewReader("username=testuser&password=testpassword")
		case "/changepassword":
			body = strings.NewReader("username=testuser&newpassword=newsecretpassword")
		case "/devlogin":
			body = strings.NewReader("username=devadmin")
		case "/dotransfer":
			body = strings.NewReader("username=testuser&password=testpass&from_acc=1001&to_acc=2002&amount=50")
		case "/getaccounts":
			body = strings.NewReader("username=testuser&password=testpass")
		default:
			body = strings.NewReader("param1=value1&param2=value2")
		}
	} else {
		// Provide query parameters for GET endpoints so parameters exist for DAST fuzzing
		if reqURL.RawQuery == "" {
			reqURL.RawQuery = "id=1001&user=testuser"
		}
	}

	req, err := http.NewRequest(method, reqURL.String(), body)
	if err != nil {
		return nil, fmt.Errorf("failed creating HTTP request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	return req, nil
}

// HandoffToFuzzer demonstrates target handoff to Engine 2 (Fuzzer), extracting parameters
// and optionally dispatching fuzzing tasks through the FuzzingPool.
func (r *MobileBackendCorrelationResult) HandoffToFuzzer(
	ctx context.Context,
	authorizedHosts []string,
	pool *fuzzer.FuzzingPool,
) (*FuzzerHandoffResult, error) {
	if r == nil {
		return nil, fmt.Errorf("nil correlation result")
	}

	targets := r.ExportEndpointsForDAST()
	result := &FuzzerHandoffResult{
		TotalTargetsConsumed: len(targets),
		TargetEndpoints:      make([]string, 0),
		ExecutionRecords:     make([]MobileFuzzExecutionRecord, 0),
	}

	authHostMap := make(map[string]bool)
	for _, h := range authorizedHosts {
		authHostMap[strings.ToLower(strings.TrimSpace(h))] = true
	}

	type taskContext struct {
		targetURL string
		path      string
		method    string
		params    []fuzzer.Parameter
	}
	taskContextMap := make(map[string]taskContext)

	extractor := fuzzer.NewParameterExtractor()
	var tasks []fuzzer.FuzzTask

	for idx, t := range targets {
		host, _ := t["host"].(string)
		if len(authHostMap) > 0 && !authHostMap[strings.ToLower(host)] {
			continue // only dispatch against authorized lab targets
		}
		result.AuthorizedTargets++

		req, err := BuildHTTPRequestFromTarget(t)
		if err != nil {
			continue
		}

		path, _ := t["path"].(string)
		result.TargetEndpoints = append(result.TargetEndpoints, fmt.Sprintf("%s %s", req.Method, path))

		params, err := extractor.Extract(req)
		if err == nil {
			result.ParametersExtracted += len(params)
		}

		taskID := fmt.Sprintf("FUZZ-TASK-%03d", idx+1)
		task := fuzzer.FuzzTask{
			ID:         taskID,
			Request:    req,
			MaxRetries: 2,
		}
		tasks = append(tasks, task)

		taskContextMap[taskID] = taskContext{
			targetURL: req.URL.String(),
			path:      path,
			method:    req.Method,
			params:    params,
		}
	}

	result.TasksCreated = len(tasks)

	if pool != nil && len(tasks) > 0 {
		dispatched, err := pool.Dispatch(ctx, tasks)
		if err != nil {
			return result, fmt.Errorf("fuzz pool dispatch error: %w", err)
		}
		result.DispatchedResults = dispatched

		for _, res := range dispatched {
			tCtx := taskContextMap[res.TaskID]
			rec := MobileFuzzExecutionRecord{
				TargetURL:       tCtx.targetURL,
				EndpointPath:    tCtx.path,
				Method:          tCtx.method,
				TaskID:          res.TaskID,
				Parameters:      tCtx.params,
				StatusCode:      res.StatusCode,
				DurationMs:      res.Duration.Milliseconds(),
				RetriesExecuted: res.RetriesExecuted,
				Executed:        true,
			}
			if res.Error != nil {
				rec.Error = res.Error.Error()
			}
			result.ExecutionRecords = append(result.ExecutionRecords, rec)
		}
	} else {
		for _, t := range tasks {
			tCtx := taskContextMap[t.ID]
			rec := MobileFuzzExecutionRecord{
				TargetURL:    tCtx.targetURL,
				EndpointPath: tCtx.path,
				Method:       tCtx.method,
				TaskID:       t.ID,
				Parameters:   tCtx.params,
				Executed:     false,
			}
			result.ExecutionRecords = append(result.ExecutionRecords, rec)
		}
	}

	return result, nil
}

// HandoffToBOLA maps exported target descriptors to BOLA EndpointTemplates, generates a formal
// TestPlan using Engine 3, and optionally executes an authorization assessment.
func (r *MobileBackendCorrelationResult) HandoffToBOLA(
	ctx context.Context,
	actx *bola.AssessmentContext,
	engine *bola.Engine,
) (*BOLAHandoffResult, error) {
	if r == nil {
		return nil, fmt.Errorf("nil correlation result")
	}

	targets := r.ExportEndpointsForDAST()
	result := &BOLAHandoffResult{
		TotalTargetsConsumed: len(targets),
		Templates:            make([]bola.EndpointTemplate, 0),
		ExecutionRecords:     make([]MobileBOLAExecutionRecord, 0),
	}

	seenPaths := make(map[string]bool)
	for _, t := range targets {
		path, _ := t["path"].(string)
		method, _ := t["method"].(string)
		if path == "" || path == "/" {
			continue
		}
		cleanPath := strings.ToLower(path)
		inferredMethod := method
		if (inferredMethod == "" || inferredMethod == http.MethodGet) &&
			(strings.Contains(cleanPath, "password") ||
				strings.Contains(cleanPath, "transfer") ||
				strings.Contains(cleanPath, "login") ||
				strings.Contains(cleanPath, "create") ||
				strings.Contains(cleanPath, "update") ||
				strings.Contains(cleanPath, "delete")) {
			inferredMethod = http.MethodPost
		}

		key := fmt.Sprintf("%s:%s", inferredMethod, path)
		if seenPaths[key] {
			continue
		}
		seenPaths[key] = true

		isStateChanging := inferredMethod == http.MethodPost || inferredMethod == http.MethodPut || inferredMethod == http.MethodPatch || inferredMethod == http.MethodDelete || strings.Contains(cleanPath, "change") || strings.Contains(cleanPath, "update") || strings.Contains(cleanPath, "transfer")
		isCollection := strings.HasSuffix(cleanPath, "s") || strings.Contains(cleanPath, "list") || strings.Contains(cleanPath, "accounts")

		tmpl := bola.EndpointTemplate{
			Method:          inferredMethod,
			PathPattern:     path,
			IsStateChanging: isStateChanging,
			IsCollection:    isCollection,
		}
		result.Templates = append(result.Templates, tmpl)
	}

	result.TemplatesMapped = len(result.Templates)

	if actx != nil && engine != nil {
		// Populate assessment context with mapped endpoints if not already specified
		if len(actx.Endpoints) == 0 {
			actx.Endpoints = result.Templates
		}

		plan, err := engine.Plan(ctx, actx)
		if err != nil {
			return result, fmt.Errorf("BOLA planning failed: %w", err)
		}
		result.Plan = plan

		// If assessment authorized, execute assessment through Engine 3
		if actx.Authorization != nil {
			assessResults, summary, err := engine.Assess(ctx, actx)
			if err != nil {
				return result, fmt.Errorf("BOLA assessment failed: %w", err)
			}
			result.Results = assessResults
			result.Summary = summary

			for _, res := range assessResults {
				rec := MobileBOLAExecutionRecord{
					EndpointPath:      res.Endpoint,
					Method:            res.Method,
					Category:          string(res.Category),
					TestID:            res.TestID,
					ObjectID:          res.ObjectID,
					OwnerAlias:        res.OwnerAlias,
					AccessorAlias:     res.AccessorAlias,
					VerificationState: res.VerificationState,
					ObservedStatus:    res.ObservedStatus,
					EvidenceSummary:   res.EvidenceSummary,
					Executed:          res.VerificationState != bola.StateInconclusive && res.VerificationState != bola.StateSkipped,
				}
				if res.Finding != nil {
					rec.FindingID = res.Finding.ID
				}
				result.ExecutionRecords = append(result.ExecutionRecords, rec)
			}
		}
	}

	return result, nil
}
