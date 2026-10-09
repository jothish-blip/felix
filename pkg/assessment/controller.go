package assessment

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"felix/pkg/api"
	"felix/pkg/auth"
	"felix/pkg/cloud"
	"felix/pkg/config"
	"felix/pkg/crawler"
	"felix/pkg/discovery"
	"felix/pkg/report"
	"felix/pkg/secrets"
	"github.com/google/uuid"
)

// Controller orchestrates the lifecycle, authorization validation, scope enforcement,
// scanning execution, and finding traceability for security assessments.
type Controller struct {
	store Store
}

// NewController creates a new Assessment Controller backed by the provided Store.
func NewController(store Store) *Controller {
	return &Controller{store: store}
}

// ExecutionOptions specifies runtime parameters and report export destinations.
type ExecutionOptions struct {
	TimeoutDuration time.Duration
	Concurrency     int
	MaxAssets       int
	MaxSizeBytes    int64
	UserAgent       string
	FelixVersion    string
	BuildID         string
	ExportHTMLPath  string
	ExportJSONPath  string
	Verbose         bool
	ProgressFunc    func(msg string)
}

// ExecutionResult encapsulates the outcome of an assessment run.
type ExecutionResult struct {
	Execution        *AssessmentExecution
	Report           *report.Report
	InventorySummary *discovery.InventorySummary
	AuthSummary      *auth.AuthSummary
	HTMLPath         string
	JSONPath         string
	Error            error
}

// RunAssessment executes a complete assessment run against authorized targets.
func (c *Controller) RunAssessment(ctx context.Context, assessmentID string, opts ExecutionOptions) (*ExecutionResult, error) {
	if opts.ProgressFunc == nil {
		opts.ProgressFunc = func(string) {}
	}

	// 1. Load the Assessment
	asm, err := c.store.GetAssessment(assessmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to load assessment: %w", err)
	}
	assessmentID = asm.ID

	// 2. Validate Status
	if asm.Status != StatusReady && asm.Status != StatusDraft {
		return nil, fmt.Errorf("assessment %s is in %s state (must be READY to execute)", asm.Ref, asm.Status)
	}

	// 3. Validate Authorization
	authRecord, err := c.store.GetAuthorization(assessmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to load authorization record: %w", err)
	}
	if authRecord == nil {
		return nil, fmt.Errorf("security refusal: no authorization record found for assessment %s", asm.Ref)
	}
	now := time.Now().UTC()
	if valid, reason := authRecord.IsCurrentlyValid(now); !valid {
		return nil, fmt.Errorf("security refusal: invalid authorization: %s", reason)
	}

	// 4. Load & Validate Targets
	targets, err := c.store.GetTargets(assessmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to load assessment targets: %w", err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("security refusal: assessment has zero approved targets")
	}

	var approvedTargetURLs []string
	targetMap := make(map[string]AssessmentTarget) // normalized URL -> AssessmentTarget
	for _, t := range targets {
		if t.ScopeStatus != "APPROVED" {
			continue
		}
		norm, err := NormalizeTargetURL(t.TargetURL)
		if err != nil {
			return nil, fmt.Errorf("invalid approved target %q: %w", t.TargetURL, err)
		}
		approvedTargetURLs = append(approvedTargetURLs, norm)
		targetMap[norm] = t
		// Also map raw URL
		targetMap[t.TargetURL] = t
	}

	if len(approvedTargetURLs) == 0 {
		return nil, fmt.Errorf("security refusal: no approved targets configured for assessment")
	}

	// 5. Load Scope Rules and Exclusions
	scopeRules, err := c.store.GetScopeRules(assessmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to load scope rules: %w", err)
	}
	exclusions, err := c.store.GetExclusions(assessmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to load exclusions: %w", err)
	}

	// Build Scope Validator
	scopeVal := NewScopeValidator(asm.ScopeMode, approvedTargetURLs, scopeRules, exclusions)

	// Pre-scan validation: ensure none of the targets themselves are excluded
	var runnableTargets []string
	for _, tURL := range approvedTargetURLs {
		if excluded, reason := scopeVal.IsExcluded(tURL); excluded {
			opts.ProgressFunc(fmt.Sprintf("[!] Warning: Approved target %s matches exclusion (%s); skipping.", tURL, reason))
			continue
		}
		runnableTargets = append(runnableTargets, tURL)
	}

	if len(runnableTargets) == 0 {
		return nil, fmt.Errorf("security refusal: all approved targets are excluded by active exclusion rules")
	}

	// 6. Build Effective Scan Configuration Snapshot
	cfgStore := config.Load()
	timeoutDur := opts.TimeoutDuration
	if timeoutDur <= 0 {
		timeoutDur = time.Duration(cfgStore.Timeout) * time.Second
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = cfgStore.Concurrency
	}
	maxAssets := opts.MaxAssets
	maxSizeBytes := opts.MaxSizeBytes
	if maxSizeBytes <= 0 {
		maxSizeBytes = int64(cfgStore.MaxSizeMB) * 1024 * 1024
	}
	userAgent := opts.UserAgent
	if userAgent == "" {
		userAgent = cfgStore.UserAgent
	}
	felixVer := opts.FelixVersion
	if felixVer == "" {
		felixVer = "2.0.0-stage1"
	}

	configSnapshot := ScanConfigSnapshot{
		TimeoutSeconds: int(timeoutDur.Seconds()),
		Concurrency:    concurrency,
		ScopeMode:      asm.ScopeMode,
		MaxAssets:      maxAssets,
		MaxSizeBytes:   maxSizeBytes,
		UserAgent:      userAgent,
		FelixVersion:   felixVer,
		BuildID:        opts.BuildID,
	}

	// 7. Create Execution Record
	execID := "exec-" + uuid.New().String()
	execRecord := &AssessmentExecution{
		ID:             execID,
		AssessmentID:   assessmentID,
		Status:         StatusRunning,
		StartedAt:      time.Now().UTC(),
		ConfigSnapshot: configSnapshot,
	}
	if err := c.store.CreateExecution(execRecord); err != nil {
		return nil, fmt.Errorf("failed to create execution record: %w", err)
	}

	// Mark Assessment as RUNNING
	_ = c.store.UpdateAssessmentStatus(assessmentID, StatusRunning)

	opts.ProgressFunc(fmt.Sprintf("[*] Assessment %s execution started (%s) against %d target(s)...", asm.Ref, execID, len(runnableTargets)))

	// 8. Invoke Existing Felix Scan Pipeline with strict redirect validation
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeoutDur,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       tlsConfig,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   timeoutDur,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			lastURL := ""
			if len(via) > 0 {
				lastURL = via[len(via)-1].URL.String()
			}
			if err := scopeVal.ValidateRedirect(lastURL, req.URL.String()); err != nil {
				return fmt.Errorf("redirect blocked by scope validator: %w", err)
			}
			return nil
		},
	}

	crawlerCfg := crawler.Config{
		Concurrency:  concurrency,
		Timeout:      timeoutDur,
		MaxAssetSize: maxSizeBytes,
		MaxAssets:    maxAssets,
		ScopeMode:    crawler.ScopeMode(asm.ScopeMode),
		UserAgent:    userAgent,
		Client:       httpClient,
		IsAllowed:    scopeVal.IsAllowed,
		IsExcluded:   func(u string) bool { excluded, _ := scopeVal.IsExcluded(u); return excluded },
	}
	cEng := crawler.New(crawlerCfg)
	detector := secrets.NewDetector()
	cloudAuditor := cloud.NewDetector(cloud.NewClient(cloud.ClientOptions{
		Timeout:         timeoutDur,
		MaxResponseSize: maxSizeBytes,
		UserAgent:       userAgent,
		HTTPClient:      httpClient,
	}))
	apiAuditor := api.NewDetector(api.NewClient(api.ClientOptions{
		Timeout:         timeoutDur,
		MaxResponseSize: maxSizeBytes,
		UserAgent:       userAgent,
		HTTPClient:      httpClient,
	}))

	startTime := time.Now()
	crawlResultsChan := cEng.CrawlConcurrently(ctx, runnableTargets)

	discoveryEng := discovery.NewEngine(discovery.Config{
		Concurrency: concurrency,
		Timeout:     timeoutDur,
		MaxAssets:   maxAssets,
	})
	var allInventoryAssets []discovery.Asset
	var allInventoryRelations []discovery.Relation

	authEng := auth.NewEngine()
	var allAuthSurfaces []auth.AuthSurface
	var allAuthCookies []auth.CookieMetadata
	var allAuthTokens []auth.TokenArtifact
	var allProtectedEndpoints []auth.ProtectedEndpointInfo

	var allReportFindings []report.Finding
	var allAssessmentFindings []AssessmentFinding
	totalDiscovered := 0
	totalEndpointsAudited := 0
	var scanErr error

	for res := range crawlResultsChan {
		if ctx.Err() != nil {
			scanErr = ctx.Err()
			break
		}

		if res.Err != nil {
			opts.ProgressFunc(fmt.Sprintf("[-] [%s] Crawl error: %v", res.Target, res.Err))
			continue
		}

		targetRecord := targetMap[res.Target]
		normTarget, _ := NormalizeTargetURL(res.Target)
		if targetRecord.ID == "" {
			targetRecord = targetMap[normTarget]
		}

		// Filter out any assets matching exclusions before passing to security detectors
		var inScopeAssets []crawler.Asset
		for _, a := range res.Assets {
			if excluded, _ := scopeVal.IsExcluded(a.URL); excluded {
				continue
			}
			if !scopeVal.IsAllowed(a.URL) {
				a.InScope = false
			}
			inScopeAssets = append(inScopeAssets, a)
		}
		totalDiscovered += len(inScopeAssets)

		// Engine 2: Secrets Intelligence
		secFindings := detector.ScanAssets(inScopeAssets)

		// Engine 3: Cloud & BaaS Intelligence
		cloudRes := cloudAuditor.Audit(ctx, inScopeAssets, secFindings)

		// Engine 4: API Security Auditing
		apiRes := apiAuditor.Audit(ctx, res.Target, inScopeAssets)
		totalEndpointsAudited += apiRes.EndpointsScanned

		// Normalize findings using existing adapters
		for _, a := range inScopeAssets {
			if f, ok := report.FromCrawlerAsset(res.Target, a); ok {
				allReportFindings = append(allReportFindings, f)
				allAssessmentFindings = append(allAssessmentFindings, toAssessmentFinding(assessmentID, execID, targetRecord.ID, f))
			}
		}
		for _, f := range secFindings {
			rf := report.FromSecretFinding(res.Target, f)
			allReportFindings = append(allReportFindings, rf)
			allAssessmentFindings = append(allAssessmentFindings, toAssessmentFinding(assessmentID, execID, targetRecord.ID, rf))
		}
		for _, f := range cloudRes.Findings {
			rf := report.FromCloudFinding(res.Target, f)
			allReportFindings = append(allReportFindings, rf)
			allAssessmentFindings = append(allAssessmentFindings, toAssessmentFinding(assessmentID, execID, targetRecord.ID, rf))
		}
		for _, f := range apiRes.Findings {
			// Ensure endpoint does not match exclusions
			if excluded, _ := scopeVal.IsExcluded(f.Endpoint); excluded {
				continue
			}
			rf := report.FromAPIFinding(res.Target, f)
			allReportFindings = append(allReportFindings, rf)
			allAssessmentFindings = append(allAssessmentFindings, toAssessmentFinding(assessmentID, execID, targetRecord.ID, rf))
		}

		// Engine 5: Unified Attack-Surface Intelligence
		var certs []*x509.Certificate
		if res.TLS != nil {
			certs = res.TLS.PeerCertificates
		}
		targetInv := discoveryEng.AnalyzeTarget(
			ctx,
			assessmentID,
			execID,
			targetRecord.ID,
			res.Target,
			string(res.HTML),
			res.Header,
			certs,
			inScopeAssets,
			scopeVal.IsAllowed,
		)
		allInventoryAssets = append(allInventoryAssets, targetInv.Assets...)
		allInventoryRelations = append(allInventoryRelations, targetInv.Relations...)

		// Engine 6: Authentication Intelligence
		authInv, authFindings := authEng.AnalyzeAuthentication(
			targetInv,
			inScopeAssets,
			res.Header,
			res.Target,
			assessmentID,
			execID,
			targetRecord.ID,
		)
		allAuthSurfaces = append(allAuthSurfaces, authInv.Surfaces...)
		allAuthCookies = append(allAuthCookies, authInv.Cookies...)
		allAuthTokens = append(allAuthTokens, authInv.Tokens...)
		allProtectedEndpoints = append(allProtectedEndpoints, authInv.ProtectedEndpoints...)

		for _, f := range authFindings {
			allReportFindings = append(allReportFindings, f)
			allAssessmentFindings = append(allAssessmentFindings, toAssessmentFinding(assessmentID, execID, targetRecord.ID, f))
		}
	}

	duration := time.Since(startTime)
	completedAt := time.Now().UTC()
	execRecord.CompletedAt = &completedAt
	execRecord.DurationMs = duration.Milliseconds()
	execRecord.RequestCount = totalDiscovered + totalEndpointsAudited
	execRecord.FindingCount = len(allAssessmentFindings)

	// Persist Attack-Surface Inventory
	if err := c.store.SaveInventory(allInventoryAssets, allInventoryRelations); err != nil {
		opts.ProgressFunc(fmt.Sprintf("[-] Warning: Failed to persist attack-surface inventory: %v", err))
	} else if len(allInventoryAssets) > 0 {
		opts.ProgressFunc(fmt.Sprintf("[+] Attack-surface inventory recorded: %d assets, %d relationships mapped", len(allInventoryAssets), len(allInventoryRelations)))
	}

	// Persist Authentication Inventory
	combinedAuthInv := auth.AuthInventory{
		Surfaces:           allAuthSurfaces,
		Cookies:            allAuthCookies,
		Tokens:             allAuthTokens,
		ProtectedEndpoints: allProtectedEndpoints,
	}
	if err := c.store.SaveAuthInventory(combinedAuthInv); err != nil {
		opts.ProgressFunc(fmt.Sprintf("[-] Warning: Failed to persist authentication inventory: %v", err))
	} else if len(allAuthSurfaces) > 0 || len(allAuthCookies) > 0 || len(allAuthTokens) > 0 {
		opts.ProgressFunc(fmt.Sprintf("[+] Authentication intelligence recorded: %d surfaces, %d cookies, %d token artifacts",
			len(allAuthSurfaces), len(allAuthCookies), len(allAuthTokens)))
	}

	// Preserve partial results on error or cancellation
	if scanErr != nil || ctx.Err() != nil {
		if ctx.Err() == context.Canceled {
			execRecord.Status = StatusCancelled
			execRecord.ErrorMessage = "Execution was cancelled by operator"
		} else {
			execRecord.Status = StatusFailed
			execRecord.ErrorMessage = fmt.Sprintf("Scan failed: %v", scanErr)
		}
		_ = c.store.UpdateExecution(execRecord)
		_ = c.store.UpdateAssessmentStatus(assessmentID, execRecord.Status)

		// Save partial findings if any were generated
		if len(allAssessmentFindings) > 0 {
			_ = c.store.SaveFindings(allAssessmentFindings)
		}

		return &ExecutionResult{
			Execution: execRecord,
			Error:     scanErr,
		}, scanErr
	}

	// 9. Persist Findings & Traceability
	if len(allAssessmentFindings) > 0 {
		if err := c.store.SaveFindings(allAssessmentFindings); err != nil {
			opts.ProgressFunc(fmt.Sprintf("[-] Warning: Failed to persist findings to database: %v", err))
		}
	}

	// 10. Generate Unified Report
	rep := report.BuildMultiTargetReport(runnableTargets, allReportFindings)
	rep.Duration = duration.Round(time.Millisecond).String()
	rep.DurationMs = duration.Milliseconds()
	rep.RequestCount = totalDiscovered + totalEndpointsAudited
	if rep.Metadata == nil {
		rep.Metadata = make(map[string]any)
	}
	rep.Metadata["assessment_id"] = assessmentID
	rep.Metadata["assessment_ref"] = asm.Ref
	rep.Metadata["execution_id"] = execID
	rep.Metadata["client_id"] = asm.ClientID

	// 11. Report File Export
	var htmlPath, jsonPath string
	managedReportsDir, _ := getReportsDir(asm.Ref)

	// HTML Export
	if opts.ExportHTMLPath != "" {
		htmlPath = opts.ExportHTMLPath
	} else if managedReportsDir != "" {
		htmlPath = filepath.Join(managedReportsDir, fmt.Sprintf("%s_%s.html", asm.Ref, execID))
	}
	if htmlPath != "" {
		if err := report.WriteHTML(rep, htmlPath); err == nil {
			_ = c.store.SaveReport(&ReportRecord{
				ID:           "rep-" + uuid.New().String(),
				AssessmentID: assessmentID,
				ExecutionID:  execID,
				Format:       "HTML",
				FilePath:     htmlPath,
				FelixVersion: felixVer,
				Status:       "GENERATED",
			})
		}
	}

	// JSON Export
	if opts.ExportJSONPath != "" {
		jsonPath = opts.ExportJSONPath
	} else if managedReportsDir != "" {
		jsonPath = filepath.Join(managedReportsDir, fmt.Sprintf("%s_%s.json", asm.Ref, execID))
	}
	if jsonPath != "" {
		if err := report.WriteJSON(rep, jsonPath); err == nil {
			_ = c.store.SaveReport(&ReportRecord{
				ID:           "rep-" + uuid.New().String(),
				AssessmentID: assessmentID,
				ExecutionID:  execID,
				Format:       "JSON",
				FilePath:     jsonPath,
				FelixVersion: felixVer,
				Status:       "GENERATED",
			})
		}
	}

	// 12. Finalize Status
	finalStatus := StatusCompleted
	execRecord.Status = finalStatus
	_ = c.store.UpdateExecution(execRecord)
	_ = c.store.UpdateAssessmentStatus(assessmentID, finalStatus)

	opts.ProgressFunc(fmt.Sprintf("[✓] Assessment %s completed in %s (%d findings, %d requests).",
		asm.Ref, duration.Round(time.Millisecond), len(allAssessmentFindings), execRecord.RequestCount))

	invSummary, _ := c.store.GetInventorySummary(assessmentID, execID)
	authSummary := authEng.GenerateSummary(combinedAuthInv)

	return &ExecutionResult{
		Execution:        execRecord,
		Report:           &rep,
		InventorySummary: invSummary,
		AuthSummary:      &authSummary,
		HTMLPath:         htmlPath,
		JSONPath:         jsonPath,
	}, nil
}

// ToAssessmentFinding maps a report.Finding to an AssessmentFinding with full relationship IDs.
func ToAssessmentFinding(assessmentID, executionID, targetID string, f report.Finding) AssessmentFinding {
	return AssessmentFinding{
		ID:                 "fnd-" + uuid.New().String(),
		AssessmentID:       assessmentID,
		ExecutionID:        executionID,
		TargetID:           targetID,
		OriginalFindingID:  f.ID,
		Title:              f.Title,
		Category:           f.Category,
		Severity:           f.Severity,
		Confidence:         f.Confidence,
		VerificationStatus: f.Verification.Status,
		TargetURL:          f.Target,
		Endpoint:           f.Endpoint,
		Method:             f.Method,
		Fingerprint:        f.Fingerprint,
		Score:              f.Score,
		EvidenceDetails:    f.EvidenceDetails,
		VerificationRecord: f.Verification,
		Remediation:        f.Remediation,
		CreatedAt:          time.Now().UTC(),
	}
}

func toAssessmentFinding(assessmentID, executionID, targetID string, f report.Finding) AssessmentFinding {
	return ToAssessmentFinding(assessmentID, executionID, targetID, f)
}

func getReportsDir(assessmentRef string) (string, error) {
	cfgDir, err := config.Dir()
	if err != nil {
		return "", err
	}
	reportsDir := filepath.Join(cfgDir, "reports", assessmentRef)
	if err := os.MkdirAll(reportsDir, 0700); err != nil {
		return "", err
	}
	return reportsDir, nil
}
