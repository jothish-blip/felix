package assessment

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"felix/pkg/auth"
	"felix/pkg/clierror"
	"felix/pkg/config"
	"felix/pkg/correlation"
	"felix/pkg/crawler"
	"felix/pkg/discovery"
	"felix/pkg/notify"
	"felix/pkg/oast"
	"felix/pkg/provenance"
	"felix/pkg/report"
	"felix/pkg/secrets"
	"felix/pkg/verification"
	"github.com/google/uuid"
)

// Controller orchestrates the lifecycle, authorization validation, scope enforcement,
// scanning execution, and finding traceability for security assessments.
type Controller struct {
	store          Store
	registry       *EngineRegistry
	oastCorrelator *oast.Correlator
}

// NewController creates a new Assessment Controller backed by the provided Store.
func NewController(store Store) *Controller {
	return &Controller{
		store:    store,
		registry: DefaultEngineRegistry(store),
	}
}

// SetOASTCorrelator configures the OAST correlator for automated probe lifecycle cleanup.
func (c *Controller) SetOASTCorrelator(correlator *oast.Correlator) {
	c.oastCorrelator = correlator
}

// SetEngineRegistry overrides the engine registry used by the controller.
func (c *Controller) SetEngineRegistry(reg *EngineRegistry) {
	c.registry = reg
}

// GetEngineRegistry returns the engine registry used by the controller, initializing default if needed.
func (c *Controller) GetEngineRegistry() *EngineRegistry {
	if c.registry == nil {
		c.registry = DefaultEngineRegistry(c.store)
	}
	return c.registry
}

// RegisterEngine registers an EngineRunner with the controller's engine registry.
func (c *Controller) RegisterEngine(runner EngineRunner) error {
	return c.GetEngineRegistry().Register(runner)
}

// ExecutionOptions specifies runtime parameters and report export destinations.
type ExecutionOptions struct {
	ExecutionID        string
	ScheduleID         string
	ScheduledFor       *time.Time
	InitiationSource   string // "manual", "scheduled", "api"
	TenantID           string
	AccountID          string
	TimeoutDuration    time.Duration
	Concurrency        int
	MaxAssets          int
	MaxSizeBytes       int64
	UserAgent          string
	FelixVersion       string
	BuildID            string
	ExportHTMLPath     string
	ExportJSONPath     string
	ExportSARIFPath    string
	Verbose            bool
	ProgressFunc       func(msg string)
	AllowLoopback      bool
	AllowPrivateIPs    bool
	InsecureSkipVerify bool
	ActiveVerification bool
	MaxRedirects       int
	MaxRetries         int
	RetryDelayMs       int
	WorkerID           string
	ResumeCheckpoint   *ScanCheckpoint
	LeaseDuration      time.Duration
	IdempotencyKey     string
	BaselineRef        string
	BaselineScope      string // "all", "new", "new_and_regressed"
}

// ExecutionResult encapsulates the outcome of an assessment run.
type ExecutionResult struct {
	Execution           *AssessmentExecution
	Snapshot            *AssessmentSnapshot
	Report              *report.Report
	InventorySummary    *discovery.InventorySummary
	AuthSummary         *auth.AuthSummary
	VerificationSummary *verification.VerificationSummary
	ChangeSummary       *report.ChangeSummary
	HTMLPath            string
	JSONPath            string
	SARIFPath           string
	Error               error
	Classification      clierror.Classification
	Provenance          *provenance.AssessmentProvenance
}

// buildSafeHTTPClient constructs an HTTP client configured with SSRF protection, strict redirects,
// and TLS verification boundaries.
func (c *Controller) buildSafeHTTPClient(
	cfgStore *config.Config,
	opts ExecutionOptions,
	scopeVal *ScopeValidator,
	timeoutDur time.Duration,
	concurrency int,
) *http.Client {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	insecureSkip := opts.InsecureSkipVerify || cfgStore.InsecureSkipVerify
	if insecureSkip {
		tlsConfig.InsecureSkipVerify = true
	}
	safeTransport := crawler.NewSafeTransport(crawler.SafeTransportOptions{
		Timeout:            timeoutDur,
		KeepAlive:          30 * time.Second,
		AllowLoopback:      opts.AllowLoopback || cfgStore.AllowLoopback,
		AllowPrivateIPs:    opts.AllowPrivateIPs || cfgStore.AllowPrivateIPs,
		InsecureSkipVerify: insecureSkip,
		TLSConfig:          tlsConfig,
	})
	transport := crawler.NewRateLimitedTransport(safeTransport, crawler.RateLimitOptions{
		MaxConcurrency: concurrency,
	})
	maxRedirects := opts.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = cfgStore.MaxRedirects
	}
	if maxRedirects <= 0 {
		maxRedirects = config.DefaultMaxRedirects
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeoutDur,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			scheme := strings.ToLower(req.URL.Scheme)
			if scheme != "http" && scheme != "https" {
				return fmt.Errorf("redirect to unsupported scheme %q blocked", req.URL.Scheme)
			}
			if req.URL.User != nil {
				return fmt.Errorf("redirect with embedded credentials blocked")
			}
			destHost := req.URL.Hostname()
			if ip := net.ParseIP(destHost); ip != nil {
				if prohibited, reason := crawler.ProhibitedIPReason(ip, opts.AllowLoopback, opts.AllowPrivateIPs); prohibited {
					return &crawler.SSRFError{Host: destHost, IP: ip, Reason: reason}
				}
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
	if c.oastCorrelator != nil {
		defer c.oastCorrelator.CancelAssessmentProbes(asm.ID)
	}

	tenantID := asm.ClientID
	if opts.TenantID != "" {
		tenantID = opts.TenantID
	}
	accountID := opts.AccountID

	// Baseline Pre-Validation (Phase 8.4)
	if opts.BaselineRef != "" {
		authCtx := TenantAuthContext{
			TenantID:  tenantID,
			AccountID: accountID,
			ClientID:  asm.ClientID,
			isAdmin:   true,
		}
		baseExec, err := c.store.ResolveExecutionRef(asm.ID, opts.BaselineRef, authCtx, false)
		if err != nil {
			return nil, fmt.Errorf("baseline %q not found or invalid: %w", opts.BaselineRef, err)
		}
		if !authCtx.Authorizes(baseExec.ClientID, baseExec.TenantID, baseExec.AccountID) {
			return nil, fmt.Errorf("cross-tenant baseline access denied: %w", ErrExecutionUnauthorized)
		}
		if baseExec.TenantID != "" && tenantID != "" && baseExec.TenantID != tenantID {
			return nil, fmt.Errorf("cross-tenant baseline denied (%q != %q): %w", baseExec.TenantID, tenantID, ErrExecutionUnauthorized)
		}
		if baseExec.AccountID != "" && accountID != "" && baseExec.AccountID != accountID {
			return nil, fmt.Errorf("cross-account baseline denied (%q != %q): %w", baseExec.AccountID, accountID, ErrExecutionUnauthorized)
		}
		if baseExec.AssessmentType != "" && asm.AssessmentType != "" && !AreAssessmentTypesCompatible(baseExec.AssessmentType, asm.AssessmentType) {
			return nil, fmt.Errorf("incompatible baseline assessment type (%q vs %q): %w", baseExec.AssessmentType, asm.AssessmentType, ErrIncompatibleAssessmentScope)
		}
		if baseExec.Status != StatusCompleted && baseExec.Status != StatusCompletedWithErrors {
			return nil, fmt.Errorf("ineligible baseline %s: status is %s (must be COMPLETED or COMPLETED_WITH_ERRORS): %w", baseExec.ID, baseExec.Status, ErrIneligibleBaseline)
		}
		if baseExec.SnapshotID != "" {
			snap, err := c.store.GetSnapshot(baseExec.SnapshotID, authCtx)
			if err != nil {
				return nil, fmt.Errorf("corrupt or missing baseline snapshot %q: %w", baseExec.SnapshotID, err)
			}
			if snap == nil || snap.IsInconclusive() {
				return nil, fmt.Errorf("ineligible baseline %s: snapshot is missing or inconclusive: %w", baseExec.ID, ErrIneligibleBaseline)
			}
			if baseExec.Status == StatusCompletedWithErrors {
				failedTgts := snap.GetFailedTargets()
				if len(failedTgts) > 0 {
					compTgts, _ := c.store.GetTargets(asm.ID)
					for _, ct := range compTgts {
						if correlation.IsSingleTargetInScope(ct.TargetURL, failedTgts) {
							return nil, fmt.Errorf("ineligible baseline %s: target %q suffered crawl failure in baseline: %w",
								baseExec.ID, ct.TargetURL, ErrIneligibleBaseline)
						}
					}
				}
				if len(snap.GetFailedCategories()) > 0 {
					return nil, fmt.Errorf("ineligible baseline %s: detector category failure compromised baseline coverage: %w",
						baseExec.ID, ErrIneligibleBaseline)
				}
			}
		} else if baseExec.Status == StatusCompletedWithErrors {
			return nil, fmt.Errorf("ineligible baseline %s: status is COMPLETED_WITH_ERRORS without snapshot: %w",
				baseExec.ID, ErrIneligibleBaseline)
		}
	}

	// Request Idempotency & De-duplication (Phase 7.5)
	if opts.IdempotencyKey != "" {
		existing, err := c.store.GetExecutionByIdempotencyKey(tenantID, assessmentID, opts.IdempotencyKey)
		if err == nil && existing != nil {
			if IsTerminalExecutionStatus(existing.Status) {
				opts.ProgressFunc(fmt.Sprintf("[✓] Returning existing execution %s (status: %s) for idempotency key %s", existing.ID, existing.Status, opts.IdempotencyKey))
				var snap *AssessmentSnapshot
				if existing.SnapshotID != "" {
					snap, _ = c.store.GetSnapshot(existing.SnapshotID, NewTenantAuthContext(asm.ClientID, tenantID, accountID))
				}
				var htmlPath, jsonPath string
				if snap != nil && snap.Metadata != nil {
					htmlPath = snap.Metadata["html_report"]
					jsonPath = snap.Metadata["json_report"]
				}
				if htmlPath == "" || jsonPath == "" {
					if reps, err := c.store.GetReports(assessmentID); err == nil {
						for _, r := range reps {
							if r.ExecutionID == existing.ID {
								if r.Format == "HTML" && htmlPath == "" {
									htmlPath = r.FilePath
								} else if r.Format == "JSON" && jsonPath == "" {
									jsonPath = r.FilePath
								}
							}
						}
					}
				}
				return &ExecutionResult{
					Execution: existing,
					Snapshot:  snap,
					HTMLPath:  htmlPath,
					JSONPath:  jsonPath,
				}, nil
			}
			if existing.Status == StatusRunning || existing.Status == StatusQueued {
				return nil, fmt.Errorf("%w: assessment %s already has active execution %s in progress for idempotency key %s", ErrExecutionOverlap, asm.Ref, existing.ID, opts.IdempotencyKey)
			}
		}
	}

	// Overlapping Execution Prevention (Phase 7.5)
	if opts.ExecutionID == "" {
		active, activeID, err := c.store.HasActiveExecution(assessmentID)
		if err == nil && active {
			return nil, fmt.Errorf("%w: assessment %s is already running (execution %s); duplicate execution prevented", ErrExecutionOverlap, asm.Ref, activeID)
		}
	}

	// 2. Validate Status
	if asm.Status != StatusReady && asm.Status != StatusDraft && asm.Status != StatusCompleted && asm.Status != StatusCompletedWithErrors && asm.Status != StatusFailed {
		return nil, fmt.Errorf("assessment %s is in %s state (must be READY, DRAFT, or COMPLETED to execute)", asm.Ref, asm.Status)
	}

	// 3. Validate Authorization
	authRecord, err := c.store.GetAuthorization(assessmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to load authorization record: %w", err)
	}
	if authRecord == nil {
		return nil, clierror.SecurityFailure("security refusal: no authorization record found for assessment %s", asm.Ref)
	}
	now := time.Now().UTC()
	if valid, reason := authRecord.IsCurrentlyValid(now); !valid {
		return nil, clierror.SecurityFailure("security refusal: invalid authorization: %s", reason)
	}

	// 4. Load & Validate Targets
	targets, err := c.store.GetTargets(assessmentID)
	if err != nil {
		return nil, fmt.Errorf("failed to load assessment targets: %w", err)
	}
	if len(targets) == 0 {
		return nil, clierror.SecurityFailure("security refusal: assessment has zero approved targets")
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
		return nil, clierror.SecurityFailure("security refusal: no approved targets configured for assessment")
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
		return nil, clierror.SecurityFailure("security refusal: all approved targets are excluded by active exclusion rules")
	}

	// Checkpoint Resumption (Phase 7.4): Filter already completed targets if resuming
	if opts.ResumeCheckpoint != nil && len(opts.ResumeCheckpoint.CompletedTargets) > 0 {
		completedMap := make(map[string]bool)
		for _, ct := range opts.ResumeCheckpoint.CompletedTargets {
			completedMap[ct] = true
			if norm, _ := NormalizeTargetURL(ct); norm != "" {
				completedMap[norm] = true
			}
		}
		var remaining []string
		for _, rt := range runnableTargets {
			norm, _ := NormalizeTargetURL(rt)
			if !completedMap[rt] && !completedMap[norm] {
				remaining = append(remaining, rt)
			}
		}
		if len(remaining) > 0 {
			opts.ProgressFunc(fmt.Sprintf("[*] Resuming from checkpoint: %d target(s) already evaluated, %d remaining.",
				len(opts.ResumeCheckpoint.CompletedTargets), len(remaining)))
			runnableTargets = remaining
		}
	}

	// 6. Build Effective Scan Configuration Snapshot
	cfgStore, err := config.LoadWithEnv("")
	if err != nil {
		return nil, fmt.Errorf("configuration error: %w", err)
	}
	timeoutDur := opts.TimeoutDuration
	if timeoutDur <= 0 {
		timeoutDur = time.Duration(cfgStore.Timeout) * time.Second
	}
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = cfgStore.Concurrency
	}
	maxAssets := opts.MaxAssets
	if maxAssets <= 0 {
		maxAssets = cfgStore.MaxAssets
	}
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
	execID := opts.ExecutionID
	if execID == "" {
		execID = "exec-" + uuid.New().String()
	}

	// Capture assessment start provenance
	prov := provenance.CaptureStart(ctx, provenance.StartOptions{
		ExecutionID:     execID,
		AssessmentID:    assessmentID,
		AssessmentRef:   asm.Ref,
		FelixVersion:    felixVer,
		BuildID:         opts.BuildID,
		Config:          configSnapshot,
		TargetIdentity:  strings.Join(runnableTargets, ", "),
		ScopeMode:       asm.ScopeMode,
		ApprovedTargets: runnableTargets,
		BaselineRef:     opts.BaselineRef,
		EnabledEngines:  []string{asm.AssessmentType},
	})
	configSnapshot.Provenance = prov

	initSource := opts.InitiationSource
	if initSource == "" {
		initSource = "manual"
	}
	workerID := opts.WorkerID
	if workerID == "" {
		workerID = "worker-" + uuid.New().String()[:8]
	}
	leaseDuration := opts.LeaseDuration
	if leaseDuration <= 0 {
		leaseDuration = 5 * time.Minute
	}
	nowInit := time.Now().UTC()
	leaseExpInit := nowInit.Add(leaseDuration)

	var execRecord *AssessmentExecution
	existingExec, _ := c.store.GetExecution(execID)
	if existingExec != nil {
		execRecord = existingExec
		execRecord.WorkerID = workerID
		execRecord.HeartbeatAt = &nowInit
		execRecord.LeaseExpiresAt = &leaseExpInit
		execRecord.Status = StatusRunning
		execRecord.UpdatedAt = nowInit
		if execRecord.Provenance == nil {
			execRecord.Provenance = prov
			execRecord.ConfigSnapshot.Provenance = prov
		}
		if err := c.store.UpdateExecution(execRecord); err != nil {
			return nil, fmt.Errorf("failed to resume execution record: %w", err)
		}
	} else {
		execRecord = &AssessmentExecution{
			ID:               execID,
			AssessmentID:     assessmentID,
			ScheduleID:       opts.ScheduleID,
			ScheduledFor:     opts.ScheduledFor,
			ClientID:         asm.ClientID,
			TenantID:         tenantID,
			AccountID:        accountID,
			InitiationSource: initSource,
			AssessmentType:   asm.AssessmentType,
			Status:           StatusRunning,
			StartedAt:        nowInit,
			CreatedAt:        nowInit,
			TargetCount:      len(runnableTargets),
			ConfigSnapshot:   configSnapshot,
			WorkerID:         workerID,
			HeartbeatAt:      &nowInit,
			LeaseExpiresAt:   &leaseExpInit,
			IdempotencyKey:   opts.IdempotencyKey,
			Provenance:       prov,
		}
		if err := c.store.CreateExecution(execRecord); err != nil {
			if errors.Is(err, ErrIdempotencyConflict) && opts.IdempotencyKey != "" {
				if existing, getErr := c.store.GetExecutionByIdempotencyKey(tenantID, assessmentID, opts.IdempotencyKey); getErr == nil && existing != nil {
					snap, _ := c.store.GetSnapshot(existing.SnapshotID, NewTenantAuthContext(asm.ClientID, tenantID, accountID))
					return &ExecutionResult{
						Execution: existing,
						Snapshot:  snap,
					}, nil
				}
			}
			return nil, fmt.Errorf("failed to create execution record: %w", err)
		}
	}

	scanCtx, cancelScan := context.WithCancel(ctx)
	defer cancelScan()

	renewalInterval := leaseDuration / 3
	if renewalInterval < 50*time.Millisecond {
		renewalInterval = 50 * time.Millisecond
	}
	renewalStop := make(chan struct{})
	var renewalMu sync.Mutex
	var leaseLostErr error

	activeExecID := execRecord.ID
	go func(renewExecID string) {
		ticker := time.NewTicker(renewalInterval)
		defer ticker.Stop()
		for {
			select {
			case <-renewalStop:
				return
			case <-ticker.C:
				hbErr := c.store.HeartbeatExecution(renewExecID, workerID, nil, leaseDuration)
				if hbErr != nil {
					if errors.Is(hbErr, ErrLeaseLost) || errors.Is(hbErr, ErrExecutionTerminal) {
						renewalMu.Lock()
						leaseLostErr = hbErr
						renewalMu.Unlock()
						cancelScan()
						return
					}
				}
			}
		}
	}(activeExecID)
	defer close(renewalStop)

	// Mark Assessment as RUNNING
	_ = c.store.UpdateAssessmentStatus(assessmentID, StatusRunning)

	opts.ProgressFunc(fmt.Sprintf("[*] Assessment %s execution started (%s) against %d target(s)...", asm.Ref, execID, len(runnableTargets)))

	// 8. Resolve Engine Runner
	runner, err := c.GetEngineRegistry().Get(asm.AssessmentType)
	if err != nil {
		execRecord.Status = StatusFailed
		execRecord.ErrorMessage = fmt.Sprintf("failed to resolve assessment engine: %v", err)
		nowFail := time.Now().UTC()
		execRecord.CompletedAt = &nowFail
		_ = c.store.UpdateExecution(execRecord)
		_ = c.store.UpdateAssessmentStatus(assessmentID, StatusFailed)
		return &ExecutionResult{
			Execution: execRecord,
			Error:     err,
		}, err
	}

	httpClient := c.buildSafeHTTPClient(&cfgStore, opts, scopeVal, timeoutDur, concurrency)

	execCtx := &EngineExecutionContext{
		Store:           c.store,
		Assessment:      asm,
		Execution:       execRecord,
		RunnableTargets: runnableTargets,
		TargetMap:       targetMap,
		ScopeValidator:  scopeVal,
		ConfigSnapshot:  configSnapshot,
		Options:         opts,
		HTTPClient:      httpClient,
		ProgressFunc:    opts.ProgressFunc,
		HeartbeatFunc: func(stage string, completedTargets []string, findingsCount int, lastURL string) error {
			chk := &ScanCheckpoint{
				Stage:            stage,
				CompletedTargets: completedTargets,
				RemainingTargets: remainingTargetsList(runnableTargets, completedTargets, nil),
				FindingsCount:    findingsCount,
				LastTargetURL:    lastURL,
				UpdatedAt:        time.Now().UTC(),
			}
			return c.store.HeartbeatExecution(execRecord.ID, workerID, chk, leaseDuration)
		},
	}

	startTime := time.Now()
	output, runErr := runner.Execute(scanCtx, execCtx)
	if output == nil {
		output = &EngineExecutionOutput{}
	}

	allReportFindings := output.ReportFindings
	allAssessmentFindings := output.AssessmentFindings
	allInventoryAssets := output.InventoryAssets
	allInventoryRelations := output.InventoryRelations
	allAuthSurfaces := output.AuthSurfaces
	allAuthCookies := output.AuthCookies
	allAuthTokens := output.AuthTokens
	allProtectedEndpoints := output.AuthProtectedEndpoints
	assessedTargets := output.AssessedTargets
	failedTargets := output.FailedTargets
	targetErrors := output.TargetErrors
	if targetErrors == nil {
		targetErrors = make(map[string]string)
	}
	totalDiscovered := output.RequestCount
	totalEndpointsAudited := 0
	var scanErr error
	if runErr != nil {
		scanErr = runErr
	} else if output.Error != nil {
		scanErr = output.Error
	}





	// Link all findings to the Common Asset Model
	if len(allInventoryAssets) > 0 {
		combinedInv := &discovery.Inventory{
			Assets:    allInventoryAssets,
			Relations: allInventoryRelations,
		}
		for i := range allReportFindings {
			allReportFindings[i].ResolveAssetIDs(combinedInv)
		}
		for i := range allAssessmentFindings {
			for _, rf := range allReportFindings {
				if allAssessmentFindings[i].OriginalFindingID == rf.ID {
					allAssessmentFindings[i].PrimaryAssetID = rf.PrimaryAssetID
					allAssessmentFindings[i].AffectedAssetIDs = rf.AffectedAssetIDs
					allAssessmentFindings[i].RuleID = rf.RuleID
					allAssessmentFindings[i].Status = rf.Status
					if allAssessmentFindings[i].Provenance != nil {
						allAssessmentFindings[i].Provenance.AssetID = rf.PrimaryAssetID
						allAssessmentFindings[i].EvidenceDetails.Provenance = allAssessmentFindings[i].Provenance
					}
					break
				}
			}
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

	seenTargetURLs := make(map[string]struct{})
	for _, t := range assessedTargets {
		seenTargetURLs[t] = struct{}{}
	}
	for _, t := range failedTargets {
		seenTargetURLs[t] = struct{}{}
	}
	for _, rt := range runnableTargets {
		if _, ok := seenTargetURLs[rt]; !ok {
			failedTargets = append(failedTargets, rt)
		}
	}

	renewalMu.Lock()
	if leaseLostErr != nil {
		scanErr = leaseLostErr
	}
	renewalMu.Unlock()

	// Preserve partial results on error or cancellation
	if scanErr != nil || ctx.Err() != nil {
		if scanErr == nil {
			scanErr = ctx.Err()
		}
		return c.finalizeInterruptedOrFailed(ctx, asm, execRecord, scanErr, runnableTargets, allAssessmentFindings, assessedTargets, failedTargets, prov, duration)
	}

	// 9. Verification Engine 2.0 (Stage 11)
	if ctx.Err() != nil {
		return c.finalizeInterruptedOrFailed(ctx, asm, execRecord, ctx.Err(), runnableTargets, allAssessmentFindings, assessedTargets, failedTargets, prov, time.Since(startTime))
	}
	var verSummary *verification.VerificationSummary
	if len(allReportFindings) > 0 {
		opts.ProgressFunc("[*] Executing Verification Engine 2.0 on candidate findings...")
		safetyChecker := verification.NewSafetyChecker(verification.SafetyOptions{
			IsAuthorized:       true,
			AllowStateChanging: false, // Default safe: non-destructive
			InScopeFunc: func(rawURL string) bool {
				if scopeVal == nil {
					return true
				}
				return scopeVal.IsAllowed(rawURL)
			},
			IsExcludedFunc: func(rawURL string) bool {
				if scopeVal == nil {
					return false
				}
				excluded, _ := scopeVal.IsExcluded(rawURL)
				return excluded
			},
			MaxRequestsPerTarget: 20,
		})
		verEngine := verification.NewEngine(safetyChecker)
		verResults, summary := verEngine.VerifyFindings(ctx, allReportFindings)
		verSummary = &summary

		// Apply verification results back to report findings
		allReportFindings = verification.ApplyVerificationToFindings(allReportFindings, verResults)

		// Update allAssessmentFindings to reflect verified status, confidence, and verification record
		findingMap := make(map[string]report.Finding, len(allReportFindings))
		for _, rf := range allReportFindings {
			findingMap[rf.ID] = rf
		}
		for i := range allAssessmentFindings {
			if rf, ok := findingMap[allAssessmentFindings[i].OriginalFindingID]; ok {
				cleanRF := report.SanitizeFinding(rf)
				allAssessmentFindings[i].VerificationStatus = cleanRF.Verification.Status
				allAssessmentFindings[i].Confidence = cleanRF.Confidence
				allAssessmentFindings[i].Score = cleanRF.Score
				allAssessmentFindings[i].VerificationRecord = cleanRF.Verification
				allAssessmentFindings[i].Status = cleanRF.Status
				allAssessmentFindings[i].AnalysisMethod = cleanRF.AnalysisMethod
			}
		}

		// Save verification run & individual results to store
		runRec := &verification.VerificationRunRecord{
			ID:                "ver-run-" + uuid.New().String(),
			AssessmentID:      assessmentID,
			ExecutionID:       execID,
			TotalFindings:     summary.TotalFindings,
			AttemptedCount:    summary.AttemptedCount,
			VerifiedCount:     summary.VerifiedCount,
			DetectedCount:     summary.DetectedCount,
			ObservedCount:     summary.ObservedCount,
			NotVerifiedCount:  summary.NotVerifiedCount,
			NotExposedCount:   summary.NotExposedCount,
			BlockedCount:      summary.BlockedCount,
			InconclusiveCount: summary.InconclusiveCount,
			SyntheticCount:    summary.SyntheticCount,
			VerifierVersion:   verEngine.Version(),
			CreatedAt:         time.Now().UTC(),
		}
		if sJSON, err := json.Marshal(summary); err == nil {
			runRec.CoverageJSON = string(sJSON)
		}
		if err := c.store.SaveVerificationRun(runRec); err != nil {
			opts.ProgressFunc(fmt.Sprintf("[-] Warning: Failed to persist verification run: %v", err))
		}
		if err := c.store.SaveVerificationResults(assessmentID, execID, verResults); err != nil {
			opts.ProgressFunc(fmt.Sprintf("[-] Warning: Failed to persist verification results: %v", err))
		}

		opts.ProgressFunc(fmt.Sprintf("[✓] Verification Engine complete: %d verified, %d detected, %d not verified, %d not exposed (attempted rate: %.1f%%)",
			summary.VerifiedCount, summary.DetectedCount, summary.NotVerifiedCount, summary.NotExposedCount, summary.VerificationRateAttempted))
	}

	// 9.5 Finding Deduplication (Phase 6.4)
	// Execute deduplication after Verification Engine 2.0 so that:
	//   1. All candidate findings across all targets/detectors receive full verification attempts with native payloads.
	//   2. Verification results and evidence inform authoritative ranking (VERIFIED > DETECTED > NOT_VERIFIED).
	//   3. Safe curl commands, reproduction steps, and HTTP metadata are consolidated without loss.
	//   4. Multi-target associations are preserved across the consolidated duplicate groups.
	if len(allReportFindings) > 1 {
		combinedInv := &discovery.Inventory{
			Assets:    allInventoryAssets,
			Relations: allInventoryRelations,
		}
		dedupRes := correlation.DeduplicateFindingsWithInventory(allReportFindings, combinedInv)
		if dedupRes.DeduplicatedCount < dedupRes.TotalInputCount {
			opts.ProgressFunc(fmt.Sprintf("[✓] Finding Deduplication complete: %d duplicate(s) consolidated into %d canonical finding(s)",
				dedupRes.TotalInputCount-dedupRes.DeduplicatedCount, dedupRes.DeduplicatedCount))
			allReportFindings = dedupRes.CanonicalFindings

			// Rebuild allAssessmentFindings with multi-target preservation and full provenance
			canonicalAssessmentFindings := make([]AssessmentFinding, len(allReportFindings))
			for i, rf := range allReportFindings {
				var matchedAFs []AssessmentFinding
				primaryTargetID := ""

				for _, af := range allAssessmentFindings {
					isMatch := af.OriginalFindingID == rf.ID
					if !isMatch && rf.EvidenceDetails.Details != nil {
						dupIDs := rf.EvidenceDetails.Details["duplicate_finding_ids"]
						if dupIDs != "" {
							for _, id := range strings.Split(dupIDs, ",") {
								id = strings.TrimSpace(id)
								if id != "" && (af.OriginalFindingID == id || af.ID == id) {
									isMatch = true
									break
								}
							}
						}
					}
					if isMatch {
						matchedAFs = append(matchedAFs, af)
						if af.OriginalFindingID == rf.ID && primaryTargetID == "" {
							primaryTargetID = af.TargetID
						}
					}
				}

				if primaryTargetID == "" && len(matchedAFs) > 0 {
					primaryTargetID = matchedAFs[0].TargetID
				}
				if primaryTargetID == "" && len(targets) > 0 {
					primaryTargetID = targets[0].ID
				}

				// Collect and preserve all distinct associated target IDs and URLs
				targetIDSet := make(map[string]struct{})
				if primaryTargetID != "" {
					targetIDSet[primaryTargetID] = struct{}{}
				}
				targetURLSet := make(map[string]struct{})
				if rf.Target != "" {
					targetURLSet[rf.Target] = struct{}{}
				}
				for _, af := range matchedAFs {
					if af.TargetID != "" {
						targetIDSet[af.TargetID] = struct{}{}
					}
					if af.TargetURL != "" {
						targetURLSet[af.TargetURL] = struct{}{}
					}
				}
				if rf.EvidenceDetails.Details != nil {
					if existingTargets := rf.EvidenceDetails.Details["associated_targets"]; existingTargets != "" {
						for _, u := range strings.Split(existingTargets, ",") {
							if u = strings.TrimSpace(u); u != "" {
								targetURLSet[u] = struct{}{}
							}
						}
					}
				}
				var allTargetIDs []string
				for tid := range targetIDSet {
					allTargetIDs = append(allTargetIDs, tid)
				}
				sort.Strings(allTargetIDs)

				var allTargetURLs []string
				for u := range targetURLSet {
					allTargetURLs = append(allTargetURLs, u)
				}
				sort.Strings(allTargetURLs)

				if rf.EvidenceDetails.Details == nil {
					rf.EvidenceDetails.Details = make(map[string]string)
				}
				rf.EvidenceDetails.Details["associated_target_ids"] = strings.Join(allTargetIDs, ",")
				rf.EvidenceDetails.Details["target_id_count"] = strconv.Itoa(len(allTargetIDs))
				if len(allTargetURLs) > 1 {
					rf.EvidenceDetails.Details["associated_targets"] = strings.Join(allTargetURLs, ", ")
				}

				canonicalAF := toAssessmentFinding(assessmentID, execID, primaryTargetID, rf)
				canonicalAF.VerificationStatus = rf.Verification.Status
				canonicalAF.Confidence = rf.Confidence
				canonicalAF.Score = rf.Score
				canonicalAF.VerificationRecord = rf.Verification
				canonicalAF.Status = rf.Status
				canonicalAF.AnalysisMethod = rf.AnalysisMethod
				canonicalAF.LifecycleStatus = rf.LifecycleStatus

				canonicalAssessmentFindings[i] = canonicalAF
			}
			allAssessmentFindings = canonicalAssessmentFindings
			execRecord.FindingCount = len(allAssessmentFindings)
		}
	}

	// 10. Persist Findings & Traceability
	if len(allAssessmentFindings) > 0 {
		if err := c.store.SaveFindings(allAssessmentFindings); err != nil {
			opts.ProgressFunc(fmt.Sprintf("[-] Warning: Failed to persist findings to database: %v", err))
		}
	}

	// 11. Correlate Findings into Evidence-Backed Attack Paths (Stage 10)
	if ctx.Err() != nil {
		return c.finalizeInterruptedOrFailed(ctx, asm, execRecord, ctx.Err(), runnableTargets, allAssessmentFindings, assessedTargets, failedTargets, prov, time.Since(startTime))
	}
	var corrAttackPaths []report.AttackPathSummary
	var corrStories []report.SecurityStory
	var corrBottleneckSummary *report.BottleneckSummary
	if len(allReportFindings) > 0 {
		corrCfg := correlation.DefaultConfig()
		corrEng := correlation.NewEngine(corrCfg)
		corrSummary, paths, _, corrErr := corrEng.Correlate(ctx, allReportFindings)
		if corrErr == nil && len(paths) > 0 {
			if corrSummary.BottleneckAnalysis != nil {
				corrBottleneckSummary = ConvertBottleneckAnalysisToReport(corrSummary.BottleneckAnalysis)
			}
			covJSON, _ := json.Marshal(corrSummary)
			runRec := &correlation.RunRecord{
				ID:                     uuid.New().String(),
				AssessmentID:           assessmentID,
				ExecutionID:            execID,
				TotalFindings:          corrSummary.TotalFindings,
				CandidateRelationships: corrSummary.CandidateRelationships,
				CandidatePaths:         corrSummary.CandidatePaths,
				VerifiedPaths:          corrSummary.VerifiedPaths,
				HighestRisk:            corrSummary.HighestRiskLevel,
				CoverageJSON:           string(covJSON),
				SyntheticFixture:       corrSummary.SyntheticFixture,
				CreatedAt:              time.Now().UTC(),
			}
			_ = c.store.SaveCorrelationRun(runRec)
			_ = c.store.SaveAttackPaths(assessmentID, execID, paths)

			for _, p := range paths {
				corrStories = append(corrStories, p.SecurityStory)
				corrAttackPaths = append(corrAttackPaths, ConvertAttackPathToSummary(p))
			}
			opts.ProgressFunc(fmt.Sprintf("[+] Correlation complete: %d attack path(s) mapped (highest risk: %s %d/100)",
				len(paths), corrSummary.HighestRiskLevel, corrSummary.HighestRiskScore))
		}
	}

	// 12. Finalize Status
	finalStatus := StatusCompleted
	if len(failedTargets) > 0 {
		if len(assessedTargets) == 0 {
			finalStatus = StatusFailed
			execRecord.ErrorMessage = "All targets failed during crawl"
		} else {
			finalStatus = StatusCompletedWithErrors
			execRecord.ErrorMessage = fmt.Sprintf("%d of %d target(s) encountered crawl failures", len(failedTargets), len(runnableTargets))
		}
	}
	execRecord.Status = finalStatus
	execRecord.FindingCount = len(allAssessmentFindings)

	// 13. Generate Unified Report
	rep := report.BuildMultiTargetReport(runnableTargets, allReportFindings)
	rep.CompletionStatus = string(finalStatus)
	if finalStatus == StatusFailed {
		rep.RiskScore = 0
		rep.RiskLevel = "UNAVAILABLE"
		rep.RiskScoreAvailable = false
		rep.Summary.ScoreAvailable = false
	}
	if verSummary != nil {
		if vMap, err := json.Marshal(verSummary); err == nil {
			var m map[string]any
			if err := json.Unmarshal(vMap, &m); err == nil {
				rep.VerificationSummary = m
			}
		}
	}
	if len(corrStories) > 0 {
		report.AttachSecurityStories(&rep, corrStories)
	}
	if len(corrAttackPaths) > 0 {
		if corrBottleneckSummary != nil {
			rep.RemediationBottlenecks = corrBottleneckSummary
		}
		report.AttachAttackPaths(&rep, corrAttackPaths)
	}
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

	// Reconcile and validate report integrity before export
	if ctx.Err() != nil {
		return c.finalizeInterruptedOrFailed(ctx, asm, execRecord, ctx.Err(), runnableTargets, allAssessmentFindings, assessedTargets, failedTargets, prov, time.Since(startTime))
	}
	if valErr := report.ValidateReportIntegrity(rep); valErr != nil {
		opts.ProgressFunc(fmt.Sprintf("[-] Critical: Generated report failed integrity validation: %v", valErr))
		execRecord.Status = StatusFailed
		execRecord.ErrorMessage = fmt.Sprintf("report integrity validation failed: %v", valErr)
		nowFail := time.Now().UTC()
		execRecord.CompletedAt = &nowFail
		_ = c.store.UpdateExecution(execRecord)
		_ = c.store.UpdateAssessmentStatus(assessmentID, StatusFailed)
		return &ExecutionResult{
			Execution: execRecord,
			Error:     valErr,
		}, valErr
	}

	// 14. Report File Export
	if ctx.Err() != nil {
		return c.finalizeInterruptedOrFailed(ctx, asm, execRecord, ctx.Err(), runnableTargets, allAssessmentFindings, assessedTargets, failedTargets, prov, time.Since(startTime))
	}
	var htmlPath, jsonPath, sarifPath string
	managedReportsDir, _ := getReportsDir(asm.Ref)

	// HTML Export
	var reportWriteErr error
	if opts.ExportHTMLPath != "" {
		if err := report.WriteHTML(rep, opts.ExportHTMLPath); err != nil {
			opts.ProgressFunc(fmt.Sprintf("[-] Failed to export HTML report to %s: %v", opts.ExportHTMLPath, err))
			reportWriteErr = fmt.Errorf("failed to export HTML report to %s: %w", opts.ExportHTMLPath, err)
		} else {
			htmlPath = opts.ExportHTMLPath
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
	} else if managedReportsDir != "" {
		mPath := filepath.Join(managedReportsDir, fmt.Sprintf("%s_%s.html", asm.Ref, execID))
		if err := report.WriteHTML(rep, mPath); err == nil {
			htmlPath = mPath
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
		if err := report.WriteJSON(rep, opts.ExportJSONPath); err != nil {
			opts.ProgressFunc(fmt.Sprintf("[-] Failed to export JSON report to %s: %v", opts.ExportJSONPath, err))
			if reportWriteErr == nil {
				reportWriteErr = fmt.Errorf("failed to export JSON report to %s: %w", opts.ExportJSONPath, err)
			}
		} else {
			jsonPath = opts.ExportJSONPath
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
	} else if managedReportsDir != "" {
		mPath := filepath.Join(managedReportsDir, fmt.Sprintf("%s_%s.json", asm.Ref, execID))
		if err := report.WriteJSON(rep, mPath); err == nil {
			jsonPath = mPath
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

	// SARIF Export
	if opts.ExportSARIFPath != "" {
		if err := report.WriteSARIF(rep, opts.ExportSARIFPath); err != nil {
			opts.ProgressFunc(fmt.Sprintf("[-] Failed to export SARIF report to %s: %v", opts.ExportSARIFPath, err))
			if reportWriteErr == nil {
				reportWriteErr = fmt.Errorf("failed to export SARIF report to %s: %w", opts.ExportSARIFPath, err)
			}
		} else {
			sarifPath = opts.ExportSARIFPath
			_ = c.store.SaveReport(&ReportRecord{
				ID:           "rep-" + uuid.New().String(),
				AssessmentID: assessmentID,
				ExecutionID:  execID,
				Format:       "SARIF",
				FilePath:     sarifPath,
				FelixVersion: felixVer,
				Status:       "GENERATED",
			})
		}
	} else if managedReportsDir != "" {
		mPath := filepath.Join(managedReportsDir, fmt.Sprintf("%s_%s.sarif", asm.Ref, execID))
		if err := report.WriteSARIF(rep, mPath); err == nil {
			sarifPath = mPath
			_ = c.store.SaveReport(&ReportRecord{
				ID:           "rep-" + uuid.New().String(),
				AssessmentID: assessmentID,
				ExecutionID:  execID,
				Format:       "SARIF",
				FilePath:     sarifPath,
				FelixVersion: felixVer,
				Status:       "GENERATED",
			})
		}
	}

	// 13. Create Durable Historical Assessment Snapshot (Phase 6.5 & 6.7)
	if ctx.Err() != nil {
		return c.finalizeInterruptedOrFailed(ctx, asm, execRecord, ctx.Err(), runnableTargets, allAssessmentFindings, assessedTargets, failedTargets, prov, time.Since(startTime))
	}
	isComplete := finalStatus != StatusFailed
	snapRec := BuildAssessmentSnapshot(asm, execRecord, runnableTargets, allAssessmentFindings, isComplete)
	snapRec.SetAssessedTargets(assessedTargets)
	if len(failedTargets) > 0 {
		snapRec.SetFailedTargets(failedTargets)
	}
	snapRec.SetCoveredCategories(runner.Capabilities().CoverageCategories)
	if finalStatus == StatusCompletedWithErrors {
		snapRec.Status = StatusCompletedWithErrors
	}
	if htmlPath != "" {
		snapRec.Metadata["html_report"] = htmlPath
	}
	if jsonPath != "" {
		snapRec.Metadata["json_report"] = jsonPath
	}
	renewalMu.Lock()
	if leaseLostErr != nil {
		scanErr = leaseLostErr
	}
	renewalMu.Unlock()
	if errors.Is(scanErr, ErrLeaseLost) {
		return &ExecutionResult{
			Execution: execRecord,
			Error:     scanErr,
		}, scanErr
	}

	// Phase 7.4: Verify lease ownership before final status update
	if hbErr := c.store.HeartbeatExecution(execRecord.ID, workerID, nil, leaseDuration); hbErr != nil {
		if errors.Is(hbErr, ErrLeaseLost) {
			opts.ProgressFunc(fmt.Sprintf("[-] Lease lost before finalization on execution %s; aborting update", execRecord.ID))
			return &ExecutionResult{
				Execution: execRecord,
				Error:     ErrLeaseLost,
			}, ErrLeaseLost
		}
	}

	// Finalize assessment provenance prior to persistence
	var artProv []provenance.ArtifactProvenance
	if htmlPath != "" {
		artProv = append(artProv, provenance.ArtifactProvenance{Format: "HTML", Path: htmlPath, Generated: true})
	} else if opts.ExportHTMLPath != "" {
		artProv = append(artProv, provenance.ArtifactProvenance{Format: "HTML", Path: opts.ExportHTMLPath, Generated: false, Error: "failed to export HTML report"})
	}
	if jsonPath != "" {
		artProv = append(artProv, provenance.ArtifactProvenance{Format: "JSON", Path: jsonPath, Generated: true})
	} else if opts.ExportJSONPath != "" {
		artProv = append(artProv, provenance.ArtifactProvenance{Format: "JSON", Path: opts.ExportJSONPath, Generated: false, Error: "failed to export JSON report"})
	}
	if sarifPath != "" {
		artProv = append(artProv, provenance.ArtifactProvenance{Format: "SARIF", Path: sarifPath, Generated: true})
	} else if opts.ExportSARIFPath != "" {
		artProv = append(artProv, provenance.ArtifactProvenance{Format: "SARIF", Path: opts.ExportSARIFPath, Generated: false, Error: "failed to export SARIF report"})
	}

	failCat := "SUCCESS"
	exitCode := clierror.ExitSuccess
	if finalStatus != StatusCompleted {
		failCat = "INCOMPLETE"
		exitCode = clierror.ExitOperational
	}

	if prov != nil {
		prov.Finalize(provenance.FinalizeOptions{
			Status:            string(finalStatus),
			FailureCategory:   failCat,
			ExitCode:          exitCode,
			DurationMs:        duration.Milliseconds(),
			CoveredCategories: runner.Capabilities().CoverageCategories,
			Artifacts:         artProv,
			IsPartial:         finalStatus == StatusCompletedWithErrors,
		})
		execRecord.Provenance = prov
		execRecord.ConfigSnapshot.Provenance = prov
	}
	if snapRec != nil && prov != nil {
		if b, err := json.Marshal(prov); err == nil {
			snapRec.Metadata["provenance"] = string(b)
		}
	}
	if rep.Metadata == nil {
		rep.Metadata = make(map[string]any)
	}
	rep.Metadata["provenance"] = prov

	histEvidence := ExtractHistoricalEvidence(snapRec.ID, allAssessmentFindings)
	var snapErr error
	if err := c.store.CreateSnapshot(snapRec, allAssessmentFindings, histEvidence); err != nil {
		opts.ProgressFunc(fmt.Sprintf("[-] Warning: Failed to persist historical snapshot: %v", err))
		snapRec = nil
		snapErr = fmt.Errorf("failed to persist historical snapshot: %w", err)
		finalStatus = StatusFailed
		execRecord.Status = StatusFailed
		execRecord.ErrorMessage = snapErr.Error()
	} else {
		execRecord.SnapshotID = snapRec.ID
		opts.ProgressFunc(fmt.Sprintf("[✓] Historical assessment snapshot recorded: %s (%s)", snapRec.SnapshotRef, snapRec.ID))
	}

	if err := c.store.UpdateExecution(execRecord); err != nil {
		opts.ProgressFunc(fmt.Sprintf("[-] Failed to update execution record: %v", err))
		return &ExecutionResult{
			Execution: execRecord,
			Snapshot:  snapRec,
			Error:     err,
		}, err
	}
	_ = c.store.UpdateAssessmentStatus(assessmentID, finalStatus)
	if snapErr != nil {
		return &ExecutionResult{
			Execution: execRecord,
			Snapshot:  nil,
			Error:     snapErr,
		}, snapErr
	}
	c.emitAssessmentNotifications(ctx, asm, execRecord, duration)

	opts.ProgressFunc(fmt.Sprintf("[✓] Assessment %s completed in %s (%d findings, %d requests).",
		asm.Ref, duration.Round(time.Millisecond), len(allAssessmentFindings), execRecord.RequestCount))

	invSummary, _ := c.store.GetInventorySummary(assessmentID, execID)
	var authSummary *auth.AuthSummary
	if len(allAuthSurfaces) > 0 || len(allAuthCookies) > 0 || len(allAuthTokens) > 0 {
		authEng := auth.NewEngine()
		s := authEng.GenerateSummary(combinedAuthInv)
		authSummary = &s
	}

	// Compute Baseline Change Summary (Phase 8.4)
	var changeSummary *report.ChangeSummary
	if execRecord.Status == StatusCompleted || execRecord.Status == StatusCompletedWithErrors {
		authCtx := TenantAuthContext{
			TenantID:  execRecord.TenantID,
			AccountID: execRecord.AccountID,
			ClientID:  execRecord.ClientID,
			isAdmin:   true,
		}
		cs, csErr := c.store.GetAssessmentChangeSummary(asm.ID, opts.BaselineRef, execRecord.ID, authCtx)
		if csErr == nil && cs != nil {
			changeSummary = cs
			if rep.Metadata == nil {
				rep.Metadata = make(map[string]any)
			}
			rep.Metadata["change_summary"] = cs
			if cs.BaselineExecutionID != "" {
				rep.Metadata["baseline_execution_id"] = cs.BaselineExecutionID
			}
			if cs.BaselineSnapshotID != "" {
				rep.Metadata["baseline_snapshot_id"] = cs.BaselineSnapshotID
			}

			// Annotate findings with their delta classification
			deltaMap := make(map[string]string)
			for _, item := range cs.ImportantChanges {
				if item.FindingID != "" {
					deltaMap[item.FindingID] = item.Classification
				}
				if item.Fingerprint != "" {
					deltaMap[item.Fingerprint] = item.Classification
				}
			}
			for i := range rep.Findings {
				if cls, ok := deltaMap[rep.Findings[i].ID]; ok {
					rep.Findings[i].LifecycleStatus = cls
				} else if cls, ok := deltaMap[rep.Findings[i].Fingerprint]; ok {
					rep.Findings[i].LifecycleStatus = cls
				}
			}
			for i := range allAssessmentFindings {
				if cls, ok := deltaMap[allAssessmentFindings[i].ID]; ok {
					allAssessmentFindings[i].LifecycleStatus = cls
				} else if cls, ok := deltaMap[allAssessmentFindings[i].Fingerprint]; ok {
					allAssessmentFindings[i].LifecycleStatus = cls
				}
			}
		} else if opts.BaselineRef != "" && csErr != nil {
			opts.ProgressFunc(fmt.Sprintf("[-] Baseline comparison failed: %v", csErr))
			if reportWriteErr == nil {
				reportWriteErr = fmt.Errorf("baseline comparison failed: %w", csErr)
			}
		}

		if changeSummary != nil && prov != nil {
			prov.BaselineExecutionID = changeSummary.BaselineExecutionID
			prov.BaselineSnapshotID = changeSummary.BaselineSnapshotID
			_ = c.store.UpdateExecution(execRecord)
		}
	}

	finalErr := snapErr
	if finalErr == nil {
		finalErr = reportWriteErr
	}

	return &ExecutionResult{
		Execution:           execRecord,
		Snapshot:            snapRec,
		Report:              &rep,
		InventorySummary:    invSummary,
		AuthSummary:         authSummary,
		VerificationSummary: verSummary,
		ChangeSummary:       changeSummary,
		HTMLPath:            htmlPath,
		JSONPath:            jsonPath,
		SARIFPath:           sarifPath,
		Provenance:          prov,
		Error:               finalErr,
	}, finalErr
}

// ToAssessmentFinding maps a report.Finding to an AssessmentFinding with full relationship IDs.
func ToAssessmentFinding(assessmentID, executionID, targetID string, f report.Finding) AssessmentFinding {
	sanitized := report.SanitizeFinding(f)
	correlation.EnsureFindingFingerprint(&sanitized, correlation.TrustPolicyRecomputeIfLegacy)
	fndKey := sanitized.ID
	if fndKey == "" {
		fndKey = report.ComputeStableFindingID(sanitized.Target, sanitized.RuleID, sanitized.Category, sanitized.Endpoint, sanitized.Method, sanitized.Fingerprint)
	}
	idScope := fndKey
	if executionID != "" {
		idScope = executionID + ":" + fndKey
	}
	stableID := ComputeAssessmentFindingID(assessmentID, idScope)

	status := sanitized.Status
	if status == "" {
		status = report.FindingStatusFromVerification(sanitized.Verification.Status)
	}
	status = report.NormalizeFindingStatus(status)

	analysisMethod := sanitized.AnalysisMethod
	if analysisMethod == "" {
		analysisMethod = report.DefaultAnalysisMethod(sanitized.Source, sanitized.EvidenceDetails.DetectionMethod)
	}

	prov := sanitized.Provenance
	if prov == nil && sanitized.EvidenceDetails.Provenance != nil {
		prov = sanitized.EvidenceDetails.Provenance
	}
	if prov != nil {
		pCopy := *prov
		if pCopy.AssessmentID == "" {
			pCopy.AssessmentID = assessmentID
		}
		if pCopy.ExecutionID == "" {
			pCopy.ExecutionID = executionID
		}
		if pCopy.TargetID == "" {
			pCopy.TargetID = targetID
		}
		if pCopy.FindingID == "" {
			pCopy.FindingID = sanitized.ID
		}
		if pCopy.AssetID == "" && sanitized.PrimaryAssetID != "" {
			pCopy.AssetID = sanitized.PrimaryAssetID
		}
		prov = &pCopy
	}
	sanitized.EvidenceDetails.Provenance = prov

	if sanitized.ScoreExplanation == nil {
		expl := report.ExplainFindingScore(sanitized)
		sanitized.ScoreExplanation = &expl
	}
	if sanitized.Score <= 0 || sanitized.Score > 40 {
		sanitized.Score = sanitized.ScoreExplanation.Score
	}

	return AssessmentFinding{
		ID:                 stableID,
		AssessmentID:       assessmentID,
		ExecutionID:        executionID,
		TargetID:           targetID,
		OriginalFindingID:  sanitized.ID,
		RuleID:             sanitized.RuleID,
		Status:             status,
		AnalysisMethod:     analysisMethod,
		PrimaryAssetID:     sanitized.PrimaryAssetID,
		AffectedAssetIDs:   sanitized.AffectedAssetIDs,
		Title:              sanitized.Title,
		Category:           sanitized.Category,
		Severity:           sanitized.Severity,
		Confidence:         sanitized.Confidence,
		VerificationStatus: sanitized.Verification.Status,
		TargetURL:          sanitized.Target,
		Endpoint:           sanitized.Endpoint,
		Method:             sanitized.Method,
		Fingerprint:        sanitized.Fingerprint,
		Score:              sanitized.Score,
		ScoreExplanation:   sanitized.ScoreExplanation,
		EvidenceDetails:    sanitized.EvidenceDetails,
		VerificationRecord: sanitized.Verification,
		Remediation:        sanitized.Remediation,
		RemediationAdvice:  sanitized.RemediationAdvice,
		Provenance:         prov,
		LifecycleStatus:    sanitized.LifecycleStatus,
		CreatedAt:          time.Now().UTC(),
	}
}

func toAssessmentFinding(assessmentID, executionID, targetID string, f report.Finding) AssessmentFinding {
	return ToAssessmentFinding(assessmentID, executionID, targetID, f)
}

// GetReportsDir returns and ensures existence of the directory for assessment reports.
func GetReportsDir(assessmentRef string) (string, error) {
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

func getReportsDir(assessmentRef string) (string, error) {
	return GetReportsDir(assessmentRef)
}


func remainingTargetsList(all []string, completed []string, failed []string) []string {
	done := make(map[string]bool)
	for _, c := range completed {
		done[c] = true
	}
	for _, f := range failed {
		done[f] = true
	}
	var rem []string
	for _, a := range all {
		if !done[a] {
			rem = append(rem, a)
		}
	}
	return rem
}


// emitAssessmentNotifications generates lifecycle and delta notifications based on configuration.
// It runs independently of the critical scan path and never modifies execution outcomes.
func (c *Controller) emitAssessmentNotifications(
	ctx context.Context,
	asm *Assessment,
	exec *AssessmentExecution,
	duration time.Duration,
) {
	if c.store == nil || asm == nil || exec == nil {
		return
	}

	cfg, err := config.LoadWithEnv("")
	if err != nil || !cfg.Notification.Enabled {
		return
	}

	now := time.Now().UTC()
	var enqueuedAny bool

	// 1. Lifecycle notification
	notifyLifecycle := false
	execStatusLower := strings.ToLower(string(exec.Status))
	for _, evt := range cfg.Notification.NotifyOnLifecycle {
		if strings.ToLower(strings.TrimSpace(evt)) == execStatusLower {
			notifyLifecycle = true
			break
		}
	}

	if notifyLifecycle {
		notif := notify.BuildLifecycleNotification(
			exec.TenantID, exec.AccountID, asm.ID, asm.Ref, exec.ID,
			string(exec.Status), exec.FindingCount, duration, exec.ErrorMessage, now,
		)
		if err := c.store.EnqueueNotification(notif); err == nil {
			enqueuedAny = true
		}
	}

	// 2. Delta & Change Summary notifications (for completed runs)
	if exec.Status == StatusCompleted || exec.Status == StatusCompletedWithErrors {
		// Critical finding alerts
		if findings, fErr := c.store.GetFindings(asm.ID, exec.ID); fErr == nil {
			for _, f := range findings {
				if strings.ToUpper(f.Severity) == notify.SeverityCritical {
					critNotif := notify.BuildCriticalFindingNotification(
						exec.TenantID, exec.AccountID, asm.ID, asm.Ref, exec.ID,
						ToReportFinding(f), now,
					)
					if err := c.store.EnqueueNotification(critNotif); err == nil {
						enqueuedAny = true
					}
				}
			}
		}

		authCtx := TenantAuthContext{
			TenantID:  exec.TenantID,
			AccountID: exec.AccountID,
			ClientID:  exec.ClientID,
			isAdmin:   true,
		}
		summary, summaryErr := c.store.GetAssessmentChangeSummary(asm.ID, "", exec.ID, authCtx)
		if summaryErr == nil && summary != nil {
			// Incomplete coverage safeguard
			if !summary.IsReliable && summary.Counts.Unverified > 0 {
				incompNotif := notify.BuildIncompleteSummaryNotification(
					exec.TenantID, exec.AccountID, asm.ID, asm.Ref, exec.ID,
					summary.BaselineExecutionID, summary.ReliabilityReason, summary.Counts.Unverified, now,
				)
				if notify.MeetsSeverityThreshold(incompNotif.Severity, cfg.Notification.MinSeverity) {
					if err := c.store.EnqueueNotification(incompNotif); err == nil {
						enqueuedAny = true
					}
				}
			}

			// Individual delta change items
			deltaFilter := make(map[string]bool)
			for _, d := range cfg.Notification.NotifyOnDeltas {
				deltaFilter[strings.ToUpper(strings.TrimSpace(d))] = true
			}

			for _, item := range summary.ImportantChanges {
				if deltaFilter[strings.ToUpper(item.Classification)] {
					if notify.MeetsSeverityThreshold(item.Severity, cfg.Notification.MinSeverity) {
						deltaNotif := notify.BuildDeltaNotification(
							exec.TenantID, exec.AccountID, asm.ID, asm.Ref, exec.ID,
							summary.BaselineExecutionID, item.Classification, item, now,
						)
						if err := c.store.EnqueueNotification(deltaNotif); err == nil {
							enqueuedAny = true
						}
					}
				}
			}
		}
	}

	// 3. Asynchronous background delivery
	if enqueuedAny && cfg.Notification.WebhookURL != "" {
		go func() {
			webhookCfg := notify.WebhookConfig{
				URL:               cfg.Notification.WebhookURL,
				Secret:            cfg.Notification.WebhookSecret,
				PreviousSecret:    cfg.Notification.WebhookPreviousSecret,
				RequireSigning:    cfg.Notification.RequireSigning,
				Timeout:           time.Duration(cfg.Notification.TimeoutSeconds) * time.Second,
				AllowInsecureHTTP: cfg.Notification.AllowInsecureHTTP,
				AllowPrivateIPs:   cfg.Notification.AllowPrivateIPs,
				AllowLoopback:     cfg.Notification.AllowLoopback,
			}
			provider, pErr := notify.NewProvider(webhookCfg, cfg.Notification.Provider)
			if pErr != nil {
				return
			}
			dispatcherCfg := notify.DispatcherConfig{
				Concurrency: cfg.Notification.Concurrency,
			}
			dispatcher := notify.NewOutboxDispatcher(c.store, provider, dispatcherCfg)
			dispatchCtx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Notification.TimeoutSeconds*3)*time.Second)
			defer cancel()
			_, _ = dispatcher.DispatchBatch(dispatchCtx, cfg.Notification.Concurrency*2)
		}()
	}
}

func (c *Controller) finalizeInterruptedOrFailed(
	ctx context.Context,
	asm *Assessment,
	execRecord *AssessmentExecution,
	scanErr error,
	runnableTargets []string,
	allAssessmentFindings []AssessmentFinding,
	assessedTargets, failedTargets []string,
	prov *provenance.AssessmentProvenance,
	duration time.Duration,
) (*ExecutionResult, error) {
	// If lease was lost to a recovery worker, do NOT overwrite DB records!
	if errors.Is(scanErr, ErrLeaseLost) {
		return &ExecutionResult{
			Execution: execRecord,
			Error:     scanErr,
		}, scanErr
	}
	if errors.Is(scanErr, context.Canceled) {
		execRecord.Status = StatusCancelled
		execRecord.ErrorMessage = "Execution was cancelled by operator"
	} else if errors.Is(scanErr, context.DeadlineExceeded) {
		execRecord.Status = StatusFailed
		execRecord.ErrorMessage = "Scan timed out: execution deadline exceeded"
	} else {
		execRecord.Status = StatusFailed
		execRecord.ErrorMessage = secrets.RedactText(fmt.Sprintf("Scan failed: %v", scanErr))
	}
	nowComp := time.Now().UTC()
	execRecord.CompletedAt = &nowComp
	execRecord.DurationMs = duration.Milliseconds()

	// Save partial findings if any were generated
	var dedupedPartial []AssessmentFinding
	if len(allAssessmentFindings) > 0 {
		dedupedPartial = DeduplicateAssessmentFindings(allAssessmentFindings)
		execRecord.FindingCount = len(dedupedPartial)
		_ = c.store.SaveFindings(dedupedPartial)
	}

	// Finalize provenance for interrupted/failed run
	var failCat string
	if errors.Is(scanErr, context.Canceled) || errors.Is(scanErr, context.DeadlineExceeded) {
		failCat = string(clierror.CategoryIncomplete)
	} else {
		failCat = string(clierror.CategoryToolFailure)
	}
	if prov != nil {
		prov.Finalize(provenance.FinalizeOptions{
			Status:          string(execRecord.Status),
			FailureCategory: failCat,
			ExitCode:        clierror.ExitOperational,
			DurationMs:      duration.Milliseconds(),
			IsPartial:       true,
			RecoveryReason:  execRecord.ErrorMessage,
		})
		execRecord.Provenance = prov
		execRecord.ConfigSnapshot.Provenance = prov
	}

	// Create durable historical snapshot for failed/cancelled/partial execution (Phase 6.5 & 6.7)
	partialSnap := BuildAssessmentSnapshot(asm, execRecord, runnableTargets, dedupedPartial, false)
	partialSnap.SetAssessedTargets(assessedTargets)
	partialSnap.SetFailedTargets(failedTargets)
	partialSnap.Metadata["is_partial"] = "true"
	partialSnap.Metadata["inconclusive"] = "true"
	partialSnap.Metadata["scan_error"] = execRecord.ErrorMessage
	if prov != nil {
		if b, err := json.Marshal(prov); err == nil {
			partialSnap.Metadata["provenance"] = string(b)
		}
	}
	partialEv := ExtractHistoricalEvidence(partialSnap.ID, dedupedPartial)
	if err := c.store.CreateSnapshot(partialSnap, dedupedPartial, partialEv); err != nil {
		partialSnap = nil
	} else {
		execRecord.SnapshotID = partialSnap.ID
	}
	if err := c.store.UpdateExecution(execRecord); err != nil {
		return &ExecutionResult{
			Execution:  execRecord,
			Snapshot:   partialSnap,
			Provenance: prov,
			Error:      err,
		}, err
	}
	_ = c.store.UpdateAssessmentStatus(asm.ID, execRecord.Status)
	c.emitAssessmentNotifications(ctx, asm, execRecord, duration)

	return &ExecutionResult{
		Execution:  execRecord,
		Snapshot:   partialSnap,
		Provenance: prov,
		Error:      scanErr,
	}, scanErr
}
