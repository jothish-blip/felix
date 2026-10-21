package ci

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"felix/pkg/assessment"
	"felix/pkg/clierror"
	"felix/pkg/config"
	"felix/pkg/policy"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

// Run executes a CI security assessment according to the provided configuration.
// It returns a comprehensive Result object with exit codes adhering to the Phase 8.1–8.4 contract:
// - 0: Operation succeeded, policy passed with 0 violations.
// - 1: Trustworthy assessment completed, security policy threshold violation established.
// - 2: Operational failure, invalid config, scan error, crawl defect, or report write failure.
func Run(ctx context.Context, cfg *Config, store *assessment.SQLiteStore) (*Result, error) {
	if cfg == nil {
		return &Result{ExitCode: clierror.ExitOperational, PolicyStatus: "ERROR"}, fmt.Errorf("configuration is nil")
	}

	// 1. Validate configuration and fail closed if invalid
	if err := ValidateConfig(cfg); err != nil {
		res := &Result{
			ExitCode:     clierror.ExitOperational,
			PolicyStatus: "ERROR",
			Error:        err,
		}
		res.DiagnosticSummary = FormatSummary(res, cfg)
		_ = WriteStepSummary(cfg.SummaryPath, res.DiagnosticSummary)
		_ = WriteStepOutputs(cfg.OutputPath, map[string]string{
			"exit_code":     "2",
			"policy_status": "ERROR",
		})
		if cfg.Provider == ProviderGitHub {
			EmitGitHubAnnotations(res)
		}
		return res, err
	}

	// 2. Resolve database store
	ownsStore := false
	if store == nil {
		dbPath := cfg.DatabasePath
		if dbPath == "" {
			dbPath = filepath.Join(cfg.OutputDir, "felix_ci.db")
		}
		s, err := assessment.NewSQLiteStore(dbPath)
		if err != nil {
			opErr := fmt.Errorf("failed initializing database store at %q: %w", dbPath, err)
			res := &Result{
				ExitCode:     clierror.ExitOperational,
				PolicyStatus: "ERROR",
				Error:        opErr,
			}
			res.DiagnosticSummary = FormatSummary(res, cfg)
			_ = WriteStepSummary(cfg.SummaryPath, res.DiagnosticSummary)
			return res, opErr
		}
		store = s
		ownsStore = true
	}
	if ownsStore {
		defer store.Close()
	}

	// 3. Resolve execution timeout
	timeoutDur := 30 * time.Second
	if strings.TrimSpace(cfg.Timeout) != "" {
		if t, err := time.ParseDuration(strings.TrimSpace(cfg.Timeout)); err == nil && t > 0 {
			timeoutDur = t
		}
	}

	// 4. Resolve output artifact paths
	sarifPath := filepath.Join(cfg.OutputDir, cfg.SARIFFile)
	jsonPath := filepath.Join(cfg.OutputDir, cfg.JSONFile)
	htmlPath := filepath.Join(cfg.OutputDir, cfg.HTMLFile)

	// 5. Load Threshold Policy if configured
	var pol *policy.ThresholdPolicy
	if cfg.PolicyPath != "" {
		p, err := policy.LoadPolicy(cfg.PolicyPath)
		if err != nil {
			opErr := fmt.Errorf("failed loading threshold policy: %w", err)
			res := &Result{
				ExitCode:     clierror.ExitOperational,
				PolicyStatus: "ERROR",
				Error:        opErr,
			}
			res.DiagnosticSummary = FormatSummary(res, cfg)
			_ = WriteStepSummary(cfg.SummaryPath, res.DiagnosticSummary)
			return res, opErr
		}
		pol = p
	}

	// 6. Setup Assessment ID and Target
	var assessmentID string
	if cfg.AssessmentRef != "" {
		asm, err := store.GetAssessment(cfg.AssessmentRef)
		if err != nil {
			opErr := fmt.Errorf("assessment project %q not found: %w", cfg.AssessmentRef, err)
			res := &Result{
				ExitCode:     clierror.ExitOperational,
				PolicyStatus: "ERROR",
				Error:        opErr,
			}
			res.DiagnosticSummary = FormatSummary(res, cfg)
			_ = WriteStepSummary(cfg.SummaryPath, res.DiagnosticSummary)
			return res, opErr
		}
		assessmentID = asm.ID
	} else {
		// Ad-hoc CI assessment project for the direct target URL
		client := &assessment.Client{
			ID:   "client-ci-" + uuid.New().String()[:8],
			Name: "CI Automated Pipeline",
		}
		_ = store.CreateClient(client)

		asm := &assessment.Assessment{
			ID:             "asm-ci-" + uuid.New().String()[:8],
			Ref:            "CI-" + strings.ToUpper(uuid.New().String()[:8]),
			ClientID:       client.ID,
			Name:           "CI Scan: " + cfg.TargetURL,
			AssessmentType: "web",
			Status:         assessment.StatusReady,
			ScopeMode:      "same-origin",
		}
		if err := store.CreateAssessment(asm); err != nil {
			opErr := fmt.Errorf("failed creating CI assessment project: %w", err)
			res := &Result{ExitCode: clierror.ExitOperational, PolicyStatus: "ERROR", Error: opErr}
			return res, opErr
		}

		target := &assessment.AssessmentTarget{
			ID:           "tgt-ci-" + uuid.New().String()[:8],
			AssessmentID: asm.ID,
			TargetURL:    cfg.TargetURL,
			ScopeStatus:  "APPROVED",
		}
		if err := store.AddTarget(target); err != nil {
			opErr := fmt.Errorf("failed registering target %q: %w", cfg.TargetURL, err)
			res := &Result{ExitCode: clierror.ExitOperational, PolicyStatus: "ERROR", Error: opErr}
			return res, opErr
		}

		now := time.Now().UTC()
		validFrom := now.Add(-1 * time.Hour)
		validUntil := now.Add(24 * time.Hour)
		_ = store.SetAuthorization(&assessment.AuthorizationRecord{
			ID:                  "auth-ci-" + uuid.New().String()[:8],
			AssessmentID:        asm.ID,
			AuthorizingParty:    "CI Security Automation Pipeline",
			AuthorizationMethod: "PIPELINE_AUTHORIZATION",
			Status:              assessment.AuthApproved,
			DateReceived:        now,
			ValidFrom:           &validFrom,
			ValidUntil:          &validUntil,
		})

		assessmentID = asm.ID
	}

	// 7. Configure Execution Options
	cfgStore, _ := config.LoadWithEnv("")
	allowLoopback := cfg.AllowLoopback || cfgStore.AllowLoopback || strings.EqualFold(os.Getenv("FELIX_ALLOW_LOOPBACK"), "true")
	allowPrivate := cfg.AllowPrivateIPs || cfgStore.AllowPrivateIPs || strings.EqualFold(os.Getenv("FELIX_ALLOW_PRIVATE_IPS"), "true")
	opts := assessment.ExecutionOptions{
		TimeoutDuration:    timeoutDur,
		Concurrency:        5,
		MaxAssets:          200,
		MaxSizeBytes:       5 * 1024 * 1024,
		ExportHTMLPath:     htmlPath,
		ExportJSONPath:     jsonPath,
		ExportSARIFPath:    sarifPath,
		BaselineRef:        cfg.BaselineRef,
		BaselineScope:      cfg.BaselineScope,
		AllowLoopback:      allowLoopback,
		AllowPrivateIPs:    allowPrivate,
		ActiveVerification: true,
		Verbose:            cfg.Verbose,
		ProgressFunc: func(msg string) {
			if !cfg.Quiet {
				fmt.Println(msg)
			}
		},
	}

	// 8. Execute Assessment
	controller := assessment.NewController(store)
	execRes, execErr := controller.RunAssessment(ctx, assessmentID, opts)

	result := &Result{
		SARIFPath: sarifPath,
		JSONPath:  jsonPath,
		HTMLPath:  htmlPath,
	}
	if execRes != nil && execRes.Provenance != nil {
		result.Provenance = execRes.Provenance
	}

	if execErr != nil {
		result.ExitCode = clierror.CodeFor(execErr)
		result.PolicyStatus = "ERROR"
		result.Error = execErr
		result.DiagnosticSummary = FormatSummary(result, cfg)
		_ = WriteStepSummary(cfg.SummaryPath, result.DiagnosticSummary)
		if cfg.Provider == ProviderGitHub {
			EmitGitHubAnnotations(result)
		}
		if (cfg.PRComment || cfg.PRInline) && !errors.Is(execErr, context.Canceled) && ctx.Err() == nil {
			_ = PublishPRFeedback(ctx, cfg, result)
		}
		outMap := map[string]string{
			"exit_code":          fmt.Sprintf("%d", result.ExitCode),
			"policy_status":      "ERROR",
			"sarif_path":         result.SARIFPath,
			"json_path":          result.JSONPath,
			"html_path":          result.HTMLPath,
			"feedback_published": fmt.Sprintf("%t", result.FeedbackPublished),
		}
		if result.Provenance != nil && result.Provenance.ConfigDigest != "" {
			outMap["provenance_config_digest"] = result.Provenance.ConfigDigest
		}
		_ = WriteStepOutputs(cfg.OutputPath, outMap)
		return result, execErr
	}

	// 9. Classify Outcome with Policy
	decision, exitCode := execRes.ClassifyOutcomeWithPolicyAndArtifacts(pol, htmlPath != "", jsonPath != "", sarifPath != "")
	result.ExitCode = exitCode
	result.Classification = execRes.Classification
	result.PolicyDecision = decision
	result.BaselineDeltas = execRes.ChangeSummary
	if execRes.Provenance != nil {
		result.Provenance = execRes.Provenance
	}

	if execRes.Report != nil {
		result.Findings = execRes.Report.Findings
		result.TotalFindings = len(execRes.Report.Findings)
		result.SeverityCounts = map[string]int{
			report.SeverityCritical: execRes.Report.Summary.CriticalCount,
			report.SeverityHigh:     execRes.Report.Summary.HighCount,
			report.SeverityMedium:   execRes.Report.Summary.MediumCount,
			report.SeverityLow:      execRes.Report.Summary.LowCount,
			report.SeverityInfo:     execRes.Report.Summary.InfoCount,
		}
	}

	switch exitCode {
	case clierror.ExitSuccess:
		if pol != nil {
			result.PolicyStatus = "PASS"
		} else {
			result.PolicyStatus = "NONE"
		}
	case clierror.ExitSecurityFail:
		result.PolicyStatus = "FAIL"
		if decision != nil && len(decision.Violations) > 0 {
			result.Error = fmt.Errorf("security policy threshold violation: %s", decision.Violations[0].Message)
		} else {
			result.Error = fmt.Errorf("assessment completed with policy threshold violations")
		}
	default:
		result.PolicyStatus = "ERROR"
		if execRes.Error != nil {
			result.Error = execRes.Error
		} else if execRes.Execution != nil && execRes.Execution.ErrorMessage != "" {
			result.Error = fmt.Errorf("assessment completed with operational error: %s", execRes.Execution.ErrorMessage)
		} else {
			result.Error = fmt.Errorf("assessment failed to produce a trustworthy result")
		}
	}

	// 10. Pull Request Feedback (opt-in PR comment and inline review comments)
	if cfg.PRComment || cfg.PRInline {
		fbErr := PublishPRFeedback(ctx, cfg, result)
		if fbErr != nil {
			result.FeedbackError = fbErr
			if strings.EqualFold(cfg.FeedbackFailurePolicy, "fail") {
				// Mandatory feedback publication failure elevates clean assessments to exit 2,
				// but MUST NEVER convert or mask a security policy violation (exit 1).
				cls := clierror.ClassifyAssessment(
					string(execRes.Execution.Status),
					execRes.Error,
					result.ExitCode == clierror.ExitSecurityFail,
					nil,
					fbErr,
				)
				result.Classification = cls
				result.ExitCode = cls.ExitCode()
				if result.ExitCode == clierror.ExitOperational && execRes.Error == nil {
					result.Error = fmt.Errorf("mandatory PR feedback publication failed: %w", fbErr)
				}
			} else {
				if cfg.Provider == ProviderGitHub {
					fmt.Printf("::warning title=FELIX Feedback::Failed to publish PR feedback: %s\n", secrets.RedactText(fbErr.Error()))
				}
			}
		}
	}

	// 11. Generate and write step summary & outputs
	result.DiagnosticSummary = FormatSummary(result, cfg)
	_ = WriteStepSummary(cfg.SummaryPath, result.DiagnosticSummary)

	stepOutputs := map[string]string{
		"exit_code":          fmt.Sprintf("%d", result.ExitCode),
		"policy_status":      result.PolicyStatus,
		"findings_count":     fmt.Sprintf("%d", result.TotalFindings),
		"sarif_path":         result.SARIFPath,
		"json_path":          result.JSONPath,
		"html_path":          result.HTMLPath,
		"feedback_published": fmt.Sprintf("%t", result.FeedbackPublished),
	}
	if result.Provenance != nil && result.Provenance.ConfigDigest != "" {
		stepOutputs["provenance_config_digest"] = result.Provenance.ConfigDigest
	}
	if result.Provenance != nil && result.Provenance.VCS.RuntimeRevision != "" {
		stepOutputs["provenance_revision"] = result.Provenance.VCS.RuntimeRevision
	}
	_ = WriteStepOutputs(cfg.OutputPath, stepOutputs)

	if cfg.Provider == ProviderGitHub {
		EmitGitHubAnnotations(result)
	}

	return result, result.Error
}
