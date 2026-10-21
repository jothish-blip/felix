package assessment

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"felix/pkg/api"
	"felix/pkg/apisec"
	"felix/pkg/auth"
	"felix/pkg/bfla"
	"felix/pkg/bola"
	"felix/pkg/bopla"
	"felix/pkg/businesslogic"
	"felix/pkg/cloud"
	"felix/pkg/cloudsec"
	"felix/pkg/crawler"
	"felix/pkg/discovery"
	"felix/pkg/report"
	"felix/pkg/secrets"
	"felix/pkg/sessionsec"
	"felix/pkg/webvuln"
	"felix/pkg/workflow"
	"github.com/google/uuid"
)

// Standard assessment type constants.
const (
	AssessmentTypeWebSecurity      = "WEB_SECURITY"
	AssessmentTypeAPISecurity      = "API_SECURITY"
	AssessmentTypeWebVulnerability = "WEB_VULNERABILITY"
	AssessmentTypeSessionSecurity  = "SESSION_SECURITY"
	AssessmentTypeCloudSecurity    = "CLOUD_SECURITY"
	AssessmentTypeBusinessLogic    = "BUSINESS_LOGIC"
	AssessmentTypeBOLA             = "BOLA"
	AssessmentTypeBFLA             = "BFLA"
	AssessmentTypeBOPLA            = "BOPLA"
	AssessmentTypeWorkflow         = "WORKFLOW"
	AssessmentTypeFull             = "FULL"
	AssessmentTypeAPKMobile        = "APK_MOBILE"
)

var (
	// ErrUnsupportedAssessmentType is returned when an assessment specifies an unregistered engine type.
	ErrUnsupportedAssessmentType = errors.New("unsupported assessment type")
	// ErrEngineAlreadyRegistered is returned when an engine registration conflict occurs.
	ErrEngineAlreadyRegistered = errors.New("engine already registered")
)

// EngineCapabilities defines the operational features and metadata of an assessment engine.
type EngineCapabilities struct {
	AssessmentType           string   `json:"assessment_type"`
	DisplayName              string   `json:"display_name"`
	Aliases                  []string `json:"aliases,omitempty"`
	CoverageCategories       []string `json:"coverage_categories"`
	SupportsCheckpointResume bool     `json:"supports_checkpoint_resume"`
	SupportsTargetIsolation  bool     `json:"supports_target_isolation"`
	SupportsCancellation     bool     `json:"supports_cancellation"`
}

// EngineExecutionContext provides input targets, configuration, and runtime dependencies to an engine runner.
type EngineExecutionContext struct {
	Store           Store
	Assessment      *Assessment
	Execution       *AssessmentExecution
	RunnableTargets []string
	TargetMap       map[string]AssessmentTarget
	ScopeValidator  *ScopeValidator
	ConfigSnapshot  ScanConfigSnapshot
	Options         ExecutionOptions
	HTTPClient      *http.Client
	HeartbeatFunc   func(stage string, completedTargets []string, findingsCount int, lastURL string) error
	ProgressFunc    func(msg string)
}

// EngineExecutionOutput contains findings, assets, target dispositions, and metrics produced by an engine execution.
type EngineExecutionOutput struct {
	ReportFindings         []report.Finding
	AssessmentFindings     []AssessmentFinding
	InventoryAssets        []discovery.Asset
	InventoryRelations     []discovery.Relation
	AuthSurfaces           []auth.AuthSurface
	AuthCookies            []auth.CookieMetadata
	AuthTokens             []auth.TokenArtifact
	AuthProtectedEndpoints []auth.ProtectedEndpointInfo
	AssessedTargets        []string
	FailedTargets          []string
	TargetErrors           map[string]string
	RequestCount           int
	Error                  error
}

// EngineRunner defines the execution contract that each assessment engine must implement.
type EngineRunner interface {
	Capabilities() EngineCapabilities
	Execute(ctx context.Context, execCtx *EngineExecutionContext) (*EngineExecutionOutput, error)
}

// EngineRegistry manages engine runners indexed by canonical type and aliases in a thread-safe manner.
type EngineRegistry struct {
	mu      sync.RWMutex
	engines map[string]EngineRunner
}

// NewEngineRegistry initializes an empty engine registry.
func NewEngineRegistry() *EngineRegistry {
	return &EngineRegistry{
		engines: make(map[string]EngineRunner),
	}
}

// Register registers an EngineRunner under its canonical assessment type and any configured aliases.
func (r *EngineRegistry) Register(runner EngineRunner) error {
	if runner == nil {
		return fmt.Errorf("runner cannot be nil")
	}
	caps := runner.Capabilities()
	if strings.TrimSpace(caps.AssessmentType) == "" {
		return fmt.Errorf("engine must declare a valid AssessmentType")
	}
	normType := NormalizeAssessmentType(caps.AssessmentType)

	r.mu.Lock()
	defer r.mu.Unlock()

	r.engines[normType] = runner
	for _, alias := range caps.Aliases {
		normAlias := NormalizeAssessmentType(alias)
		if normAlias != "" {
			r.engines[normAlias] = runner
		}
	}
	return nil
}

// Get retrieves an EngineRunner by its assessment type or alias.
func (r *EngineRegistry) Get(assessmentType string) (EngineRunner, error) {
	norm := NormalizeAssessmentType(assessmentType)
	r.mu.RLock()
	defer r.mu.RUnlock()

	if runner, ok := r.engines[norm]; ok {
		return runner, nil
	}
	return nil, fmt.Errorf("%w: %q (normalized: %q)", ErrUnsupportedAssessmentType, assessmentType, norm)
}

// ListSupportedTypes returns a sorted list of all unique canonical assessment types supported by the registry.
func (r *EngineRegistry) ListSupportedTypes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := make(map[string]bool)
	var list []string
	for _, runner := range r.engines {
		canon := NormalizeAssessmentType(runner.Capabilities().AssessmentType)
		if !seen[canon] {
			seen[canon] = true
			list = append(list, canon)
		}
	}
	sort.Strings(list)
	return list
}

// NormalizeAssessmentType maps aliases, abbreviations, and case variations to the canonical assessment type.
func NormalizeAssessmentType(raw string) string {
	cleaned := strings.ToUpper(strings.TrimSpace(raw))
	cleaned = strings.ReplaceAll(cleaned, "-", "_")
	switch cleaned {
	case "WEB_SECURITY", "BLACK_BOX_WEB", "BLACK_BOX", "WEB", "WEBSEC", "":
		return AssessmentTypeWebSecurity
	case "API_SECURITY", "API_AUDIT", "APISEC", "API":
		return AssessmentTypeAPISecurity
	case "WEB_VULNERABILITY", "WEBVULN", "VULN", "VULNERABILITY":
		return AssessmentTypeWebVulnerability
	case "SESSION_SECURITY", "SESSIONSEC", "SESSION", "IDENTITY":
		return AssessmentTypeSessionSecurity
	case "CLOUD_SECURITY", "CLOUDSEC", "CLOUD":
		return AssessmentTypeCloudSecurity
	case "BUSINESS_LOGIC", "BIZLOGIC", "LOGIC":
		return AssessmentTypeBusinessLogic
	case "BOLA", "IDOR":
		return AssessmentTypeBOLA
	case "BFLA":
		return AssessmentTypeBFLA
	case "BOPLA":
		return AssessmentTypeBOPLA
	case "WORKFLOW", "WORKFLOWS", "INTEGRITY":
		return AssessmentTypeWorkflow
	case "FULL", "HYBRID", "ALL":
		return AssessmentTypeFull
	case "APK_MOBILE", "APK", "MOBILE":
		return AssessmentTypeAPKMobile
	default:
		return cleaned
	}
}

// AreAssessmentTypesCompatible determines whether two assessment types have compatible scopes for comparison.
// Each distinct assessment type (including FULL/composite) represents a distinct operational scope.
// Cross-type comparisons are rejected to prevent false positive resolutions or inaccurate deltas.
func AreAssessmentTypesCompatible(t1, t2 string) bool {
	norm1 := NormalizeAssessmentType(t1)
	norm2 := NormalizeAssessmentType(t2)
	if norm1 == "" || norm2 == "" {
		return true // Permissive if type is missing or unrecorded in legacy rows
	}
	return norm1 == norm2
}

func toAuthRecord(ar *AuthorizationRecord) *auth.AuthorizationRecord {
	if ar == nil {
		return nil
	}
	return &auth.AuthorizationRecord{
		ID:                  ar.ID,
		AuthorizingParty:    ar.AuthorizingParty,
		AuthorizationMethod: ar.AuthorizationMethod,
		Status:              string(ar.Status),
		ValidFrom:           ar.ValidFrom,
		ValidUntil:          ar.ValidUntil,
	}
}

// DefaultEngineRegistry constructs an EngineRegistry populated with all standard FELIX assessment engines.
func DefaultEngineRegistry(store Store) *EngineRegistry {
	reg := NewEngineRegistry()
	_ = reg.Register(&WebSecurityRunner{store: store})
	_ = reg.Register(&APISecRunner{store: store})
	_ = reg.Register(&WebVulnRunner{store: store})
	_ = reg.Register(&SessionSecRunner{store: store})
	_ = reg.Register(&CloudSecRunner{store: store})
	_ = reg.Register(&BusinessLogicRunner{store: store})
	_ = reg.Register(&BOLARunner{store: store})
	_ = reg.Register(&BFLARunner{store: store})
	_ = reg.Register(&BOPLARunner{store: store})
	_ = reg.Register(&WorkflowRunner{store: store})
	_ = reg.Register(&FullRunner{registry: reg, store: store})
	return reg
}

// --- 1. Web Security Runner ---

// WebSecurityRunner executes the deep crawling, secret intelligence, cloud audit, API detection,
// attack-surface discovery, and authentication analysis pipeline.
type WebSecurityRunner struct {
	store Store
}

func (r *WebSecurityRunner) Capabilities() EngineCapabilities {
	return EngineCapabilities{
		AssessmentType:           AssessmentTypeWebSecurity,
		DisplayName:              "Web Security & Discovery Intelligence",
		Aliases:                  []string{"BLACK_BOX_WEB", "BLACK_BOX", "WEB", "WEBSEC"},
		CoverageCategories:       []string{"secrets", "api", "cloud", "auth", "webvuln", "headers", "cookies", "cors"},
		SupportsCheckpointResume: true,
		SupportsTargetIsolation:  true,
		SupportsCancellation:     true,
	}
}

func (r *WebSecurityRunner) Execute(ctx context.Context, execCtx *EngineExecutionContext) (*EngineExecutionOutput, error) {
	output := &EngineExecutionOutput{
		TargetErrors: make(map[string]string),
	}

	timeoutDur := time.Duration(execCtx.ConfigSnapshot.TimeoutSeconds) * time.Second
	concurrency := execCtx.ConfigSnapshot.Concurrency
	if concurrency <= 0 {
		concurrency = 4
	}

	cEng := crawler.New(crawler.Config{
		Concurrency:     concurrency,
		Timeout:         timeoutDur,
		MaxAssetSize:    execCtx.ConfigSnapshot.MaxSizeBytes,
		MaxAssets:       execCtx.ConfigSnapshot.MaxAssets,
		ScopeMode:       crawler.ScopeMode(execCtx.Assessment.ScopeMode),
		UserAgent:       execCtx.ConfigSnapshot.UserAgent,
		Client:          execCtx.HTTPClient,
		AllowLoopback:   execCtx.Options.AllowLoopback,
		AllowPrivateIPs: execCtx.Options.AllowPrivateIPs,
		IsAllowed:       execCtx.ScopeValidator.IsAllowed,
		IsExcluded:      func(u string) bool { excluded, _ := execCtx.ScopeValidator.IsExcluded(u); return excluded },
		Progress:        execCtx.ProgressFunc,
	})

	detector := secrets.NewDetector()
	cloudAuditor := cloud.NewDetector(cloud.NewClient(cloud.ClientOptions{
		Timeout:         timeoutDur,
		MaxResponseSize: execCtx.ConfigSnapshot.MaxSizeBytes,
		UserAgent:       execCtx.ConfigSnapshot.UserAgent,
		HTTPClient:      execCtx.HTTPClient,
	}), func(u string) bool {
		return execCtx.ScopeValidator.IsAllowed(u)
	})
	cloudAuditor.SetAllowActiveVerification(execCtx.Options.ActiveVerification)

	apiAuditor := api.NewDetector(api.NewClient(api.ClientOptions{
		Timeout:         timeoutDur,
		MaxResponseSize: execCtx.ConfigSnapshot.MaxSizeBytes,
		UserAgent:       execCtx.ConfigSnapshot.UserAgent,
		HTTPClient:      execCtx.HTTPClient,
	}), api.DetectorOptions{
		IsAllowed: execCtx.ScopeValidator.IsAllowed,
		IsExcluded: func(u string) bool {
			excluded, _ := execCtx.ScopeValidator.IsExcluded(u)
			return excluded
		},
	})

	crawlResultsChan := cEng.CrawlConcurrently(ctx, execCtx.RunnableTargets)

	discoveryEng := discovery.NewEngine(discovery.Config{
		Concurrency: concurrency,
		Timeout:     timeoutDur,
		MaxAssets:   execCtx.ConfigSnapshot.MaxAssets,
	})

	authEng := auth.NewEngine()

	// Resume checkpoint findings if applicable
	if execCtx.Options.ResumeCheckpoint != nil && len(execCtx.Options.ResumeCheckpoint.CompletedTargets) > 0 {
		output.AssessedTargets = append(output.AssessedTargets, execCtx.Options.ResumeCheckpoint.CompletedTargets...)
		if r.store != nil {
			existingFindings, _ := r.store.GetFindings(execCtx.Assessment.ID, execCtx.Execution.ID)
			if len(existingFindings) > 0 {
				output.AssessmentFindings = append(output.AssessmentFindings, existingFindings...)
				for _, f := range existingFindings {
					output.ReportFindings = append(output.ReportFindings, ToReportFinding(f))
				}
			}
		}
	}

	totalDiscovered := 0
	totalEndpointsAudited := 0

	for res := range crawlResultsChan {
		if ctx.Err() != nil {
			output.Error = ctx.Err()
			break
		}

		if res.Err != nil {
			execCtx.ProgressFunc(fmt.Sprintf("[-] [%s] Crawl error: %v", res.Target, res.Err))
			output.FailedTargets = append(output.FailedTargets, res.Target)
			output.TargetErrors[res.Target] = res.Err.Error()
			continue
		}

		output.AssessedTargets = append(output.AssessedTargets, res.Target)

		targetRecord := execCtx.TargetMap[res.Target]
		normTarget, _ := NormalizeTargetURL(res.Target)
		if targetRecord.ID == "" {
			targetRecord = execCtx.TargetMap[normTarget]
		}

		var inScopeAssets []crawler.Asset
		for _, a := range res.Assets {
			if excluded, _ := execCtx.ScopeValidator.IsExcluded(a.URL); excluded {
				continue
			}
			if !execCtx.ScopeValidator.IsAllowed(a.URL) {
				a.InScope = false
			}
			inScopeAssets = append(inScopeAssets, a)
		}
		totalDiscovered += len(inScopeAssets)

		// Secrets Intelligence
		secFindings := detector.ScanAssets(inScopeAssets)

		// Cloud & BaaS Intelligence
		cloudRes := cloudAuditor.Audit(ctx, inScopeAssets, secFindings)

		// API Security Auditing
		apiRes := apiAuditor.Audit(ctx, res.Target, inScopeAssets)
		totalEndpointsAudited += apiRes.EndpointsScanned

		// Normalize findings
		for _, a := range inScopeAssets {
			if f, ok := report.FromCrawlerAsset(res.Target, a); ok {
				output.ReportFindings = append(output.ReportFindings, f)
				output.AssessmentFindings = append(output.AssessmentFindings, toAssessmentFinding(execCtx.Assessment.ID, execCtx.Execution.ID, targetRecord.ID, f))
			}
		}
		for _, f := range secFindings {
			rf := report.FromSecretFinding(res.Target, f)
			output.ReportFindings = append(output.ReportFindings, rf)
			output.AssessmentFindings = append(output.AssessmentFindings, toAssessmentFinding(execCtx.Assessment.ID, execCtx.Execution.ID, targetRecord.ID, rf))
		}
		for _, f := range cloudRes.Findings {
			rf := report.FromCloudFinding(res.Target, f)
			output.ReportFindings = append(output.ReportFindings, rf)
			output.AssessmentFindings = append(output.AssessmentFindings, toAssessmentFinding(execCtx.Assessment.ID, execCtx.Execution.ID, targetRecord.ID, rf))
		}
		for _, f := range apiRes.Findings {
			if excluded, _ := execCtx.ScopeValidator.IsExcluded(f.Endpoint); excluded {
				continue
			}
			rf := report.FromAPIFinding(res.Target, f)
			output.ReportFindings = append(output.ReportFindings, rf)
			output.AssessmentFindings = append(output.AssessmentFindings, toAssessmentFinding(execCtx.Assessment.ID, execCtx.Execution.ID, targetRecord.ID, rf))
		}

		// Attack-Surface Intelligence
		var certs []*x509.Certificate
		if res.TLS != nil {
			certs = res.TLS.PeerCertificates
		}
		targetInv := discoveryEng.AnalyzeTarget(
			ctx,
			execCtx.Assessment.ID,
			execCtx.Execution.ID,
			targetRecord.ID,
			res.Target,
			string(res.HTML),
			res.Header,
			certs,
			inScopeAssets,
			execCtx.ScopeValidator.IsAllowed,
		)

		rootAppID := ""
		for _, a := range targetInv.Assets {
			if a.Type == discovery.AssetTypeApplication {
				rootAppID = a.ID
				break
			}
		}
		if rootAppID == "" {
			rootApp := discovery.NewApplicationAsset(execCtx.Assessment.ID, execCtx.Execution.ID, targetRecord.ID, res.Target, discovery.ApplicationDetails{
				AppType: "web",
				RootURL: res.Target,
			})
			rootAppID = targetInv.AddAsset(rootApp)
		}

		for _, a := range inScopeAssets {
			discovery.IngestCrawlerAsset(targetInv, execCtx.Assessment.ID, execCtx.Execution.ID, targetRecord.ID, rootAppID, a)
		}
		if len(apiRes.DiscoveredEndpoints) > 0 {
			discovery.IngestAPIEndpoints(targetInv, execCtx.Assessment.ID, execCtx.Execution.ID, targetRecord.ID, res.Target, rootAppID, apiRes.DiscoveredEndpoints)
		}
		if len(cloudRes.DiscoveredServices) > 0 {
			discovery.IngestDiscoveredServices(targetInv, execCtx.Assessment.ID, execCtx.Execution.ID, targetRecord.ID, rootAppID, cloudRes.DiscoveredServices)
		} else if len(cloudRes.Services) > 0 {
			discovery.IngestCloudServices(targetInv, execCtx.Assessment.ID, execCtx.Execution.ID, targetRecord.ID, rootAppID, cloudRes.Services)
		}

		output.InventoryAssets = append(output.InventoryAssets, targetInv.Assets...)
		output.InventoryRelations = append(output.InventoryRelations, targetInv.Relations...)

		// Authentication Intelligence
		authInv, authFindings := authEng.AnalyzeAuthentication(
			targetInv,
			inScopeAssets,
			res.Header,
			res.Target,
			execCtx.Assessment.ID,
			execCtx.Execution.ID,
			targetRecord.ID,
		)
		output.AuthSurfaces = append(output.AuthSurfaces, authInv.Surfaces...)
		output.AuthCookies = append(output.AuthCookies, authInv.Cookies...)
		output.AuthTokens = append(output.AuthTokens, authInv.Tokens...)
		output.AuthProtectedEndpoints = append(output.AuthProtectedEndpoints, authInv.ProtectedEndpoints...)

		for _, f := range authFindings {
			output.ReportFindings = append(output.ReportFindings, f)
			output.AssessmentFindings = append(output.AssessmentFindings, toAssessmentFinding(execCtx.Assessment.ID, execCtx.Execution.ID, targetRecord.ID, f))
		}

		// Target heartbeat & checkpoint renewal
		if execCtx.HeartbeatFunc != nil {
			if hbErr := execCtx.HeartbeatFunc("CRAWL_PARTIAL", output.AssessedTargets, len(output.AssessmentFindings), res.Target); hbErr != nil {
				if errors.Is(hbErr, ErrLeaseLost) {
					output.Error = hbErr
					break
				}
			}
		}
	}

	output.RequestCount = totalDiscovered + totalEndpointsAudited
	return output, output.Error
}

// --- 2. API Security Runner ---

// APISecRunner assesses OWASP API Security Top 10 vulnerabilities.
type APISecRunner struct {
	store Store
}

func (r *APISecRunner) Capabilities() EngineCapabilities {
	return EngineCapabilities{
		AssessmentType:     AssessmentTypeAPISecurity,
		DisplayName:        "OWASP API Security Top 10 Audit",
		Aliases:            []string{"API_AUDIT", "APISEC", "API"},
		CoverageCategories: []string{"api1_bola", "api2_broken_auth", "api3_bopla", "api4_resource_consumption", "api5_bfla", "api6_business_flows", "api7_ssrf", "api8_misconfiguration", "api9_inventory", "api10_unsafe_consumption"},
		SupportsCheckpointResume: false,
		SupportsTargetIsolation:  true,
		SupportsCancellation:     true,
	}
}

func (r *APISecRunner) Execute(ctx context.Context, execCtx *EngineExecutionContext) (*EngineExecutionOutput, error) {
	output := &EngineExecutionOutput{
		TargetErrors: make(map[string]string),
	}

	cfg := apisec.DefaultConfig()
	engine := apisec.NewEngine(execCtx.HTTPClient, cfg)

	for _, target := range execCtx.RunnableTargets {
		if ctx.Err() != nil {
			output.Error = ctx.Err()
			break
		}

		targetRecord := execCtx.TargetMap[target]
		normTarget, _ := NormalizeTargetURL(target)
		if targetRecord.ID == "" {
			targetRecord = execCtx.TargetMap[normTarget]
		}

		var endpoints []apisec.APIEndpoint
		endpoints = append(endpoints, apisec.AnalyzeEndpoint("GET", "/", "target_root"))
		endpoints = append(endpoints, apisec.AnalyzeEndpoint("GET", "/api/v1/health", "candidate"))

		actx := &apisec.AssessmentContext{
			AssessmentID: execCtx.Assessment.ID,
			ExecutionID:  execCtx.Execution.ID,
			BaseURL:      target,
			Endpoints:    endpoints,
			IsAllowed:    execCtx.ScopeValidator.IsAllowed,
			IsExcluded:   func(u string) bool { excluded, _ := execCtx.ScopeValidator.IsExcluded(u); return excluded },
		}

		results, findings, summary, err := engine.Assess(ctx, actx)
		if err != nil {
			output.FailedTargets = append(output.FailedTargets, target)
			output.TargetErrors[target] = err.Error()
			execCtx.ProgressFunc(fmt.Sprintf("[-] [%s] API Security audit error: %v", target, err))
			continue
		}

		output.AssessedTargets = append(output.AssessedTargets, target)
		output.RequestCount += len(results)

		for _, f := range findings {
			output.ReportFindings = append(output.ReportFindings, f)
			output.AssessmentFindings = append(output.AssessmentFindings, ToAssessmentFinding(execCtx.Assessment.ID, execCtx.Execution.ID, targetRecord.ID, f))
		}

		rootApp := discovery.NewApplicationAsset(execCtx.Assessment.ID, execCtx.Execution.ID, targetRecord.ID, target, discovery.ApplicationDetails{
			AppType: "api",
			RootURL: target,
		})
		output.InventoryAssets = append(output.InventoryAssets, rootApp)

		if r.store != nil {
			_ = r.store.SaveAPISecResults(results)
			if summary != nil {
				covJSON, _ := json.Marshal(summary.CoverageMap)
				runRec := &apisec.RunRecord{
					ID:                 uuid.New().String(),
					AssessmentID:       execCtx.Assessment.ID,
					ExecutionID:        execCtx.Execution.ID,
					TotalTests:         summary.TotalTests,
					CategoriesAssessed: summary.CategoriesCovered,
					VerifiedCount:      summary.VerifiedCount,
					CandidateCount:     summary.CandidateCount,
					ObservedCount:      summary.ObservedCount,
					CoverageJSON:       string(covJSON),
					CreatedAt:          time.Now().UTC(),
				}
				_ = r.store.SaveAPISecRun(runRec)
			}
		}
	}

	return output, output.Error
}

// --- 3. Web Vulnerability Runner ---

// WebVulnRunner assesses and verifies web application vulnerabilities (XSS, SQLi, SSRF, SSTI, etc.).
type WebVulnRunner struct {
	store Store
}

func (r *WebVulnRunner) Capabilities() EngineCapabilities {
	return EngineCapabilities{
		AssessmentType:     AssessmentTypeWebVulnerability,
		DisplayName:        "Web Vulnerability Verification Engine",
		Aliases:            []string{"WEBVULN", "VULN", "VULNERABILITY"},
		CoverageCategories: []string{"xss", "sqli", "nosqli", "cmdi", "pathtraversal", "fileinclusion", "ssti", "ssrf", "openredirect", "request_issues", "infodisclosure", "deserialization", "misconfiguration"},
		SupportsCheckpointResume: false,
		SupportsTargetIsolation:  true,
		SupportsCancellation:     true,
	}
}

func (r *WebVulnRunner) Execute(ctx context.Context, execCtx *EngineExecutionContext) (*EngineExecutionOutput, error) {
	output := &EngineExecutionOutput{
		TargetErrors: make(map[string]string),
	}

	cfg := webvuln.DefaultConfig()
	engine := webvuln.NewEngine(execCtx.HTTPClient, cfg)

	for _, target := range execCtx.RunnableTargets {
		if ctx.Err() != nil {
			output.Error = ctx.Err()
			break
		}

		targetRecord := execCtx.TargetMap[target]
		normTarget, _ := NormalizeTargetURL(target)
		if targetRecord.ID == "" {
			targetRecord = execCtx.TargetMap[normTarget]
		}

		var targetEndpoints []webvuln.TargetEndpoint
		targetEndpoints = append(targetEndpoints, webvuln.TargetEndpoint{
			Method:     "GET",
			Path:       "/",
			Parameters: []string{"q", "id", "search"},
		})

		actx := &webvuln.AssessmentContext{
			AssessmentID: execCtx.Assessment.ID,
			ExecutionID:  execCtx.Execution.ID,
			BaseURL:      target,
			Endpoints:    targetEndpoints,
			IsAllowed:    execCtx.ScopeValidator.IsAllowed,
			IsExcluded:   func(u string) bool { excluded, _ := execCtx.ScopeValidator.IsExcluded(u); return excluded },
		}

		results, findings, summary, err := engine.Assess(ctx, actx)
		if err != nil {
			output.FailedTargets = append(output.FailedTargets, target)
			output.TargetErrors[target] = err.Error()
			execCtx.ProgressFunc(fmt.Sprintf("[-] [%s] Web vulnerability audit error: %v", target, err))
			continue
		}

		output.AssessedTargets = append(output.AssessedTargets, target)
		output.RequestCount += len(results)

		for _, f := range findings {
			output.ReportFindings = append(output.ReportFindings, f)
			output.AssessmentFindings = append(output.AssessmentFindings, ToAssessmentFinding(execCtx.Assessment.ID, execCtx.Execution.ID, targetRecord.ID, f))
		}

		rootApp := discovery.NewApplicationAsset(execCtx.Assessment.ID, execCtx.Execution.ID, targetRecord.ID, target, discovery.ApplicationDetails{
			AppType: "web",
			RootURL: target,
		})
		output.InventoryAssets = append(output.InventoryAssets, rootApp)

		if r.store != nil {
			_ = r.store.SaveWebVulnResults(results)
			if summary != nil {
				covJSON, _ := json.Marshal(summary.CoverageMap)
				runRec := &webvuln.RunRecord{
					ID:                 uuid.New().String(),
					AssessmentID:       execCtx.Assessment.ID,
					ExecutionID:        execCtx.Execution.ID,
					TotalTests:         summary.TotalTests,
					CategoriesAssessed: summary.CategoriesCovered,
					VerifiedCount:      summary.VerifiedCount,
					CandidateCount:     summary.CandidateCount,
					ObservedCount:      summary.ObservedCount,
					CoverageJSON:       string(covJSON),
					CreatedAt:          time.Now().UTC(),
				}
				_ = r.store.SaveWebVulnRun(runRec)
			}
		}
	}

	return output, output.Error
}

// --- 4. Session Security Runner ---

// SessionSecRunner assesses session lifecycle, cookie security, JWT flaws, and identity boundaries.
type SessionSecRunner struct {
	store Store
}

func (r *SessionSecRunner) Capabilities() EngineCapabilities {
	return EngineCapabilities{
		AssessmentType:     AssessmentTypeSessionSecurity,
		DisplayName:        "Session & Identity Security Engine",
		Aliases:            []string{"SESSIONSEC", "SESSION", "IDENTITY"},
		CoverageCategories: []string{"session_fixation", "cookie_security", "jwt_vulnerabilities", "session_invalidation", "concurrent_sessions", "password_recovery", "account_enumeration", "session_puzzling", "session_isolation"},
		SupportsCheckpointResume: false,
		SupportsTargetIsolation:  true,
		SupportsCancellation:     true,
	}
}

func (r *SessionSecRunner) Execute(ctx context.Context, execCtx *EngineExecutionContext) (*EngineExecutionOutput, error) {
	output := &EngineExecutionOutput{
		TargetErrors: make(map[string]string),
	}

	cfg := sessionsec.DefaultConfig()
	engine := sessionsec.NewEngine(execCtx.HTTPClient, cfg)

	for _, target := range execCtx.RunnableTargets {
		if ctx.Err() != nil {
			output.Error = ctx.Err()
			break
		}

		targetRecord := execCtx.TargetMap[target]
		normTarget, _ := NormalizeTargetURL(target)
		if targetRecord.ID == "" {
			targetRecord = execCtx.TargetMap[normTarget]
		}

		var endpoints []sessionsec.TargetEndpoint
		endpoints = append(endpoints, sessionsec.TargetEndpoint{
			Method: "GET",
			Path:   "/",
			Type:   "protected",
		})

		var authRec *auth.AuthorizationRecord
		if execCtx.Store != nil {
			rec, _ := execCtx.Store.GetAuthorization(execCtx.Assessment.ID)
			authRec = toAuthRecord(rec)
		}

		var dispatched int32
		actx := &sessionsec.AssessmentContext{
			AssessmentID:       execCtx.Assessment.ID,
			ExecutionID:        execCtx.Execution.ID,
			BaseURL:            target,
			Endpoints:          endpoints,
			IsAllowed:          execCtx.ScopeValidator.IsAllowed,
			IsExcluded:         func(u string) bool { excluded, _ := execCtx.ScopeValidator.IsExcluded(u); return excluded },
			Authorization:      authRec,
			DispatchedRequests: &dispatched,
		}

		results, findings, summary, err := engine.Assess(ctx, actx)
		if err != nil {
			output.FailedTargets = append(output.FailedTargets, target)
			output.TargetErrors[target] = err.Error()
			execCtx.ProgressFunc(fmt.Sprintf("[-] [%s] Session security audit error: %v", target, err))
			continue
		}

		output.AssessedTargets = append(output.AssessedTargets, target)
		output.RequestCount += int(dispatched)

		for _, f := range findings {
			output.ReportFindings = append(output.ReportFindings, f)
			output.AssessmentFindings = append(output.AssessmentFindings, ToAssessmentFinding(execCtx.Assessment.ID, execCtx.Execution.ID, targetRecord.ID, f))
		}

		rootApp := discovery.NewApplicationAsset(execCtx.Assessment.ID, execCtx.Execution.ID, targetRecord.ID, target, discovery.ApplicationDetails{
			AppType: "session_identity",
			RootURL: target,
		})
		output.InventoryAssets = append(output.InventoryAssets, rootApp)

		if r.store != nil {
			_ = r.store.SaveSessionSecResults(results)
			if summary != nil {
				covJSON, _ := json.Marshal(summary.CoverageMap)
				runRec := &sessionsec.RunRecord{
					ID:                 uuid.New().String(),
					AssessmentID:       execCtx.Assessment.ID,
					ExecutionID:        execCtx.Execution.ID,
					TotalTests:         summary.TotalTests,
					CategoriesAssessed: summary.CategoriesCovered,
					VerifiedCount:      summary.VerifiedCount,
					CandidateCount:     summary.CandidateCount,
					InconclusiveCount:  summary.InconclusiveCount,
					BlockedCount:       summary.BlockedCount,
					CoverageJSON:       string(covJSON),
					CreatedAt:          time.Now().UTC(),
				}
				_ = r.store.SaveSessionSecRun(runRec)
			}
		}
	}

	return output, output.Error
}

// --- 5. Cloud Security Runner ---

// CloudSecRunner audits cloud infrastructure, bucket exposure, IAM, metadata, and provider surfaces.
type CloudSecRunner struct {
	store Store
}

func (r *CloudSecRunner) Capabilities() EngineCapabilities {
	return EngineCapabilities{
		AssessmentType:     AssessmentTypeCloudSecurity,
		DisplayName:        "Cloud Infrastructure & Surface Security",
		Aliases:            []string{"CLOUDSEC", "CLOUD"},
		CoverageCategories: []string{"aws", "azure", "gcp", "metadata_exposure", "iam", "storage_buckets", "serverless"},
		SupportsCheckpointResume: false,
		SupportsTargetIsolation:  true,
		SupportsCancellation:     true,
	}
}

func (r *CloudSecRunner) Execute(ctx context.Context, execCtx *EngineExecutionContext) (*EngineExecutionOutput, error) {
	output := &EngineExecutionOutput{
		TargetErrors: make(map[string]string),
	}

	cfg := cloudsec.DefaultConfig()
	engine := cloudsec.NewEngine(cfg)

	var extTargets []cloudsec.ExternalTarget
	for _, t := range execCtx.RunnableTargets {
		u, _ := url.Parse(t)
		host := t
		scheme := "https"
		if u != nil {
			if u.Hostname() != "" {
				host = u.Hostname()
			}
			if u.Scheme != "" {
				scheme = u.Scheme
			}
		}
		extTargets = append(extTargets, cloudsec.ExternalTarget{
			URL:      t,
			Hostname: host,
			Scheme:   scheme,
			Source:   "approved_target",
		})
	}

	actx := &cloudsec.AssessmentContext{
		AssessmentID:    execCtx.Assessment.ID,
		ExecutionID:     execCtx.Execution.ID,
		Mode:            cloudsec.ModeExternal,
		ExternalTargets: extTargets,
		IsAllowed:       execCtx.ScopeValidator.IsAllowed,
		IsExcluded:      func(u string) bool { excluded, _ := execCtx.ScopeValidator.IsExcluded(u); return excluded },
	}

	results, findings, summary, err := engine.Assess(ctx, actx)
	if err != nil {
		output.Error = err
		return output, err
	}

	output.AssessedTargets = append(output.AssessedTargets, execCtx.RunnableTargets...)
	output.RequestCount += len(results)

	primaryTargetID := ""
	if len(execCtx.RunnableTargets) > 0 {
		tgt := execCtx.TargetMap[execCtx.RunnableTargets[0]]
		primaryTargetID = tgt.ID
	}

	for _, f := range findings {
		output.ReportFindings = append(output.ReportFindings, f)
		output.AssessmentFindings = append(output.AssessmentFindings, ToAssessmentFinding(execCtx.Assessment.ID, execCtx.Execution.ID, primaryTargetID, f))
	}

	if r.store != nil {
		_ = r.store.SaveCloudSecResults(results)
		if summary != nil {
			covJSON, _ := json.Marshal(summary.ServiceCoverageMap)
			runRec := &cloudsec.RunRecord{
				ID:               uuid.New().String(),
				AssessmentID:     execCtx.Assessment.ID,
				ExecutionID:      execCtx.Execution.ID,
				Mode:             cloudsec.ModeExternal,
				TotalChecks:      summary.TotalChecks,
				ServicesAssessed: summary.ServicesAssessed,
				VerifiedCount:    summary.VerifiedCount,
				CandidateCount:   summary.CandidateCount,
				ObservedCount:    summary.ObservedCount,
				CoverageJSON:     string(covJSON),
				CreatedAt:        time.Now().UTC(),
			}
			_ = r.store.SaveCloudSecRun(runRec)
		}
	}

	return output, nil
}

// --- 6. Business Logic Runner ---

// BusinessLogicRunner tests business workflows, price manipulation, mass assignment, and state bypasses.
type BusinessLogicRunner struct {
	store Store
}

func (r *BusinessLogicRunner) Capabilities() EngineCapabilities {
	return EngineCapabilities{
		AssessmentType:     AssessmentTypeBusinessLogic,
		DisplayName:        "Business Logic & Workflow Abuse Engine",
		Aliases:            []string{"BIZLOGIC", "LOGIC"},
		CoverageCategories: []string{"price_manipulation", "workflow_bypass", "mass_assignment", "rate_limit_bypass", "race_condition"},
		SupportsCheckpointResume: false,
		SupportsTargetIsolation:  true,
		SupportsCancellation:     true,
	}
}

func (r *BusinessLogicRunner) Execute(ctx context.Context, execCtx *EngineExecutionContext) (*EngineExecutionOutput, error) {
	output := &EngineExecutionOutput{
		TargetErrors: make(map[string]string),
	}

	cfg := businesslogic.DefaultConfig()
	engine := businesslogic.NewEngine(execCtx.HTTPClient, cfg)

	for _, target := range execCtx.RunnableTargets {
		if ctx.Err() != nil {
			output.Error = ctx.Err()
			break
		}

		targetRecord := execCtx.TargetMap[target]
		normTarget, _ := NormalizeTargetURL(target)
		if targetRecord.ID == "" {
			targetRecord = execCtx.TargetMap[normTarget]
		}

		var endpoints []businesslogic.DiscoveredEndpoint
		endpoints = append(endpoints, businesslogic.DiscoveredEndpoint{
			Method: "GET",
			Path:   "/",
			Type:   "step",
		})

		actx := &businesslogic.AssessmentContext{
			AssessmentID: execCtx.Assessment.ID,
			ExecutionID:  execCtx.Execution.ID,
			BaseURL:      target,
			Endpoints:    endpoints,
			IsAllowed:    execCtx.ScopeValidator.IsAllowed,
			IsExcluded:   func(u string) bool { excluded, _ := execCtx.ScopeValidator.IsExcluded(u); return excluded },
		}

		results, findings, summary, err := engine.Assess(ctx, actx)
		if err != nil {
			output.FailedTargets = append(output.FailedTargets, target)
			output.TargetErrors[target] = err.Error()
			continue
		}

		output.AssessedTargets = append(output.AssessedTargets, target)
		output.RequestCount += len(results)

		for _, f := range findings {
			output.ReportFindings = append(output.ReportFindings, f)
			output.AssessmentFindings = append(output.AssessmentFindings, ToAssessmentFinding(execCtx.Assessment.ID, execCtx.Execution.ID, targetRecord.ID, f))
		}

		if r.store != nil {
			_ = r.store.SaveBusinessLogicResults(results)
			if summary != nil {
				covJSON, _ := json.Marshal(summary.CategoryCoverageMap)
				runRec := &businesslogic.RunRecord{
					ID:                 uuid.New().String(),
					AssessmentID:       execCtx.Assessment.ID,
					ExecutionID:        execCtx.Execution.ID,
					TargetURL:          target,
					TotalChecks:        summary.TotalChecks,
					CategoriesAssessed: summary.CategoriesAssessed,
					WorkflowsModeled:   summary.WorkflowsModeled,
					VerifiedCount:      summary.VerifiedCount,
					CandidateCount:     summary.CandidateCount,
					ObservedCount:      summary.ObservedCount,
					InconclusiveCount:  summary.InconclusiveCount,
					BlockedCount:       summary.BlockedCount,
					NotVulnerableCount: summary.NotVulnerableCount,
					CoverageJSON:       string(covJSON),
					CreatedAt:          time.Now().UTC(),
				}
				_ = r.store.SaveBusinessLogicRun(runRec)
			}
		}
	}

	return output, output.Error
}

// --- 7. BOLA Runner ---

// BOLARunner evaluates Broken Object Level Authorization (IDOR) across targets and object hierarchies.
type BOLARunner struct {
	store Store
}

func (r *BOLARunner) Capabilities() EngineCapabilities {
	return EngineCapabilities{
		AssessmentType:     AssessmentTypeBOLA,
		DisplayName:        "Broken Object Level Authorization (BOLA/IDOR)",
		Aliases:            []string{"IDOR"},
		CoverageCategories: []string{"bola", "idor", "horizontal_privilege_escalation"},
		SupportsCheckpointResume: false,
		SupportsTargetIsolation:  true,
		SupportsCancellation:     true,
	}
}

func (r *BOLARunner) Execute(ctx context.Context, execCtx *EngineExecutionContext) (*EngineExecutionOutput, error) {
	output := &EngineExecutionOutput{
		TargetErrors: make(map[string]string),
	}

	cfg := bola.DefaultConfig()
	engine := bola.NewEngine(execCtx.HTTPClient, cfg)

	for _, target := range execCtx.RunnableTargets {
		if ctx.Err() != nil {
			output.Error = ctx.Err()
			break
		}

		targetRecord := execCtx.TargetMap[target]
		normTarget, _ := NormalizeTargetURL(target)
		if targetRecord.ID == "" {
			targetRecord = execCtx.TargetMap[normTarget]
		}

		var endpoints []bola.EndpointTemplate
		endpoints = append(endpoints, bola.EndpointTemplate{
			Method:      "GET",
			PathPattern: "/",
		})

		var authRec *auth.AuthorizationRecord
		if execCtx.Store != nil {
			rec, _ := execCtx.Store.GetAuthorization(execCtx.Assessment.ID)
			authRec = toAuthRecord(rec)
		}

		var dispatched int32
		actx := &bola.AssessmentContext{
			AssessmentID:       execCtx.Assessment.ID,
			ExecutionID:        execCtx.Execution.ID,
			BaseURL:            target,
			Endpoints:          endpoints,
			IsAllowed:          execCtx.ScopeValidator.IsAllowed,
			IsExcluded:         func(u string) bool { excluded, _ := execCtx.ScopeValidator.IsExcluded(u); return excluded },
			Authorization:      authRec,
			DispatchedRequests: &dispatched,
		}

		results, summary, err := engine.Assess(ctx, actx)
		if err != nil {
			output.FailedTargets = append(output.FailedTargets, target)
			output.TargetErrors[target] = err.Error()
			continue
		}

		output.AssessedTargets = append(output.AssessedTargets, target)
		output.RequestCount += int(dispatched)

		for _, res := range results {
			if res.Finding != nil {
				output.ReportFindings = append(output.ReportFindings, *res.Finding)
				output.AssessmentFindings = append(output.AssessmentFindings, ToAssessmentFinding(execCtx.Assessment.ID, execCtx.Execution.ID, targetRecord.ID, *res.Finding))
			}
		}

		if r.store != nil {
			_ = r.store.SaveBOLAResults(results)
			if summary != nil {
				covJSON, _ := json.Marshal(summary.CoverageMap)
				runRec := &bola.RunRecord{
					ID:                 uuid.New().String(),
					AssessmentID:       execCtx.Assessment.ID,
					ExecutionID:        execCtx.Execution.ID,
					TotalTests:         summary.TotalTests,
					CategoriesAssessed: summary.CategoriesCovered,
					VerifiedCount:      summary.VerifiedCount,
					CandidateCount:     summary.CandidateCount,
					NotVulnerableCount: summary.NotVulnerableCount,
					CoverageJSON:       string(covJSON),
					CreatedAt:          time.Now().UTC(),
				}
				_ = r.store.SaveBOLARun(runRec)
			}
		}
	}

	return output, output.Error
}

// --- 8. BFLA Runner ---

// BFLARunner evaluates Broken Function Level Authorization and privilege escalation paths.
type BFLARunner struct {
	store Store
}

func (r *BFLARunner) Capabilities() EngineCapabilities {
	return EngineCapabilities{
		AssessmentType:     AssessmentTypeBFLA,
		DisplayName:        "Broken Function Level Authorization (BFLA)",
		Aliases:            []string{},
		CoverageCategories: []string{"bfla", "vertical_privilege_escalation", "administrative_bypass"},
		SupportsCheckpointResume: false,
		SupportsTargetIsolation:  true,
		SupportsCancellation:     true,
	}
}

func (r *BFLARunner) Execute(ctx context.Context, execCtx *EngineExecutionContext) (*EngineExecutionOutput, error) {
	output := &EngineExecutionOutput{
		TargetErrors: make(map[string]string),
	}

	cfg := bfla.DefaultConfig()
	engine := bfla.NewEngine(execCtx.HTTPClient, cfg)

	for _, target := range execCtx.RunnableTargets {
		if ctx.Err() != nil {
			output.Error = ctx.Err()
			break
		}

		targetRecord := execCtx.TargetMap[target]
		normTarget, _ := NormalizeTargetURL(target)
		if targetRecord.ID == "" {
			targetRecord = execCtx.TargetMap[normTarget]
		}

		var policies []bfla.FunctionPolicy
		policies = append(policies, bfla.FunctionPolicy{
			FunctionID:   "fn_root",
			Name:         "Root Endpoint",
			Path:         "/",
			Method:       "GET",
			Category:     bfla.CategoryBFLAPrivilegeEscalation,
			AllowedRoles: []string{"admin"},
		})

		var authRec *auth.AuthorizationRecord
		if execCtx.Store != nil {
			rec, _ := execCtx.Store.GetAuthorization(execCtx.Assessment.ID)
			authRec = toAuthRecord(rec)
		}

		var dispatched int32
		actx := &bfla.AssessmentContext{
			AssessmentID:       execCtx.Assessment.ID,
			ExecutionID:        execCtx.Execution.ID,
			BaseURL:            target,
			Policies:           policies,
			IsAllowed:          execCtx.ScopeValidator.IsAllowed,
			IsExcluded:         func(u string) bool { excluded, _ := execCtx.ScopeValidator.IsExcluded(u); return excluded },
			Authorization:      authRec,
			DispatchedRequests: &dispatched,
		}

		results, summary, err := engine.Assess(ctx, actx)
		if err != nil {
			output.FailedTargets = append(output.FailedTargets, target)
			output.TargetErrors[target] = err.Error()
			continue
		}

		output.AssessedTargets = append(output.AssessedTargets, target)
		output.RequestCount += int(dispatched)

		for _, res := range results {
			if res.Finding != nil {
				output.ReportFindings = append(output.ReportFindings, *res.Finding)
				output.AssessmentFindings = append(output.AssessmentFindings, ToAssessmentFinding(execCtx.Assessment.ID, execCtx.Execution.ID, targetRecord.ID, *res.Finding))
			}
		}

		if r.store != nil {
			_ = r.store.SaveBFLAResults(results)
			if summary != nil {
				covJSON, _ := json.Marshal(summary.CoverageMap)
				runRec := &bfla.RunRecord{
					ID:                 uuid.New().String(),
					AssessmentID:       execCtx.Assessment.ID,
					ExecutionID:        execCtx.Execution.ID,
					TotalTests:         summary.TotalTests,
					CategoriesAssessed: summary.CategoriesCovered,
					VerifiedCount:      summary.VerifiedCount,
					CandidateCount:     summary.CandidateCount,
					NotVulnerableCount: summary.NotVulnerableCount,
					CoverageJSON:       string(covJSON),
					CreatedAt:          time.Now().UTC(),
				}
				_ = r.store.SaveBFLARun(runRec)
			}
		}
	}

	return output, output.Error
}

// --- 9. BOPLA Runner ---

// BOPLARunner evaluates Broken Object Property Level Authorization (mass assignment & excessive data exposure).
type BOPLARunner struct {
	store Store
}

func (r *BOPLARunner) Capabilities() EngineCapabilities {
	return EngineCapabilities{
		AssessmentType:     AssessmentTypeBOPLA,
		DisplayName:        "Broken Object Property Level Authorization (BOPLA)",
		Aliases:            []string{},
		CoverageCategories: []string{"bopla", "mass_assignment", "excessive_data_exposure"},
		SupportsCheckpointResume: false,
		SupportsTargetIsolation:  true,
		SupportsCancellation:     true,
	}
}

func (r *BOPLARunner) Execute(ctx context.Context, execCtx *EngineExecutionContext) (*EngineExecutionOutput, error) {
	output := &EngineExecutionOutput{
		TargetErrors: make(map[string]string),
	}

	cfg := bopla.DefaultConfig()
	engine := bopla.NewEngine(execCtx.HTTPClient, cfg)

	for _, target := range execCtx.RunnableTargets {
		if ctx.Err() != nil {
			output.Error = ctx.Err()
			break
		}

		targetRecord := execCtx.TargetMap[target]
		normTarget, _ := NormalizeTargetURL(target)
		if targetRecord.ID == "" {
			targetRecord = execCtx.TargetMap[normTarget]
		}

		var policies []bopla.PropertyPolicy
		policies = append(policies, bopla.PropertyPolicy{
			PropertyID:   "prop_root",
			Name:         "Root Property",
			Endpoint:     "/",
			Method:       "GET",
			Category:     bopla.CategoryBOPLAExcessiveExposure,
			PropertyPath: "role",
		})

		var authRec *auth.AuthorizationRecord
		if execCtx.Store != nil {
			rec, _ := execCtx.Store.GetAuthorization(execCtx.Assessment.ID)
			authRec = toAuthRecord(rec)
		}

		var dispatched int32
		actx := &bopla.AssessmentContext{
			AssessmentID:       execCtx.Assessment.ID,
			ExecutionID:        execCtx.Execution.ID,
			BaseURL:            target,
			Policies:           policies,
			IsAllowed:          execCtx.ScopeValidator.IsAllowed,
			IsExcluded:         func(u string) bool { excluded, _ := execCtx.ScopeValidator.IsExcluded(u); return excluded },
			Authorization:      authRec,
			DispatchedRequests: &dispatched,
		}

		results, summary, err := engine.Assess(ctx, actx)
		if err != nil {
			output.FailedTargets = append(output.FailedTargets, target)
			output.TargetErrors[target] = err.Error()
			continue
		}

		output.AssessedTargets = append(output.AssessedTargets, target)
		output.RequestCount += int(dispatched)

		for _, res := range results {
			if res.Finding != nil {
				output.ReportFindings = append(output.ReportFindings, *res.Finding)
				output.AssessmentFindings = append(output.AssessmentFindings, ToAssessmentFinding(execCtx.Assessment.ID, execCtx.Execution.ID, targetRecord.ID, *res.Finding))
			}
		}

		if r.store != nil {
			_ = r.store.SaveBOPLAResults(results)
			if summary != nil {
				covJSON, _ := json.Marshal(summary.CoverageMap)
				runRec := &bopla.RunRecord{
					ID:                 uuid.New().String(),
					AssessmentID:       execCtx.Assessment.ID,
					ExecutionID:        execCtx.Execution.ID,
					TotalTests:         summary.TotalTests,
					CategoriesAssessed: summary.CategoriesCovered,
					VerifiedCount:      summary.VerifiedCount,
					CandidateCount:     summary.CandidateCount,
					NotVulnerableCount: summary.NotVulnerableCount,
					CoverageJSON:       string(covJSON),
					CreatedAt:          time.Now().UTC(),
				}
				_ = r.store.SaveBOPLARun(runRec)
			}
		}
	}

	return output, output.Error
}

// --- 10. Workflow Runner ---

// WorkflowRunner evaluates multi-step business process integrity, step-skipping, and replay protection.
type WorkflowRunner struct {
	store Store
}

func (r *WorkflowRunner) Capabilities() EngineCapabilities {
	return EngineCapabilities{
		AssessmentType:     AssessmentTypeWorkflow,
		DisplayName:        "Multi-Step Workflow Integrity Engine",
		Aliases:            []string{"WORKFLOWS", "INTEGRITY"},
		CoverageCategories: []string{"workflow_integrity", "step_skipping", "state_tampering", "replay_attacks"},
		SupportsCheckpointResume: false,
		SupportsTargetIsolation:  true,
		SupportsCancellation:     true,
	}
}

func (r *WorkflowRunner) Execute(ctx context.Context, execCtx *EngineExecutionContext) (*EngineExecutionOutput, error) {
	output := &EngineExecutionOutput{
		TargetErrors: make(map[string]string),
	}

	cfg := workflow.DefaultConfig()
	engine := workflow.NewEngine(execCtx.HTTPClient, cfg)

	for _, target := range execCtx.RunnableTargets {
		if ctx.Err() != nil {
			output.Error = ctx.Err()
			break
		}

		targetRecord := execCtx.TargetMap[target]
		normTarget, _ := NormalizeTargetURL(target)
		if targetRecord.ID == "" {
			targetRecord = execCtx.TargetMap[normTarget]
		}

		actx := &workflow.AssessmentContext{
			AssessmentID: execCtx.Assessment.ID,
			ExecutionID:  execCtx.Execution.ID,
			BaseURL:      target,
			IsAllowed:    execCtx.ScopeValidator.IsAllowed,
			IsExcluded:   func(u string) bool { excluded, _ := execCtx.ScopeValidator.IsExcluded(u); return excluded },
		}

		results, summary, err := engine.Assess(ctx, actx)
		if err != nil {
			output.FailedTargets = append(output.FailedTargets, target)
			output.TargetErrors[target] = err.Error()
			continue
		}

		output.AssessedTargets = append(output.AssessedTargets, target)
		output.RequestCount += len(results)

		for _, res := range results {
			if res.Finding != nil {
				output.ReportFindings = append(output.ReportFindings, *res.Finding)
				output.AssessmentFindings = append(output.AssessmentFindings, ToAssessmentFinding(execCtx.Assessment.ID, execCtx.Execution.ID, targetRecord.ID, *res.Finding))
			}
		}

		if r.store != nil {
			_ = r.store.SaveWorkflowResults(results)
			if summary != nil {
				covJSON, _ := json.Marshal(summary.CategoryCoverageMap)
				runRec := &workflow.RunRecord{
					ID:                 uuid.New().String(),
					AssessmentID:       execCtx.Assessment.ID,
					ExecutionID:        execCtx.Execution.ID,
					TargetURL:          target,
					TotalWorkflows:     summary.TotalWorkflows,
					TotalChecks:        summary.TotalChecks,
					CategoriesAssessed: summary.CategoriesAssessed,
					VerifiedCount:      summary.VerifiedCount,
					CandidateCount:     summary.CandidateCount,
					NotVulnerableCount: summary.NotVulnerableCount,
					InconclusiveCount:  summary.InconclusiveCount,
					BlockedCount:       summary.BlockedCount,
					CoverageJSON:       string(covJSON),
					CreatedAt:          time.Now().UTC(),
				}
				_ = r.store.SaveWorkflowRun(runRec)
			}
		}
	}

	return output, output.Error
}

// --- 11. Full Runner ---

// FullRunner executes an aggregated multi-engine assessment combining web security, API security,
// web vulnerability auditing, and session security.
type FullRunner struct {
	registry *EngineRegistry
	store    Store
}

func (r *FullRunner) Capabilities() EngineCapabilities {
	return EngineCapabilities{
		AssessmentType:     AssessmentTypeFull,
		DisplayName:        "Full Multi-Engine Security Assessment",
		Aliases:            []string{"HYBRID", "ALL"},
		CoverageCategories: []string{"secrets", "api", "cloud", "auth", "webvuln", "headers", "cookies", "cors", "session", "businesslogic"},
		SupportsCheckpointResume: false,
		SupportsTargetIsolation:  true,
		SupportsCancellation:     true,
	}
}

func (r *FullRunner) Execute(ctx context.Context, execCtx *EngineExecutionContext) (*EngineExecutionOutput, error) {
	output := &EngineExecutionOutput{
		TargetErrors: make(map[string]string),
	}

	engineTypes := []string{
		AssessmentTypeWebSecurity,
		AssessmentTypeAPISecurity,
		AssessmentTypeWebVulnerability,
		AssessmentTypeSessionSecurity,
	}

	for _, engType := range engineTypes {
		if ctx.Err() != nil {
			output.Error = ctx.Err()
			break
		}

		runner, err := r.registry.Get(engType)
		if err != nil {
			continue
		}

		engOut, runErr := runner.Execute(ctx, execCtx)
		if engOut != nil {
			output.ReportFindings = append(output.ReportFindings, engOut.ReportFindings...)
			output.AssessmentFindings = append(output.AssessmentFindings, engOut.AssessmentFindings...)
			output.InventoryAssets = append(output.InventoryAssets, engOut.InventoryAssets...)
			output.InventoryRelations = append(output.InventoryRelations, engOut.InventoryRelations...)
			output.AuthSurfaces = append(output.AuthSurfaces, engOut.AuthSurfaces...)
			output.AuthCookies = append(output.AuthCookies, engOut.AuthCookies...)
			output.AuthTokens = append(output.AuthTokens, engOut.AuthTokens...)
			output.AuthProtectedEndpoints = append(output.AuthProtectedEndpoints, engOut.AuthProtectedEndpoints...)
			output.RequestCount += engOut.RequestCount

			for _, t := range engOut.AssessedTargets {
				found := false
				for _, at := range output.AssessedTargets {
					if at == t {
						found = true
						break
					}
				}
				if !found {
					output.AssessedTargets = append(output.AssessedTargets, t)
				}
			}
			for _, t := range engOut.FailedTargets {
				found := false
				for _, ft := range output.FailedTargets {
					if ft == t {
						found = true
						break
					}
				}
				if !found {
					output.FailedTargets = append(output.FailedTargets, t)
				}
			}
			for k, v := range engOut.TargetErrors {
				output.TargetErrors[k] = v
			}
		}
		if runErr != nil && output.Error == nil {
			output.Error = runErr
		}
	}

	return output, output.Error
}
