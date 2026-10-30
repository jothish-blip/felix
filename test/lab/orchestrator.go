package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/discovery"

	"github.com/google/uuid"
)

// Orchestrator coordinates local test fixture servers, CLI subprocess executions,
// ground-truth verification, and structured test result collection.
type Orchestrator struct {
	RepoRoot      string
	BinPath       string
	ResultsPath   string
	tempDirs      []string
	fixtures      []interface{ Close() }
	mu            sync.Mutex
	report        LabExecutionReport
}

// NewOrchestrator creates a new local lab orchestrator.
func NewOrchestrator(repoRoot string) (*Orchestrator, error) {
	absRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("invalid repo root: %w", err)
	}

	binName := "felix"
	if os.PathSeparator == '\\' {
		binName = "felix.exe"
	}
	binPath := filepath.Join(absRoot, "bin", binName)

	resultsPath := filepath.Join(absRoot, "test", "lab", "lab_results.json")

	report := LabExecutionReport{
		GeneratedAt: time.Now().UTC(),
		Results:     []TestCaseContract{},
	}

	if data, err := os.ReadFile(resultsPath); err == nil && len(data) > 0 {
		var existing LabExecutionReport
		if err := json.Unmarshal(data, &existing); err == nil {
			report = existing
		}
	}

	return &Orchestrator{
		RepoRoot:    absRoot,
		BinPath:     binPath,
		ResultsPath: resultsPath,
		report:      report,
	}, nil
}

// EnsureBinary builds the felix CLI binary if missing.
func (o *Orchestrator) EnsureBinary() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if _, err := os.Stat(o.BinPath); err == nil {
		return nil
	}

	binDir := filepath.Dir(o.BinPath)
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return fmt.Errorf("failed to create bin dir: %w", err)
	}

	cmd := exec.Command("go", "build", "-o", o.BinPath, filepath.Join(o.RepoRoot, "cmd", "felix"))
	cmd.Dir = o.RepoRoot
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to compile felix binary: %w, output: %s", err, string(out))
	}
	return nil
}

// ValidateScope checks that the given target URL is strictly loopback (127.0.0.1 or localhost).
// If a target points outside loopback, it fails closed to prevent unintended network access.
func (o *Orchestrator) ValidateScope(targetURL string) error {
	u, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	hostname := u.Hostname()
	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
		return nil
	}

	ip := net.ParseIP(hostname)
	if ip != nil && ip.IsLoopback() {
		return nil
	}

	return fmt.Errorf("SECURITY REFUSAL: Target %q is outside authorized local test scope (strictly 127.0.0.1 / localhost)", targetURL)
}

// SetupTestAssessment creates an isolated temporary SQLite database and populates
// the assessment, target, and approved authorization record for the test run.
func (o *Orchestrator) SetupTestAssessment(targetURL string, asmRef string) (dbPath string, cleanup func(), err error) {
	if err := o.ValidateScope(targetURL); err != nil {
		return "", nil, err
	}

	tempDir, err := os.MkdirTemp("", "felix-lab-*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	o.mu.Lock()
	o.tempDirs = append(o.tempDirs, tempDir)
	o.mu.Unlock()

	dbPath = filepath.Join(tempDir, "felix_lab.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return "", nil, fmt.Errorf("failed to initialize SQLite store: %w", err)
	}

	client := assessment.Client{
		ID:        "client-lab-test",
		Name:      "Lab Test Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(&client)

	asm := assessment.Assessment{
		ID:        "asm-" + strings.ToLower(asmRef),
		Ref:       asmRef,
		ClientID:  client.ID,
		Name:      "Lab BOLA Verification Assessment",
		Status:    assessment.StatusDraft,
		ScopeMode: "explicit",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateAssessment(&asm); err != nil {
		store.Close()
		_ = os.RemoveAll(tempDir)
		return "", nil, fmt.Errorf("failed to create assessment record: %w", err)
	}

	target := assessment.AssessmentTarget{
		ID:           "target-lab-1",
		AssessmentID: asm.ID,
		TargetURL:    targetURL,
		ScopeStatus:  "APPROVED",
		CreatedAt:    time.Now().UTC(),
	}
	_ = store.AddTarget(&target)

	// Approved authorization record
	past := time.Now().UTC().Add(-1 * time.Hour)
	future := time.Now().UTC().Add(24 * time.Hour)
	authRec := assessment.AuthorizationRecord{
		ID:                  "auth-lab-1",
		AssessmentID:        asm.ID,
		AuthorizingParty:    "Security Assessment Lab Lead",
		AuthorizationMethod: "Written Lab Authorization",
		Status:              assessment.AuthApproved,
		ValidFrom:           &past,
		ValidUntil:          &future,
		DateReceived:        past,
		CreatedAt:           time.Now().UTC(),
		UpdatedAt:           time.Now().UTC(),
	}
	_ = store.SetAuthorization(&authRec)
	store.Close()

	cleanup = func() {
		_ = os.RemoveAll(tempDir)
	}

	return dbPath, cleanup, nil
}

// LabEndpoint defines an endpoint to seed into assessment inventory.
type LabEndpoint struct {
	Method     string
	Path       string
	Parameters []string
}

// SetupTestAssessmentWithEndpoints creates an isolated assessment and seeds the specified endpoints as inventory assets.
func (o *Orchestrator) SetupTestAssessmentWithEndpoints(targetURL string, asmRef string, endpoints []LabEndpoint) (dbPath string, cleanup func(), err error) {
	if err := o.ValidateScope(targetURL); err != nil {
		return "", nil, err
	}

	tempDir, err := os.MkdirTemp("", "felix-lab-*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	o.mu.Lock()
	o.tempDirs = append(o.tempDirs, tempDir)
	o.mu.Unlock()

	dbPath = filepath.Join(tempDir, "felix_lab.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return "", nil, fmt.Errorf("failed to initialize SQLite store: %w", err)
	}

	client := assessment.Client{
		ID:        "client-lab-test",
		Name:      "Lab Test Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	_ = store.CreateClient(&client)

	asm := assessment.Assessment{
		ID:        "asm-" + strings.ToLower(asmRef),
		Ref:       asmRef,
		ClientID:  client.ID,
		Name:      "Lab Verification Assessment",
		Status:    assessment.StatusDraft,
		ScopeMode: "explicit",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateAssessment(&asm); err != nil {
		store.Close()
		_ = os.RemoveAll(tempDir)
		return "", nil, fmt.Errorf("failed to create assessment record: %w", err)
	}

	target := assessment.AssessmentTarget{
		ID:           "target-lab-1",
		AssessmentID: asm.ID,
		TargetURL:    targetURL,
		ScopeStatus:  "APPROVED",
		CreatedAt:    time.Now().UTC(),
	}
	_ = store.AddTarget(&target)

	// Approved authorization record
	past := time.Now().UTC().Add(-1 * time.Hour)
	future := time.Now().UTC().Add(24 * time.Hour)
	authRec := assessment.AuthorizationRecord{
		ID:                  "auth-lab-1",
		AssessmentID:        asm.ID,
		AuthorizingParty:    "Security Assessment Lab Lead",
		AuthorizationMethod: "Written Lab Authorization",
		Status:              assessment.AuthApproved,
		ValidFrom:           &past,
		ValidUntil:          &future,
		DateReceived:        past,
		CreatedAt:           time.Now().UTC(),
		UpdatedAt:           time.Now().UTC(),
	}
	_ = store.SetAuthorization(&authRec)

	execRecord := &assessment.AssessmentExecution{
		ID:           "exec-init-" + uuid.New().String(),
		AssessmentID: asm.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    past,
	}
	if err := store.CreateExecution(execRecord); err != nil {
		store.Close()
		_ = os.RemoveAll(tempDir)
		return "", nil, fmt.Errorf("failed to create execution record: %w", err)
	}

	if len(endpoints) > 0 {
		var assets []discovery.Asset
		now := time.Now().UTC()
		for _, ep := range endpoints {
			method := strings.ToUpper(ep.Method)
			if method == "" {
				method = "GET"
			}
			var paramsAny []any
			for _, p := range ep.Parameters {
				paramsAny = append(paramsAny, p)
			}
			asset := discovery.Asset{
				ID:              "asset-" + uuid.New().String(),
				AssessmentID:    asm.ID,
				ExecutionID:     execRecord.ID,
				TargetID:        target.ID,
				Type:            discovery.AssetTypeEndpoint,
				DisplayName:     ep.Path,
				CanonicalID:     fmt.Sprintf("%s %s", method, ep.Path),
				DiscoveryMethod: "LAB_FIXTURE",
				DiscoveryStatus: discovery.StatusObserved,
				Confidence:      discovery.ConfidenceHigh,
				InScope:         true,
				Metadata: map[string]any{
					"method": method,
					"path":   ep.Path,
					"params": paramsAny,
				},
				FirstSeen: now,
				LastSeen:  now,
			}
			assets = append(assets, asset)
		}
		if err := store.SaveInventory(assets, nil); err != nil {
			store.Close()
			_ = os.RemoveAll(tempDir)
			return "", nil, fmt.Errorf("failed to save inventory assets: %w", err)
		}
	}

	store.Close()

	cleanup = func() {
		_ = os.RemoveAll(tempDir)
	}

	return dbPath, cleanup, nil
}

// RunSubprocess executes a felix CLI command as a subprocess with custom env and args.
func (o *Orchestrator) RunSubprocess(ctx context.Context, env map[string]string, args ...string) (stdout, stderr string, exitCode int, duration time.Duration, err error) {
	if err := o.EnsureBinary(); err != nil {
		return "", "", -1, 0, err
	}

	cmd := exec.CommandContext(ctx, o.BinPath, args...)
	cmd.Dir = o.RepoRoot

	// Build environment
	fullEnv := os.Environ()
	fullEnv = append(fullEnv, "FELIX_ALLOW_LOOPBACK=true")
	for k, v := range env {
		fullEnv = append(fullEnv, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = fullEnv

	var stdoutBuf, stderrBuf strings.Builder
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	start := time.Now()
	runErr := cmd.Run()
	duration = time.Since(start)

	stdout = stdoutBuf.String()
	stderr = stderrBuf.String()

	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
			err = runErr
		}
	} else {
		exitCode = 0
	}

	return stdout, stderr, exitCode, duration, err
}

// RecordTestCase records an evaluated test case result into the lab report.
func (o *Orchestrator) RecordTestCase(tc TestCaseContract) {
	o.mu.Lock()
	defer o.mu.Unlock()

	tc.ExecutedAt = time.Now().UTC()

	found := false
	for i, r := range o.report.Results {
		if r.TestID == tc.TestID {
			o.report.Results[i] = tc
			found = true
			break
		}
	}
	if !found {
		o.report.Results = append(o.report.Results, tc)
	}

	// Recalculate totals
	var passed, failed, blocked, notTested int
	for _, r := range o.report.Results {
		switch r.Status {
		case StatusPass:
			passed++
		case StatusFail:
			failed++
		case StatusBlocked:
			blocked++
		case StatusNotTested:
			notTested++
		}
	}
	o.report.Passed = passed
	o.report.Failed = failed
	o.report.Blocked = blocked
	o.report.NotTested = notTested
	o.report.TotalCases = len(o.report.Results)
}

// SaveReport writes the structured lab results to test/lab/lab_results.json.
func (o *Orchestrator) SaveReport() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.report.GeneratedAt = time.Now().UTC()
	data, err := json.MarshalIndent(o.report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize lab results: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(o.ResultsPath), 0755); err != nil {
		return fmt.Errorf("failed to create results directory: %w", err)
	}

	if err := os.WriteFile(o.ResultsPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write lab results file: %w", err)
	}

	return nil
}

// RegisterFixture registers a fixture server for cleanup.
func (o *Orchestrator) RegisterFixture(f interface{ Close() }) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.fixtures = append(o.fixtures, f)
}

// Cleanup cleans up all temporary resources, directories, and fixture servers.
func (o *Orchestrator) Cleanup() {
	o.mu.Lock()
	defer o.mu.Unlock()

	for _, f := range o.fixtures {
		if f != nil {
			f.Close()
		}
	}
	o.fixtures = nil

	for _, d := range o.tempDirs {
		_ = os.RemoveAll(d)
	}
	o.tempDirs = nil
}
