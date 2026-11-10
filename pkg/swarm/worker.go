package swarm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"felix/pkg/crawler"
	"felix/pkg/report"
)

// ScanHandlerFunc executes vulnerability checks for a given scan task.
type ScanHandlerFunc func(task ScanTask) ([]report.Finding, error)

// Worker represents a local loopback or distributed node executing tasks assigned by the master.
type Worker struct {
	id          string
	masterURL   string
	authToken   string
	httpClient  *http.Client
	scanHandler ScanHandlerFunc

	pollInterval      time.Duration
	heartbeatInterval time.Duration
	allowedDomains    []string

	activeTaskID atomic.Value // string
	killed       int32
	stopped      int32

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// WorkerConfig configures a loopback worker node.
type WorkerConfig struct {
	WorkerID          string
	MasterURL         string
	AuthToken         string
	PollInterval      time.Duration
	HeartbeatInterval time.Duration
	ScanHandler       ScanHandlerFunc
	AllowedDomains    []string
}

// NewWorker initializes a worker instance.
func NewWorker(cfg WorkerConfig) *Worker {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 50 * time.Millisecond
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 200 * time.Millisecond
	}

	ctx, cancel := context.WithCancel(context.Background())

	w := &Worker{
		id:                cfg.WorkerID,
		masterURL:         strings.TrimRight(cfg.MasterURL, "/"),
		authToken:         cfg.AuthToken,
		scanHandler:       cfg.ScanHandler,
		pollInterval:      cfg.PollInterval,
		heartbeatInterval: cfg.HeartbeatInterval,
		allowedDomains:    cfg.AllowedDomains,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		ctx:    ctx,
		cancel: cancel,
	}
	w.activeTaskID.Store("")
	return w
}

// ID returns the worker identifier.
func (w *Worker) ID() string {
	return w.id
}

// Register connects to the master coordinator and registers this worker node.
func (w *Worker) Register(ctx context.Context) error {
	reqBody := RegisterRequest{
		WorkerID:      w.id,
		WorkerAddress: fmt.Sprintf("loopback://%s", w.id),
		AuthToken:     w.authToken,
		Labels: map[string]string{
			"type": "loopback_agent",
		},
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.masterURL+"/api/v1/swarm/workers/register", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+w.authToken)
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("worker %s registration failed: %w", w.id, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("worker %s registration rejected (status %d): %s", w.id, resp.StatusCode, string(b))
	}

	return nil
}

// Start initiates worker background loops for heartbeat reporting and task execution.
func (w *Worker) Start(ctx context.Context) error {
	if err := w.Register(ctx); err != nil {
		return err
	}

	// 1. Heartbeat Loop
	w.wg.Add(1)
	go w.runHeartbeat()

	// 2. Task Polling & Execution Loop
	w.wg.Add(1)
	go w.runTaskLoop()

	return nil
}

// runHeartbeat periodically sends vitality attestation to the master coordinator.
func (w *Worker) runHeartbeat() {
	defer w.wg.Done()

	ticker := time.NewTicker(w.heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			if atomic.LoadInt32(&w.killed) == 1 {
				// Abruptly cease heartbeats
				return
			}
			w.sendHeartbeat()
		}
	}
}

func (w *Worker) sendHeartbeat() {
	activeID, _ := w.activeTaskID.Load().(string)
	reqBody := HeartbeatRequest{
		WorkerID:     w.id,
		AuthToken:    w.authToken,
		Timestamp:    time.Now().UTC(),
		ActiveTaskID: activeID,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(w.ctx, http.MethodPost, w.masterURL+"/api/v1/swarm/workers/heartbeat", bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if w.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+w.authToken)
	}

	resp, err := w.httpClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

// runTaskLoop continuously polls for scan assignments, executes them safely, and streams findings.
func (w *Worker) runTaskLoop() {
	defer w.wg.Done()

	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			if atomic.LoadInt32(&w.killed) == 1 {
				// Cease execution abruptly
				return
			}
			w.pollAndExecuteTask()
		}
	}
}

func (w *Worker) pollAndExecuteTask() {
	pollReq := TaskPollRequest{
		WorkerID:  w.id,
		AuthToken: w.authToken,
	}

	data, err := json.Marshal(pollReq)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(w.ctx, http.MethodPost, w.masterURL+"/api/v1/swarm/tasks/poll", bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if w.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+w.authToken)
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	var pollResp TaskPollResponse
	if err := json.NewDecoder(resp.Body).Decode(&pollResp); err != nil || !pollResp.HasTask || pollResp.Task == nil {
		return
	}

	task := pollResp.Task
	w.activeTaskID.Store(task.ID)
	defer w.activeTaskID.Store("")

	if atomic.LoadInt32(&w.killed) == 1 {
		return // Abruptly die mid-scan
	}

	// 1. Worker Independent Scope Enforcement (Defense-in-depth safety guardrail)
	if _, err := crawler.ValidateTargetURL(task.TargetURL); err != nil {
		w.reportTaskCompletion(task.ID, false, fmt.Sprintf("scope violation: %v", err), 0, 0)
		return
	}
	if len(w.allowedDomains) > 0 {
		parsed, _ := url.Parse(task.TargetURL)
		allowed := false
		for _, dom := range w.allowedDomains {
			if parsed.Hostname() == dom || strings.HasSuffix(parsed.Hostname(), "."+dom) {
				allowed = true
				break
			}
		}
		if !allowed {
			w.reportTaskCompletion(task.ID, false, fmt.Sprintf("scope domain %s rejected by worker policy", parsed.Hostname()), 0, 0)
			return
		}
	}

	start := time.Now()
	var findings []report.Finding

	if w.scanHandler != nil {
		fnds, scanErr := w.scanHandler(*task)
		if scanErr != nil {
			durationMs := float64(time.Since(start).Microseconds()) / 1000.0
			w.reportTaskCompletion(task.ID, false, scanErr.Error(), durationMs, 0)
			return
		}
		findings = fnds
	}

	// Check if killed during scan execution
	if atomic.LoadInt32(&w.killed) == 1 {
		return
	}

	durationMs := float64(time.Since(start).Microseconds()) / 1000.0

	// 2. Stream findings to master writer
	if len(findings) > 0 {
		if err := w.submitFindings(task.ID, findings); err != nil {
			w.reportTaskCompletion(task.ID, false, fmt.Sprintf("finding submission failed: %v", err), durationMs, 0)
			return
		}
	}

	// Check if killed prior to completion report
	if atomic.LoadInt32(&w.killed) == 1 {
		return
	}

	// 3. Report completion
	w.reportTaskCompletion(task.ID, true, "", durationMs, len(findings))
}

// submitFindings streams a batch of findings to the master coordinator.
func (w *Worker) submitFindings(taskID string, findings []report.Finding) error {
	sub := FindingSubmission{
		WorkerID:     w.id,
		AuthToken:    w.authToken,
		TaskID:       taskID,
		SubmissionID: fmt.Sprintf("SUB-%s-%s-%d", w.id, taskID, time.Now().UnixNano()),
		Findings:     findings,
	}

	data, err := json.Marshal(sub)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(w.ctx, http.MethodPost, w.masterURL+"/api/v1/swarm/findings", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+w.authToken)
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("finding submission failed (status %d): %s", resp.StatusCode, string(b))
	}

	return nil
}

// reportTaskCompletion informs the master coordinator of task completion or failure.
func (w *Worker) reportTaskCompletion(taskID string, success bool, errMsg string, durationMs float64, count int) {
	reqBody := TaskCompleteRequest{
		WorkerID:       w.id,
		AuthToken:      w.authToken,
		TaskID:         taskID,
		Success:        success,
		ErrorMessage:   errMsg,
		ScanDurationMs: durationMs,
		FindingsCount:  count,
		CompletedAt:    time.Now().UTC(),
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(w.ctx, http.MethodPost, w.masterURL+"/api/v1/swarm/tasks/complete", bytes.NewReader(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if w.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+w.authToken)
	}

	resp, err := w.httpClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

// Kill simulates an abrupt crash, OOM kill, or power failure of the worker node.
// Ceases heartbeats and execution loops immediately without unregistering.
func (w *Worker) Kill() {
	atomic.StoreInt32(&w.killed, 1)
	w.cancel()
}

// Reconnect restarts a previously killed worker and re-registers it with the master.
func (w *Worker) Reconnect(ctx context.Context) error {
	w.wg.Wait()
	atomic.StoreInt32(&w.killed, 0)
	w.ctx, w.cancel = context.WithCancel(context.Background())
	return w.Start(ctx)
}

// Stop gracefully terminates the worker.
func (w *Worker) Stop() {
	if atomic.CompareAndSwapInt32(&w.stopped, 0, 1) {
		w.cancel()
		w.wg.Wait()
	}
}
