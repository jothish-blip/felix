package swarm

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"felix/pkg/crawler"
)

// Coordinator is the master swarm coordinator orchestrating distributed loopback worker nodes,
// managing task queues, detecting node failures via heartbeats, and reassigning uncompleted tasks.
type Coordinator struct {
	cfg       CoordinatorConfig
	writer    *WALWriter
	server    *http.Server
	listener  net.Listener
	serverURL string

	mu      sync.RWMutex
	workers map[string]*WorkerNode
	tasks   map[string]*ScanTask
	taskQ   []string // FIFO queue of pending task IDs

	metrics SwarmMetrics
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	closed  int32
}

// NewCoordinator initializes the master coordinator, configures the single-writer WAL engine,
// and starts the lightweight REST API on local loopback.
func NewCoordinator(cfg CoordinatorConfig, writer *WALWriter) (*Coordinator, error) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:0"
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 250 * time.Millisecond
	}
	if cfg.HeartbeatTimeout <= 0 {
		cfg.HeartbeatTimeout = 1000 * time.Millisecond
	}
	if cfg.ReaperInterval <= 0 {
		cfg.ReaperInterval = 200 * time.Millisecond
	}
	if cfg.MaxTaskRetries <= 0 {
		cfg.MaxTaskRetries = 3
	}

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed listening on %s: %w", cfg.ListenAddr, err)
	}

	serverURL := fmt.Sprintf("http://%s", listener.Addr().String())
	ctx, cancel := context.WithCancel(context.Background())

	c := &Coordinator{
		cfg:       cfg,
		writer:    writer,
		listener:  listener,
		serverURL: serverURL,
		workers:   make(map[string]*WorkerNode),
		tasks:     make(map[string]*ScanTask),
		taskQ:     make([]string, 0),
		ctx:       ctx,
		cancel:    cancel,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/swarm/workers/register", c.handleRegister)
	mux.HandleFunc("/api/v1/swarm/workers/heartbeat", c.handleHeartbeat)
	mux.HandleFunc("/api/v1/swarm/tasks/poll", c.handleTaskPoll)
	mux.HandleFunc("/api/v1/swarm/tasks/complete", c.handleTaskComplete)
	mux.HandleFunc("/api/v1/swarm/findings", c.handleFindings)
	mux.HandleFunc("/api/v1/swarm/metrics", c.handleMetrics)
	mux.HandleFunc("/api/v1/swarm/status", c.handleStatus)

	c.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Launch HTTP Server
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		if err := c.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			// server closed
		}
	}()

	// Launch Worker Failure Reaper Loop
	c.wg.Add(1)
	go c.runReaper()

	return c, nil
}

// URL returns the dynamic loopback address of the master coordinator HTTP server.
func (c *Coordinator) URL() string {
	return c.serverURL
}

// AddTask enqueues a new scan task onto the coordinator after validating scope.
func (c *Coordinator) AddTask(t ScanTask) error {
	if atomic.LoadInt32(&c.closed) == 1 {
		return ErrCoordinatorClosed
	}

	// 1. Validate Target URL Syntax & Basic Security Rules
	if _, err := crawler.ValidateTargetURL(t.TargetURL); err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	// 2. Validate Scope Boundaries (if configured)
	if len(c.cfg.ScopeTargets) > 0 {
		parsedTarget, _ := url.Parse(t.TargetURL)
		inScope := false
		for _, s := range c.cfg.ScopeTargets {
			parsedScope, err := url.Parse(s)
			if err == nil && parsedScope.Hostname() == parsedTarget.Hostname() {
				inScope = true
				break
			}
		}
		if !inScope {
			return fmt.Errorf("%w: target %s outside configured scope %v", ErrScopeViolation, t.TargetURL, c.cfg.ScopeTargets)
		}
	}

	if t.ID == "" {
		t.ID = fmt.Sprintf("TASK-%d", time.Now().UnixNano())
	}
	if t.MaxRetries <= 0 {
		t.MaxRetries = c.cfg.MaxTaskRetries
	}
	t.Status = TaskStatusPending

	c.mu.Lock()
	defer c.mu.Unlock()

	c.tasks[t.ID] = &t
	c.taskQ = append(c.taskQ, t.ID)
	c.metrics.TotalTasksDistributed++

	return nil
}

// AddTasks bulk enqueues multiple scan tasks.
func (c *Coordinator) AddTasks(tasks []ScanTask) error {
	for _, t := range tasks {
		if err := c.AddTask(t); err != nil {
			return err
		}
	}
	return nil
}

// runReaper periodically inspects worker nodes for missed heartbeats,
// marks dead workers, and reassigns interrupted scanning tasks.
func (c *Coordinator) runReaper() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.cfg.ReaperInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.checkWorkerHeartbeats()
		}
	}
}

// checkWorkerHeartbeats identifies stale workers and reassigns their pending tasks.
func (c *Coordinator) checkWorkerHeartbeats() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for _, w := range c.workers {
		if w.Status == WorkerStatusDead {
			continue
		}

		if now.Sub(w.LastHeartbeat) > c.cfg.HeartbeatTimeout {
			w.Status = WorkerStatusDead
			c.metrics.WorkerFailuresDetected++

			// Check if worker had an active in-flight task
			if w.ActiveTaskID != "" {
				task, exists := c.tasks[w.ActiveTaskID]
				if exists && task.Status != TaskStatusCompleted {
					w.FailedTasks++
					c.reclaimTaskLocked(task, fmt.Sprintf("worker %s heartbeat timed out (>%v)", w.ID, c.cfg.HeartbeatTimeout))
				}
				w.ActiveTaskID = ""
			}
		}
	}
}

// reclaimTaskLocked reclaims an unfinished task and requeues it for another worker.
func (c *Coordinator) reclaimTaskLocked(task *ScanTask, reason string) {
	if task.RetryCount < task.MaxRetries {
		task.Status = TaskStatusPending
		task.AssignedWorkerID = ""
		task.RetryCount++
		c.taskQ = append(c.taskQ, task.ID) // Requeue at back of FIFO queue
		c.metrics.TasksReassigned++
	} else {
		task.Status = TaskStatusFailed
		c.metrics.TasksFailed++
	}
}

// authenticate verifies the incoming HTTP request bearer token.
func (c *Coordinator) authenticate(r *http.Request) bool {
	if c.cfg.AuthToken == "" {
		return true
	}
	authHeader := r.Header.Get("Authorization")
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1] == c.cfg.AuthToken
	}
	return false
}

// HTTP Handlers

func (c *Coordinator) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !c.authenticate(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.WorkerID == "" {
		http.Error(w, "worker_id required", http.StatusBadRequest)
		return
	}

	c.mu.Lock()
	now := time.Now()
	node, exists := c.workers[req.WorkerID]
	if !exists {
		node = &WorkerNode{
			ID:           req.WorkerID,
			Address:      req.WorkerAddress,
			Status:       WorkerStatusOnline,
			LastHeartbeat: now,
			RegisteredAt: now,
			Labels:       req.Labels,
		}
		c.workers[req.WorkerID] = node
		c.metrics.TotalRegisteredWorkers++
	} else {
		// Worker reconnected / re-registered
		node.Status = WorkerStatusOnline
		node.Address = req.WorkerAddress
		node.LastHeartbeat = now
	}
	c.mu.Unlock()

	resp := RegisterResponse{
		Accepted:          true,
		HeartbeatInterval: c.cfg.HeartbeatInterval,
		Message:           "Registration accepted",
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (c *Coordinator) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !c.authenticate(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req HeartbeatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	c.mu.Lock()
	node, exists := c.workers[req.WorkerID]
	if !exists {
		c.mu.Unlock()
		http.Error(w, ErrWorkerNotFound.Error(), http.StatusNotFound)
		return
	}

	node.LastHeartbeat = time.Now()
	if node.Status == WorkerStatusDead || node.Status == WorkerStatusUnresponsive {
		node.Status = WorkerStatusOnline
	}
	if req.ActiveTaskID != "" {
		node.ActiveTaskID = req.ActiveTaskID
	}
	c.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(HeartbeatResponse{Acknowledged: true})
}

func (c *Coordinator) handleTaskPoll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !c.authenticate(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req TaskPollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	c.mu.Lock()
	node, exists := c.workers[req.WorkerID]
	if !exists {
		c.mu.Unlock()
		http.Error(w, ErrWorkerNotFound.Error(), http.StatusNotFound)
		return
	}

	// Dequeue next pending task
	var selectedTask *ScanTask
	for len(c.taskQ) > 0 {
		taskID := c.taskQ[0]
		c.taskQ = c.taskQ[1:]

		t, found := c.tasks[taskID]
		if found && t.Status == TaskStatusPending {
			selectedTask = t
			break
		}
	}

	if selectedTask != nil {
		selectedTask.Status = TaskStatusAssigned
		selectedTask.AssignedWorkerID = req.WorkerID
		selectedTask.AssignedAt = time.Now()
		node.ActiveTaskID = selectedTask.ID
		node.Status = WorkerStatusBusy
	} else {
		node.ActiveTaskID = ""
		node.Status = WorkerStatusOnline
	}
	c.mu.Unlock()

	resp := TaskPollResponse{
		HasTask: selectedTask != nil,
		Task:    selectedTask,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (c *Coordinator) handleTaskComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !c.authenticate(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req TaskCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	c.mu.Lock()
	task, exists := c.tasks[req.TaskID]
	if !exists {
		c.mu.Unlock()
		http.Error(w, ErrTaskNotFound.Error(), http.StatusNotFound)
		return
	}

	if req.Success {
		task.Status = TaskStatusCompleted
		task.CompletedAt = time.Now()
		c.metrics.TasksCompletedSuccessfully++
	} else {
		c.reclaimTaskLocked(task, req.ErrorMessage)
	}

	if node, ok := c.workers[req.WorkerID]; ok {
		if req.Success {
			node.CompletedTasks++
		} else {
			node.FailedTasks++
		}
		if node.ActiveTaskID == req.TaskID {
			node.ActiveTaskID = ""
			node.Status = WorkerStatusOnline
		}
	}
	c.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(TaskCompleteResponse{Acknowledged: true})
}

func (c *Coordinator) handleFindings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !c.authenticate(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req FindingSubmission
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	accepted := 0
	dropped := 0
	for _, f := range req.Findings {
		err := c.writer.Submit(f)
		if err != nil {
			if err == ErrQueueFull {
				// Signal backpressure to worker
				http.Error(w, "Swarm queue at capacity (backpressure active)", http.StatusTooManyRequests)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		accepted++
	}

	resp := FindingSubmissionResponse{
		AcceptedCount: accepted,
		DroppedCount:  dropped,
		Status:        "ACCEPTED",
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (c *Coordinator) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := c.GetMetrics()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metrics)
}

func (c *Coordinator) handleStatus(w http.ResponseWriter, r *http.Request) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	status := map[string]interface{}{
		"active_workers":   len(c.workers),
		"pending_tasks":    len(c.taskQ),
		"total_tasks":      len(c.tasks),
		"server_url":       c.serverURL,
		"metrics":          c.GetMetrics(),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

// GetMetrics returns combined cluster coordinator and WALWriter metrics.
func (c *Coordinator) GetMetrics() SwarmMetrics {
	c.mu.RLock()
	m := c.metrics
	activeCount := 0
	for _, w := range c.workers {
		if w.Status == WorkerStatusOnline || w.Status == WorkerStatusBusy {
			activeCount++
		}
	}
	m.ActiveWorkers = activeCount
	m.TotalRegisteredWorkers = len(c.workers)
	c.mu.RUnlock()

	if c.writer != nil {
		wm := c.writer.GetMetrics()
		m.TotalFindingsReceived = wm.TotalFindingsReceived
		m.TotalFindingsPersisted = wm.TotalFindingsPersisted
		m.DuplicateFindingsDropped = wm.DuplicateFindingsDropped
		m.BatchesCommitted = wm.BatchesCommitted
		m.SQLiteBusyErrors = wm.SQLiteBusyErrors
		m.TotalBatchDurationMs = wm.TotalBatchDurationMs
		m.ThroughputFindingsPerSecond = wm.ThroughputFindingsPerSecond
	}

	return m
}

// GetTask returns a copy of a scan task by ID.
func (c *Coordinator) GetTask(id string) (*ScanTask, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	t, found := c.tasks[id]
	if !found {
		return nil, false
	}
	cp := *t
	return &cp, true
}

// Shutdown gracefully shuts down the coordinator HTTP server, stops worker monitoring,
// and drains all remaining findings through the single-writer WAL engine.
func (c *Coordinator) Shutdown(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return nil
	}

	c.cancel()
	_ = c.server.Shutdown(ctx)
	c.wg.Wait()

	if c.writer != nil {
		return c.writer.DrainAndClose(ctx)
	}
	return nil
}
