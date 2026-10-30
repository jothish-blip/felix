package fuzzer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPool_HardUpperBoundConcurrency(t *testing.T) {
	concurrencyCap := 8
	var activeGoroutines atomic.Int64
	var maxObserved atomic.Int64

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := activeGoroutines.Add(1)
		defer activeGoroutines.Add(-1)

		for {
			max := maxObserved.Load()
			if current <= max {
				break
			}
			if maxObserved.CompareAndSwap(max, current) {
				break
			}
		}

		// Hold request briefly to ensure multiple workers overlap
		time.Sleep(20 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	cfg := DefaultPoolConfig()
	cfg.Workers = concurrencyCap
	cfg.BaseTransport = ts.Client().Transport
	pool := NewFuzzingPool(cfg)
	defer pool.Close()

	taskCount := 50
	tasks := make([]FuzzTask, taskCount)
	for i := 0; i < taskCount; i++ {
		req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
		tasks[i] = FuzzTask{
			ID:      fmt.Sprintf("task-%d", i),
			Request: req,
		}
	}

	results, err := pool.Dispatch(context.Background(), tasks)
	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}

	if len(results) != taskCount {
		t.Fatalf("Expected %d results, got %d", taskCount, len(results))
	}

	observedPeak := maxObserved.Load()
	t.Logf("Configured Workers: %d, Observed Peak Concurrency: %d", concurrencyCap, observedPeak)

	if observedPeak > int64(concurrencyCap) {
		t.Fatalf("Concurrency cap violated: observed %d concurrent requests, max allowed was %d", observedPeak, concurrencyCap)
	}

	stats := pool.Stats()
	if stats.PeakConcurrency > int64(concurrencyCap) {
		t.Fatalf("Pool internal peak concurrency violated cap: %d > %d", stats.PeakConcurrency, concurrencyCap)
	}
}

func TestPool_TaskCompletionWithoutLossOrDuplication(t *testing.T) {
	var processedTasks sync.Map
	taskCount := 100

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if _, loaded := processedTasks.LoadOrStore(id, true); loaded {
			t.Errorf("Duplicate processing detected for task ID: %s", id)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "DONE")
	}))
	defer ts.Close()

	cfg := DefaultPoolConfig()
	cfg.Workers = 15
	cfg.BaseTransport = ts.Client().Transport
	pool := NewFuzzingPool(cfg)
	defer pool.Close()

	tasks := make([]FuzzTask, taskCount)
	for i := 0; i < taskCount; i++ {
		taskID := fmt.Sprintf("work-%03d", i)
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s?id=%s", ts.URL, taskID), nil)
		tasks[i] = FuzzTask{
			ID:      taskID,
			Request: req,
		}
	}

	results, err := pool.Dispatch(context.Background(), tasks)
	if err != nil {
		t.Fatalf("Dispatch returned error: %v", err)
	}

	completedCount := 0
	for _, res := range results {
		if res.Error != nil {
			t.Errorf("Task %s failed: %v", res.TaskID, res.Error)
		} else if res.StatusCode == http.StatusOK {
			completedCount++
		}
	}

	if completedCount != taskCount {
		t.Fatalf("Task loss detected: completed %d / %d tasks", completedCount, taskCount)
	}

	stats := pool.Stats()
	if stats.TotalCompleted != int64(taskCount) {
		t.Fatalf("Stats TotalCompleted mismatch: expected %d, got %d", taskCount, stats.TotalCompleted)
	}
}

func TestPool_ContextCancellationAndDeadlines(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := DefaultPoolConfig()
	cfg.Workers = 5
	cfg.BaseTransport = ts.Client().Transport
	pool := NewFuzzingPool(cfg)
	defer pool.Close()

	// Cancel context after 50ms
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	tasks := make([]FuzzTask, 20)
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
		tasks[i] = FuzzTask{
			ID:      fmt.Sprintf("cancel-task-%d", i),
			Request: req,
		}
	}

	results, _ := pool.Dispatch(ctx, tasks)
	cancelledCount := 0
	for _, res := range results {
		if res.Error != nil {
			cancelledCount++
		}
	}

	if cancelledCount == 0 {
		t.Fatalf("Expected cancellation errors for timed out tasks, got 0")
	}
	t.Logf("Prompt context cancellation verified: %d tasks terminated early", cancelledCount)
}

func TestPool_AdaptiveRateLimiter_429BackoffAndRecovery(t *testing.T) {
	var requestCount atomic.Int64
	var throttledCount atomic.Int64
	totalTasks := 100

	// Server simulates a burst of HTTP 429 Too Many Requests for the first 15 requests
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := requestCount.Add(1)
		if count <= 15 {
			throttledCount.Add(1)
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, "Rate limit exceeded")
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	cfg := DefaultPoolConfig()
	cfg.Workers = 10
	cfg.MinWorkers = 2
	cfg.BackoffBase = 10 * time.Millisecond
	cfg.MaxBackoff = 100 * time.Millisecond
	cfg.BaseTransport = ts.Client().Transport
	pool := NewFuzzingPool(cfg)
	defer pool.Close()

	tasks := make([]FuzzTask, totalTasks)
	for i := 0; i < totalTasks; i++ {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s?req=%d", ts.URL, i), nil)
		tasks[i] = FuzzTask{
			ID:      fmt.Sprintf("adapt-%d", i),
			Request: req,
		}
	}

	start := time.Now()
	results, err := pool.Dispatch(context.Background(), tasks)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}

	// Assert: Exactly 0 lost requests (all 100 tasks must succeed)
	successCount := 0
	for _, res := range results {
		if res.StatusCode == http.StatusOK && res.Error == nil {
			successCount++
		} else {
			t.Errorf("Task %s failed: status=%d, err=%v", res.TaskID, res.StatusCode, res.Error)
		}
	}

	if successCount != totalTasks {
		t.Fatalf("Lost requests under 429 throttling: %d / %d completed", successCount, totalTasks)
	}

	stats := pool.Stats()
	t.Logf("=== 429 BACKOFF & RECOVERY METRICS ===")
	t.Logf("  Total Tasks Dispatched : %d", stats.TotalDispatched)
	t.Logf("  Total Tasks Completed  : %d", stats.TotalCompleted)
	t.Logf("  Total 429s Received    : %d", stats.TotalThrottled)
	t.Logf("  Total Retries Executed : %d", stats.TotalRetried)
	t.Logf("  Total Failed Requests  : %d (0 lost requests)", stats.TotalFailed)
	t.Logf("  Elapsed Time           : %v", elapsed)

	if stats.TotalThrottled == 0 {
		t.Fatal("Expected at least one 429 response to trigger backoff")
	}
	if stats.TotalRetried == 0 {
		t.Fatal("Expected retries to recover throttled requests")
	}
	if stats.TotalFailed != 0 {
		t.Fatalf("Expected 0 total failed requests, got %d", stats.TotalFailed)
	}
}

func TestPool_BlocksCloudMetadataSSRF(t *testing.T) {
	cfg := DefaultPoolConfig()
	pool := NewFuzzingPool(cfg)
	defer pool.Close()

	metadataURLs := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://[fd00:ec2::254]/latest/meta-data/",
	}

	for _, u := range metadataURLs {
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		_, err := pool.Client().Do(req)
		if err == nil {
			t.Fatalf("Expected request to cloud metadata %s to be blocked, but succeeded", u)
		}
		t.Logf("Verified blocked metadata request: %s -> %v", u, err)
	}
}

func TestPool_DetectorCompatibility(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html><body>Hello World</body></html>")
	}))
	defer ts.Close()

	cfg := DefaultPoolConfig()
	cfg.Workers = 5
	cfg.BaseTransport = ts.Client().Transport
	pool := NewFuzzingPool(cfg)
	defer pool.Close()

	pe := NewParameterExtractor()

	// Verify all Phase 2 analyzers accept pool.Client() without breaking interfaces
	_ = NewSQLiAnalyzer(pool.Client(), pe)
	_ = NewXSSAnalyzer(pool.Client(), pe)
	_ = NewTraversalAnalyzer(pool.Client(), pe)
	_ = NewRCEAnalyzer(pool.Client(), pe)
	_ = NewSSTIAnalyzer(pool.Client(), pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?param=test", nil)
	resp, err := pool.Client().Do(req)
	if err != nil {
		t.Fatalf("Failed to execute request with detector client: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Unexpected status: %d", resp.StatusCode)
	}
	t.Logf("Detector client compatibility verified with pool transport")
}

// TestPool_RatePacing_ZeroLockContention verifies that per-host rate pacing releases
// the transport mutex before sleeping, preventing deadlock or thread starvation across hosts.
func TestPool_RatePacing_ZeroLockContention(t *testing.T) {
	tsA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "hostA")
	}))
	defer tsA.Close()

	tsB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "hostB")
	}))
	defer tsB.Close()

	cfg := DefaultPoolConfig()
	cfg.Workers = 10
	cfg.BaseRate = 100.0 // 10ms target interval
	pool := NewFuzzingPool(cfg)
	defer pool.Close()

	totalTasks := 40
	tasks := make([]FuzzTask, totalTasks)
	for i := 0; i < totalTasks; i++ {
		target := tsA.URL
		if i%2 == 1 {
			target = tsB.URL
		}
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/pace?id=%d", target, i), nil)
		tasks[i] = FuzzTask{
			ID:      fmt.Sprintf("pace-%d", i),
			Request: req,
		}
	}

	// Concurrently query pool stats while pacing to assert zero mutex contention
	stopStats := make(chan struct{})
	statsQueried := atomic.Int64{}
	go func() {
		for {
			select {
			case <-stopStats:
				return
			default:
				_ = pool.Stats()
				statsQueried.Add(1)
				time.Sleep(1 * time.Millisecond)
			}
		}
	}()

	results, err := pool.Dispatch(context.Background(), tasks)
	close(stopStats)

	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}

	for _, res := range results {
		if res.Error != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("Task %s failed: status=%d, err=%v", res.TaskID, res.StatusCode, res.Error)
		}
	}

	if statsQueried.Load() == 0 {
		t.Fatal("Expected concurrent stats queries to succeed without lock contention")
	}
	t.Logf("Rate pacing lock contention test passed: 40 tasks completed, %d stats queries served concurrently", statsQueried.Load())
}

// TestPool_RetryAfter_BoundedByMaxBackoff_And_Formats verifies integer-seconds, HTTP-date,
// and malformed headers all enforce MaxBackoff and BackoffBase safely.
func TestPool_RetryAfter_BoundedByMaxBackoff_And_Formats(t *testing.T) {
	cfg := DefaultPoolConfig()
	cfg.BackoffBase = 50 * time.Millisecond
	cfg.MaxBackoff = 500 * time.Millisecond

	pool := NewFuzzingPool(cfg)
	defer pool.Close()

	tr := pool.transport

	// 1. Integer seconds exceeding MaxBackoff
	b1 := tr.Record429("86400") // 24 hours
	if b1 > cfg.MaxBackoff {
		t.Fatalf("Expected backoff to be capped at MaxBackoff (%v), got %v", cfg.MaxBackoff, b1)
	}

	// 2. Reasonable integer seconds
	b2 := tr.Record429("0") // Zero seconds -> should fall back safely to base/exponential
	if b2 <= 0 || b2 > cfg.MaxBackoff {
		t.Fatalf("Expected safe backoff for Retry-After: 0, got %v", b2)
	}

	// 3. HTTP-Date in distant future -> must be capped to MaxBackoff
	futureDate := time.Now().Add(24 * time.Hour).UTC().Format(http.TimeFormat)
	b3 := tr.Record429(futureDate)
	if b3 > cfg.MaxBackoff {
		t.Fatalf("Expected HTTP-date backoff to be capped at MaxBackoff (%v), got %v", cfg.MaxBackoff, b3)
	}

	// 4. HTTP-Date in the past -> must fall back to base
	pastDate := time.Now().Add(-1 * time.Hour).UTC().Format(http.TimeFormat)
	b4 := tr.Record429(pastDate)
	if b4 <= 0 || b4 > cfg.MaxBackoff {
		t.Fatalf("Expected safe fallback for past HTTP-date, got %v", b4)
	}

	// 5. Negative string -> must fall back safely
	b5 := tr.Record429("-120")
	if b5 <= 0 || b5 > cfg.MaxBackoff {
		t.Fatalf("Expected safe fallback for negative Retry-After, got %v", b5)
	}

	// 6. Malformed header -> must fall back safely
	b6 := tr.Record429("not-a-valid-date-or-number")
	if b6 <= 0 || b6 > cfg.MaxBackoff {
		t.Fatalf("Expected safe fallback for malformed Retry-After, got %v", b6)
	}

	t.Logf("Retry-After parsing & MaxBackoff ceiling verified across all formats: %v, %v, %v, %v, %v, %v", b1, b2, b3, b4, b5, b6)
}

// TestPool_ConcurrentSubmitAndClose_NoPanicsOrDeadlocks repeatedly exercises concurrent
// submissions and pool teardown, asserting zero panics and prompt termination.
func TestPool_ConcurrentSubmitAndClose_NoPanicsOrDeadlocks(t *testing.T) {
	for round := 0; round < 15; round++ {
		cfg := DefaultPoolConfig()
		cfg.Workers = 4
		cfg.QueueCapacity = 20
		pool := NewFuzzingPool(cfg)

		var submitWg sync.WaitGroup
		concurrency := 20
		submitWg.Add(concurrency)

		for i := 0; i < concurrency; i++ {
			workerID := i
			go func() {
				defer submitWg.Done()
				for j := 0; j < 30; j++ {
					req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:9/dummy", nil)
					task := FuzzTask{
						ID:      fmt.Sprintf("r%d-w%d-t%d", round, workerID, j),
						Request: req,
					}
					_, err := pool.Submit(context.Background(), task)
					if err != nil && !errors.Is(err, ErrPoolClosed) && !errors.Is(err, context.Canceled) {
						t.Errorf("Unexpected submit error: %v", err)
					}
				}
			}()
		}

		// Close pool concurrently while submissions are in flight
		time.Sleep(2 * time.Millisecond)
		closeErr := pool.Close()
		if closeErr != nil {
			t.Fatalf("Close failed: %v", closeErr)
		}

		submitWg.Wait()
	}
	t.Logf("Concurrent Submit and Close verified: 15 rounds completed with 0 panics and 0 deadlocks")
}

// TestPool_RequestBodyReplay_On429Retries verifies that POST requests preserve their body
// across retries, that oversized bodies (>10 MiB) abort retries safely with ErrBodyExceedsReplayLimit
// while allowing attempt 0, and that non-replayable bodies fail safely with ErrNonReplayableBody.
func TestPool_RequestBodyReplay_On429Retries(t *testing.T) {
	canaryPayload := `{"probe":"felix_canary_audit_body","random":94821}`
	var requestAttempts atomic.Int64
	var receivedBodies []string
	var bodiesMu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		bodiesMu.Lock()
		receivedBodies = append(receivedBodies, string(bodyBytes))
		bodiesMu.Unlock()

		attempt := requestAttempts.Add(1)
		if attempt == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, "Rate limited")
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Success")
	}))
	defer ts.Close()

	cfg := DefaultPoolConfig()
	cfg.Workers = 2
	cfg.BackoffBase = 10 * time.Millisecond
	cfg.BaseTransport = ts.Client().Transport
	pool := NewFuzzingPool(cfg)
	defer pool.Close()

	// 1. Replayable POST body (<= 10 MiB)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/post-test", strings.NewReader(canaryPayload))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	task := FuzzTask{
		ID:      "body-replay-task-1",
		Request: req,
	}

	resCh, err := pool.Submit(context.Background(), task)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}

	res := <-resCh
	if res.Error != nil {
		t.Fatalf("Expected successful replay, got error: %v", res.Error)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK after retry, got: %d", res.StatusCode)
	}
	if res.RetriesExecuted != 1 {
		t.Fatalf("Expected 1 retry executed, got: %d", res.RetriesExecuted)
	}

	bodiesMu.Lock()
	if len(receivedBodies) != 2 {
		t.Fatalf("Expected 2 attempts at server, got %d", len(receivedBodies))
	}
	if receivedBodies[0] != canaryPayload {
		t.Fatalf("Attempt 0 payload corrupted: %s", receivedBodies[0])
	}
	if receivedBodies[1] != canaryPayload {
		t.Fatalf("Attempt 1 payload empty or corrupted upon retry: %s", receivedBodies[1])
	}
	bodiesMu.Unlock()

	t.Logf("Request body integrity verified across 429 retries: received exact payload on both wire attempts")

	// 2. Oversized body test: Body exceeding 10 MiB limit (> MaxReplayBodySize)
	// Server returns 200 OK -> attempt 0 must succeed without error (first-attempt behavior preserved)
	oversizedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read entire oversized body to verify first attempt is intact
		n, _ := io.Copy(io.Discard, r.Body)
		if r.URL.Query().Get("throttle") == "1" {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Read %d bytes", n)
	}))
	defer oversizedServer.Close()

	// A: Oversized body on 200 OK -> succeeds on attempt 0
	oversizedData := make([]byte, MaxReplayBodySize+1024)
	for i := range oversizedData {
		oversizedData[i] = 'A'
	}
	oversizedReqOk, _ := http.NewRequest(http.MethodPost, oversizedServer.URL+"/oversized?throttle=0", bytes.NewReader(oversizedData))
	oversizedReqOk.GetBody = nil // Ensure pool's body buffering policy is exercised
	resChOk, err := pool.Submit(context.Background(), FuzzTask{ID: "oversized-ok", Request: oversizedReqOk})
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}
	resOk := <-resChOk
	if resOk.Error != nil {
		t.Fatalf("Expected oversized body to succeed on attempt 0, got: %v", resOk.Error)
	}
	if resOk.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK for oversized body attempt 0, got: %d", resOk.StatusCode)
	}
	t.Logf("Oversized body (>10 MiB) attempt 0 preserved and executed successfully: status=%d", resOk.StatusCode)

	// B: Oversized body on 429 -> aborts retry with ErrBodyExceedsReplayLimit
	oversizedReqThrottle, _ := http.NewRequest(http.MethodPost, oversizedServer.URL+"/oversized?throttle=1", bytes.NewReader(oversizedData))
	oversizedReqThrottle.GetBody = nil
	resChThrottle, err := pool.Submit(context.Background(), FuzzTask{ID: "oversized-throttle", Request: oversizedReqThrottle})
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}
	resThrottle := <-resChThrottle
	if !errors.Is(resThrottle.Error, ErrBodyExceedsReplayLimit) {
		t.Fatalf("Expected ErrBodyExceedsReplayLimit for oversized retry, got: %v", resThrottle.Error)
	}
	t.Logf("Oversized body retry rejected cleanly with ErrBodyExceedsReplayLimit: %v", resThrottle.Error)

	// 3. Non-replayable body test: reader without GetBody where body cannot be rewound
	unseekableReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/non-replayable", strings.NewReader("sample"))
	unseekableReq.GetBody = nil
	_, _ = io.ReadAll(unseekableReq.Body)
	_ = unseekableReq.Body.Close()

	unseekableTask := FuzzTask{
		ID:      "unseekable-task",
		Request: unseekableReq,
	}
	unseekableResCh, err := pool.Submit(context.Background(), unseekableTask)
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}
	unseekableRes := <-unseekableResCh
	if unseekableRes.Error == nil {
		t.Fatal("Expected error for non-replayable body, but succeeded")
	}
	t.Logf("Non-replayable body rejected cleanly: %v", unseekableRes.Error)
}

// TestPool_ObservedAdaptiveConcurrency_ReducesUnder429 validates that when 429 throttling
// is received, active in-flight requests are strictly clamped to the throttled concurrency limit,
// and recovery additively increases concurrency without exceeding the configured maximum.
func TestPool_ObservedAdaptiveConcurrency_ReducesUnder429(t *testing.T) {
	initialWorkers := 8
	minWorkers := 2

	var currentInFlight atomic.Int64
	var peakBeforeThrottling atomic.Int64
	var peakDuringThrottling atomic.Int64
	var peakAfterRecovery atomic.Int64
	var phase atomic.Int32 // 0: baseline, 1: throttled, 2: recovery

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active := currentInFlight.Add(1)
		defer currentInFlight.Add(-1)

		p := phase.Load()
		switch p {
		case 0: // Baseline
			for {
				peak := peakBeforeThrottling.Load()
				if active <= peak {
					break
				}
				if peakBeforeThrottling.CompareAndSwap(peak, active) {
					break
				}
			}
		case 1: // Throttled
			for {
				peak := peakDuringThrottling.Load()
				if active <= peak {
					break
				}
				if peakDuringThrottling.CompareAndSwap(peak, active) {
					break
				}
			}
		case 2: // Recovery
			for {
				peak := peakAfterRecovery.Load()
				if active <= peak {
					break
				}
				if peakAfterRecovery.CompareAndSwap(peak, active) {
					break
				}
			}
		}

		time.Sleep(20 * time.Millisecond)

		if r.URL.Query().Get("throttle") == "1" {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, "Throttled")
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	cfg := DefaultPoolConfig()
	cfg.Workers = initialWorkers
	cfg.MinWorkers = minWorkers
	cfg.BackoffBase = 5 * time.Millisecond
	cfg.MaxBackoff = 20 * time.Millisecond
	cfg.RecoveryStep = 3 // Rapid recovery for testing
	cfg.BaseTransport = ts.Client().Transport
	pool := NewFuzzingPool(cfg)
	defer pool.Close()

	// 1. Baseline Phase: Verify normal concurrent dispatch
	phase.Store(0)
	baseTasks := make([]FuzzTask, 16)
	for i := 0; i < 16; i++ {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"?throttle=0", nil)
		baseTasks[i] = FuzzTask{
			ID:      fmt.Sprintf("base-%d", i),
			Request: req,
		}
	}
	_, _ = pool.Dispatch(context.Background(), baseTasks)
	observedBaseline := peakBeforeThrottling.Load()
	t.Logf("Phase 1 (Baseline) Observed Peak Concurrency: %d (Cap: %d)", observedBaseline, initialWorkers)

	// 2. Throttled Phase: Induce 429 throttling
	throttleTasks := make([]FuzzTask, 8)
	for i := 0; i < 8; i++ {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"?throttle=1", nil)
		throttleTasks[i] = FuzzTask{
			ID:      fmt.Sprintf("th-%d", i),
			Request: req,
		}
	}
	_, _ = pool.Dispatch(context.Background(), throttleTasks)

	reducedWorkers := pool.transport.CurrentWorkers()
	t.Logf("Concurrency cap after throttling induction: %d (MinWorkers: %d)", reducedWorkers, minWorkers)
	if reducedWorkers != int32(minWorkers) {
		t.Fatalf("Expected concurrency cap to be reduced to minWorkers (%d), got %d", minWorkers, reducedWorkers)
	}

	// Now measure observed in-flight concurrency while in throttled state
	phase.Store(1)
	peakDuringThrottling.Store(0)
	throttledWave := make([]FuzzTask, 12)
	for i := 0; i < 12; i++ {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"?throttle=1", nil)
		throttledWave[i] = FuzzTask{
			ID:      fmt.Sprintf("th-wave-%d", i),
			Request: req,
		}
	}
	_, _ = pool.Dispatch(context.Background(), throttledWave)

	observedThrottled := peakDuringThrottling.Load()
	t.Logf("Phase 2 (Throttled) Concurrency Cap: %d, Observed Peak In-Flight: %d (MinWorkers: %d)",
		reducedWorkers, observedThrottled, minWorkers)

	if observedThrottled > int64(reducedWorkers) {
		t.Fatalf("Observed peak in-flight concurrency %d exceeded throttled cap %d", observedThrottled, reducedWorkers)
	}

	// 3. Recovery Phase: Send successful requests and assert additive expansion up to maxWorkers
	phase.Store(2)
	recoverTasks := make([]FuzzTask, 30)
	for i := 0; i < 30; i++ {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"?throttle=0", nil)
		recoverTasks[i] = FuzzTask{
			ID:      fmt.Sprintf("rec-%d", i),
			Request: req,
		}
	}
	results, err := pool.Dispatch(context.Background(), recoverTasks)
	if err != nil {
		t.Fatalf("Recovery dispatch failed: %v", err)
	}
	for _, res := range results {
		if res.Error != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("Recovery task failed: status=%d, err=%v", res.StatusCode, res.Error)
		}
	}

	recoveredWorkers := pool.transport.CurrentWorkers()
	observedRecoveryPeak := peakAfterRecovery.Load()
	t.Logf("Phase 3 (Recovery) Concurrency Cap: %d, Observed Peak In-Flight: %d (MaxWorkers: %d)",
		recoveredWorkers, observedRecoveryPeak, initialWorkers)

	if recoveredWorkers <= int32(minWorkers) {
		t.Fatalf("Expected concurrency cap to increase from %d during recovery, remained %d", minWorkers, recoveredWorkers)
	}
	if recoveredWorkers > int32(initialWorkers) {
		t.Fatalf("Recovered concurrency cap %d exceeded maxWorkers %d", recoveredWorkers, initialWorkers)
	}
	if observedRecoveryPeak > int64(initialWorkers) {
		t.Fatalf("Observed in-flight recovery peak %d exceeded maxWorkers %d", observedRecoveryPeak, initialWorkers)
	}

	t.Logf("Adaptive concurrency enforcement verified across all 3 phases: Baseline=%d, Throttled=%d, Recovered=%d",
		observedBaseline, observedThrottled, recoveredWorkers)
}

// TestPool_SSRF_MetadataDialBoundary_And_Redirects tests that cloud metadata requests
// are blocked at both URL boundary, dial-time resolution boundary, and HTTP 302 redirects.
func TestPool_SSRF_MetadataDialBoundary_And_Redirects(t *testing.T) {
	cfg := DefaultPoolConfig()
	pool := NewFuzzingPool(cfg)
	defer pool.Close()

	// 1. Literal IP addresses
	blockedTargets := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://[fd00:ec2::254]/latest/meta-data/",
		"http://[::ffff:169.254.169.254]/latest/meta-data/",
		"http://169.254.1.1/internal", // Link-local range 169.254.0.0/16
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://instance-data/latest/meta-data/",
	}

	for _, target := range blockedTargets {
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		_, err := pool.Client().Do(req)
		if err == nil {
			t.Fatalf("Expected target %s to be blocked, but succeeded", target)
		}
		if !errors.Is(err, ErrMetadataSSRFBlocked) && !strings.Contains(err.Error(), "blocked request to cloud metadata") {
			t.Fatalf("Unexpected error for %s: %v", target, err)
		}
		t.Logf("Verified blocked target: %s -> %v", target, err)
	}

	// 2. HTTP 302 Redirect to Cloud Metadata
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer redirectServer.Close()

	redirectReq, _ := http.NewRequest(http.MethodGet, redirectServer.URL, nil)
	_, rErr := pool.Client().Do(redirectReq)
	if rErr == nil {
		t.Fatal("Expected redirect to cloud metadata to be blocked, but succeeded")
	}
	if !strings.Contains(rErr.Error(), "blocked request to cloud metadata") && !errors.Is(rErr, ErrMetadataSSRFBlocked) {
		t.Fatalf("Unexpected redirect error: %v", rErr)
	}
	t.Logf("Verified redirect to cloud metadata blocked: %v", rErr)

	// 3. Ordinary Allowed Destination: Loopback test server must succeed normally
	allowedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "allowed destination verified")
	}))
	defer allowedServer.Close()

	allowedReq, _ := http.NewRequest(http.MethodGet, allowedServer.URL+"/legit-path", nil)
	allowedResp, aErr := pool.Client().Do(allowedReq)
	if aErr != nil {
		t.Fatalf("Expected ordinary allowed destination to succeed, got error: %v", aErr)
	}
	defer allowedResp.Body.Close()
	if allowedResp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK for allowed destination, got: %d", allowedResp.StatusCode)
	}
	t.Logf("Ordinary allowed destination verified successfully with pinned dial: %d OK", allowedResp.StatusCode)

	// 4. Dial-time Pinned IP Verification: Test createSafeMetadataDialer directly
	dialerFn := createSafeMetadataDialer(nil)

	// Blocked literal IP
	_, dErr := dialerFn(context.Background(), "tcp", "169.254.169.254:80")
	if dErr == nil || (!errors.Is(dErr, ErrMetadataSSRFBlocked) && !strings.Contains(dErr.Error(), "blocked request to cloud metadata")) {
		t.Fatalf("Expected metadata dial to be blocked, got: %v", dErr)
	}

	// Blocked metadata hostname
	_, dErrHost := dialerFn(context.Background(), "tcp", "metadata.google.internal:80")
	if dErrHost == nil || (!errors.Is(dErrHost, ErrMetadataSSRFBlocked) && !strings.Contains(dErrHost.Error(), "blocked request to cloud metadata")) {
		t.Fatalf("Expected metadata hostname dial to be blocked, got: %v", dErrHost)
	}

	t.Logf("createSafeMetadataDialer dial-time IP pinning and boundary checks verified")
}

// trackedCloser wraps an io.Reader and tracks Close calls and errors.
type trackedCloser struct {
	io.Reader
	closed atomic.Bool
	err    error
}

func (tc *trackedCloser) Read(p []byte) (int, error) {
	if tc.err != nil {
		return 0, tc.err
	}
	return tc.Reader.Read(p)
}

func (tc *trackedCloser) Close() error {
	tc.closed.Store(true)
	return nil
}

func TestPool_RequestBodySemantics_Exhaustive(t *testing.T) {
	// 1. Payloads below 10 MiB (e.g. 512 KiB)
	// - Transmits exact original payload
	// - ContentLength matches transmitted body
	// - Replayed correctly on 429 retry
	// - Original stream closed upon buffering (resource cleanup)
	t.Run("Below_10MiB_Replayable", func(t *testing.T) {
		payloadSize := 512 * 1024
		data := make([]byte, payloadSize)
		for i := range data {
			data[i] = byte(i % 251)
		}
		expectedHash := sha256.Sum256(data)

		var attemptsMu sync.Mutex
		var attemptCount int
		var receivedHashes []string
		var receivedCLs []int64

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attemptsMu.Lock()
			attemptCount++
			cur := attemptCount
			receivedCLs = append(receivedCLs, r.ContentLength)
			attemptsMu.Unlock()

			bodyBytes, _ := io.ReadAll(r.Body)
			h := sha256.Sum256(bodyBytes)
			attemptsMu.Lock()
			receivedHashes = append(receivedHashes, hex.EncodeToString(h[:]))
			attemptsMu.Unlock()

			if cur == 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		cfg := DefaultPoolConfig()
		cfg.Workers = 2
		cfg.BackoffBase = 5 * time.Millisecond
		cfg.BaseTransport = ts.Client().Transport
		pool := NewFuzzingPool(cfg)
		defer pool.Close()

		tc := &trackedCloser{Reader: bytes.NewReader(data)}
		req, _ := http.NewRequest(http.MethodPost, ts.URL, tc)
		req.GetBody = nil // enforce pool buffering

		resCh, err := pool.Submit(context.Background(), FuzzTask{ID: "below-10mb", Request: req})
		if err != nil {
			t.Fatalf("Submit failed: %v", err)
		}
		res := <-resCh
		if res.Error != nil {
			t.Fatalf("Expected success, got: %v", res.Error)
		}
		if res.StatusCode != http.StatusOK {
			t.Fatalf("Expected 200, got: %d", res.StatusCode)
		}
		if res.RetriesExecuted != 1 {
			t.Fatalf("Expected 1 retry, got %d", res.RetriesExecuted)
		}

		if !tc.closed.Load() {
			t.Errorf("Expected original body stream to be closed during buffering for cleanup")
		}

		attemptsMu.Lock()
		defer attemptsMu.Unlock()
		if attemptCount != 2 {
			t.Fatalf("Expected 2 wire attempts, got %d", attemptCount)
		}
		expectedHex := hex.EncodeToString(expectedHash[:])
		if receivedHashes[0] != expectedHex || receivedHashes[1] != expectedHex {
			t.Fatalf("Payload hash mismatch across retries: attempt0=%s, attempt1=%s, want=%s",
				receivedHashes[0], receivedHashes[1], expectedHex)
		}
		if receivedCLs[0] != int64(payloadSize) || receivedCLs[1] != int64(payloadSize) {
			t.Fatalf("ContentLength mismatch: got attempt0=%d, attempt1=%d, want=%d",
				receivedCLs[0], receivedCLs[1], payloadSize)
		}
	})

	// 2. Payloads exactly at 10 MiB (MaxReplayBodySize = 10485760 bytes)
	// - Must NOT be classified as oversized (boundary condition)
	// - Successfully buffered and replayed on 429
	// - Original stream closed upon buffering
	t.Run("Exactly_At_10MiB_Replayable", func(t *testing.T) {
		payloadSize := MaxReplayBodySize
		data := make([]byte, payloadSize)
		for i := range data {
			data[i] = byte(i % 239)
		}
		expectedHash := sha256.Sum256(data)

		var attemptsMu sync.Mutex
		var attemptCount int
		var receivedHashes []string
		var receivedCLs []int64

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attemptsMu.Lock()
			attemptCount++
			cur := attemptCount
			receivedCLs = append(receivedCLs, r.ContentLength)
			attemptsMu.Unlock()

			bodyBytes, _ := io.ReadAll(r.Body)
			h := sha256.Sum256(bodyBytes)
			attemptsMu.Lock()
			receivedHashes = append(receivedHashes, hex.EncodeToString(h[:]))
			attemptsMu.Unlock()

			if cur == 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		cfg := DefaultPoolConfig()
		cfg.Workers = 2
		cfg.BackoffBase = 5 * time.Millisecond
		cfg.BaseTransport = ts.Client().Transport
		pool := NewFuzzingPool(cfg)
		defer pool.Close()

		tc := &trackedCloser{Reader: bytes.NewReader(data)}
		req, _ := http.NewRequest(http.MethodPost, ts.URL, tc)
		req.GetBody = nil

		resCh, err := pool.Submit(context.Background(), FuzzTask{ID: "exact-10mb", Request: req})
		if err != nil {
			t.Fatalf("Submit failed: %v", err)
		}
		res := <-resCh
		if res.Error != nil {
			t.Fatalf("Expected success, got: %v", res.Error)
		}
		if res.StatusCode != http.StatusOK {
			t.Fatalf("Expected 200, got: %d", res.StatusCode)
		}
		if res.RetriesExecuted != 1 {
			t.Fatalf("Expected 1 retry, got %d", res.RetriesExecuted)
		}

		if !tc.closed.Load() {
			t.Errorf("Expected original body stream to be closed during buffering for cleanup")
		}

		attemptsMu.Lock()
		defer attemptsMu.Unlock()
		if attemptCount != 2 {
			t.Fatalf("Expected 2 wire attempts, got %d", attemptCount)
		}
		expectedHex := hex.EncodeToString(expectedHash[:])
		if receivedHashes[0] != expectedHex || receivedHashes[1] != expectedHex {
			t.Fatalf("Exact 10 MiB payload mismatch: attempt0=%s, attempt1=%s, want=%s",
				receivedHashes[0], receivedHashes[1], expectedHex)
		}
		if receivedCLs[0] != int64(payloadSize) || receivedCLs[1] != int64(payloadSize) {
			t.Fatalf("ContentLength mismatch: got %d, want %d", receivedCLs[0], payloadSize)
		}
	})

	// 3. Payloads above 10 MiB (MaxReplayBodySize + 64 KiB)
	// - Attempt 0 transmits exact original stream without truncation
	// - Resource cleanup: original stream is closed upon completion
	// - 429 response cleanly aborts with ErrBodyExceedsReplayLimit
	// - CRITICAL: Never retries on wire with missing or corrupted bytes (attempts == 1)
	t.Run("Above_10MiB_Attempt0_Success_And_429_Never_Retried", func(t *testing.T) {
		payloadSize := MaxReplayBodySize + 64*1024
		data := make([]byte, payloadSize)
		for i := range data {
			data[i] = byte(i % 199)
		}
		expectedHash := sha256.Sum256(data)

		var attemptsMu sync.Mutex
		var attemptCount int
		var receivedHashes []string
		var receivedCLs []int64

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attemptsMu.Lock()
			attemptCount++
			receivedCLs = append(receivedCLs, r.ContentLength)
			attemptsMu.Unlock()

			bodyBytes, _ := io.ReadAll(r.Body)
			h := sha256.Sum256(bodyBytes)
			attemptsMu.Lock()
			receivedHashes = append(receivedHashes, hex.EncodeToString(h[:]))
			attemptsMu.Unlock()

			if r.URL.Query().Get("throttle") == "1" {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		cfg := DefaultPoolConfig()
		cfg.Workers = 2
		cfg.BaseTransport = ts.Client().Transport
		pool := NewFuzzingPool(cfg)
		defer pool.Close()

		// A: Attempt 0 OK transmission
		tcOk := &trackedCloser{Reader: bytes.NewReader(data)}
		reqOk, _ := http.NewRequest(http.MethodPost, ts.URL+"?throttle=0", tcOk)
		reqOk.ContentLength = int64(payloadSize)
		reqOk.GetBody = nil

		resChOk, err := pool.Submit(context.Background(), FuzzTask{ID: "above-10mb-ok", Request: reqOk})
		if err != nil {
			t.Fatalf("Submit failed: %v", err)
		}
		resOk := <-resChOk
		if resOk.Error != nil {
			t.Fatalf("Expected attempt 0 to succeed, got: %v", resOk.Error)
		}
		if resOk.StatusCode != http.StatusOK {
			t.Fatalf("Expected 200 OK, got: %d", resOk.StatusCode)
		}
		if !tcOk.closed.Load() {
			t.Errorf("Expected original body stream Closer to be invoked upon request completion")
		}

		attemptsMu.Lock()
		expectedHex := hex.EncodeToString(expectedHash[:])
		if len(receivedHashes) != 1 || receivedHashes[0] != expectedHex {
			t.Fatalf("Attempt 0 payload corrupted or truncated: got %v, want %s", receivedHashes, expectedHex)
		}
		if receivedCLs[0] != int64(payloadSize) {
			t.Fatalf("ContentLength mismatch: got %d, want %d", receivedCLs[0], payloadSize)
		}
		attemptsMu.Unlock()

		// B: Throttled transmission: 429 must abort with ErrBodyExceedsReplayLimit
		// and server must receive exactly 1 attempt total (NO RETRY ON WIRE)
		attemptsMu.Lock()
		attemptCount = 0
		receivedHashes = nil
		receivedCLs = nil
		attemptsMu.Unlock()

		tcThrottle := &trackedCloser{Reader: bytes.NewReader(data)}
		reqThrottle, _ := http.NewRequest(http.MethodPost, ts.URL+"?throttle=1", tcThrottle)
		reqThrottle.ContentLength = int64(payloadSize)
		reqThrottle.GetBody = nil

		resChThrottle, err := pool.Submit(context.Background(), FuzzTask{ID: "above-10mb-throttle", Request: reqThrottle})
		if err != nil {
			t.Fatalf("Submit failed: %v", err)
		}
		resThrottle := <-resChThrottle
		if !errors.Is(resThrottle.Error, ErrBodyExceedsReplayLimit) {
			t.Fatalf("Expected ErrBodyExceedsReplayLimit, got: %v", resThrottle.Error)
		}

		attemptsMu.Lock()
		if attemptCount != 1 {
			t.Fatalf("CRITICAL SAFETY VIOLATION: Server received %d attempts. Oversized body was retried with drained stream!", attemptCount)
		}
		attemptsMu.Unlock()

		if !tcThrottle.closed.Load() {
			t.Errorf("Expected original body stream Closer to be invoked after attempt 0 round trip")
		}
	})

	// 4. Non-replayable body with 429 returns ErrNonReplayableBody
	t.Run("Non_Replayable_Body_Returns_Documented_Error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer ts.Close()

		cfg := DefaultPoolConfig()
		cfg.Workers = 2
		cfg.BaseTransport = ts.Client().Transport
		pool := NewFuzzingPool(cfg)
		defer pool.Close()

		// Case A: Request explicitly marked non-replayable (GetBody is nil, no buffering)
		reqA, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader("sample-payload"))
		reqA.Header.Set("X-Felix-No-Replay", "true")
		reqA.GetBody = nil

		resChA, err := pool.Submit(context.Background(), FuzzTask{ID: "no-replay-header", Request: reqA})
		if err != nil {
			t.Fatalf("Submit failed: %v", err)
		}
		resA := <-resChA
		if !errors.Is(resA.Error, ErrNonReplayableBody) {
			t.Fatalf("Expected ErrNonReplayableBody for Case A, got: %v", resA.Error)
		}

		// Case B: Request where GetBody returns ErrNonReplayableBody
		reqB, _ := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader("sample-payload"))
		reqB.GetBody = func() (io.ReadCloser, error) {
			return nil, ErrNonReplayableBody
		}

		resChB, err := pool.Submit(context.Background(), FuzzTask{ID: "getbody-err", Request: reqB})
		if err != nil {
			t.Fatalf("Submit failed: %v", err)
		}
		resB := <-resChB
		if !errors.Is(resB.Error, ErrNonReplayableBody) {
			t.Fatalf("Expected ErrNonReplayableBody for Case B, got: %v", resB.Error)
		}
	})

	// 5. Read errors, cancellation, and resource cleanup
	t.Run("Body_Read_Errors_And_Cancellation_Cleanup", func(t *testing.T) {
		cfg := DefaultPoolConfig()
		cfg.Workers = 2
		pool := NewFuzzingPool(cfg)
		defer pool.Close()

		// Read error handling
		readErr := errors.New("simulated read failure mid-stream")
		tcErr := &trackedCloser{Reader: bytes.NewReader([]byte("partial")), err: readErr}
		reqErr, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:9999", tcErr)
		reqErr.GetBody = nil

		resChErr, err := pool.Submit(context.Background(), FuzzTask{ID: "read-err", Request: reqErr})
		if err != nil {
			t.Fatalf("Submit failed: %v", err)
		}
		resErr := <-resChErr
		if resErr.Error == nil || !strings.Contains(resErr.Error.Error(), "simulated read failure") {
			t.Fatalf("Expected read error failure, got: %v", resErr.Error)
		}
		if !tcErr.closed.Load() {
			t.Errorf("Expected body to be closed upon read error")
		}

		// Context cancellation handling
		cancCtx, cancel := context.WithCancel(context.Background())
		cancel() // immediately cancelled
		tcCanc := &trackedCloser{Reader: bytes.NewReader([]byte("cancellation-test"))}
		reqCanc, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:9999", tcCanc)
		reqCanc.GetBody = nil

		resChCanc, err := pool.Submit(cancCtx, FuzzTask{ID: "canc-task", Request: reqCanc})
		if err == nil {
			resCanc := <-resChCanc
			if !errors.Is(resCanc.Error, context.Canceled) {
				t.Fatalf("Expected context.Canceled, got: %v", resCanc.Error)
			}
		}
	})
}
