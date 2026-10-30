package fuzzer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestBenchmark_FuzzingConcurrencyAndAdaptiveRateLimiter executes the authoritative 500-request
// benchmark with 25 concurrent goroutines and simulated HTTP 429 throttling.
func TestBenchmark_FuzzingConcurrencyAndAdaptiveRateLimiter(t *testing.T) {
	totalRequests := 500
	concurrencyLimit := 25

	var requestCounter atomic.Int64
	var throttledCounter atomic.Int64
	var peakActive atomic.Int64
	var currentActive atomic.Int64

	// Controlled local server simulating HTTP 429 rate limiting for the first 35 requests
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active := currentActive.Add(1)
		defer currentActive.Add(-1)

		for {
			peak := peakActive.Load()
			if active <= peak {
				break
			}
			if peakActive.CompareAndSwap(peak, active) {
				break
			}
		}

		reqNum := requestCounter.Add(1)
		// First 35 requests encounter target rate-limiting and return HTTP 429
		if reqNum <= 35 {
			throttledCounter.Add(1)
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, "Rate limit exceeded (simulated 429)")
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer ts.Close()

	cfg := DefaultPoolConfig()
	cfg.Workers = concurrencyLimit
	cfg.MinWorkers = 4
	cfg.BackoffBase = 5 * time.Millisecond
	cfg.MaxBackoff = 50 * time.Millisecond
	cfg.BaseTransport = ts.Client().Transport
	pool := NewFuzzingPool(cfg)
	defer pool.Close()

	tasks := make([]FuzzTask, totalRequests)
	for i := 0; i < totalRequests; i++ {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/fuzz?id=%d", ts.URL, i), nil)
		tasks[i] = FuzzTask{
			ID:      fmt.Sprintf("fuzz-req-%04d", i),
			Request: req,
		}
	}

	start := time.Now()
	results, err := pool.Dispatch(context.Background(), tasks)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Dispatch failed: %v", err)
	}

	// Verify all 500 requests completed with HTTP 200 (zero lost requests)
	successCount := 0
	lostCount := 0
	for _, res := range results {
		if res.StatusCode == http.StatusOK && res.Error == nil {
			successCount++
		} else {
			lostCount++
			t.Errorf("Request %s lost or failed: status=%d, err=%v", res.TaskID, res.StatusCode, res.Error)
		}
	}

	stats := pool.Stats()
	throughput := float64(totalRequests) / elapsed.Seconds()
	observedPeak := peakActive.Load()

	t.Logf("=== SUBPHASE 2.6 EMPIRICAL BENCHMARK RESULTS ===")
	t.Logf("  Total Requests Dispatched : %d", totalRequests)
	t.Logf("  Total Successful Requests : %d", successCount)
	t.Logf("  Total Lost Requests       : %d (Metric: 0 lost requests)", lostCount)
	t.Logf("  Configured Workers        : %d", concurrencyLimit)
	t.Logf("  Observed Peak Concurrency : %d (Max Allowed: %d)", observedPeak, concurrencyLimit)
	t.Logf("  Total 429s Throttled      : %d", stats.TotalThrottled)
	t.Logf("  Total Retries Recovered   : %d", stats.TotalRetried)
	t.Logf("  Total Benchmark Duration  : %v", elapsed)
	t.Logf("  Loopback Throughput       : %.2f req/s (Metric: >100 req/s)", throughput)

	// Assertions against authoritative Exit Gate Criteria
	if lostCount > 0 {
		t.Fatalf("Iron Gate Violation: %d requests lost under simulated HTTP 429", lostCount)
	}
	if successCount != totalRequests {
		t.Fatalf("Expected all %d requests to complete successfully, got %d", totalRequests, successCount)
	}
	if stats.TotalThrottled == 0 {
		t.Fatal("Expected simulated 429 responses to trigger adaptive backoff")
	}
	if stats.TotalRetried == 0 {
		t.Fatal("Expected retries to recover all throttled requests")
	}
	if observedPeak > int64(concurrencyLimit) {
		t.Fatalf("Observed peak concurrency %d exceeded hard cap %d", observedPeak, concurrencyLimit)
	}
	if throughput < 100.0 {
		t.Fatalf("Throughput %.2f req/s fell below mandatory >100 req/s threshold", throughput)
	}

	// Verify Evidence Receipt
	receiptPath := filepath.Join("..", "..", "test", "evidence", "phase2", "2.6_rate_limiter_recovery_proof.json")
	receiptBytes, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("Failed to read required evidence receipt at %s: %v", receiptPath, err)
	}

	var diskReceipt map[string]any
	if err := json.Unmarshal(receiptBytes, &diskReceipt); err != nil {
		t.Fatalf("Failed to parse evidence receipt at %s: %v", receiptPath, err)
	}

	expectedHash, ok := diskReceipt["sha256_hash"].(string)
	if !ok || expectedHash == "" {
		t.Fatalf("Receipt at %s is missing sha256_hash", receiptPath)
	}

	delete(diskReceipt, "sha256_hash")
	var verifyBuf bytes.Buffer
	encVerify := json.NewEncoder(&verifyBuf)
	encVerify.SetEscapeHTML(false)
	if err := encVerify.Encode(diskReceipt); err != nil {
		t.Fatalf("Failed to encode receipt for verification: %v", err)
	}
	computedHashBytes := bytes.TrimRight(verifyBuf.Bytes(), "\n")
	computedHashSum := sha256.Sum256(computedHashBytes)
	computedHash := hex.EncodeToString(computedHashSum[:])

	if computedHash != expectedHash {
		t.Fatalf("Evidence receipt SHA-256 verification mismatch: expected %s, got %s", expectedHash, computedHash)
	}
	t.Logf("Receipt SHA-256 cryptographically verified: %s (file: %s)", computedHash, receiptPath)
}

// TestLiveBenchmark_WebGoatLoopbackStress verifies live loopback stress throughput
// and concurrency safety against running WebGoat on port 8082 / 8080.
func TestLiveBenchmark_WebGoatLoopbackStress(t *testing.T) {
	baseURL := "http://127.0.0.1:8082/WebGoat/login"
	if !checkHostReachability(baseURL) {
		baseURL = "http://127.0.0.1:8080/WebGoat/login"
		if !checkHostReachability(baseURL) {
			t.Skip("WebGoat is not running on port 8082 or 8080; skipping live loopback stress test")
		}
	}

	liveRequests := 100
	workers := 20

	cfg := DefaultPoolConfig()
	cfg.Workers = workers
	cfg.Timeout = 5 * time.Second
	pool := NewFuzzingPool(cfg)
	defer pool.Close()

	tasks := make([]FuzzTask, liveRequests)
	for i := 0; i < liveRequests; i++ {
		req, _ := http.NewRequest(http.MethodGet, baseURL, nil)
		tasks[i] = FuzzTask{
			ID:      fmt.Sprintf("live-wg-%03d", i),
			Request: req,
		}
	}

	start := time.Now()
	results, err := pool.Dispatch(context.Background(), tasks)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Live WebGoat dispatch failed: %v", err)
	}

	successCount := 0
	for _, res := range results {
		if res.StatusCode == http.StatusOK && res.Error == nil {
			successCount++
		}
	}

	throughput := float64(liveRequests) / elapsed.Seconds()
	t.Logf("=== LIVE WEBGOAT LOOPBACK STRESS METRICS ===")
	t.Logf("  Target URL           : %s", baseURL)
	t.Logf("  Total Requests       : %d", liveRequests)
	t.Logf("  Successful (200 OK)  : %d / %d", successCount, liveRequests)
	t.Logf("  Concurrent Workers   : %d", workers)
	t.Logf("  Elapsed Time         : %v", elapsed)
	t.Logf("  Live Throughput      : %.2f req/s", throughput)

	if successCount < int(float64(liveRequests)*0.95) {
		t.Fatalf("Live WebGoat stress dropped requests: %d / %d succeeded", successCount, liveRequests)
	}
	t.Logf("Live WebGoat loopback stress test successfully verified.")
}
