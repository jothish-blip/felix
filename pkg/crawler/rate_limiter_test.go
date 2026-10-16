package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRateLimitedTransport_PerHostPacing tests that requests to the same host respect the rate limit.
func TestRateLimitedTransport_PerHostPacing(t *testing.T) {
	var requestTimes []time.Time
	var mu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestTimes = append(requestTimes, time.Now())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Rate: 10 requests per second -> 100ms interval
	rate := 10.0
	rt := NewRateLimitedTransport(ts.Client().Transport, RateLimitOptions{
		Rate:           rate,
		MaxConcurrency: 2,
	})

	client := &http.Client{Transport: rt}

	// Dispatch 4 sequential requests
	for i := 0; i < 4; i++ {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		resp.Body.Close()
	}

	mu.Lock()
	defer mu.Unlock()

	if len(requestTimes) != 4 {
		t.Fatalf("expected 4 requests, got %d", len(requestTimes))
	}

	for i := 1; i < len(requestTimes); i++ {
		interval := requestTimes[i].Sub(requestTimes[i-1])
		// Expect at least ~80ms (allowing 20ms tolerance for OS scheduler jitter)
		if interval < 80*time.Millisecond {
			t.Errorf("request %d followed request %d too quickly: interval was %v (expected >= 80ms)", i, i-1, interval)
		}
	}

	if rt.TotalRequests() != 4 {
		t.Errorf("expected 4 total requests in metrics, got %d", rt.TotalRequests())
	}
}

// TestRateLimitedTransport_ConcurrencyCap asserts that active concurrent requests never exceed MaxConcurrency.
func TestRateLimitedTransport_ConcurrencyCap(t *testing.T) {
	var activeNow atomic.Int64
	var maxActive atomic.Int64

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := activeNow.Add(1)
		defer activeNow.Add(-1)

		for {
			peak := maxActive.Load()
			if cur <= peak || maxActive.CompareAndSwap(peak, cur) {
				break
			}
		}

		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	maxConcurrency := 2
	rt := NewRateLimitedTransport(ts.Client().Transport, RateLimitOptions{
		Rate:           100.0, // High rate so concurrency is the bottleneck
		MaxConcurrency: maxConcurrency,
	})

	client := &http.Client{Transport: rt}

	var wg sync.WaitGroup
	numWorkers := 8

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
			if err != nil {
				return
			}
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}()
	}

	wg.Wait()

	if max := maxActive.Load(); max > int64(maxConcurrency) {
		t.Errorf("active requests exceeded max concurrency: observed %d, limit %d", max, maxConcurrency)
	}

	if peak := rt.PeakConcurrency(); peak > int64(maxConcurrency) {
		t.Errorf("peak concurrency in metrics exceeded limit: observed %d, limit %d", peak, maxConcurrency)
	}

	if rt.TotalRequests() != int64(numWorkers) {
		t.Errorf("expected %d total requests, got %d", numWorkers, rt.TotalRequests())
	}
}

// TestRateLimitedTransport_ContextCancellation asserts that cancelled requests release semaphore and don't leak.
func TestRateLimitedTransport_ContextCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	rt := NewRateLimitedTransport(ts.Client().Transport, RateLimitOptions{
		Rate:           1.0,
		MaxConcurrency: 1,
	})

	client := &http.Client{Transport: rt}

	// 1. Launch a request that holds the single slot
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	go func() {
		req, _ := http.NewRequestWithContext(ctx1, http.MethodGet, ts.URL, nil)
		resp, _ := client.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
	}()

	time.Sleep(20 * time.Millisecond)

	// 2. Launch a second request with short timeout that will get cancelled while waiting
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel2()

	req2, _ := http.NewRequestWithContext(ctx2, http.MethodGet, ts.URL, nil)
	_, err := client.Do(req2)
	if err == nil {
		t.Fatal("expected request 2 to be cancelled, got nil error")
	}

	// 3. Cancel request 1 to free the slot
	cancel1()
	time.Sleep(50 * time.Millisecond)

	// 4. Verify transport recovers and can process new requests
	req3, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	resp3, err3 := client.Do(req3)
	if err3 != nil {
		t.Fatalf("expected request 3 to succeed after cancellation recovery, got: %v", err3)
	}
	resp3.Body.Close()
}

// TestRateLimitedTransport_RedirectsCounted asserts that redirect hops pass through the transport.
func TestRateLimitedTransport_RedirectsCounted(t *testing.T) {
	redirectsSeen := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			redirectsSeen++
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	rt := NewRateLimitedTransport(ts.Client().Transport, RateLimitOptions{
		Rate:           50.0,
		MaxConcurrency: 2,
	})

	client := &http.Client{Transport: rt}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/redirect", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	// Both the redirect hop (/redirect) and destination (/target) should be processed through RoundTrip
	if rt.TotalRequests() != 2 {
		t.Errorf("expected 2 total requests including redirect hop, got %d", rt.TotalRequests())
	}
}

// TestRateLimitedTransport_ConcurrentRequestsPaced verifies that concurrent goroutines to the same host
// are strictly paced by the per-host rate limiter even when MaxConcurrency allows multiple simultaneous requests.
func TestRateLimitedTransport_ConcurrentRequestsPaced(t *testing.T) {
	var arrivalTimes []time.Time
	var mu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		arrivalTimes = append(arrivalTimes, time.Now())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Rate: 10.0 req/sec -> 100ms interval
	rate := 10.0
	rt := NewRateLimitedTransport(ts.Client().Transport, RateLimitOptions{
		Rate:           rate,
		MaxConcurrency: 5, // High concurrency, but per-host rate limiter must pace them
	})
	client := &http.Client{Transport: rt}

	var wg sync.WaitGroup
	numRequests := 4
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
			if err != nil {
				return
			}
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()

	if len(arrivalTimes) != numRequests {
		t.Fatalf("expected %d requests received, got %d", numRequests, len(arrivalTimes))
	}

	// Sort arrival times to measure inter-arrival intervals
	for i := 0; i < len(arrivalTimes)-1; i++ {
		for j := i + 1; j < len(arrivalTimes); j++ {
			if arrivalTimes[j].Before(arrivalTimes[i]) {
				arrivalTimes[i], arrivalTimes[j] = arrivalTimes[j], arrivalTimes[i]
			}
		}
	}

	for i := 1; i < len(arrivalTimes); i++ {
		interval := arrivalTimes[i].Sub(arrivalTimes[i-1])
		// 100ms nominal; allowing 75ms for OS scheduler / timer resolution on Windows
		if interval < 75*time.Millisecond {
			t.Errorf("concurrent request %d followed %d too quickly: interval was %v (expected >= 75ms)", i, i-1, interval)
		}
	}

	if rt.TotalRequests() != int64(numRequests) {
		t.Errorf("expected %d total requests, got %d", numRequests, rt.TotalRequests())
	}
}

// TestRateLimitedTransport_RetriesPaced verifies that retry attempts pass through the transport
// and increment the transport counter.
func TestRateLimitedTransport_RetriesPaced(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	rt := NewRateLimitedTransport(ts.Client().Transport, RateLimitOptions{
		Rate:           20.0,
		MaxConcurrency: 2,
	})
	client := &http.Client{Transport: rt}

	// Dispatch request with retry loop
	maxRetries := 3
	var finalResp *http.Response
	for retry := 0; retry < maxRetries; retry++ {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			finalResp = resp
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
	}

	if finalResp == nil {
		t.Fatal("expected request to succeed after retries")
	}
	finalResp.Body.Close()

	if attempts != 3 {
		t.Errorf("expected 3 server attempts, got %d", attempts)
	}
	if rt.TotalRequests() != 3 {
		t.Errorf("expected 3 transport requests counted, got %d", rt.TotalRequests())
	}
}

// TestRateLimitedTransport_IndependentHostsNotBlocked verifies that rate limiting on host A
// does not unnecessarily block immediate requests to distinct host B.
func TestRateLimitedTransport_IndependentHostsNotBlocked(t *testing.T) {
	tsA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tsA.Close()

	tsB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer tsB.Close()

	// Slow rate of 1 req/sec on each host, but concurrency = 5
	rt := NewRateLimitedTransport(tsA.Client().Transport, RateLimitOptions{
		Rate:           1.0, // 1 second interval per host
		MaxConcurrency: 5,
	})
	client := &http.Client{Transport: rt}

	start := time.Now()

	// Send to host A
	reqA, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, tsA.URL, nil)
	respA, errA := client.Do(reqA)
	if errA != nil {
		t.Fatalf("request A failed: %v", errA)
	}
	respA.Body.Close()

	// Immediately send to host B (different host)
	reqB, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, tsB.URL, nil)
	respB, errB := client.Do(reqB)
	if errB != nil {
		t.Fatalf("request B failed: %v", errB)
	}
	respB.Body.Close()

	elapsed := time.Since(start)

	// Since host B has its own independent rate limiter, it should NOT wait 1 second for host A
	if elapsed > 600*time.Millisecond {
		t.Errorf("request to host B took %v; expected independent per-host pacing (< 600ms)", elapsed)
	}
	if rt.TotalRequests() != 2 {
		t.Errorf("expected 2 total requests, got %d", rt.TotalRequests())
	}
}

func TestRateLimitedTransport_BlocksCloudMetadata(t *testing.T) {
	// Even with a dummy RoundTripper, RateLimitedTransport must block metadata endpoints
	dummyTransport := http.DefaultTransport
	rt := NewRateLimitedTransport(dummyTransport, RateLimitOptions{
		Rate: 10.0,
	})
	client := &http.Client{Transport: rt}

	metadataURLs := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.169.254:80/computeMetadata/v1/",
		"http://[fd00:ec2::254]/latest/meta-data/",
	}

	for _, u := range metadataURLs {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
		_, err := client.Do(req)
		if err == nil {
			t.Fatalf("expected request to metadata endpoint %q to be blocked, but succeeded", u)
		}
		if !strings.Contains(err.Error(), "cloud metadata service address") {
			t.Errorf("expected cloud metadata SSRF error, got: %v", err)
		}
	}
}
