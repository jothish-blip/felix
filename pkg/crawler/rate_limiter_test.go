package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
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
