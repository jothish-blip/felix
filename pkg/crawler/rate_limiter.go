package crawler

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RateLimitOptions configures the outbound request pacing and concurrency controls.
type RateLimitOptions struct {
	// Rate is the maximum requests per second per host. <= 0 means unlimited.
	Rate float64
	// MaxConcurrency is the maximum concurrent requests across all targets. <= 0 means unlimited.
	MaxConcurrency int
	// Clock provides an optional time source for deterministic testing.
	Clock func() time.Time
	// Sleeper provides an optional sleep hook for deterministic testing.
	Sleeper func(ctx context.Context, d time.Duration) error
}

// RateLimitedTransport wraps an http.RoundTripper with strict per-host rate limiting,
// global concurrency throttling, and accurate wire request telemetry.
type RateLimitedTransport struct {
	base            http.RoundTripper
	rate            float64
	minInterval     time.Duration
	sem             chan struct{}
	hostMu          sync.Mutex
	lastRequestTime map[string]time.Time
	nowFunc         func() time.Time
	sleepFunc       func(ctx context.Context, d time.Duration) error

	// Telemetry counters
	totalRequests   atomic.Int64
	activeRequests  atomic.Int64
	peakConcurrency atomic.Int64
}

// NewRateLimitedTransport constructs a RateLimitedTransport around the provided RoundTripper.
func NewRateLimitedTransport(base http.RoundTripper, opts RateLimitOptions) *RateLimitedTransport {
	if base == nil {
		base = http.DefaultTransport
	}

	var minInterval time.Duration
	if opts.Rate > 0 {
		minInterval = time.Duration(float64(time.Second) / opts.Rate)
	}

	var sem chan struct{}
	if opts.MaxConcurrency > 0 {
		sem = make(chan struct{}, opts.MaxConcurrency)
	}

	nowFunc := opts.Clock
	if nowFunc == nil {
		nowFunc = time.Now
	}

	sleepFunc := opts.Sleeper
	if sleepFunc == nil {
		sleepFunc = func(ctx context.Context, d time.Duration) error {
			if d <= 0 {
				return nil
			}
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}
	}

	return &RateLimitedTransport{
		base:            base,
		rate:            opts.Rate,
		minInterval:     minInterval,
		sem:             sem,
		lastRequestTime: make(map[string]time.Time),
		nowFunc:         nowFunc,
		sleepFunc:       sleepFunc,
	}
}

// RoundTrip coordinates rate limits, concurrency limits, and request dispatch.
func (t *RateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()

	// 1. Enforce overall concurrency cap (if configured)
	if t.sem != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case t.sem <- struct{}{}:
			defer func() { <-t.sem }()
		}
	}

	// 2. Track in-flight concurrency metrics
	current := t.activeRequests.Add(1)
	defer t.activeRequests.Add(-1)

	// Update peak concurrency
	for {
		peak := t.peakConcurrency.Load()
		if current <= peak || t.peakConcurrency.CompareAndSwap(peak, current) {
			break
		}
	}

	// 3. Enforce per-host rate limit (if configured)
	if t.minInterval > 0 {
		host := strings.ToLower(req.URL.Host)
		if host == "" {
			host = strings.ToLower(req.Host)
		}
		if host == "" {
			host = strings.ToLower(req.URL.Hostname())
		}
		// Normalize default ports for consistent bucketing
		if strings.HasSuffix(host, ":80") && (req.URL.Scheme == "http" || req.URL.Scheme == "") {
			host = strings.TrimSuffix(host, ":80")
		} else if strings.HasSuffix(host, ":443") && (req.URL.Scheme == "https" || req.URL.Scheme == "") {
			host = strings.TrimSuffix(host, ":443")
		}

		var waitDuration time.Duration
		t.hostMu.Lock()
		last, exists := t.lastRequestTime[host]
		now := t.nowFunc()
		if exists {
			elapsed := now.Sub(last)
			if elapsed < t.minInterval {
				waitDuration = t.minInterval - elapsed
			}
		}
		// Reserve the upcoming timestamp
		t.lastRequestTime[host] = now.Add(waitDuration)
		t.hostMu.Unlock()

		if waitDuration > 0 {
			if err := t.sleepFunc(ctx, waitDuration); err != nil {
				return nil, err
			}
		}
	}

	// 4. Record actual wire request execution
	t.totalRequests.Add(1)

	// 5. Forward to underlying transport (SafeTransport)
	return t.base.RoundTrip(req)
}

// TotalRequests returns the cumulative count of actual outbound HTTP requests dispatched through this transport.
func (t *RateLimitedTransport) TotalRequests() int64 {
	return t.totalRequests.Load()
}

// ActiveRequests returns the current count of in-flight HTTP requests.
func (t *RateLimitedTransport) ActiveRequests() int64 {
	return t.activeRequests.Load()
}

// PeakConcurrency returns the maximum number of simultaneous requests observed.
func (t *RateLimitedTransport) PeakConcurrency() int64 {
	return t.peakConcurrency.Load()
}
