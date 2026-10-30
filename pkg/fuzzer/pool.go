package fuzzer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ErrPoolClosed indicates an attempt to submit tasks to a terminated pool.
var ErrPoolClosed = errors.New("fuzzing pool is closed")

// ErrTaskCancelled indicates the task was cancelled prior to or during execution.
var ErrTaskCancelled = errors.New("fuzz task cancelled")

// ErrMaxRetriesExceeded indicates that a request failed after exhausting all retry attempts.
var ErrMaxRetriesExceeded = errors.New("maximum retries exceeded under rate limit throttling")

// ErrMetadataSSRFBlocked indicates that a request attempted to contact a protected cloud metadata endpoint.
var ErrMetadataSSRFBlocked = errors.New("blocked request to cloud metadata service")

// ErrNonReplayableBody indicates that a retry was required but the request body could not be rewound.
var ErrNonReplayableBody = errors.New("request body is not replayable across retries (missing GetBody)")

// ErrBodyExceedsReplayLimit indicates that the request body exceeded the 10 MiB limit for retry buffering.
var ErrBodyExceedsReplayLimit = errors.New("request body exceeds 10 MiB replay buffer limit")

// MaxReplayBodySize defines the maximum request body size (10 MiB) buffered in memory for retry replay.
const MaxReplayBodySize = 10 * 1024 * 1024

// combinedReadCloser combines an io.Reader and an io.Closer into a single io.ReadCloser.
type combinedReadCloser struct {
	io.Reader
	io.Closer
}

// Blocked metadata addresses to prevent SSRF against cloud infrastructure.
var (
	blockedMetadataIPv4 = net.ParseIP("169.254.169.254")
	blockedMetadataIPv6 = net.ParseIP("fd00:ec2::254")
	linkLocalIPv4Net    = &net.IPNet{
		IP:   net.ParseIP("169.254.0.0"),
		Mask: net.CIDRMask(16, 32),
	}
)

func isBlockedMetadataIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Check IPv4 and IPv4-mapped IPv6 (::ffff:169.254.169.254)
	if v4 := ip.To4(); v4 != nil {
		if v4.Equal(blockedMetadataIPv4) || linkLocalIPv4Net.Contains(v4) {
			return true
		}
	}
	if ip.Equal(blockedMetadataIPv6) {
		return true
	}
	return false
}

func isBlockedMetadataHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	// Strip port if present
	if sh, _, err := net.SplitHostPort(h); err == nil {
		h = sh
	}
	h = strings.TrimPrefix(h, "[")
	h = strings.TrimSuffix(h, "]")

	if h == "metadata.google.internal" || h == "instance-data" {
		return true
	}

	if ip := net.ParseIP(h); ip != nil {
		return isBlockedMetadataIP(ip)
	}

	return false
}

func createSafeMetadataDialer(baseDialContext func(ctx context.Context, network, addr string) (net.Conn, error)) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
			port = "80"
		}

		if isBlockedMetadataHost(host) {
			return nil, fmt.Errorf("%w: %s", ErrMetadataSSRFBlocked, host)
		}

		// Dial-time DNS resolution validation: prevent DNS rebinding to metadata
		var targetIP net.IP
		if parsedIP := net.ParseIP(host); parsedIP != nil {
			if isBlockedMetadataIP(parsedIP) {
				return nil, fmt.Errorf("%w: %s", ErrMetadataSSRFBlocked, host)
			}
			targetIP = parsedIP
		} else {
			// Resolve hostname at connection time
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve target %s: %w", host, err)
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("no IP addresses found for target %s", host)
			}

			// Validate every resolved IP address against metadata and link-local ranges
			for _, ip := range ips {
				if isBlockedMetadataIP(ip) {
					return nil, fmt.Errorf("%w: %s resolves to %s", ErrMetadataSSRFBlocked, host, ip.String())
				}
			}

			// Pin connection directly to the first safe validated IP address
			targetIP = ips[0]
		}

		// CRITICAL: Pin connection strictly to the validated IP address to prevent TOCTOU DNS rebinding
		pinnedAddr := net.JoinHostPort(targetIP.String(), port)

		if baseDialContext != nil {
			return baseDialContext(ctx, network, pinnedAddr)
		}
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, pinnedAddr)
	}
}

// PoolConfig specifies parameters for the fuzzing worker pool and adaptive rate limiter.
type PoolConfig struct {
	Workers          int                                              // Maximum concurrent workers (default: 20, testbed: 25)
	MinWorkers       int                                              // Minimum throttled concurrency (default: 2)
	QueueCapacity    int                                              // Max queued tasks (default: 2000)
	BaseRate         float64                                          // Target requests/sec (0 = unconstrained)
	MinRate          float64                                          // Floor request rate under backoff (default: 5.0 req/s)
	BackoffBase      time.Duration                                    // Initial backoff duration on HTTP 429 (default: 100ms)
	MaxBackoff       time.Duration                                    // Cap for exponential backoff (default: 3s)
	RecoveryStep     int                                              // Successful consecutive requests before stepping up (default: 5)
	MaxRetries       int                                              // Retries per throttled request (default: 5)
	Timeout          time.Duration                                    // Per-request default timeout (default: 10s)
	BaseTransport    http.RoundTripper                                // Underlying transport
	Clock            func() time.Time                                 // Time provider for deterministic testing
	Sleep            func(ctx context.Context, d time.Duration) error // Sleep hook for deterministic testing
}

// DefaultPoolConfig returns standard production configuration.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		Workers:       20,
		MinWorkers:    2,
		QueueCapacity: 2000,
		BaseRate:      0, // Unconstrained by default, bounded by concurrency
		MinRate:       5.0,
		BackoffBase:   100 * time.Millisecond,
		MaxBackoff:    3 * time.Second,
		RecoveryStep:  5,
		MaxRetries:    5,
		Timeout:       10 * time.Second,
		BaseTransport: http.DefaultTransport,
	}
}

// FuzzTask encapsulates an individual HTTP fuzzing operation.
type FuzzTask struct {
	ID         string
	Request    *http.Request
	Execute    func(ctx context.Context, client *http.Client) (*http.Response, error)
	MaxRetries int
}

// FuzzResult records the outcome of an executed FuzzTask.
type FuzzResult struct {
	TaskID          string
	StatusCode      int
	Body            []byte
	Duration        time.Duration
	RetriesExecuted int
	Throttled       bool
	Error           error
}

// PoolStats provides a telemetry snapshot of pool execution.
type PoolStats struct {
	TotalDispatched int64   `json:"total_dispatched"`
	TotalCompleted  int64   `json:"total_completed"`
	TotalThrottled  int64   `json:"total_throttled"`
	TotalRetried    int64   `json:"total_retried"`
	TotalFailed     int64   `json:"total_failed"`
	PeakConcurrency int64   `json:"peak_concurrency"`
	CurrentActive   int64   `json:"current_active"`
	CurrentWorkers  int32   `json:"current_workers"`
	CurrentRate     float64 `json:"current_rate"`
}

// FuzzingPool orchestrates bounded concurrency, task scheduling, and adaptive 429 backoff.
type FuzzingPool struct {
	cfg       PoolConfig
	client    *http.Client
	transport *AdaptiveRateLimitedTransport

	taskQueue chan taskEnvelope
	wg        sync.WaitGroup
	submitWg  sync.WaitGroup
	closeMu   sync.RWMutex
	closeOnce sync.Once
	closed    atomic.Bool
	quitCh    chan struct{}

	nowFunc   func() time.Time
	sleepFunc func(ctx context.Context, d time.Duration) error
}

type taskEnvelope struct {
	ctx      context.Context
	task     FuzzTask
	resultCh chan<- FuzzResult
}

// NewFuzzingPool creates a new concurrency pool and adaptive rate limiter.
func NewFuzzingPool(cfg PoolConfig) *FuzzingPool {
	if cfg.Workers <= 0 {
		cfg.Workers = 20
	}
	if cfg.MinWorkers <= 0 {
		cfg.MinWorkers = 2
	}
	if cfg.MinWorkers > cfg.Workers {
		cfg.MinWorkers = cfg.Workers
	}
	if cfg.QueueCapacity <= 0 {
		cfg.QueueCapacity = 2000
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 100 * time.Millisecond
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 3 * time.Second
	}
	if cfg.RecoveryStep <= 0 {
		cfg.RecoveryStep = 5
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 5
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.BaseTransport == nil {
		cfg.BaseTransport = http.DefaultTransport
	}

	nowFunc := cfg.Clock
	if nowFunc == nil {
		nowFunc = time.Now
	}

	sleepFunc := cfg.Sleep
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

	transport := newAdaptiveRateLimitedTransport(cfg, nowFunc, sleepFunc)
	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if req.URL != nil && isBlockedMetadataHost(req.URL.Hostname()) {
				return fmt.Errorf("%w: redirect to %s blocked", ErrMetadataSSRFBlocked, req.URL.Hostname())
			}
			return nil
		},
	}

	pool := &FuzzingPool{
		cfg:       cfg,
		client:    client,
		transport: transport,
		taskQueue: make(chan taskEnvelope, cfg.QueueCapacity),
		quitCh:    make(chan struct{}),
		nowFunc:   nowFunc,
		sleepFunc: sleepFunc,
	}

	// Start worker pool goroutines
	for i := 0; i < cfg.Workers; i++ {
		pool.wg.Add(1)
		go pool.workerLoop(i)
	}

	return pool
}

// Client returns an HTTP client routed through the pool's adaptive rate limiter.
func (p *FuzzingPool) Client() *http.Client {
	return p.client
}

// Submit queues a single FuzzTask and returns a receive-only channel for its result.
// Thread-safe and immune to WaitGroup misuse panics when called concurrently with Close().
func (p *FuzzingPool) Submit(ctx context.Context, task FuzzTask) (<-chan FuzzResult, error) {
	p.closeMu.RLock()
	if p.closed.Load() {
		p.closeMu.RUnlock()
		return nil, ErrPoolClosed
	}
	p.submitWg.Add(1)
	p.closeMu.RUnlock()
	defer p.submitWg.Done()

	resCh := make(chan FuzzResult, 1)
	env := taskEnvelope{
		ctx:      ctx,
		task:     task,
		resultCh: resCh,
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.quitCh:
		return nil, ErrPoolClosed
	case p.taskQueue <- env:
		p.transport.totalDispatched.Add(1)
		return resCh, nil
	}
}

// Dispatch executes a collection of tasks concurrently through the pool,
// collecting all results while enforcing concurrency caps and rate limits.
func (p *FuzzingPool) Dispatch(ctx context.Context, tasks []FuzzTask) ([]FuzzResult, error) {
	if len(tasks) == 0 {
		return nil, nil
	}

	results := make([]FuzzResult, len(tasks))
	var dispatchWg sync.WaitGroup
	dispatchWg.Add(len(tasks))

	for i, task := range tasks {
		idx := i
		t := task
		go func() {
			defer dispatchWg.Done()
			resCh, err := p.Submit(ctx, t)
			if err != nil {
				results[idx] = FuzzResult{
					TaskID: t.ID,
					Error:  err,
				}
				return
			}

			select {
			case <-ctx.Done():
				results[idx] = FuzzResult{
					TaskID: t.ID,
					Error:  ctx.Err(),
				}
			case res, ok := <-resCh:
				if !ok {
					results[idx] = FuzzResult{
						TaskID: t.ID,
						Error:  ErrTaskCancelled,
					}
				} else {
					results[idx] = res
				}
			}
		}()
	}

	dispatchWg.Wait()
	return results, nil
}

// Close gracefully stops accepting new tasks, waits for in-flight submissions to resolve,
// terminates worker goroutines, and unblocks without panic or leak.
func (p *FuzzingPool) Close() error {
	p.closeOnce.Do(func() {
		p.closeMu.Lock()
		p.closed.Store(true)
		p.closeMu.Unlock()

		close(p.quitCh)    // unblock any Submit blocked on quitCh or taskQueue
		p.submitWg.Wait()  // wait for all active registered Submits to exit
		close(p.taskQueue) // 100% safe: zero goroutines sending to taskQueue
		p.wg.Wait()        // wait for worker loops to drain and terminate
	})
	return nil
}

// Stats returns an instantaneous snapshot of pool performance and health.
func (p *FuzzingPool) Stats() PoolStats {
	return PoolStats{
		TotalDispatched: p.transport.totalDispatched.Load(),
		TotalCompleted:  p.transport.totalCompleted.Load(),
		TotalThrottled:  p.transport.totalThrottled.Load(),
		TotalRetried:    p.transport.totalRetried.Load(),
		TotalFailed:     p.transport.totalFailed.Load(),
		PeakConcurrency: p.transport.peakConcurrency.Load(),
		CurrentActive:   p.transport.currentActiveMetric.Load(),
		CurrentWorkers:  p.transport.CurrentWorkers(),
		CurrentRate:     p.transport.CurrentRate(),
	}
}

func (p *FuzzingPool) workerLoop(workerID int) {
	defer p.wg.Done()

	for env := range p.taskQueue {
		// Check context cancellation before executing
		if env.ctx.Err() != nil {
			env.resultCh <- FuzzResult{
				TaskID: env.task.ID,
				Error:  env.ctx.Err(),
			}
			close(env.resultCh)
			p.transport.totalCompleted.Add(1)
			continue
		}

		res := p.executeTask(env.ctx, env.task)
		env.resultCh <- res
		close(env.resultCh)
		p.transport.totalCompleted.Add(1)
	}
}

func (p *FuzzingPool) executeTask(ctx context.Context, task FuzzTask) FuzzResult {
	maxRetries := task.MaxRetries
	if maxRetries <= 0 {
		maxRetries = p.cfg.MaxRetries
	}

	var isOversizedBody bool

	// Request-Body Replay Safety: Ensure body can be rewound across retries up to MaxReplayBodySize (10 MiB)
	if task.Request != nil && task.Request.Body != nil && task.Request.Body != http.NoBody {
		if task.Request.GetBody == nil && task.Request.Header.Get("X-Felix-No-Replay") != "true" {
			if ctx.Err() != nil {
				_ = task.Request.Body.Close()
				return FuzzResult{
					TaskID: task.ID,
					Error:  ctx.Err(),
				}
			}

			// Read with bounded limit: MaxReplayBodySize + 1 to detect oversized bodies
			limited := io.LimitReader(task.Request.Body, MaxReplayBodySize+1)
			bodyBytes, err := io.ReadAll(limited)
			if err != nil {
				_ = task.Request.Body.Close()
				p.transport.totalFailed.Add(1)
				return FuzzResult{
					TaskID: task.ID,
					Error:  fmt.Errorf("failed to read request body: %w", err),
				}
			}

			if int64(len(bodyBytes)) > MaxReplayBodySize {
				// Body exceeds 10 MiB limit: do not buffer in memory for retries.
				// Reconstruct stream for attempt 0 to preserve first-attempt execution:
				isOversizedBody = true
				origBody := task.Request.Body
				task.Request.Body = combinedReadCloser{
					Reader: io.MultiReader(bytes.NewReader(bodyBytes), origBody),
					Closer: origBody,
				}
				// Leave GetBody as nil so attempts to retry oversized bodies abort explicitly
			} else {
				// Body is within 10 MiB limit: close original stream, replace Body and set GetBody
				_ = task.Request.Body.Close()
				task.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				task.Request.GetBody = func() (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(bodyBytes)), nil
				}
				if task.Request.ContentLength <= 0 && len(task.Request.TransferEncoding) == 0 {
					task.Request.ContentLength = int64(len(bodyBytes))
				}
			}
		}
	}

	var retriesExecuted int
	var wasThrottled bool
	startTime := p.nowFunc()

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if ctx.Err() != nil {
			return FuzzResult{
				TaskID:          task.ID,
				Duration:        p.nowFunc().Sub(startTime),
				RetriesExecuted: retriesExecuted,
				Throttled:       wasThrottled,
				Error:           ctx.Err(),
			}
		}

		var resp *http.Response
		var err error

		if task.Execute != nil {
			resp, err = task.Execute(ctx, p.client)
		} else if task.Request != nil {
			reqWithCtx := task.Request.Clone(ctx)
			// For retry attempts (attempt > 0), rewind body via GetBody
			if attempt > 0 && reqWithCtx.Body != nil && reqWithCtx.Body != http.NoBody {
				if reqWithCtx.GetBody != nil {
					freshBody, bErr := reqWithCtx.GetBody()
					if bErr != nil {
						p.transport.totalFailed.Add(1)
						if errors.Is(bErr, ErrNonReplayableBody) {
							return FuzzResult{
								TaskID:          task.ID,
								Duration:        p.nowFunc().Sub(startTime),
								RetriesExecuted: retriesExecuted,
								Throttled:       wasThrottled,
								Error:           ErrNonReplayableBody,
							}
						}
						return FuzzResult{
							TaskID:          task.ID,
							Duration:        p.nowFunc().Sub(startTime),
							RetriesExecuted: retriesExecuted,
							Throttled:       wasThrottled,
							Error:           fmt.Errorf("failed to rewind request body for retry: %w", bErr),
						}
					}
					reqWithCtx.Body = freshBody
				} else {
					p.transport.totalFailed.Add(1)
					if isOversizedBody {
						return FuzzResult{
							TaskID:          task.ID,
							Duration:        p.nowFunc().Sub(startTime),
							RetriesExecuted: retriesExecuted,
							Throttled:       wasThrottled,
							Error:           ErrBodyExceedsReplayLimit,
						}
					}
					return FuzzResult{
						TaskID:          task.ID,
						Duration:        p.nowFunc().Sub(startTime),
						RetriesExecuted: retriesExecuted,
						Throttled:       wasThrottled,
						Error:           ErrNonReplayableBody,
					}
				}
			}
			resp, err = p.client.Do(reqWithCtx)
		} else {
			return FuzzResult{
				TaskID: task.ID,
				Error:  errors.New("fuzz task has neither Request nor Execute function"),
			}
		}

		// Handle connection dropout / network errors
		if err != nil {
			// Check if temporary connection dropout that can be retried
			if attempt < maxRetries && isRetryableNetworkError(err) {
				retriesExecuted++
				wasThrottled = true
				p.transport.totalRetried.Add(1)
				p.transport.RecordConnectionDrop()
				_ = p.sleepFunc(ctx, p.cfg.BackoffBase)
				continue
			}

			p.transport.totalFailed.Add(1)
			return FuzzResult{
				TaskID:          task.ID,
				Duration:        p.nowFunc().Sub(startTime),
				RetriesExecuted: retriesExecuted,
				Throttled:       wasThrottled,
				Error:           err,
			}
		}

		// Handle HTTP 429 Too Many Requests
		if resp.StatusCode == http.StatusTooManyRequests {
			wasThrottled = true
			p.transport.totalThrottled.Add(1)

			if attempt < maxRetries {
				retriesExecuted++
				p.transport.totalRetried.Add(1)

				// Extract Retry-After if available
				retryAfterStr := resp.Header.Get("Retry-After")
				_ = resp.Body.Close()

				// Tell transport to dynamically back off and sleep
				backoff := p.transport.Record429(retryAfterStr)
				_ = p.sleepFunc(ctx, backoff)
				continue
			}

			// Retries exhausted
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			_ = resp.Body.Close()
			p.transport.totalFailed.Add(1)
			return FuzzResult{
				TaskID:          task.ID,
				StatusCode:      resp.StatusCode,
				Body:            body,
				Duration:        p.nowFunc().Sub(startTime),
				RetriesExecuted: retriesExecuted,
				Throttled:       true,
				Error:           ErrMaxRetriesExceeded,
			}
		}

		// Successful response (2xx, 3xx, 4xx other than 429, 5xx)
		p.transport.RecordSuccess()

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		_ = resp.Body.Close()

		return FuzzResult{
			TaskID:          task.ID,
			StatusCode:      resp.StatusCode,
			Body:            body,
			Duration:        p.nowFunc().Sub(startTime),
			RetriesExecuted: retriesExecuted,
			Throttled:       wasThrottled,
			Error:           readErr,
		}
	}

	p.transport.totalFailed.Add(1)
	return FuzzResult{
		TaskID:          task.ID,
		Duration:        p.nowFunc().Sub(startTime),
		RetriesExecuted: retriesExecuted,
		Throttled:       wasThrottled,
		Error:           ErrMaxRetriesExceeded,
	}
}

// AdaptiveRateLimitedTransport implements RoundTripper with dynamic concurrency
// adjustment and rate adaptation in response to HTTP 429 and server backoff signals.
type AdaptiveRateLimitedTransport struct {
	base            http.RoundTripper
	cfg             PoolConfig
	nowFunc         func() time.Time
	sleepFunc       func(ctx context.Context, d time.Duration) error

	mu              sync.Mutex
	currentRate     float64
	currentWorkers  int32
	maxWorkers      int32
	minWorkers      int32
	consecutive429s int
	consecutive200s int
	backoffUntil    time.Time
	lastRequestTime map[string]time.Time

	// Dynamic Concurrency Semaphore
	currentActive   int32
	slotAvailable   chan struct{}

	// Metrics
	totalDispatched     atomic.Int64
	totalCompleted      atomic.Int64
	totalThrottled      atomic.Int64
	totalRetried        atomic.Int64
	totalFailed         atomic.Int64
	peakConcurrency     atomic.Int64
	currentActiveMetric atomic.Int64
}

func newAdaptiveRateLimitedTransport(cfg PoolConfig, nowFunc func() time.Time, sleepFunc func(ctx context.Context, d time.Duration) error) *AdaptiveRateLimitedTransport {
	base := cfg.BaseTransport
	if base == nil {
		base = http.DefaultTransport
	}

	// Dial-time socket boundary protection against cloud metadata SSRF
	if httpTr, ok := base.(*http.Transport); ok {
		cloned := httpTr.Clone()
		cloned.DialContext = createSafeMetadataDialer(httpTr.DialContext)
		base = cloned
	}

	return &AdaptiveRateLimitedTransport{
		base:            base,
		cfg:             cfg,
		nowFunc:         nowFunc,
		sleepFunc:       sleepFunc,
		currentRate:     cfg.BaseRate,
		currentWorkers:  int32(cfg.Workers),
		maxWorkers:      int32(cfg.Workers),
		minWorkers:      int32(cfg.MinWorkers),
		lastRequestTime: make(map[string]time.Time),
		slotAvailable:   make(chan struct{}),
	}
}

// RoundTrip acquires concurrency slots, enforces adaptive pacing, and forwards to base transport.
func (t *AdaptiveRateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// 1. SSRF Guard: reject cloud metadata addresses and hostnames at request boundary
	if req.URL != nil {
		host := req.URL.Hostname()
		if isBlockedMetadataHost(host) {
			return nil, fmt.Errorf("%w: %s", ErrMetadataSSRFBlocked, host)
		}
		// Resolve host to detect DNS rebinding to metadata IPs before network dispatch
		if host != "" && net.ParseIP(host) == nil {
			if ips, err := net.DefaultResolver.LookupIP(req.Context(), "ip", host); err == nil {
				for _, ip := range ips {
					if isBlockedMetadataIP(ip) {
						return nil, fmt.Errorf("%w: %s resolves to %s", ErrMetadataSSRFBlocked, host, ip.String())
					}
				}
			}
		}
	}

	ctx := req.Context()

	// 2. Check and wait for active backoff window if throttled
	if err := t.waitBackoff(ctx); err != nil {
		return nil, err
	}

	// 3. Acquire dynamic concurrency slot (strictly bounded by currentWorkers)
	if err := t.acquireSlot(ctx); err != nil {
		return nil, err
	}
	defer t.releaseSlot()

	// 4. Rate pacing per target host (lock released before sleeping)
	if err := t.paceRequest(ctx, req); err != nil {
		return nil, err
	}

	// 5. Execute request via base RoundTripper
	return t.base.RoundTrip(req)
}

func (t *AdaptiveRateLimitedTransport) acquireSlot(ctx context.Context) error {
	for {
		t.mu.Lock()
		if t.currentActive < t.currentWorkers {
			t.currentActive++
			t.currentActiveMetric.Store(int64(t.currentActive))
			active := int64(t.currentActive)
			for {
				peak := t.peakConcurrency.Load()
				if active <= peak {
					break
				}
				if t.peakConcurrency.CompareAndSwap(peak, active) {
					break
				}
			}
			t.mu.Unlock()
			return nil
		}
		notify := t.slotAvailable
		t.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-notify:
		}
	}
}

func (t *AdaptiveRateLimitedTransport) releaseSlot() {
	t.mu.Lock()
	if t.currentActive > 0 {
		t.currentActive--
		t.currentActiveMetric.Store(int64(t.currentActive))
	}
	oldNotify := t.slotAvailable
	t.slotAvailable = make(chan struct{})
	t.mu.Unlock()
	close(oldNotify)
}

func (t *AdaptiveRateLimitedTransport) waitBackoff(ctx context.Context) error {
	t.mu.Lock()
	until := t.backoffUntil
	now := t.nowFunc()
	t.mu.Unlock()

	if until.After(now) {
		remaining := until.Sub(now)
		return t.sleepFunc(ctx, remaining)
	}
	return nil
}

// paceRequest enforces requests-per-second pacing without holding the transport lock while sleeping.
func (t *AdaptiveRateLimitedTransport) paceRequest(ctx context.Context, req *http.Request) error {
	var delay time.Duration

	t.mu.Lock()
	if t.currentRate > 0 && req.URL != nil {
		hostKey := req.URL.Host
		now := t.nowFunc()
		interval := time.Duration(float64(time.Second) / t.currentRate)

		lastScheduled, exists := t.lastRequestTime[hostKey]
		if !exists || lastScheduled.Before(now) {
			t.lastRequestTime[hostKey] = now
			delay = 0
		} else {
			nextScheduled := lastScheduled.Add(interval)
			t.lastRequestTime[hostKey] = nextScheduled
			delay = nextScheduled.Sub(now)
		}
	}
	t.mu.Unlock()

	if delay > 0 {
		return t.sleepFunc(ctx, delay)
	}
	return nil
}

// Record429 adjusts the limiter downwards (AIMD: Multiplicative Decrease) and computes backoff duration.
func (t *AdaptiveRateLimitedTransport) Record429(retryAfterHeader string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.consecutive429s++
	t.consecutive200s = 0

	// 1. Reduce concurrency: halve current worker cap down to minWorkers
	newWorkers := t.currentWorkers / 2
	if newWorkers < t.minWorkers {
		newWorkers = t.minWorkers
	}
	t.currentWorkers = newWorkers

	// 2. Reduce rate limit if configured
	if t.currentRate > 0 {
		newRate := t.currentRate * 0.5
		if newRate < t.cfg.MinRate {
			newRate = t.cfg.MinRate
		}
		t.currentRate = newRate
	}

	// 3. Compute backoff duration with support for integer seconds and HTTP-date formats
	var backoff time.Duration
	if trimmed := strings.TrimSpace(retryAfterHeader); trimmed != "" {
		if secs, err := strconv.Atoi(trimmed); err == nil {
			if secs > 0 {
				backoff = time.Duration(secs) * time.Second
			}
		} else if parsedDate, err := http.ParseTime(trimmed); err == nil {
			now := t.nowFunc()
			if parsedDate.After(now) {
				backoff = parsedDate.Sub(now)
			}
		}
	}

	if backoff <= 0 {
		// Exponential backoff: base * 2^(min(429s-1, 4))
		factor := math.Pow(2, float64(intMin(t.consecutive429s-1, 4)))
		backoff = time.Duration(float64(t.cfg.BackoffBase) * factor)
	}

	// Consistently cap backoff against MaxBackoff ceiling and BackoffBase floor
	if backoff > t.cfg.MaxBackoff {
		backoff = t.cfg.MaxBackoff
	}
	if backoff <= 0 {
		backoff = t.cfg.BackoffBase
	}

	t.backoffUntil = t.nowFunc().Add(backoff)
	return backoff
}

// RecordConnectionDrop applies backoff when an unexpected connection reset occurs.
func (t *AdaptiveRateLimitedTransport) RecordConnectionDrop() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.consecutive429s++
	t.consecutive200s = 0

	newWorkers := t.currentWorkers - 2
	if newWorkers < t.minWorkers {
		newWorkers = t.minWorkers
	}
	t.currentWorkers = newWorkers
	t.backoffUntil = t.nowFunc().Add(t.cfg.BackoffBase)
}

// RecordSuccess adjusts the limiter upwards (AIMD: Additive Increase) after stable responses.
func (t *AdaptiveRateLimitedTransport) RecordSuccess() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.consecutive200s++
	if t.consecutive200s >= t.cfg.RecoveryStep {
		t.consecutive200s = 0
		t.consecutive429s = 0

		// Additive increase in workers up to maxWorkers
		if t.currentWorkers < t.maxWorkers {
			t.currentWorkers++
			oldNotify := t.slotAvailable
			t.slotAvailable = make(chan struct{})
			close(oldNotify)
		}

		// Additive increase in rate up to BaseRate
		if t.cfg.BaseRate > 0 && t.currentRate < t.cfg.BaseRate {
			step := (t.cfg.BaseRate - t.cfg.MinRate) * 0.2
			if step < 1.0 {
				step = 1.0
			}
			t.currentRate = math.Min(t.cfg.BaseRate, t.currentRate+step)
		}
	}
}

// CurrentWorkers returns the active dynamic concurrency cap.
func (t *AdaptiveRateLimitedTransport) CurrentWorkers() int32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.currentWorkers
}

// CurrentRate returns the active requests per second pacing.
func (t *AdaptiveRateLimitedTransport) CurrentRate() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.currentRate
}

func isRetryableNetworkError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	msg := err.Error()
	return bytes.Contains([]byte(msg), []byte("connection reset")) ||
		bytes.Contains([]byte(msg), []byte("broken pipe")) ||
		bytes.Contains([]byte(msg), []byte("EOF"))
}

func intMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}
