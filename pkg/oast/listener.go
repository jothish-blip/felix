package oast

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/dns/dnsmessage"
)

var (
	ErrExternalBindingDenied  = errors.New("oast: external listener binding requires explicit AllowExternal authorization")
	ErrListenerNotRunning     = errors.New("oast: listener is not running")
	ErrListenerAlreadyRunning = errors.New("oast: listener is already running")
)

var tokenExtractorRegex = regexp.MustCompile(`(?i)(?:^|\.)(?:probe-)?([0-9a-f]{32})(?:\.|$)`)

// ExtractTokenFromHost extracts a 32-hex character OAST token from a hostname or domain name.
// Supports probe-<token>.<domain>, <token>.<domain>, and standalone token strings.
func ExtractTokenFromHost(host string) string {
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	match := tokenExtractorRegex.FindStringSubmatch(host)
	if len(match) == 2 {
		return strings.ToLower(match[1])
	}
	return ""
}

// ListenerConfig defines the binding, security boundaries, and protocol behavior of the OAST Listener.
type ListenerConfig struct {
	OASTDomain     string        `json:"oast_domain"`
	HTTPBindAddr   string        `json:"http_bind_addr"`
	DNSBindAddr    string        `json:"dns_bind_addr"`
	ResponseIPv4   net.IP        `json:"response_ipv4"`
	DefaultTTL     time.Duration `json:"default_ttl"`
	MaxBodyBytes   int64         `json:"max_body_bytes"`
	MaxProbes      int           `json:"max_probes"`
	AllowLoopback  bool          `json:"allow_loopback"`
	AllowExternal  bool          `json:"allow_external"`
}

// LatencyPercentiles provides nanosecond-precision statistical percentiles for callback matching.
type LatencyPercentiles struct {
	Count int64   `json:"count"`
	MinUS float64 `json:"min_us"`
	MaxUS float64 `json:"max_us"`
	P50US float64 `json:"p50_us"`
	P90US float64 `json:"p90_us"`
	P95US float64 `json:"p95_us"`
	P99US float64 `json:"p99_us"`
	P50NS int64   `json:"p50_ns"`
	P90NS int64   `json:"p90_ns"`
	P95NS int64   `json:"p95_ns"`
	P99NS int64   `json:"p99_ns"`
}

// ListenerMetrics records operation counts and matching latencies.
type ListenerMetrics struct {
	ProbesGenerated      int64 `json:"probes_generated"`
	DNSQueriesReceived   int64 `json:"dns_queries_received"`
	HTTPRequestsReceived int64 `json:"http_requests_received"`
	CorrelatedCount      int64 `json:"correlated_count"`
	DuplicateCount       int64 `json:"duplicate_count"`
	UnknownTokenCount    int64 `json:"unknown_token_count"`
	ExpiredTokenCount    int64 `json:"expired_token_count"`
	ErrorCount           int64 `json:"error_count"`

	mu                sync.Mutex
	matchingLatencies []time.Duration
}

// RecordLatency logs a matching duration.
func (m *ListenerMetrics) RecordLatency(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.matchingLatencies = append(m.matchingLatencies, d)
}

// Percentiles calculates exact statistical percentiles from measured latencies.
func (m *ListenerMetrics) Percentiles() LatencyPercentiles {
	m.mu.Lock()
	defer m.mu.Unlock()

	n := len(m.matchingLatencies)
	if n == 0 {
		return LatencyPercentiles{}
	}

	sorted := make([]time.Duration, n)
	copy(sorted, m.matchingLatencies)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	perc := func(p float64) time.Duration {
		idx := int(float64(n-1) * p)
		if idx < 0 {
			idx = 0
		}
		if idx >= n {
			idx = n - 1
		}
		return sorted[idx]
	}

	p50 := perc(0.50)
	p90 := perc(0.90)
	p95 := perc(0.95)
	p99 := perc(0.99)
	min := sorted[0]
	max := sorted[n-1]

	return LatencyPercentiles{
		Count: int64(n),
		MinUS: float64(min.Nanoseconds()) / 1000.0,
		MaxUS: float64(max.Nanoseconds()) / 1000.0,
		P50US: float64(p50.Nanoseconds()) / 1000.0,
		P90US: float64(p90.Nanoseconds()) / 1000.0,
		P95US: float64(p95.Nanoseconds()) / 1000.0,
		P99US: float64(p99.Nanoseconds()) / 1000.0,
		P50NS: p50.Nanoseconds(),
		P90NS: p90.Nanoseconds(),
		P95NS: p95.Nanoseconds(),
		P99NS: p99.Nanoseconds(),
	}
}

// Listener provides unified management of DNS and HTTP out-of-band callback endpoints.
type Listener struct {
	cfg        ListenerConfig
	correlator *Correlator
	metrics    *ListenerMetrics

	httpListener net.Listener
	httpServer   *http.Server
	httpAddr     net.Addr

	dnsConn *net.UDPConn
	dnsAddr *net.UDPAddr

	running  bool
	stopOnce sync.Once
	stopChan chan struct{}
	wg       sync.WaitGroup
	mu       sync.RWMutex
}

// NewListener creates an initialized OAST Listener instance.
func NewListener(cfg ListenerConfig, correlator *Correlator) (*Listener, error) {
	if correlator == nil {
		var err error
		correlatorCfg := DefaultConfig()
		correlatorCfg.AllowLoopback = cfg.AllowLoopback
		if cfg.OASTDomain != "" {
			correlatorCfg.OASTDomain = cfg.OASTDomain
		}
		if cfg.MaxProbes > 0 {
			correlatorCfg.MaxProbes = cfg.MaxProbes
		}
		correlator, err = NewCorrelator(correlatorCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize default correlator: %w", err)
		}
	} else if cfg.MaxProbes > 0 {
		correlator.mu.Lock()
		correlator.cfg.MaxProbes = cfg.MaxProbes
		correlator.mu.Unlock()
	}

	if cfg.HTTPBindAddr == "" {
		cfg.HTTPBindAddr = "127.0.0.1:0"
	}
	if cfg.DNSBindAddr == "" {
		cfg.DNSBindAddr = "127.0.0.1:0"
	}
	if cfg.ResponseIPv4 == nil {
		cfg.ResponseIPv4 = net.ParseIP("127.0.0.1")
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 64 * 1024
	}
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = 30 * time.Second
	}
	if cfg.OASTDomain == "" {
		cfg.OASTDomain = "oast.felix.internal"
	}

	return &Listener{
		cfg:        cfg,
		correlator: correlator,
		metrics:    &ListenerMetrics{},
		stopChan:   make(chan struct{}),
	}, nil
}

// Start binds and starts both the DNS and HTTP callback listeners.
func (l *Listener) Start(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return ErrListenerAlreadyRunning
	}

	// 1. Start DNS Listener
	if err := l.startDNS(); err != nil {
		return fmt.Errorf("failed to start DNS listener: %w", err)
	}

	// 2. Start HTTP Listener
	if err := l.startHTTP(); err != nil {
		_ = l.stopDNS()
		return fmt.Errorf("failed to start HTTP listener: %w", err)
	}

	l.running = true
	return nil
}

func (l *Listener) startDNS() error {
	udpAddr, err := net.ResolveUDPAddr("udp", l.cfg.DNSBindAddr)
	if err != nil {
		return fmt.Errorf("resolve DNS bind addr %q: %w", l.cfg.DNSBindAddr, err)
	}

	// Enforce external listener restriction
	if !l.cfg.AllowExternal {
		if udpAddr.IP != nil && !udpAddr.IP.IsLoopback() && !udpAddr.IP.IsUnspecified() {
			return ErrExternalBindingDenied
		}
		if udpAddr.IP != nil && udpAddr.IP.IsUnspecified() {
			return ErrExternalBindingDenied
		}
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen UDP on %s: %w", udpAddr, err)
	}

	l.dnsConn = conn
	l.dnsAddr = conn.LocalAddr().(*net.UDPAddr)

	l.wg.Add(1)
	go l.serveDNS()
	return nil
}

func (l *Listener) serveDNS() {
	defer l.wg.Done()
	buf := make([]byte, 4096)

	for {
		select {
		case <-l.stopChan:
			return
		default:
		}

		n, remoteAddr, err := l.dnsConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-l.stopChan:
				return
			default:
				if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				continue
			}
		}

		atomic.AddInt64(&l.metrics.DNSQueriesReceived, 1)

		var msg dnsmessage.Message
		if err := msg.Unpack(buf[:n]); err != nil {
			atomic.AddInt64(&l.metrics.ErrorCount, 1)
			continue
		}

		l.handleDNSMessage(&msg, remoteAddr)
	}
}

func (l *Listener) handleDNSMessage(reqMsg *dnsmessage.Message, remoteAddr *net.UDPAddr) {
	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 reqMsg.ID,
			Response:           true,
			Authoritative:      true,
			RecursionAvailable: false,
		},
		Questions: reqMsg.Questions,
	}

	matchedAny := false
	tokenFound := false

	clientIP := ""
	if remoteAddr != nil {
		clientIP = remoteAddr.IP.String()
	}

	for _, q := range reqMsg.Questions {
		qName := q.Name.String()
		token := ExtractTokenFromHost(qName)
		if token == "" {
			continue
		}
		tokenFound = true

		startNano := MonotonicNowNano()
		interaction := Interaction{
			ID:         uuid.New().String(),
			Token:      token,
			Protocol:   ProtocolDNS,
			ClientIP:   clientIP,
			Method:     "DNS_" + q.Type.String(),
			Path:       qName,
			ReceivedAt: time.Now().UTC(),
		}

		result, err := l.correlator.RecordInteraction(context.Background(), interaction)
		matchLatency := time.Duration(MonotonicNowNano() - startNano)
		l.metrics.RecordLatency(matchLatency)

		if err == nil && result != nil && result.Matched {
			matchedAny = true
			atomic.AddInt64(&l.metrics.CorrelatedCount, 1)
		} else if err == ErrDuplicateCallback {
			matchedAny = true
			atomic.AddInt64(&l.metrics.DuplicateCount, 1)
		} else if err == ErrProbeNotFound {
			atomic.AddInt64(&l.metrics.UnknownTokenCount, 1)
		} else if err == ErrProbeExpired {
			atomic.AddInt64(&l.metrics.ExpiredTokenCount, 1)
		}

		// Generate RFC 1035 response answers
		switch q.Type {
		case dnsmessage.TypeA:
			respIP := l.cfg.ResponseIPv4
			if respIP == nil {
				respIP = net.ParseIP("127.0.0.1")
			}
			var ip4 [4]byte
			copy(ip4[:], respIP.To4())
			resp.Answers = append(resp.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  q.Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AResource{A: ip4},
			})
		case dnsmessage.TypeAAAA:
			var ip6 [16]byte
			ip := net.ParseIP("::1")
			copy(ip6[:], ip.To16())
			resp.Answers = append(resp.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  q.Name,
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AAAAResource{AAAA: ip6},
			})
		case dnsmessage.TypeTXT:
			resp.Answers = append(resp.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  q.Name,
					Type:  dnsmessage.TypeTXT,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.TXTResource{TXT: []string{"felix-oast-ack"}},
			})
		}
	}

	if tokenFound && !matchedAny {
		resp.RCode = dnsmessage.RCodeNameError
	} else {
		resp.RCode = dnsmessage.RCodeSuccess
	}

	packed, err := resp.Pack()
	if err != nil {
		atomic.AddInt64(&l.metrics.ErrorCount, 1)
		return
	}

	_, _ = l.dnsConn.WriteToUDP(packed, remoteAddr)
}

func (l *Listener) stopDNS() error {
	if l.dnsConn != nil {
		return l.dnsConn.Close()
	}
	return nil
}

func (l *Listener) startHTTP() error {
	tcpAddr, err := net.ResolveTCPAddr("tcp", l.cfg.HTTPBindAddr)
	if err != nil {
		return fmt.Errorf("resolve HTTP bind addr %q: %w", l.cfg.HTTPBindAddr, err)
	}

	if !l.cfg.AllowExternal {
		if tcpAddr.IP != nil && !tcpAddr.IP.IsLoopback() && !tcpAddr.IP.IsUnspecified() {
			return ErrExternalBindingDenied
		}
		if tcpAddr.IP != nil && tcpAddr.IP.IsUnspecified() {
			return ErrExternalBindingDenied
		}
	}

	ln, err := net.Listen("tcp", l.cfg.HTTPBindAddr)
	if err != nil {
		return fmt.Errorf("listen TCP on %s: %w", l.cfg.HTTPBindAddr, err)
	}
	l.httpListener = ln
	l.httpAddr = ln.Addr()

	// Update correlator base URL with the exact allocated listener address
	if l.cfg.AllowLoopback {
		_ = l.correlator.SetBaseURL(fmt.Sprintf("http://%s", l.httpAddr.String()))
	}

	handler := http.HandlerFunc(l.handleHTTPRequest)
	l.httpServer = &http.Server{
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		if err := l.httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			atomic.AddInt64(&l.metrics.ErrorCount, 1)
		}
	}()

	return nil
}

func (l *Listener) handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&l.metrics.HTTPRequestsReceived, 1)

	token := extractToken(r)
	if token == "" {
		atomic.AddInt64(&l.metrics.ErrorCount, 1)
		http.Error(w, `{"error":"missing interaction token"}`, http.StatusBadRequest)
		return
	}

	maxBytes := l.cfg.MaxBodyBytes
	if maxBytes <= 0 {
		maxBytes = 64 * 1024
	}

	lr := io.LimitReader(r.Body, maxBytes+1)
	bodyBytes, err := io.ReadAll(lr)
	if err != nil {
		atomic.AddInt64(&l.metrics.ErrorCount, 1)
		http.Error(w, `{"error":"failed to read request body"}`, http.StatusBadRequest)
		return
	}
	if int64(len(bodyBytes)) > maxBytes {
		atomic.AddInt64(&l.metrics.ErrorCount, 1)
		http.Error(w, `{"error":"`+ErrPayloadTooLarge.Error()+`"}`, http.StatusRequestEntityTooLarge)
		return
	}

	sanitizedBody := SanitizeInteractionData(string(bodyBytes))
	rawHeaders := make(map[string]string)
	for k, vals := range r.Header {
		if len(vals) > 0 {
			rawHeaders[k] = strings.Join(vals, ", ")
		}
	}
	sanitizedHeaders := SanitizeInteractionHeaders(rawHeaders)

	clientIP := r.RemoteAddr
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}
	clientIP = strings.TrimPrefix(strings.TrimSuffix(clientIP, "]"), "[")
	clientIP = SanitizeInteractionData(clientIP)

	sanitizedMethod := sanitizeMethod(r.Method)
	sanitizedPath := SanitizeInteractionData(r.URL.Path)
	if len(sanitizedPath) > 1024 {
		sanitizedPath = sanitizedPath[:1024]
	}

	assessmentID := SanitizeInteractionData(r.Header.Get("X-Felix-Assessment"))

	interaction := Interaction{
		ID:           uuid.New().String(),
		Token:        token,
		AssessmentID: assessmentID,
		Protocol:     ProtocolHTTP,
		ClientIP:     clientIP,
		Method:       sanitizedMethod,
		Path:         sanitizedPath,
		Headers:      sanitizedHeaders,
		Body:         sanitizedBody,
		ReceivedAt:   time.Now().UTC(),
	}

	startNano := MonotonicNowNano()
	result, err := l.correlator.RecordInteraction(r.Context(), interaction)
	matchLatency := time.Duration(MonotonicNowNano() - startNano)
	l.metrics.RecordLatency(matchLatency)

	if err != nil {
		switch err {
		case ErrProbeNotFound:
			atomic.AddInt64(&l.metrics.UnknownTokenCount, 1)
			http.Error(w, `{"error":"probe not found"}`, http.StatusNotFound)
			return
		case ErrProbeExpired:
			atomic.AddInt64(&l.metrics.ExpiredTokenCount, 1)
			http.Error(w, `{"error":"probe expired"}`, http.StatusGone)
			return
		case ErrProbeCancelled:
			http.Error(w, `{"error":"probe cancelled"}`, http.StatusGone)
			return
		case ErrCrossAssessment:
			http.Error(w, `{"error":"cross-assessment isolation violation"}`, http.StatusForbidden)
			return
		case ErrDuplicateCallback:
			atomic.AddInt64(&l.metrics.DuplicateCount, 1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":    "duplicate_recorded",
				"duplicate": true,
				"token":     token,
			})
			return
		default:
			atomic.AddInt64(&l.metrics.ErrorCount, 1)
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
	}

	atomic.AddInt64(&l.metrics.CorrelatedCount, 1)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":      "correlated",
		"probe_id":    result.Probe.ID,
		"interaction": result.Interaction.ID,
		"token":       token,
	})
}

// Stop gracefully shuts down both DNS and HTTP listeners and waits for goroutines to exit.
func (l *Listener) Stop() error {
	var errs []string
	l.stopOnce.Do(func() {
		l.mu.Lock()
		l.running = false
		l.mu.Unlock()

		close(l.stopChan)

		if l.dnsConn != nil {
			if err := l.dnsConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, fmt.Sprintf("dns close error: %v", err))
			}
		}

		if l.httpServer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := l.httpServer.Shutdown(ctx); err != nil {
				errs = append(errs, fmt.Sprintf("http shutdown error: %v", err))
			}
		}

		l.wg.Wait()
	})

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// RegisterProbe registers a new probe directly through the listener's correlator.
func (l *Listener) RegisterProbe(opts ProbeOptions) (*Probe, error) {
	if opts.OASTDomain == "" {
		opts.OASTDomain = l.cfg.OASTDomain
	}
	p, err := l.correlator.RegisterProbe(opts)
	if err == nil {
		atomic.AddInt64(&l.metrics.ProbesGenerated, 1)
	}
	return p, err
}

// DNSAddr returns the local listening UDP address.
func (l *Listener) DNSAddr() *net.UDPAddr {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.dnsAddr
}

// HTTPAddr returns the local listening TCP address.
func (l *Listener) HTTPAddr() net.Addr {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.httpAddr
}

// Metrics returns the active telemetry counters and latency data.
func (l *Listener) Metrics() *ListenerMetrics {
	return l.metrics
}

// Correlator returns the underlying correlator instance.
func (l *Listener) Correlator() *Correlator {
	return l.correlator
}

// PruneExpired purges expired probes that have no verified interaction evidence.
func (l *Listener) PruneExpired() int {
	return l.correlator.PruneExpired()
}
