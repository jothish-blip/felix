package oast

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// GenerateInteractionToken generates a cryptographically secure, unpredictable 128-bit token (32 hex characters).
func GenerateInteractionToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate secure interaction token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Correlator manages active OAST probes, callback correlation, duplicate suppression,
// and cross-assessment isolation.
type Correlator struct {
	cfg Config
	mu  sync.RWMutex

	probesByToken      map[string]*Probe
	probesByID         map[string]*Probe
	probesByAssessment map[string][]*Probe
	probesByFinding    map[string][]*Probe
	waiters            map[string][]chan *Interaction
	closed             bool
}

// NewCorrelator constructs an initialized Correlator instance.
func NewCorrelator(cfg Config) (*Correlator, error) {
	if cfg.BaseURL != "" {
		if err := ValidateCanaryDestination(cfg.BaseURL, cfg); err != nil {
			return nil, err
		}
	}
	if cfg.OASTDomain == "" {
		cfg.OASTDomain = "oast.felix.internal"
	}
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = 30 * time.Second
	}
	if cfg.MaxInteractionsPerProbe <= 0 {
		cfg.MaxInteractionsPerProbe = 10
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 64 * 1024
	}
	if cfg.MaxProbes <= 0 {
		cfg.MaxProbes = 10000
	}

	return &Correlator{
		cfg:                cfg,
		probesByToken:      make(map[string]*Probe),
		probesByID:         make(map[string]*Probe),
		probesByAssessment: make(map[string][]*Probe),
		probesByFinding:    make(map[string][]*Probe),
		waiters:            make(map[string][]chan *Interaction),
	}, nil
}

// SetBaseURL updates the callback base URL (e.g., when initializing local simulator).
func (c *Correlator) SetBaseURL(baseURL string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrCorrelatorClosed
	}
	if baseURL != "" {
		if err := ValidateCanaryDestination(baseURL, c.cfg); err != nil {
			return err
		}
	}
	c.cfg.BaseURL = baseURL
	return nil
}

// SetAllowLoopback updates the loopback policy.
func (c *Correlator) SetAllowLoopback(allow bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cfg.AllowLoopback = allow
}

// SetOASTDomain updates the OAST domain used for callback probes.
func (c *Correlator) SetOASTDomain(domain string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cfg.OASTDomain = domain
}

// Config returns a copy of the current configuration.
func (c *Correlator) Config() Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg
}

// RegisterProbe registers a new out-of-band probe with a unique cryptographic token and metadata.
func (c *Correlator) RegisterProbe(opts ProbeOptions) (*Probe, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, ErrCorrelatorClosed
	}

	// Enforce bounded storage capacity
	if c.cfg.MaxProbes > 0 && len(c.probesByToken) >= c.cfg.MaxProbes {
		c.pruneExpiredLocked()
		if len(c.probesByToken) >= c.cfg.MaxProbes {
			return nil, ErrMaxProbesReached
		}
	}

	token, err := GenerateInteractionToken()
	if err != nil {
		return nil, err
	}

	ttl := opts.TTL
	if ttl <= 0 {
		ttl = c.cfg.DefaultTTL
	}

	oastDomain := opts.OASTDomain
	if oastDomain == "" {
		oastDomain = c.cfg.OASTDomain
	}
	if oastDomain == "" {
		oastDomain = "oast.felix.internal"
	}

	callbackDomain := fmt.Sprintf("probe-%s.%s", token, oastDomain)

	callbackURL := c.cfg.BaseURL
	if callbackURL != "" {
		if strings.Contains(callbackURL, "?") {
			callbackURL += "&token=" + token
		} else {
			callbackURL = strings.TrimRight(callbackURL, "/") + "/c/" + token
		}
	} else {
		callbackURL = fmt.Sprintf("http://%s/c/%s", callbackDomain, token)
	}

	proto := opts.Protocol
	if proto == "" {
		proto = ProtocolHTTP
	}

	probe := &Probe{
		ID:             uuid.New().String(),
		Token:          token,
		FindingID:      opts.FindingID,
		TemplateID:     opts.TemplateID,
		ProbeType:      opts.ProbeType,
		CallbackDomain: callbackDomain,
		AssessmentID:   opts.AssessmentID,
		ExecutionID:    opts.ExecutionID,
		TargetURL:      opts.TargetURL,
		Endpoint:       opts.Endpoint,
		Parameter:      opts.Parameter,
		Protocol:       proto,
		CallbackURL:    callbackURL,
		CreatedAt:      time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().Add(ttl),
		Status:         ProbeStatusPending,
		Interactions:   make([]Interaction, 0),
	}

	c.probesByToken[token] = probe
	c.probesByID[probe.ID] = probe
	if opts.AssessmentID != "" {
		c.probesByAssessment[opts.AssessmentID] = append(c.probesByAssessment[opts.AssessmentID], probe)
	}
	if opts.FindingID != "" {
		c.probesByFinding[opts.FindingID] = append(c.probesByFinding[opts.FindingID], probe)
	}

	return probe, nil
}

// GenerateProbe creates and registers a new out-of-band probe with a unique cryptographic token.
func (c *Correlator) GenerateProbe(assessmentID, executionID, targetURL, endpoint, parameter string, proto Protocol, ttl time.Duration) (*Probe, error) {
	return c.RegisterProbe(ProbeOptions{
		AssessmentID: assessmentID,
		ExecutionID:  executionID,
		TargetURL:    targetURL,
		Endpoint:     endpoint,
		Parameter:    parameter,
		Protocol:     proto,
		TTL:          ttl,
	})
}

// RecordInteraction matches an incoming interaction against registered probes.
// Enforces cross-assessment isolation, expiration, and duplicate suppression.
func (c *Correlator) RecordInteraction(ctx context.Context, interaction Interaction) (*CorrelationResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, ErrCorrelatorClosed
	}

	if interaction.Token == "" {
		return &CorrelationResult{Matched: false}, ErrProbeNotFound
	}

	probe, exists := c.probesByToken[interaction.Token]
	if !exists {
		return &CorrelationResult{Matched: false}, ErrProbeNotFound
	}

	// Cross-assessment isolation verification
	if interaction.AssessmentID != "" && probe.AssessmentID != "" && interaction.AssessmentID != probe.AssessmentID {
		return &CorrelationResult{Matched: false, Probe: probe}, ErrCrossAssessment
	}

	now := time.Now().UTC()
	if now.After(probe.ExpiresAt) || probe.Status == ProbeStatusExpired {
		probe.Status = ProbeStatusExpired
		return &CorrelationResult{Matched: true, Probe: probe}, ErrProbeExpired
	}

	if probe.Status == ProbeStatusCancelled {
		return &CorrelationResult{Matched: true, Probe: probe}, ErrProbeCancelled
	}

	if interaction.ID == "" {
		interaction.ID = uuid.New().String()
	}
	if interaction.ReceivedAt.IsZero() {
		interaction.ReceivedAt = now
	}
	interaction.ProbeID = probe.ID
	if interaction.AssessmentID == "" {
		interaction.AssessmentID = probe.AssessmentID
	}

	// Duplicate callback suppression: record on probe but mark as duplicate
	if len(probe.Interactions) > 0 {
		interaction.IsDuplicate = true
		if len(probe.Interactions) < c.cfg.MaxInteractionsPerProbe {
			probe.Interactions = append(probe.Interactions, interaction)
		}
		probeCopy := cloneProbeLocked(probe)
		interCopy := interaction
		return &CorrelationResult{
			Matched:     true,
			IsDuplicate: true,
			Probe:       probeCopy,
			Interaction: &interCopy,
		}, ErrDuplicateCallback
	}

	// First verified interaction
	probe.Status = ProbeStatusCorrelated
	probe.Interactions = append(probe.Interactions, interaction)

	probeCopy := cloneProbeLocked(probe)
	interCopy := interaction
	res := &CorrelationResult{
		Matched:     true,
		IsDuplicate: false,
		Probe:       probeCopy,
		Interaction: &interCopy,
	}

	// Notify active waiters for this token
	if waiters, ok := c.waiters[probe.Token]; ok {
		for _, ch := range waiters {
			select {
			case ch <- &interaction:
			default:
			}
		}
		delete(c.waiters, probe.Token)
	}

	return res, nil
}

// WaitForInteraction blocks until an interaction for the specified token is received,
// the timeout expires, or ctx is cancelled.
func (c *Correlator) WaitForInteraction(ctx context.Context, token string, timeout time.Duration) (*Interaction, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrCorrelatorClosed
	}

	probe, exists := c.probesByToken[token]
	if !exists {
		c.mu.Unlock()
		return nil, ErrProbeNotFound
	}

	if len(probe.Interactions) > 0 {
		interCopy := probe.Interactions[0]
		c.mu.Unlock()
		return &interCopy, nil
	}

	if time.Now().UTC().After(probe.ExpiresAt) || probe.Status == ProbeStatusExpired {
		probe.Status = ProbeStatusExpired
		c.mu.Unlock()
		return nil, ErrProbeExpired
	}

	if probe.Status == ProbeStatusCancelled {
		c.mu.Unlock()
		return nil, ErrProbeCancelled
	}

	ch := make(chan *Interaction, 1)
	c.waiters[token] = append(c.waiters[token], ch)
	c.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		c.removeWaiter(token, ch)
		return nil, ctx.Err()
	case <-timer.C:
		c.removeWaiter(token, ch)
		return nil, ErrProbeExpired
	case interaction, ok := <-ch:
		if !ok || interaction == nil {
			return nil, ErrProbeCancelled
		}
		interCopy := *interaction
		return &interCopy, nil
	}
}

func (c *Correlator) removeWaiter(token string, ch chan *Interaction) {
	c.mu.Lock()
	defer c.mu.Unlock()
	waiters := c.waiters[token]
	for i, w := range waiters {
		if w == ch {
			c.waiters[token] = append(waiters[:i], waiters[i+1:]...)
			break
		}
	}
	if len(c.waiters[token]) == 0 {
		delete(c.waiters, token)
	}
}

// CancelAssessmentProbes cancels all pending probes associated with the specified assessment,
// freeing any waiting goroutines.
func (c *Correlator) CancelAssessmentProbes(assessmentID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	probes := c.probesByAssessment[assessmentID]
	for _, probe := range probes {
		if probe.Status == ProbeStatusPending {
			probe.Status = ProbeStatusCancelled
		}
		if waiters, ok := c.waiters[probe.Token]; ok {
			for _, ch := range waiters {
				close(ch)
			}
			delete(c.waiters, probe.Token)
		}
	}
}

func cloneProbeLocked(p *Probe) *Probe {
	if p == nil {
		return nil
	}
	cp := *p
	if len(p.Interactions) > 0 {
		cp.Interactions = make([]Interaction, len(p.Interactions))
		copy(cp.Interactions, p.Interactions)
	}
	return &cp
}

// GetProbe retrieves a probe by token.
func (c *Correlator) GetProbe(token string) (*Probe, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	probe, exists := c.probesByToken[token]
	if !exists {
		return nil, false
	}
	return cloneProbeLocked(probe), true
}

// GetProbesForAssessment returns all probes generated for a given assessment.
func (c *Correlator) GetProbesForAssessment(assessmentID string) []*Probe {
	c.mu.RLock()
	defer c.mu.RUnlock()
	probes := c.probesByAssessment[assessmentID]
	out := make([]*Probe, len(probes))
	for i, p := range probes {
		out[i] = cloneProbeLocked(p)
	}
	return out
}

// GetProbesForFinding returns all probes registered for a given finding ID.
func (c *Correlator) GetProbesForFinding(findingID string) []*Probe {
	c.mu.RLock()
	defer c.mu.RUnlock()
	probes := c.probesByFinding[findingID]
	out := make([]*Probe, len(probes))
	for i, p := range probes {
		out[i] = cloneProbeLocked(p)
	}
	return out
}

// PruneExpired purges expired probes that have no verified interaction evidence.
// Active probes and valid callback evidence are strictly preserved.
func (c *Correlator) PruneExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pruneExpiredLocked()
}

func (c *Correlator) pruneExpiredLocked() int {
	now := time.Now().UTC()
	var toDelete []string

	for token, probe := range c.probesByToken {
		// Never remove active pending probes
		if probe.Status == ProbeStatusPending && now.Before(probe.ExpiresAt) {
			continue
		}
		// Never remove valid callback evidence
		if len(probe.Interactions) > 0 || probe.Status == ProbeStatusCorrelated {
			continue
		}
		// Expired or cancelled probe without interactions is eligible for cleanup
		if now.After(probe.ExpiresAt) || probe.Status == ProbeStatusExpired || probe.Status == ProbeStatusCancelled {
			toDelete = append(toDelete, token)
		}
	}

	for _, token := range toDelete {
		c.deleteProbeLocked(token)
	}

	return len(toDelete)
}

func (c *Correlator) deleteProbeLocked(token string) {
	probe, exists := c.probesByToken[token]
	if !exists {
		return
	}

	delete(c.probesByToken, token)
	delete(c.probesByID, probe.ID)

	// Remove from probesByAssessment
	if probe.AssessmentID != "" {
		probes := c.probesByAssessment[probe.AssessmentID]
		for i, p := range probes {
			if p.ID == probe.ID {
				c.probesByAssessment[probe.AssessmentID] = append(probes[:i], probes[i+1:]...)
				break
			}
		}
		if len(c.probesByAssessment[probe.AssessmentID]) == 0 {
			delete(c.probesByAssessment, probe.AssessmentID)
		}
	}

	// Remove from probesByFinding
	if probe.FindingID != "" {
		probes := c.probesByFinding[probe.FindingID]
		for i, p := range probes {
			if p.ID == probe.ID {
				c.probesByFinding[probe.FindingID] = append(probes[:i], probes[i+1:]...)
				break
			}
		}
		if len(c.probesByFinding[probe.FindingID]) == 0 {
			delete(c.probesByFinding, probe.FindingID)
		}
	}

	// Close and remove any lingering waiters
	if waiters, ok := c.waiters[token]; ok {
		for _, ch := range waiters {
			close(ch)
		}
		delete(c.waiters, token)
	}
}

// ProbeCount returns the current count of active and retained probes.
func (c *Correlator) ProbeCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.probesByToken)
}

// Capacity returns the maximum probe storage boundary.
func (c *Correlator) Capacity() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg.MaxProbes
}

// Close closes the correlator and cancels all pending waiters.
func (c *Correlator) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	for token, waiters := range c.waiters {
		for _, ch := range waiters {
			close(ch)
		}
		delete(c.waiters, token)
	}
}
