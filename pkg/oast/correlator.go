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
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = 30 * time.Second
	}
	if cfg.MaxInteractionsPerProbe <= 0 {
		cfg.MaxInteractionsPerProbe = 10
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 64 * 1024
	}

	return &Correlator{
		cfg:                cfg,
		probesByToken:      make(map[string]*Probe),
		probesByID:         make(map[string]*Probe),
		probesByAssessment: make(map[string][]*Probe),
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

// Config returns a copy of the current configuration.
func (c *Correlator) Config() Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg
}

// GenerateProbe creates and registers a new out-of-band probe with a unique cryptographic token.
func (c *Correlator) GenerateProbe(assessmentID, executionID, targetURL, endpoint, parameter string, proto Protocol, ttl time.Duration) (*Probe, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, ErrCorrelatorClosed
	}

	token, err := GenerateInteractionToken()
	if err != nil {
		return nil, err
	}

	if ttl <= 0 {
		ttl = c.cfg.DefaultTTL
	}

	callbackURL := c.cfg.BaseURL
	if callbackURL != "" {
		if strings.Contains(callbackURL, "?") {
			callbackURL += "&token=" + token
		} else {
			callbackURL = strings.TrimRight(callbackURL, "/") + "/c/" + token
		}
	}

	probe := &Probe{
		ID:           uuid.New().String(),
		Token:        token,
		AssessmentID: assessmentID,
		ExecutionID:  executionID,
		TargetURL:    targetURL,
		Endpoint:     endpoint,
		Parameter:    parameter,
		Protocol:     proto,
		CallbackURL:  callbackURL,
		CreatedAt:    time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(ttl),
		Status:       ProbeStatusPending,
		Interactions: make([]Interaction, 0),
	}

	c.probesByToken[token] = probe
	c.probesByID[probe.ID] = probe
	if assessmentID != "" {
		c.probesByAssessment[assessmentID] = append(c.probesByAssessment[assessmentID], probe)
	}

	return probe, nil
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
		return &CorrelationResult{
			Matched:     true,
			IsDuplicate: true,
			Probe:       probe,
			Interaction: &interaction,
		}, ErrDuplicateCallback
	}

	// First verified interaction
	probe.Status = ProbeStatusCorrelated
	probe.Interactions = append(probe.Interactions, interaction)

	res := &CorrelationResult{
		Matched:     true,
		IsDuplicate: false,
		Probe:       probe,
		Interaction: &interaction,
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
		c.mu.Unlock()
		return &probe.Interactions[0], nil
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
		return interaction, nil
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

// GetProbe retrieves a probe by token.
func (c *Correlator) GetProbe(token string) (*Probe, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	probe, exists := c.probesByToken[token]
	if !exists {
		return nil, false
	}
	cp := *probe
	return &cp, true
}

// GetProbesForAssessment returns all probes generated for a given assessment.
func (c *Correlator) GetProbesForAssessment(assessmentID string) []*Probe {
	c.mu.RLock()
	defer c.mu.RUnlock()
	probes := c.probesByAssessment[assessmentID]
	out := make([]*Probe, len(probes))
	for i, p := range probes {
		cp := *p
		out[i] = &cp
	}
	return out
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
