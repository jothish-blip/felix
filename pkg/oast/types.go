package oast

import (
	"context"
	"errors"
	"net"
	"time"
)

// Standard OAST errors.
var (
	ErrProbeNotFound      = errors.New("oast: probe not found or unknown interaction token")
	ErrProbeExpired       = errors.New("oast: interaction token has expired")
	ErrProbeCancelled     = errors.New("oast: probe was cancelled")
	ErrDuplicateCallback  = errors.New("oast: duplicate interaction callback received")
	ErrUnauthorizedCanary = errors.New("oast: canary destination is unauthorized or unsafe")
	ErrCorrelatorClosed   = errors.New("oast: correlator is closed")
	ErrCrossAssessment    = errors.New("oast: cross-assessment callback isolation violation")
	ErrPayloadTooLarge    = errors.New("oast: callback payload exceeds maximum permitted size")
)

// Protocol represents the communication channel used for the out-of-band probe.
type Protocol string

const (
	ProtocolHTTP  Protocol = "HTTP"
	ProtocolHTTPS Protocol = "HTTPS"
	ProtocolDNS   Protocol = "DNS"
)

// ProbeStatus defines the lifecycle status of an individual OAST probe.
type ProbeStatus string

const (
	ProbeStatusPending    ProbeStatus = "PENDING"
	ProbeStatusCorrelated ProbeStatus = "CORRELATED"
	ProbeStatusExpired    ProbeStatus = "EXPIRED"
	ProbeStatusCancelled  ProbeStatus = "CANCELLED"
)

// Probe captures an outstanding out-of-band test probe and its associated assessment context.
type Probe struct {
	ID           string        `json:"id"`
	Token        string        `json:"token"`
	AssessmentID string        `json:"assessment_id"`
	ExecutionID  string        `json:"execution_id"`
	TargetURL    string        `json:"target_url"`
	Endpoint     string        `json:"endpoint"`
	Parameter    string        `json:"parameter"`
	Protocol     Protocol      `json:"protocol"`
	CallbackURL  string        `json:"callback_url"`
	CreatedAt    time.Time     `json:"created_at"`
	ExpiresAt    time.Time     `json:"expires_at"`
	Status       ProbeStatus   `json:"status"`
	Interactions []Interaction `json:"interactions,omitempty"`
}

// Interaction represents an observed callback received by the OAST infrastructure.
type Interaction struct {
	ID           string            `json:"id"`
	Token        string            `json:"token"`
	ProbeID      string            `json:"probe_id"`
	AssessmentID string            `json:"assessment_id"`
	Protocol     Protocol          `json:"protocol"`
	ClientIP     string            `json:"client_ip"`
	Method       string            `json:"method"`
	Path         string            `json:"path"`
	Headers      map[string]string `json:"headers,omitempty"`
	Body         string            `json:"body,omitempty"`
	ReceivedAt   time.Time         `json:"received_at"`
	IsDuplicate  bool              `json:"is_duplicate"`
}

// CorrelationResult details the outcome of matching an interaction against registered probes.
type CorrelationResult struct {
	Matched     bool         `json:"matched"`
	IsDuplicate bool         `json:"is_duplicate"`
	Probe       *Probe       `json:"probe,omitempty"`
	Interaction *Interaction `json:"interaction,omitempty"`
}

// DNSResolver is a function type for resolving hostnames to IP addresses during validation.
type DNSResolver func(ctx context.Context, host string) ([]net.IP, error)

// Config configures the OAST correlator and safe probe dispatch.
type Config struct {
	BaseURL                 string        `json:"base_url"`
	DefaultTTL              time.Duration `json:"default_ttl"`
	MaxInteractionsPerProbe int           `json:"max_interactions_per_probe"`
	MaxBodyBytes            int64         `json:"max_body_bytes"`
	AllowLoopback           bool          `json:"allow_loopback"`
	AllowPrivateIPs         bool          `json:"allow_private_ips"`
	AuthorizedHosts         []string      `json:"authorized_hosts,omitempty"`
	RequireExplicitOptIn    bool          `json:"require_explicit_opt_in"`
	DNSResolver             DNSResolver   `json:"-"`
}

// DefaultConfig provides secure defaults for OAST operations.
func DefaultConfig() Config {
	return Config{
		DefaultTTL:              30 * time.Second,
		MaxInteractionsPerProbe: 10,
		MaxBodyBytes:            64 * 1024, // 64 KB limit for callback payloads
		AllowLoopback:           false,
		AllowPrivateIPs:         false,
		RequireExplicitOptIn:    true,
	}
}
