package mobile

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// DeviceType classifies the connection category of an Android device.
type DeviceType string

const (
	DeviceTypeEmulator DeviceType = "emulator"
	DeviceTypePhysical DeviceType = "physical"
	DeviceTypeMock     DeviceType = "mock"
	DeviceTypeUnknown  DeviceType = "unknown"
)

// DeviceState indicates connectivity status.
type DeviceState string

const (
	DeviceStateOnline       DeviceState = "online"
	DeviceStateOffline      DeviceState = "offline"
	DeviceStateUnauthorized DeviceState = "unauthorized"
	DeviceStateUnknown      DeviceState = "unknown"
)

// DeviceInfo records hardware and connection metadata for a target device.
type DeviceInfo struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Type       DeviceType  `json:"type"`
	State      DeviceState `json:"state"`
	Model      string      `json:"model,omitempty"`
	ABI        string      `json:"abi,omitempty"`
	OSVersion  string      `json:"os_version,omitempty"`
	Authorized bool        `json:"authorized"`
}

// SessionState tracks the lifecycle of an instrumentation session.
type SessionState string

const (
	SessionStateCreated    SessionState = "CREATED"
	SessionStateAttaching  SessionState = "ATTACHING"
	SessionStateRunning    SessionState = "RUNNING"
	SessionStateDetaching  SessionState = "DETACHING"
	SessionStateTerminated SessionState = "TERMINATED"
	SessionStateFailed     SessionState = "FAILED"
)

// RuntimeEventType categorizes observable runtime behaviors.
type RuntimeEventType string

const (
	EventTypeLifecycle RuntimeEventType = "lifecycle"
	EventTypeCrypto    RuntimeEventType = "crypto"
	EventTypeNetwork   RuntimeEventType = "network"
	EventTypeTLS       RuntimeEventType = "tls"
	EventTypeStorage   RuntimeEventType = "storage"
	EventTypeAPI       RuntimeEventType = "api"
	EventTypeError     RuntimeEventType = "error"
)

// RuntimeEvent models a single security-relevant runtime event emitted by instrumentation.
type RuntimeEvent struct {
	ID          string           `json:"id"`
	Type        RuntimeEventType `json:"type"`
	Timestamp   time.Time        `json:"timestamp"`
	PackageName string           `json:"package_name"`
	Class       string           `json:"class,omitempty"`
	Method      string           `json:"method,omitempty"`
	Details     map[string]any   `json:"details,omitempty"`
	RawMessage  string           `json:"raw_message,omitempty"`
}

// SessionConfig configures a dynamic instrumentation session.
type SessionConfig struct {
	DeviceID       string        `json:"device_id"`
	TargetPackage  string        `json:"target_package"`
	TargetActivity string        `json:"target_activity,omitempty"`
	Spawn          bool          `json:"spawn"`
	Timeout        time.Duration `json:"timeout"`
	MaxEvents      int           `json:"max_events"`
	HookLifecycle  bool          `json:"hook_lifecycle"`
	HookCrypto     bool          `json:"hook_crypto"`
	HookNetwork    bool          `json:"hook_network"`
	HookTLS        bool          `json:"hook_tls"`
	HookStorage    bool          `json:"hook_storage"`
}

// DefaultSessionConfig returns sensible default options for laboratory instrumentation.
func DefaultSessionConfig(targetPackage string) SessionConfig {
	return SessionConfig{
		TargetPackage: targetPackage,
		Spawn:         true,
		Timeout:       15 * time.Second,
		MaxEvents:     1000,
		HookLifecycle: true,
		HookCrypto:    true,
		HookNetwork:   true,
		HookTLS:       true,
		HookStorage:   true,
	}
}

// DynamicExecutionResult records the complete outcome of a dynamic instrumentation run.
type DynamicExecutionResult struct {
	TargetPackage     string          `json:"target_package"`
	Device            DeviceInfo      `json:"device"`
	FridaVersion      string          `json:"frida_version"`
	StartedAt         time.Time       `json:"started_at"`
	CompletedAt       time.Time       `json:"completed_at"`
	DurationMs        int64           `json:"duration_ms"`
	TotalEvents       int             `json:"total_events"`
	EventsByType      map[string]int  `json:"events_by_type"`
	Events            []RuntimeEvent  `json:"events"`
	Findings          []MobileFinding `json:"findings"`
	Errors            []string        `json:"errors,omitempty"`
	Status            string          `json:"status"` // "COMPLETED", "TERMINATED", "FAILED", "ENVIRONMENT_UNAVAILABLE"
	EnvironmentNotice string          `json:"environment_notice,omitempty"`
}

// DynamicManager defines the primary interface for managing Frida dynamic instrumentation.
type DynamicManager interface {
	DetectFrida() (*FridaInfo, error)
	EnumerateDevices(ctx context.Context) ([]DeviceInfo, error)
	GetDevice(ctx context.Context, id string) (*DeviceInfo, error)
	ValidateTargetPackage(pkg string) error
	CreateSession(ctx context.Context, cfg SessionConfig) (DynamicSession, error)
}

// DynamicSession represents an active or completed dynamic instrumentation session.
type DynamicSession interface {
	Start(ctx context.Context) error
	Events() <-chan RuntimeEvent
	Stop() error
	State() SessionState
	Result() *DynamicExecutionResult
}

// AuthorizedLaboratoryPackages defines the explicit laboratory allowlist.
// FELIX will strictly refuse to instrument any application outside this inventory.
var AuthorizedLaboratoryPackages = []string{
	"com.android.insecurebankv2",
	"owasp.mstg.uncrackable1",
	"owasp.mstg.uncrackable2",
	"owasp.mstg.uncrackable3",
	"re.pwnme",
	"sg.vantagepoint.helloworldjni",
	"App1.App1",
	"sg.vp.owasp_mobile.omtg_android",
	"com.android.dns.exploitaes",
}

// IsPackageAuthorized returns true if the package is in the laboratory allowlist.
func IsPackageAuthorized(pkg string) bool {
	normalized := strings.TrimSpace(strings.ToLower(pkg))
	for _, auth := range AuthorizedLaboratoryPackages {
		if strings.ToLower(auth) == normalized {
			return true
		}
	}
	return false
}

// ValidateLaboratoryPackage returns an error if target is not in the allowlist.
func ValidateLaboratoryPackage(pkg string) error {
	if !IsPackageAuthorized(pkg) {
		return fmt.Errorf("target package %q is rejected: not in authorized laboratory allowlist", pkg)
	}
	return nil
}
