package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Snapshot schema and ceiling bounds
const (
	CurrentSnapshotSchemaVersion = 1
	MaxSnapshotSizeBytes         = 10 * 1024 * 1024 // 10 MiB limit for snapshot files
	MaxSnapshotRoutes            = 10000            // Maximum surface routes per snapshot
	DefaultRetainSnapshots       = 30
	DefaultRetainEvents          = 1000
)

// Documentation status constants
const (
	DocStatusDocumented   = "DOCUMENTED"
	DocStatusUndocumented = "UNDOCUMENTED"
	DocStatusAmbiguous    = "AMBIGUOUS"
	DocStatusUnknown      = "UNKNOWN"
)

// Reachability constants
const (
	ReachabilityConfirmed    = "CONFIRMED"
	ReachabilityUnconfirmed  = "UNCONFIRMED"
	ReachabilityInconclusive = "INCONCLUSIVE"
)

// SurfaceRoute models a single canonical API endpoint observed on an authorized target.
type SurfaceRoute struct {
	CanonicalPath        string   `json:"canonical_path"`
	RawPath              string   `json:"raw_path"`
	Methods              []string `json:"methods"`
	ParameterShapes      []string `json:"parameter_shapes,omitempty"`
	DocumentationStatus  string   `json:"documentation_status"`
	SensitiveIdentifiers []string `json:"sensitive_identifiers,omitempty"`
	ProbeStatus          string   `json:"probe_status,omitempty"`
	Reachability         string   `json:"reachability,omitempty"`
	DiscoverySource      string   `json:"discovery_source,omitempty"`
	DiscoveryConfidence  string   `json:"discovery_confidence,omitempty"`
	OriginatingAsset     string   `json:"originating_asset,omitempty"`
	MatchedSpec          string   `json:"matched_spec,omitempty"`
	OperationID          string   `json:"operation_id,omitempty"`
	Evidence             string   `json:"evidence,omitempty"`
}

// IdentityKey returns the canonical identifier key for route equality and matching.
func (r *SurfaceRoute) IdentityKey() string {
	return strings.ToLower(strings.TrimSpace(r.CanonicalPath))
}

// HasSensitiveIdentifiers returns true if the route has any detected authorization-sensitive parameters.
func (r *SurfaceRoute) HasSensitiveIdentifiers() bool {
	return len(r.SensitiveIdentifiers) > 0
}

// Snapshot encapsulates an immutable, versioned observation of an authorized target's API surface.
type Snapshot struct {
	ID            string            `json:"id"`
	SchemaVersion int               `json:"schema_version"`
	TargetID      string            `json:"target_id"`
	TargetName    string            `json:"target_name"`
	BaseURLs      []string          `json:"base_urls"`
	CollectedAt   time.Time         `json:"collected_at"`
	IsComplete    bool              `json:"is_complete"`
	Truncated     bool              `json:"truncated"`
	Limitations   []string          `json:"limitations,omitempty"`
	Routes        []SurfaceRoute    `json:"routes"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// RouteCount returns the total number of routes recorded in this snapshot.
func (s *Snapshot) RouteCount() int {
	return len(s.Routes)
}

// GenerateSnapshotID constructs a deterministic or timestamped snapshot ID.
func GenerateSnapshotID(targetID string, t time.Time) string {
	cleanID := SanitizeTargetID(targetID)
	return fmt.Sprintf("snap_%s_%s_%06d", cleanID, t.UTC().Format("20060102_150405"), t.UTC().Nanosecond()/1000)
}

// SnapshotSummary provides lightweight metadata for listing and status display.
type SnapshotSummary struct {
	ID          string    `json:"id"`
	TargetID    string    `json:"target_id"`
	CollectedAt time.Time `json:"collected_at"`
	RouteCount  int       `json:"route_count"`
	IsComplete  bool      `json:"is_complete"`
	IsBaseline  bool      `json:"is_baseline"`
	SizeBytes   int64     `json:"size_bytes"`
}

// SanitizeTargetID cleans a target identifier for safe directory and file usage.
// Strictly prevents path traversal (e.g. .., slashes, backslashes, control characters).
func SanitizeTargetID(targetID string) string {
	targetID = strings.TrimSpace(targetID)
	if targetID == "" {
		return "default_target"
	}
	var sb strings.Builder
	for _, r := range targetID {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('_')
		}
	}
	clean := strings.Trim(sb.String(), "._-")
	if clean == "" || clean == ".." || clean == "." {
		h := sha256.Sum256([]byte(targetID))
		return "target_" + hex.EncodeToString(h[:8])
	}
	if len(clean) > 64 {
		clean = clean[:64]
	}
	return clean
}
