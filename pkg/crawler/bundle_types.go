package crawler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// RouteCandidateSourceType categorizes the build mechanism or artifact from which a candidate was extracted.
type RouteCandidateSourceType string

const (
	SourceTypeJavaScriptAST     RouteCandidateSourceType = "JAVASCRIPT_AST"
	SourceTypeNextServerAction  RouteCandidateSourceType = "NEXT_SERVER_ACTION"
	SourceTypeNextManifest      RouteCandidateSourceType = "NEXT_MANIFEST"
	SourceTypeWebpackChunk      RouteCandidateSourceType = "WEBPACK_CHUNK"
	SourceTypeReactNativeBundle RouteCandidateSourceType = "REACT_NATIVE_BUNDLE"
	SourceTypeSourceMap         RouteCandidateSourceType = "SOURCE_MAP"
)

// ExtractionConfidence represents the evidentiary strength of the route extraction.
type ExtractionConfidence string

const (
	ConfidenceConfirmed ExtractionConfidence = "CONFIRMED" // Exact literal, manifest entry, or direct API call
	ConfidenceInferred  ExtractionConfidence = "INFERRED"  // Statically reconstructed template or concatenated string
	ConfidenceHeuristic ExtractionConfidence = "HEURISTIC" // Structural pattern or regex-assisted clue
)

// ServerActionReference encapsulates metadata for a Next.js Server Action discovered in client bundles.
// An action identifier is not a concrete HTTP route and must be preserved separately.
type ServerActionReference struct {
	ID             string    `json:"id"`
	ActionID       string    `json:"action_id"`
	ExportName     string    `json:"export_name,omitempty"`
	SourceArtifact string    `json:"source_artifact"`
	Line           int       `json:"line,omitempty"`
	Column         int       `json:"column,omitempty"`
	IsBound        bool      `json:"is_bound,omitempty"`
	BoundArgsCount int       `json:"bound_args_count,omitempty"`
	AssociatedPath string    `json:"associated_path,omitempty"`
	DiscoveredAt   time.Time `json:"discovered_at"`
}

// RouteCandidate models a discovered API route or endpoint candidate extracted from client-side bundles.
type RouteCandidate struct {
	ID                       string                   `json:"id"`
	Path                     string                   `json:"path"`
	RawPath                  string                   `json:"raw_path"`
	HTTPMethod               string                   `json:"http_method"` // "GET", "POST", etc., or "UNKNOWN"
	OriginatingAsset         string                   `json:"originating_asset"`
	BundleType               string                   `json:"bundle_type"` // "WEB_WEBPACK", "WEB_NEXTJS", "REACT_NATIVE", "GENERIC_JS"
	SourceType               RouteCandidateSourceType `json:"source_type"`
	Location                 string                   `json:"location,omitempty"` // e.g. "AST_CALL:line 42"
	Line                     int                      `json:"line,omitempty"`
	Column                   int                      `json:"column,omitempty"`
	ModuleID                 string                   `json:"module_id,omitempty"` // Webpack or Metro module ID
	ExtractionMethod         string                   `json:"extraction_method"`
	Confidence               ExtractionConfidence     `json:"confidence"`
	IsLiteral                bool                     `json:"is_literal"`
	IsStaticallyReconstructed bool                     `json:"is_statically_reconstructed"`
	ServerAction             *ServerActionReference   `json:"server_action,omitempty"`
	Evidence                 string                   `json:"evidence,omitempty"`
	DiscoveredAt             time.Time                `json:"discovered_at"`
	Warnings                 []string                 `json:"warnings,omitempty"`
}

// ChunkInspectionResult captures the traversal outcome of a Webpack asynchronous chunk.
type ChunkInspectionResult struct {
	URL        string `json:"url"`
	ChunkID    string `json:"chunk_id,omitempty"`
	Status     string `json:"status"` // "PROCESSED", "SKIPPED_OUT_OF_SCOPE", "MALFORMED", "NOT_FOUND", "SIZE_EXCEEDED"
	Size       int64  `json:"size,omitempty"`
	Error      string `json:"error,omitempty"`
	Discovered int    `json:"routes_discovered"`
}

// BundleAnalysisReport provides an audit summary of client bundle deobfuscation and route extraction.
type BundleAnalysisReport struct {
	TotalBundlesScanned          int                     `json:"total_bundles_scanned"`
	TotalChunksTraversed         int                     `json:"total_chunks_traversed"`
	TotalCandidatesDiscovered    int                     `json:"total_candidates_discovered"`
	TotalServerActionsDiscovered int                     `json:"total_server_actions_discovered"`
	Chunks                       []ChunkInspectionResult `json:"chunks,omitempty"`
	Warnings                     []string                `json:"warnings,omitempty"`
}

// BundleAnalysisOptions configures static deobfuscation and extraction behavior.
type BundleAnalysisOptions struct {
	MaxBundleSize      int64             `json:"max_bundle_size"`
	MaxTokens          int               `json:"max_tokens"`
	MaxChunks          int               `json:"max_chunks"`
	TraverseChunks     bool              `json:"traverse_chunks"`
	IncludeSourceMaps  bool              `json:"include_source_maps"`
	ScopeURL           string            `json:"scope_url"`
	TargetHost         string            `json:"target_host"`
	RedactSecrets      bool              `json:"redact_secrets"`
	CustomConstants    map[string]string `json:"custom_constants,omitempty"`
}

// DefaultBundleAnalysisOptions provides safe default constraints for client bundle analysis.
func DefaultBundleAnalysisOptions() BundleAnalysisOptions {
	return BundleAnalysisOptions{
		MaxBundleSize:     10 * 1024 * 1024, // 10MB
		MaxTokens:         500000,
		MaxChunks:         50,
		TraverseChunks:    true,
		IncludeSourceMaps: true,
		RedactSecrets:     true,
	}
}

// GenerateRouteCandidateID generates a deterministic, stable identifier for a route candidate.
func GenerateRouteCandidateID(path, method, assetURL string) string {
	raw := fmt.Sprintf("%s|%s|%s", strings.ToUpper(strings.TrimSpace(method)), strings.TrimSpace(path), strings.TrimSpace(assetURL))
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("RCAND-%s", hex.EncodeToString(h[:8]))
}

// GenerateServerActionID generates a deterministic, stable identifier for a server action reference.
func GenerateServerActionID(actionID, assetURL string) string {
	raw := fmt.Sprintf("%s|%s", strings.TrimSpace(actionID), strings.TrimSpace(assetURL))
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("ACTION-%s", hex.EncodeToString(h[:8]))
}
