package remediation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"felix/pkg/correlation"
	"felix/pkg/report"
)

// Verification Provenance Architectural Boundary Note:
// Phase 7.3 is strictly a non-destructive developer code-level remediation diff generator.
// It generates, parses, and validates unified diffs in memory against source context.
// It does NOT apply patches to live targets, deploy services, or rerun dynamic exploit attacks.
//
// In FELIX, live remediation retesting is scheduled for a future dedicated verification phase
// (Phase 9.2 Remediation Retest Engine). A genuine, protected verification authority must:
// 1. Execute within an out-of-band, protected execution environment isolated from untrusted callers.
// 2. Produce non-forgeable, cryptographically signed attestations (e.g., asymmetric hardware/PKI signatures or audit logs).
// 3. Be an internal, immutable engine boundary rather than an exported, mutable in-process interface or global variable.
//
// Consequently, Phase 7.3 intentionally exposes no caller-controlled authority registration mechanism or mutable global hook.
// All LIVE_TARGET artifacts are strictly rejected as unauthenticated, ensuring that proposed remediation plans
// never claim VERIFIED_PATH_BREAK without authentic, protected execution provenance.

// ComputeArtifactIntegrityHash computes a deterministic SHA-256 over normalized verification artifact fields.
func ComputeArtifactIntegrityHash(art *VerificationArtifact) string {
	if art == nil {
		return ""
	}
	type canonicalArtifactPayload struct {
		AffectedEdgeID       string                `json:"affected_edge_id"`
		AttackRerun          AttackRerunResult     `json:"attack_rerun"`
		ExecutionEnvironment ExecutionEnvironment `json:"execution_environment"`
		PatchContentHash     string                `json:"patch_content_hash"`
		RegressionChecks     RegressionCheckResult `json:"regression_checks"`
		RemediationID        string                `json:"remediation_id"`
		SchemaVersion        string                `json:"schema_version"`
		Target               string                `json:"target"`
		WorkflowID           string                `json:"workflow_id"`
	}
	payload := canonicalArtifactPayload{
		AffectedEdgeID:       art.AffectedEdgeID,
		AttackRerun:          art.AttackRerun,
		ExecutionEnvironment: art.ExecutionEnvironment,
		PatchContentHash:     art.PatchContentHash,
		RegressionChecks:     art.RegressionChecks,
		RemediationID:        art.RemediationID,
		SchemaVersion:        art.SchemaVersion,
		Target:               art.Target,
		WorkflowID:           art.WorkflowID,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ComputePatchContentHash returns the normalized SHA-256 hash of a unified diff string.
func ComputePatchContentHash(unifiedDiff string) string {
	clean := strings.TrimSpace(strings.ReplaceAll(unifiedDiff, "\r\n", "\n"))
	sum := sha256.Sum256([]byte(clean))
	return hex.EncodeToString(sum[:])
}

// LoadVerificationArtifact reads a persisted verification artifact from disk, verifies file integrity, and returns the artifact and raw file SHA-256.
func LoadVerificationArtifact(filePath string) (*VerificationArtifact, string, error) {
	if strings.TrimSpace(filePath) == "" {
		return nil, "", errors.New("empty artifact path")
	}
	cleanPath := filepath.Clean(filePath)
	b, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed reading verification artifact file: %w", err)
	}
	if len(b) == 0 {
		return nil, "", errors.New("verification artifact file is empty")
	}

	rawHash := sha256.Sum256(b)
	rawHashHex := hex.EncodeToString(rawHash[:])

	var art VerificationArtifact
	if err := json.Unmarshal(b, &art); err != nil {
		return nil, "", fmt.Errorf("failed unmarshaling verification artifact JSON: %w", err)
	}

	return &art, rawHashHex, nil
}

// ValidateVerificationEvidence enforces the strict, anti-forgery verification contract for attack-path breaks:
// 1. Rejects caller-supplied boolean assertions, matching IDs, notes, or arbitrary receipt strings without an actual persisted artifact.
// 2. Requires a persisted VerificationArtifact on disk, loaded and bound to the exact remediation ID, affected edge ID, target, and patch content hash.
// 3. Verifies raw file integrity hash (rejecting arbitrary or malformed receipt hashes).
// 4. Verifies the internal deterministic canonical integrity hash of the artifact payload.
// 5. Strictly distinguishes execution provenance: synthetic fixtures (ISOLATED_FIXTURE), mocks (MOCK_SIMULATED), and declarative claims (DECLARATIVE_CLAIM) cannot represent live target verification.
// 6. Enforces cryptographic provenance: self-contained SHA-256 hashing verifies data integrity only, not authenticity. Phase 7.3 does not expose any mutable authority-registration mechanism or in-process mock hooks, and unconditionally rejects all caller-supplied LIVE_TARGET artifacts as unauthenticated pending a future dedicated verification phase (Phase 9.2).
// 7. Verifies that the attack rerun was executed and prevented, and that regression check suites passed with zero failures.
func ValidateVerificationEvidence(it *RemediationItem, expectedEdgeID string) (bool, string) {
	if it == nil {
		return false, "nil remediation item"
	}

	ve := it.VerificationEvidence
	if ve == nil && it.Evidence != nil {
		ve = it.Evidence.StructuredEvidence
	}

	// 1. Rejection of missing evidence or purely declarative claims
	if ve == nil {
		return false, "missing structured verification evidence: declarative receipt references, proof strings, or boolean flags are insufficient"
	}

	// 2. Anti-Forgery Check: All boolean fields set to true without a persisted artifact MUST be rejected
	if strings.TrimSpace(ve.ArtifactPath) == "" {
		return false, "caller-supplied boolean assertions rejected: empirical verification requires a persisted, integrity-checked verification artifact (artifact_path is required)"
	}

	// 3. Load persisted artifact from disk
	artifact, calculatedFileHash, err := LoadVerificationArtifact(ve.ArtifactPath)
	if err != nil {
		return false, fmt.Sprintf("failed loading persisted verification artifact at %q: %v", ve.ArtifactPath, err)
	}

	// 4. Validate artifact file hash (tamper detection and malformed hash rejection)
	if ve.ArtifactHash != "" {
		cleanHash := strings.TrimSpace(ve.ArtifactHash)
		if len(cleanHash) != 64 {
			return false, fmt.Sprintf("malformed artifact receipt hash %q: must be a 64-character hexadecimal SHA-256 string", ve.ArtifactHash)
		}
		if _, hexErr := hex.DecodeString(cleanHash); hexErr != nil {
			return false, fmt.Sprintf("malformed artifact receipt hash %q: invalid hexadecimal encoding", ve.ArtifactHash)
		}
		if !strings.EqualFold(cleanHash, calculatedFileHash) {
			return false, fmt.Sprintf("artifact hash mismatch: declared receipt hash %q does not match actual persisted file SHA-256 %q", ve.ArtifactHash, calculatedFileHash)
		}
	}

	// 5. Validate internal integrity hash of the artifact
	expectedIntegrity := ComputeArtifactIntegrityHash(artifact)
	if strings.TrimSpace(artifact.IntegrityHash) == "" {
		return false, "verification artifact missing integrity_hash"
	}
	if len(artifact.IntegrityHash) != 64 {
		return false, fmt.Sprintf("malformed artifact integrity_hash %q: must be a 64-character hexadecimal SHA-256 string", artifact.IntegrityHash)
	}
	if !strings.EqualFold(artifact.IntegrityHash, expectedIntegrity) {
		return false, fmt.Sprintf("artifact integrity hash verification failed: artifact claims %q, computed canonical payload hash is %q", artifact.IntegrityHash, expectedIntegrity)
	}

	// 6. Traceability & Binding Checks:
	// 6a. Remediation ID binding
	if strings.TrimSpace(artifact.RemediationID) == "" {
		return false, "verification artifact missing remediation_id"
	}
	if it.ID != "" && artifact.RemediationID != it.ID {
		return false, fmt.Sprintf("artifact remediation ID mismatch: artifact was issued for %q, but item ID is %q", artifact.RemediationID, it.ID)
	}
	if ve.RemediationID != "" && ve.RemediationID != artifact.RemediationID {
		return false, fmt.Sprintf("verification evidence remediation ID mismatch: evidence claims %q, artifact has %q", ve.RemediationID, artifact.RemediationID)
	}

	// 6b. Affected Edge ID binding
	if strings.TrimSpace(artifact.AffectedEdgeID) == "" {
		return false, "verification artifact missing affected_edge_id"
	}
	if expectedEdgeID != "" && artifact.AffectedEdgeID != expectedEdgeID {
		return false, fmt.Sprintf("artifact affected edge ID mismatch: artifact targets edge %q, but DAG path edge is %q", artifact.AffectedEdgeID, expectedEdgeID)
	}
	if ve.AffectedEdgeID != "" && ve.AffectedEdgeID != artifact.AffectedEdgeID {
		return false, fmt.Sprintf("verification evidence edge ID mismatch: evidence claims %q, artifact has %q", ve.AffectedEdgeID, artifact.AffectedEdgeID)
	}

	// 6c. Patch Content Hash binding
	if it.Diff != nil && strings.TrimSpace(it.Diff.UnifiedDiff) != "" {
		expectedPatchHash := ComputePatchContentHash(it.Diff.UnifiedDiff)
		if strings.TrimSpace(artifact.PatchContentHash) == "" {
			return false, "verification artifact missing patch_content_hash"
		}
		if !strings.EqualFold(artifact.PatchContentHash, expectedPatchHash) {
			return false, fmt.Sprintf("artifact patch hash mismatch: artifact was verified against patch %q, but current remediation diff hash is %q", artifact.PatchContentHash, expectedPatchHash)
		}
	}

	// 7. Execution Provenance & Synthetic Fixture Distinction
	// In Phase 7.3, no live verification authority exists to authenticate live execution provenance.
	// Synthetic fixtures, mock simulation, and declarative claims are strictly rejected.
	switch artifact.ExecutionEnvironment {
	case EnvironmentIsolatedFixture:
		return false, "synthetic fixture evidence cannot be represented as live target verification (requires LIVE_TARGET execution provenance)"
	case EnvironmentMockSimulated:
		return false, "mock simulated evidence cannot be represented as live target verification"
	case EnvironmentDeclarativeClaim:
		return false, "declarative claims cannot verify attack-path breaks"
	case EnvironmentLiveTarget:
		// Valid environment enum for live testing; proceed to validate rerun and regression fields,
		// but final execution provenance must be authenticated by a protected authority.
	default:
		return false, fmt.Sprintf("unauthorized execution environment %q in verification artifact: requires LIVE_TARGET", artifact.ExecutionEnvironment)
	}

	// 8. Empirical Attack Rerun & Prevention Verification
	if !artifact.AttackRerun.Executed {
		return false, "verification artifact reports attack rerun was not executed"
	}
	if !artifact.AttackRerun.Prevented {
		return false, "verification artifact reports attack rerun succeeded against target (vulnerability not prevented)"
	}
	if artifact.AttackRerun.HTTPStatusCode >= 200 && artifact.AttackRerun.HTTPStatusCode < 300 {
		return false, fmt.Sprintf("contradictory evidence: attack rerun returned HTTP %d (success) indicating vulnerability still active", artifact.AttackRerun.HTTPStatusCode)
	}

	// 9. Legitimate Application Regression Checks Verification
	if !artifact.RegressionChecks.Passed {
		return false, "verification artifact reports regression checks failed (legitimate application functionality broken)"
	}
	if artifact.RegressionChecks.FailedCount > 0 {
		return false, fmt.Sprintf("verification artifact reports %d regression check failures", artifact.RegressionChecks.FailedCount)
	}

	// 10. Consistency check with caller-supplied evidence fields
	if !ve.PatchApplied {
		return false, "caller-supplied evidence claims patch was not applied"
	}
	if !ve.AttackRerunExecuted {
		return false, "caller-supplied evidence claims attack rerun was not executed"
	}
	if !ve.AttackPrevented {
		return false, "caller-supplied evidence claims attack was not prevented"
	}
	if !ve.RegressionPassed {
		return false, "caller-supplied evidence claims regression tests failed"
	}

	// Update in-memory reference to loaded artifact
	ve.Artifact = artifact

	// 11. Protected Authority & Execution Provenance Boundary:
	// Phase 7.3 is strictly a non-destructive remediation diff generator with no live patch-application
	// or attack-rerun workflow. Even when an artifact satisfies structural validation and claims LIVE_TARGET,
	// caller-generated or self-hashed artifacts cannot establish authenticated origin without a protected,
	// trusted verification authority (Phase 9.2). Therefore, all live target claims remain unauthenticated.
	return false, "unauthenticated live execution provenance: Phase 7.3 is strictly a non-destructive remediation diff generator with no live patch-application or exploit-rerun workflow; caller-supplied or self-hashed LIVE_TARGET artifacts cannot establish authenticated origin without a protected, trusted verification authority (outcome remains PROPOSED_PATH_BREAK)"
}

// hasValidationEvidence checks if an item has empirical proof/verification evidence confirming vulnerability remediation.
func hasValidationEvidence(it *RemediationItem, expectedEdgeID string) (bool, string) {
	return ValidateVerificationEvidence(it, expectedEdgeID)
}

// AnalyzeDAGRemediation computes attack-path-aware prioritization and path breakage analysis.
func AnalyzeDAGRemediation(path *correlation.DAGPath, graph *correlation.DAGAttackGraph, items []*RemediationItem) (*DAGBreakAnalysis, []string) {
	if items == nil {
		items = []*RemediationItem{}
	}

	analysis := &DAGBreakAnalysis{
		Status:                  PathBreakStatusNone,
		BrokenPathCount:         0,
		EliminatedEdges:         []string{},
		ProposedBrokenPathCount: 0,
		ProposedEliminatedEdges: []string{},
		ProtectedAssets:         []string{},
		BottleneckNodeIDs:       []string{},
		EntrypointNodeIDs:       []string{},
	}

	if path == nil && graph == nil {
		// No DAG provided: sort items by severity then ID
		prioritizedIDs := sortItemsDefault(items)
		return analysis, prioritizedIDs
	}

	if path != nil {
		analysis.PathID = path.ID
	}

	// 1. Identify entrypoint and bottleneck nodes
	nodeUsageCount := make(map[string]int)
	if graph != nil {
		for _, node := range graph.Nodes {
			if len(graph.InEdges[node.ID]) == 0 {
				analysis.EntrypointNodeIDs = append(analysis.EntrypointNodeIDs, node.ID)
			}
			nodeUsageCount[node.ID] = len(graph.Adjacency[node.ID]) + len(graph.InEdges[node.ID])
		}
	} else if path != nil && len(path.Nodes) > 0 {
		analysis.EntrypointNodeIDs = append(analysis.EntrypointNodeIDs, path.Nodes[0].ID)
		for _, n := range path.Nodes {
			nodeUsageCount[n.ID]++
		}
	}

	// Bottlenecks: nodes with highest connectivity
	for nodeID, count := range nodeUsageCount {
		if count >= 2 {
			analysis.BottleneckNodeIDs = append(analysis.BottleneckNodeIDs, nodeID)
		}
	}
	sort.Strings(analysis.EntrypointNodeIDs)
	sort.Strings(analysis.BottleneckNodeIDs)

	// 2. Identify protected critical assets
	seenAssets := make(map[string]bool)
	if path != nil {
		for _, n := range path.Nodes {
			if n.Type == correlation.NodeTypeCriticalAsset || n.Type == correlation.NodeTypeSensitiveData || n.IsCriticalAsset || strings.Contains(strings.ToUpper(n.Title), "DATABASE") || strings.Contains(strings.ToUpper(n.Title), "PII") {
				if !seenAssets[n.Title] {
					seenAssets[n.Title] = true
					analysis.ProtectedAssets = append(analysis.ProtectedAssets, fmt.Sprintf("%s (%s)", n.Title, n.ID))
				}
			}
		}
	}
	sort.Strings(analysis.ProtectedAssets)

	// 3. Map items to DAG nodes and assign priorities
	itemByFindingID := make(map[string]*RemediationItem)
	for _, it := range items {
		if it != nil && it.FindingID != "" {
			itemByFindingID[it.FindingID] = it
		}
	}

	var narrativeBuilder strings.Builder
	anyVerifiedBroken := false
	anyProposedBroken := false

	if path != nil && len(path.Nodes) > 0 {
		for i, node := range path.Nodes {
			it, exists := itemByFindingID[node.FindingID]
			if !exists {
				// Try matching by node ID
				for _, candidate := range items {
					if candidate.Evidence != nil && candidate.Evidence.DAGNodeID == node.ID {
						it = candidate
						exists = true
						break
					}
				}
			}

			if exists && it != nil {
				// Priority: Entrypoints get 1, Bottlenecks get 2, others get 3+
				isEntrypoint := false
				for _, epID := range analysis.EntrypointNodeIDs {
					if epID == node.ID {
						isEntrypoint = true
						break
					}
				}
				isBottleneck := false
				for _, bnID := range analysis.BottleneckNodeIDs {
					if bnID == node.ID {
						isBottleneck = true
						break
					}
				}

				if isEntrypoint || i == 0 {
					it.Priority = 1
				} else if isBottleneck {
					it.Priority = 2
				} else {
					it.Priority = 3
				}

				// Construct edge description string
				var edgeStr string
				var edgeID string
				if i < len(path.Edges) {
					edge := path.Edges[i]
					edgeID = edge.ID
					edgeStr = fmt.Sprintf("%s (%s -> %s)", edge.ID, edge.SourceID, edge.TargetID)
					if string(edge.ValidationStatus) == "HYPOTHESIS" || edge.ValidationStatus == correlation.ValidationInconclusive || node.VerificationStatus == "HYPOTHESIS" {
						edgeStr += " [HYPOTHETICAL]"
					}
				}

				// Check remediation lifecycle standing:
				// 1. Verified remediation: (StatusVerified or StatusTested) AND supporting structured validation evidence
				isValidVerif, verifReason := hasValidationEvidence(it, edgeID)
				isVerified := (it.Status == StatusVerified || it.Status == StatusTested) && isValidVerif

				// 2. Proposed remediation: Source-validated, syntactically validated, applied-untested, or verified-without-complete-evidence
				isProposed := (it.Status == StatusSyntacticallyValidated || it.Status == StatusSourceValidated || it.Status == StatusApplied || it.Status == StatusTested || it.Status == StatusVerified) && !isVerified

				if isVerified {
					anyVerifiedBroken = true
					if edgeStr != "" {
						analysis.EliminatedEdges = append(analysis.EliminatedEdges, edgeStr)
						analysis.ProposedEliminatedEdges = append(analysis.ProposedEliminatedEdges, edgeStr)
					}
				} else if isProposed {
					anyProposedBroken = true
					if edgeStr != "" {
						analysis.ProposedEliminatedEdges = append(analysis.ProposedEliminatedEdges, edgeStr)
					}
				}

				// Link hypothesis state
				if node.VerificationStatus != "" && string(node.VerificationStatus) == "HYPOTHESIS" {
					if it.Evidence != nil {
						it.Evidence.IsHypothesis = true
					}
					it.Rationale += " [NOTE: Remediates a hypothetical exposure vector along the DAG attack path; target finding is not confirmed on live backend and edge remains hypothetical]"
				}

				// Build narrative for perimeter entrypoint
				if i == 0 {
					targetAssetStr := "downstream assets"
					if len(analysis.ProtectedAssets) > 0 {
						targetAssetStr = analysis.ProtectedAssets[0]
					}
					if isVerified {
						narrativeBuilder.WriteString(fmt.Sprintf("Verified remediation for perimeter entrypoint '%s' (%s) confirms path %s is broken at the boundary, preventing traversal toward %s (Status: VERIFIED_PATH_BREAK; backed by live target verification artifact). ", node.Title, it.ID, path.ID, targetAssetStr))
					} else if isProposed {
						if it.Status == StatusVerified || it.Status == StatusTested {
							narrativeBuilder.WriteString(fmt.Sprintf("Remediation for perimeter entrypoint '%s' (%s) claims verified status but lacks a valid live verification artifact (%s); actual path remains unverified until an authorized verification workflow executes (Status: PROPOSED_PATH_BREAK; projected path interruption). ", node.Title, it.ID, verifReason))
						} else if it.Status == StatusApplied {
							narrativeBuilder.WriteString(fmt.Sprintf("Remediation for perimeter entrypoint '%s' (%s) is applied to source but untested; actual path remains unverified until test confirmation (Status: PROPOSED_PATH_BREAK; projected path interruption). ", node.Title, it.ID))
						} else {
							narrativeBuilder.WriteString(fmt.Sprintf("Remediating perimeter entrypoint '%s' (%s) breaks path %s at the boundary upon application, preventing traversal toward %s (Status: PROPOSED_PATH_BREAK; projected path interruption, patch not yet applied or verified). ", node.Title, it.ID, path.ID, targetAssetStr))
						}
					} else if it.Status == StatusRecommendationOnly {
						narrativeBuilder.WriteString(fmt.Sprintf("Perimeter entrypoint '%s' (%s) is a recommendation only (target source not validated); path %s remains unbroken. ", node.Title, it.ID, path.ID))
					} else {
						narrativeBuilder.WriteString(fmt.Sprintf("Perimeter entrypoint '%s' (%s) could not be validated for remediation (status: %s); path %s remains unbroken. ", node.Title, it.ID, it.Status, path.ID))
					}
				}
			}
		}
	}

	if anyVerifiedBroken && path != nil {
		analysis.Status = PathBreakStatusVerified
		analysis.BrokenPathCount = 1
		analysis.ProposedBrokenPathCount = 1
	} else if anyProposedBroken && path != nil {
		analysis.Status = PathBreakStatusProposed
		analysis.BrokenPathCount = 0
		analysis.EliminatedEdges = []string{}
		analysis.ProposedBrokenPathCount = 1
	} else {
		analysis.Status = PathBreakStatusNone
		analysis.BrokenPathCount = 0
		analysis.EliminatedEdges = []string{}
		analysis.ProposedBrokenPathCount = 0
		analysis.ProposedEliminatedEdges = []string{}
	}

	sort.Strings(analysis.EliminatedEdges)
	sort.Strings(analysis.ProposedEliminatedEdges)
	analysis.BreakageNarrative = strings.TrimSpace(narrativeBuilder.String())

	// 4. Compute deterministic prioritization list of item IDs
	prioritizedIDs := sortItemsByPriority(items)

	return analysis, prioritizedIDs
}

// DetectSharedRootCauses identifies findings that target the exact same file and line boundaries.
func DetectSharedRootCauses(findings []*report.Finding, items []*RemediationItem) []*SharedRootCause {
	if len(items) < 2 {
		return nil
	}

	// Group items by TargetFile
	byFile := make(map[string][]*RemediationItem)
	for _, it := range items {
		if it == nil || it.TargetFile == "" || it.Diff == nil || it.Diff.IsReferencePattern {
			continue
		}
		byFile[it.TargetFile] = append(byFile[it.TargetFile], it)
	}

	var rootCauses []*SharedRootCause

	for file, fileItems := range byFile {
		if len(fileItems) < 2 {
			continue
		}

		// Find subsets with exact or overlapping lines
		for i := 0; i < len(fileItems); i++ {
			for j := i + 1; j < len(fileItems); j++ {
				a := fileItems[i]
				b := fileItems[j]

				// Only group findings that share the same vulnerability category
				if a.Category != b.Category {
					continue
				}

				// Overlap condition
				startMax := a.StartLine
				if b.StartLine > startMax {
					startMax = b.StartLine
				}
				endMin := a.EndLine
				if b.EndLine < endMin {
					endMin = b.EndLine
				}

				if startMax <= endMin {
					hashInput := fmt.Sprintf("%s:%d-%d:%s:%s", file, startMax, endMin, a.ID, b.ID)
					srcID := "SRC-" + hex.EncodeToString(sha256.New().Sum([]byte(hashInput)))[:8]

					src := &SharedRootCause{
						ID:                 srcID,
						Title:              fmt.Sprintf("Shared Root Cause in %s", file),
						TargetFile:         file,
						LineRange:          fmt.Sprintf("%d-%d", startMax, endMin),
						FindingIDs:         []string{a.FindingID, b.FindingID},
						Explanation:        fmt.Sprintf("Findings %s and %s stem from identical code context in %s (lines %d-%d); applying consolidated remediation %s addresses both exposures.", a.FindingID, b.FindingID, file, startMax, endMin, a.ID),
						ConsolidatedItemID: a.ID,
					}
					rootCauses = append(rootCauses, src)
				}
			}
		}
	}

	// Sort shared root causes deterministically
	sort.Slice(rootCauses, func(i, j int) bool {
		return rootCauses[i].ID < rootCauses[j].ID
	})

	return rootCauses
}

func sortItemsDefault(items []*RemediationItem) []string {
	sorted := make([]*RemediationItem, len(items))
	copy(sorted, items)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority < sorted[j].Priority
		}
		return sorted[i].ID < sorted[j].ID
	})
	ids := make([]string, len(sorted))
	for i, it := range sorted {
		ids[i] = it.ID
	}
	return ids
}

func sortItemsByPriority(items []*RemediationItem) []string {
	sorted := make([]*RemediationItem, len(items))
	copy(sorted, items)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority < sorted[j].Priority
		}
		return sorted[i].ID < sorted[j].ID
	})
	ids := make([]string, len(sorted))
	for i, it := range sorted {
		ids[i] = it.ID
	}
	return ids
}
