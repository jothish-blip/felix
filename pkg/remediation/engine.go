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
	"strconv"
	"strings"
	"time"

	"felix/pkg/report"
	"felix/pkg/secrets"
)

// RemediationEngine coordinates finding inspection, pattern resolution, diff generation, and validation.
type RemediationEngine struct {
	Registry *PatternRegistry
	Version  string
}

// NewRemediationEngine creates a new instance with the default pattern registry.
func NewRemediationEngine(registry *PatternRegistry) *RemediationEngine {
	if registry == nil {
		registry = NewPatternRegistry()
	}
	return &RemediationEngine{
		Registry: registry,
		Version:  "3.0.0",
	}
}

// GeneratePlan builds a complete, consolidated remediation package for the provided request.
func (e *RemediationEngine) GeneratePlan(req *RemediationRequest) (*RemediationPlan, error) {
	if req == nil {
		return nil, errors.New("remediation request cannot be nil")
	}

	if len(req.Findings) == 0 {
		return nil, errors.New("cannot generate remediation plan from empty findings list")
	}

	target := "unknown-target"
	var candidates []string
	for _, f := range req.Findings {
		if f != nil {
			if f.Target != "" {
				candidates = append(candidates, f.Target)
			} else if f.Endpoint != "" {
				clean := f.Endpoint
				if colon := strings.LastIndex(clean, ":"); colon > 0 {
					clean = clean[:colon]
				}
				candidates = append(candidates, clean)
			}
		}
	}
	if len(candidates) > 0 {
		sort.Strings(candidates)
		target = candidates[0]
	}

	var items []*RemediationItem

	for i, f := range req.Findings {
		if f == nil {
			return nil, fmt.Errorf("finding at index %d is nil", i)
		}

		item, err := e.GenerateItem(f, req)
		if err != nil {
			return nil, fmt.Errorf("failed generating remediation for finding %s: %w", f.ID, err)
		}
		items = append(items, item)
	}

	// Sort items deterministically by ID to ensure stable output across arbitrary finding ordering
	sort.Slice(items, func(i, j int) bool {
		return items[i].ID < items[j].ID
	})

	var consolidatedDiffs []string
	for _, it := range items {
		if it.Diff != nil && it.Diff.UnifiedDiff != "" {
			consolidatedDiffs = append(consolidatedDiffs, it.Diff.UnifiedDiff)
		}
	}

	// Conflict detection
	conflicts := DetectConflicts(items)
	if len(conflicts) > 0 {
		for _, it := range items {
			for _, conf := range conflicts {
				if strings.Contains(conf, it.ID) {
					it.Status = StatusConflicting
					if it.Validation != nil {
						it.Validation.ValidationErrors = append(it.Validation.ValidationErrors, conf)
					}
				}
			}
		}
	}

	// DAG integration & prioritization
	var dagAnalysis *DAGBreakAnalysis
	var prioritization []string
	if req.DAGPath != nil || req.DAGGraph != nil {
		dagAnalysis, prioritization = AnalyzeDAGRemediation(req.DAGPath, req.DAGGraph, items)
	} else {
		prioritization = sortItemsDefault(items)
	}

	// Shared root cause analysis
	sharedRootCauses := DetectSharedRootCauses(req.Findings, items)

	// Determine overall plan status
	overallStatus := StatusSyntacticallyValidated
	for _, it := range items {
		if it.Status == StatusConflicting {
			overallStatus = StatusConflicting
			break
		} else if it.Status == StatusRejected {
			overallStatus = StatusRejected
			break
		} else if it.Status == StatusInsufficientContext && overallStatus != StatusConflicting {
			overallStatus = StatusInsufficientContext
		} else if it.Status == StatusRecommendationOnly && overallStatus != StatusConflicting && overallStatus != StatusInsufficientContext {
			overallStatus = StatusRecommendationOnly
		}
	}

	planID := fmt.Sprintf("REM-PLAN-%s-%d", hex.EncodeToString(sha256.New().Sum([]byte(target)))[:8], len(items))

	plan := &RemediationPlan{
		ID:               planID,
		Title:            fmt.Sprintf("Remediation Plan for %s", target),
		Target:           target,
		TargetStack:      req.TargetStack,
		Status:           overallStatus,
		Items:            items,
		ConsolidatedDiff: strings.Join(consolidatedDiffs, "\n"),
		DAGBreakAnalysis: dagAnalysis,
		Prioritization:   prioritization,
		SharedRootCauses: sharedRootCauses,
		Metadata: RemediationMetadata{
			EngineVersion:      e.Version,
			GeneratedAt:        time.Now().UTC().Format(time.RFC3339),
			TotalFindingsCount: len(req.Findings),
			TotalItemsCount:    len(items),
			RepoPath:           req.RepoPath,
		},
	}

	// Compute bit-for-bit deterministic canonical content hash
	hash, err := e.CanonicalHash(plan)
	if err != nil {
		return nil, fmt.Errorf("failed computing canonical hash: %w", err)
	}
	plan.DeterministicContentHash = hash

	return plan, nil
}

// GenerateItem generates a single remediation item for a finding.
func (e *RemediationEngine) GenerateItem(f *report.Finding, req *RemediationRequest) (*RemediationItem, error) {
	if f == nil {
		return nil, ErrNilFinding
	}

	itemID := fmt.Sprintf("REM-ITEM-%s", f.ID)

	evidence := &RemediationEvidence{
		FindingID:          f.ID,
		Category:           f.Category,
		Provenance:         f.RuleID,
		EvidenceReferences: []string{secrets.RedactText(f.Evidence)},
	}

	// 1. Resolve pattern
	pattern, err := e.Registry.Resolve(f.Category)
	if err != nil {
		return &RemediationItem{
			ID:             itemID,
			FindingID:      f.ID,
			Category:       f.Category,
			Title:          f.Title,
			Status:         StatusUnsupported,
			SecurityImpact: "No automated remediation pattern available for this category",
			Rationale:      fmt.Sprintf("Category %q is not currently supported for automated diff generation", f.Category),
			Validation: &RemediationValidation{
				ValidationErrors: []string{err.Error()},
			},
			Evidence: evidence,
		}, nil
	}

	// 2. Extract source location
	targetFile, lineNum, hasSource := ExtractSourceLocation(f)
	if hasSource {
		evidence.SourceLocation = fmt.Sprintf("%s:%d", targetFile, lineNum)
	}

	// 3. Obtain source content (from in-memory map or repo-path read)
	var sourceContent string
	var sourceFound bool
	if hasSource && req != nil {
		if req.SourceContext != nil && req.SourceContext[targetFile] != "" {
			sourceContent = req.SourceContext[targetFile]
			sourceFound = true
		} else if req.RepoPath != "" {
			fullPath := filepath.Join(req.RepoPath, targetFile)
			// Read-only filesystem access; never write
			if b, readErr := os.ReadFile(fullPath); readErr == nil {
				sourceContent = string(b)
				sourceFound = true
			}
		}
	}

	// 4. If source is NOT available: handle reference pattern vs insufficient context
	if !sourceFound || !hasSource {
		if req != nil && req.AllowReference {
			refDiff, impact, rationale, tests, imports, breaking := pattern.GenerateReference(f, req.TargetStack)
			refDiff.UnifiedDiff = secrets.RedactText(refDiff.UnifiedDiff)

			return &RemediationItem{
				ID:                            itemID,
				FindingID:                     f.ID,
				Category:                      f.Category,
				Title:                         f.Title,
				TargetFile:                    refDiff.TargetFile,
				StartLine:                     refDiff.Hunks[0].OldStart,
				EndLine:                       refDiff.Hunks[0].OldStart + refDiff.Hunks[0].OldCount - 1,
				Status:                        StatusRecommendationOnly,
				Priority:                      3,
				SecurityImpact:                secrets.RedactText(impact),
				Rationale:                     secrets.RedactText(rationale),
				Diff:                          refDiff,
				RequiredImports:               imports,
				PotentialBreakingChanges:      breaking,
				RegressionTestRecommendations: tests,
				Validation: &RemediationValidation{
					SyntacticallyValid:     true,
					ApplicableToSource:     false,
					PreservesUnrelatedCode: false,
					NoSecretLeakage:        true,
					SafetyRulesPassed:      true,
					ValidationWarnings:     []string{"Reference pattern only: target repository source code was not available; do not apply as a tested fix"},
				},
				Evidence: evidence,
			}, nil
		}

		// Strictly reject fabricating patches when source is missing
		return &RemediationItem{
			ID:             itemID,
			FindingID:      f.ID,
			Category:       f.Category,
			Title:          f.Title,
			Status:         StatusInsufficientContext,
			SecurityImpact: "Source code context is unavailable for this finding",
			Rationale:      "Source file location was missing, ambiguous, or not present in the provided source repository. Patch generation withheld to prevent fabrication.",
			Validation: &RemediationValidation{
				ValidationErrors: []string{"insufficient source code context"},
			},
			Evidence: evidence,
		}, nil
	}

	// 5. Source IS available: generate exact diff, validate applicability and safety
	origLines := strings.Split(strings.ReplaceAll(sourceContent, "\r\n", "\n"), "\n")
	if lineNum < 1 || lineNum > len(origLines) {
		return &RemediationItem{
			ID:             itemID,
			FindingID:      f.ID,
			Category:       f.Category,
			Title:          f.Title,
			TargetFile:     targetFile,
			StartLine:      lineNum,
			EndLine:        lineNum,
			Status:         StatusInsufficientContext,
			SecurityImpact: "Line number out of bounds in source file",
			Rationale:      fmt.Sprintf("Reported line %d exceeds file length of %d lines", lineNum, len(origLines)),
			Validation: &RemediationValidation{
				ValidationErrors: []string{fmt.Sprintf("line number %d out of bounds", lineNum)},
			},
			Evidence: evidence,
		}, nil
	}

	targetLine := strings.TrimSpace(origLines[lineNum-1])
	if targetLine == "" || targetLine == "{" || targetLine == "}" || targetLine == "};" || targetLine == "]" || targetLine == ")" {
		return &RemediationItem{
			ID:             itemID,
			FindingID:      f.ID,
			Category:       f.Category,
			Title:          f.Title,
			TargetFile:     targetFile,
			StartLine:      lineNum,
			EndLine:        lineNum,
			Status:         StatusInsufficientContext,
			SecurityImpact: "Ambiguous or stale source line context",
			Rationale:      fmt.Sprintf("Source line %d (%q) is empty or non-executable punctuation; remediation withheld to prevent corrupting source code", lineNum, targetLine),
			Validation: &RemediationValidation{
				ValidationErrors: []string{fmt.Sprintf("ambiguous or stale source line context at line %d", lineNum)},
			},
			Evidence: evidence,
		}, nil
	}

	evidence.MatchedContext = origLines[lineNum-1]

	endLine, replacements, imports, breaking, impact, rationale, tests, err := pattern.GenerateFix(f, targetFile, lineNum, origLines, req.TargetStack)
	if err != nil {
		return nil, fmt.Errorf("pattern fix generation error: %w", err)
	}

	// Build unified diff
	diff, err := BuildUnifiedDiff(targetFile, origLines, replacements, lineNum, endLine, 3)
	if err != nil {
		return nil, fmt.Errorf("diff building error: %w", err)
	}

	// 6. Validate diff syntax
	syntaxOK, syntaxErrs := ValidateDiffSyntax(diff.UnifiedDiff)

	// 7. Verify in-memory patch applicability & code preservation
	patchedMemory, applyErr := ApplyPatchToMemory(sourceContent, diff)
	applicable := (applyErr == nil)

	// 8. Validate patch safety (no secrets, no weakening controls)
	safetyOK, safetyErrs := ValidatePatchSafety(diff, patchedMemory)

	// Redact secrets in diff and rationale
	diff.UnifiedDiff = secrets.RedactText(diff.UnifiedDiff)
	impact = secrets.RedactText(impact)
	rationale = secrets.RedactText(rationale)

	var validationErrs []string
	if !syntaxOK {
		validationErrs = append(validationErrs, syntaxErrs...)
	}
	if applyErr != nil {
		validationErrs = append(validationErrs, applyErr.Error())
	}
	if !safetyOK {
		validationErrs = append(validationErrs, safetyErrs...)
	}

	status := StatusSyntacticallyValidated
	if !syntaxOK {
		status = StatusInsufficientContext
	} else if !safetyOK {
		status = StatusRejected
	} else if !applicable {
		status = StatusInsufficientContext
	}

	item := &RemediationItem{
		ID:                            itemID,
		FindingID:                     f.ID,
		Category:                      f.Category,
		Title:                         f.Title,
		TargetFile:                    targetFile,
		StartLine:                     lineNum,
		EndLine:                       endLine,
		Status:                        status,
		Priority:                      3, // Default priority; DAG analysis elevates entrypoints to 1 and bottlenecks to 2
		SecurityImpact:                impact,
		Rationale:                     rationale,
		Diff:                          diff,
		RequiredImports:               imports,
		PotentialBreakingChanges:      breaking,
		RegressionTestRecommendations: tests,
		Validation: &RemediationValidation{
			SyntacticallyValid:     syntaxOK,
			ApplicableToSource:     applicable,
			PreservesUnrelatedCode: applicable,
			NoSecretLeakage:        safetyOK,
			SafetyRulesPassed:      safetyOK,
			ValidationErrors:       validationErrs,
		},
		Evidence: evidence,
	}

	return item, nil
}

// CanonicalHash computes a stable, bit-for-bit reproducible SHA-256 over normalized plan contents.
func (e *RemediationEngine) CanonicalHash(plan *RemediationPlan) (string, error) {
	if plan == nil {
		return "", errors.New("cannot hash nil remediation plan")
	}

	// Sort items deterministically by ID
	sortedItems := make([]*RemediationItem, len(plan.Items))
	copy(sortedItems, plan.Items)
	sort.Slice(sortedItems, func(i, j int) bool {
		return sortedItems[i].ID < sortedItems[j].ID
	})

	var canonicalItems []canonicalItemPayload
	for _, it := range sortedItems {
		var diffText string
		var isRef bool
		var added, removed int
		if it.Diff != nil {
			diffText = it.Diff.UnifiedDiff
			isRef = it.Diff.IsReferencePattern
			added = it.Diff.AddedLinesCount
			removed = it.Diff.RemovedLinesCount
		}

		canonicalItems = append(canonicalItems, canonicalItemPayload{
			AddedLinesCount:               added,
			Category:                      it.Category,
			EndLine:                       it.EndLine,
			FindingID:                     it.FindingID,
			ID:                            it.ID,
			IsReferencePattern:            isRef,
			PotentialBreakingChanges:      it.PotentialBreakingChanges,
			Priority:                      it.Priority,
			Rationale:                     it.Rationale,
			RegressionTestRecommendations: it.RegressionTestRecommendations,
			RemovedLinesCount:             removed,
			RequiredImports:               it.RequiredImports,
			SecurityImpact:                it.SecurityImpact,
			StartLine:                     it.StartLine,
			Status:                        it.Status,
			TargetFile:                    it.TargetFile,
			Title:                         it.Title,
			UnifiedDiff:                   diffText,
			VerificationEvidence:          it.VerificationEvidence,
		})
	}

	var canonicalCauses []canonicalCausePayload
	if len(plan.SharedRootCauses) > 0 {
		sortedCauses := make([]*SharedRootCause, len(plan.SharedRootCauses))
		copy(sortedCauses, plan.SharedRootCauses)
		sort.Slice(sortedCauses, func(i, j int) bool {
			return sortedCauses[i].ID < sortedCauses[j].ID
		})
		for _, c := range sortedCauses {
			canonicalCauses = append(canonicalCauses, canonicalCausePayload{
				ConsolidatedItemID: c.ConsolidatedItemID,
				Explanation:        c.Explanation,
				FindingIDs:         c.FindingIDs,
				ID:                 c.ID,
				LineRange:          c.LineRange,
				TargetFile:         c.TargetFile,
				Title:              c.Title,
			})
		}
	}

	var canonicalDAG *canonicalDAGPayload
	if plan.DAGBreakAnalysis != nil {
		canonicalDAG = &canonicalDAGPayload{
			BottleneckNodeIDs:       plan.DAGBreakAnalysis.BottleneckNodeIDs,
			BreakageNarrative:       plan.DAGBreakAnalysis.BreakageNarrative,
			BrokenPathCount:         plan.DAGBreakAnalysis.BrokenPathCount,
			EliminatedEdges:         plan.DAGBreakAnalysis.EliminatedEdges,
			EntrypointNodeIDs:       plan.DAGBreakAnalysis.EntrypointNodeIDs,
			PathID:                  plan.DAGBreakAnalysis.PathID,
			ProposedBrokenPathCount: plan.DAGBreakAnalysis.ProposedBrokenPathCount,
			ProposedEliminatedEdges: plan.DAGBreakAnalysis.ProposedEliminatedEdges,
			ProtectedAssets:         plan.DAGBreakAnalysis.ProtectedAssets,
			Status:                  plan.DAGBreakAnalysis.Status,
		}
	}

	payload := canonicalPlanPayload{
		ConsolidatedDiff: plan.ConsolidatedDiff,
		DAGBreakAnalysis: canonicalDAG,
		ID:               plan.ID,
		Items:            canonicalItems,
		Prioritization:   plan.Prioritization,
		SharedRootCauses: canonicalCauses,
		Status:           plan.Status,
		Target:           plan.Target,
		TargetStack:      plan.TargetStack,
		Title:            plan.Title,
	}

	canonicalBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed marshaling canonical remediation payload: %w", err)
	}

	sum := sha256.Sum256(canonicalBytes)
	return hex.EncodeToString(sum[:]), nil
}

// Canonical payloads for stable JSON serialization
type canonicalPlanPayload struct {
	ConsolidatedDiff string                 `json:"consolidated_diff"`
	DAGBreakAnalysis *canonicalDAGPayload   `json:"dag_break_analysis,omitempty"`
	ID               string                 `json:"id"`
	Items            []canonicalItemPayload `json:"items"`
	Prioritization   []string               `json:"prioritization"`
	SharedRootCauses []canonicalCausePayload `json:"shared_root_causes,omitempty"`
	Status           RemediationStatus      `json:"status"`
	Target           string                 `json:"target"`
	TargetStack      string                 `json:"target_stack"`
	Title            string                 `json:"title"`
}

type canonicalItemPayload struct {
	AddedLinesCount               int               `json:"added_lines_count"`
	Category                      string            `json:"category"`
	EndLine                       int               `json:"end_line"`
	FindingID                     string            `json:"finding_id"`
	ID                            string            `json:"id"`
	IsReferencePattern            bool              `json:"is_reference_pattern"`
	PotentialBreakingChanges      []string          `json:"potential_breaking_changes,omitempty"`
	Priority                      int               `json:"priority"`
	Rationale                     string            `json:"rationale"`
	RegressionTestRecommendations []string          `json:"regression_test_recommendations"`
	RemovedLinesCount             int               `json:"removed_lines_count"`
	RequiredImports               []string          `json:"required_imports,omitempty"`
	SecurityImpact                string            `json:"security_impact"`
	StartLine                     int               `json:"start_line"`
	Status                        RemediationStatus `json:"status"`
	TargetFile                    string            `json:"target_file"`
	Title                         string            `json:"title"`
	UnifiedDiff                   string                `json:"unified_diff"`
	VerificationEvidence          *VerificationEvidence `json:"verification_evidence,omitempty"`
}

type canonicalCausePayload struct {
	ConsolidatedItemID string   `json:"consolidated_item_id"`
	Explanation        string   `json:"explanation"`
	FindingIDs         []string `json:"finding_ids"`
	ID                 string   `json:"id"`
	LineRange          string   `json:"line_range"`
	TargetFile         string   `json:"target_file"`
	Title              string   `json:"title"`
}

type canonicalDAGPayload struct {
	BottleneckNodeIDs       []string        `json:"bottleneck_node_ids"`
	BreakageNarrative       string          `json:"breakage_narrative"`
	BrokenPathCount         int             `json:"broken_path_count"`
	EliminatedEdges         []string        `json:"eliminated_edges"`
	EntrypointNodeIDs       []string        `json:"entrypoint_node_ids"`
	PathID                  string          `json:"path_id"`
	ProposedBrokenPathCount int             `json:"proposed_broken_path_count"`
	ProposedEliminatedEdges []string        `json:"proposed_eliminated_edges"`
	ProtectedAssets         []string        `json:"protected_assets"`
	Status                  PathBreakStatus `json:"status"`
}

// ExtractSourceLocation extracts the target relative file path and line number from finding metadata.
func ExtractSourceLocation(f *report.Finding) (string, int, bool) {
	if f == nil {
		return "", 0, false
	}

	candidates := []string{}
	if f.Provenance != nil && f.Provenance.Location != "" {
		candidates = append(candidates, f.Provenance.Location)
	}
	if f.EvidenceDetails.Location != "" {
		candidates = append(candidates, f.EvidenceDetails.Location)
	}
	if f.Endpoint != "" {
		candidates = append(candidates, f.Endpoint)
	}

	for _, raw := range candidates {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}

		// Reject URLs and web schemes
		if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") || strings.Contains(trimmed, "://") {
			continue
		}

		// Check for file:line format
		lastColon := strings.LastIndex(trimmed, ":")
		if lastColon > 0 {
			pathCandidate := filepath.ToSlash(filepath.Clean(trimmed[:lastColon]))
			lineStr := strings.TrimSpace(trimmed[lastColon+1:])
			if lineNum, err := strconv.Atoi(lineStr); err == nil && lineNum > 0 {
				if isValidSourceExtension(pathCandidate) {
					return pathCandidate, lineNum, true
				}
			}
		}

		// Direct source file path
		cleanPath := filepath.ToSlash(filepath.Clean(trimmed))
		if isValidSourceExtension(cleanPath) {
			return cleanPath, 1, true
		}
	}

	return "", 0, false
}

func isValidSourceExtension(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".js", ".ts", ".jsx", ".tsx", ".py", ".go", ".java", ".c", ".cpp", ".cs", ".php", ".rb", ".json", ".yaml", ".yml", ".conf":
		return true
	default:
		return false
	}
}
