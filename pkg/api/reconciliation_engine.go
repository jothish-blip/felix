package api

import (
	"fmt"
	"sort"
	"strings"

	"felix/pkg/crawler"
)

// ReconciliationOptions configures the topology reconciliation engine.
type ReconciliationOptions struct {
	ScopeHost            string
	EnforceScope         bool
	Environment          string
	RequireExactMethod   bool
	MaxCandidateMatches  int
}

// DefaultReconciliationOptions returns standard safe options for reconciliation.
func DefaultReconciliationOptions() ReconciliationOptions {
	return ReconciliationOptions{
		RequireExactMethod:  true,
		MaxCandidateMatches: 10,
	}
}

// ReconciliationEngine reconciles discovered route candidates against documented API specifications.
type ReconciliationEngine struct {
	options      ReconciliationOptions
	primaryIndex map[string][]DocumentedOperation // key: METHOD:canonicalPath
	pathIndex    map[string][]DocumentedOperation // key: canonicalPath
	allSpecs     []SpecMetadata
	allOps       []DocumentedOperation
}

// NewReconciliationEngine creates an evidence-aware reconciliation engine initialized with specifications.
func NewReconciliationEngine(specs []SpecMetadata, operations []DocumentedOperation, opts ReconciliationOptions) *ReconciliationEngine {
	engine := &ReconciliationEngine{
		options:      opts,
		primaryIndex: make(map[string][]DocumentedOperation),
		pathIndex:    make(map[string][]DocumentedOperation),
		allSpecs:     specs,
		allOps:       operations,
	}

	for _, op := range operations {
		key := fmt.Sprintf("%s:%s", strings.ToUpper(op.Method), op.CanonicalPath)
		engine.primaryIndex[key] = append(engine.primaryIndex[key], op)
		engine.pathIndex[op.CanonicalPath] = append(engine.pathIndex[op.CanonicalPath], op)
	}

	return engine
}

// Reconcile analyzes a list of discovered route candidates and produces a comprehensive reconciliation report.
func (re *ReconciliationEngine) Reconcile(candidates []crawler.RouteCandidate) *ReconciliationReport {
	report := &ReconciliationReport{
		TotalDiscoveredCandidates: len(candidates),
		TotalDocumentedOperations: len(re.allOps),
		Specifications:            re.allSpecs,
	}

	// Group and deduplicate candidates by (method, canonicalPath), preserving all provenance sources
	type candGroupKey struct {
		method        string
		canonicalPath string
	}

	grouped := make(map[candGroupKey][]crawler.RouteCandidate)
	var orderedKeys []candGroupKey

	for _, c := range candidates {
		canonical := CanonicalizeRoutePath(c.Path)
		method := strings.ToUpper(strings.TrimSpace(c.HTTPMethod))
		if method == "" {
			method = "UNKNOWN"
		}

		key := candGroupKey{
			method:        method,
			canonicalPath: canonical,
		}

		if _, exists := grouped[key]; !exists {
			orderedKeys = append(orderedKeys, key)
		}
		grouped[key] = append(grouped[key], c)
	}

	// Evaluate each distinct candidate
	for _, key := range orderedKeys {
		cGroup := grouped[key]
		primaryCandidate := cGroup[0]

		// Choose the highest-confidence candidate in group
		for _, c := range cGroup {
			if c.Confidence == crawler.ConfidenceConfirmed && primaryCandidate.Confidence != crawler.ConfidenceConfirmed {
				primaryCandidate = c
			}
		}

		canonicalPath := key.canonicalPath
		candMethod := key.method

		// Detect sensitive identifiers across path, query, and evidence
		sensitiveHits := DetectSensitiveIdentifiers(primaryCandidate.Path, nil, nil, primaryCandidate.Evidence)
		if primaryCandidate.RawPath != "" && primaryCandidate.RawPath != primaryCandidate.Path {
			rawHits := DetectSensitiveIdentifiers(primaryCandidate.RawPath, nil, nil, "")
			sensitiveHits = mergeSensitiveHits(sensitiveHits, rawHits)
		}

		item := ReconciliationItem{
			CandidateID:         primaryCandidate.ID,
			Method:              candMethod,
			Path:                primaryCandidate.Path,
			CanonicalPath:       canonicalPath,
			RawPath:             primaryCandidate.RawPath,
			OriginatingAsset:    primaryCandidate.OriginatingAsset,
			DiscoverySource:     string(primaryCandidate.SourceType),
			DiscoveryConfidence: string(primaryCandidate.Confidence),
			SensitiveHits:       sensitiveHits,
			ServerAction:        primaryCandidate.ServerAction,
			DiscoveredAt:        primaryCandidate.DiscoveredAt,
			Warnings:            append([]string{}, primaryCandidate.Warnings...),
		}

		// Record repeated discovery sources if multiple bundles exposed this route
		if len(cGroup) > 1 {
			var assets []string
			for _, cg := range cGroup {
				assets = append(assets, cg.OriginatingAsset)
			}
			item.Warnings = append(item.Warnings, fmt.Sprintf("Observed across %d independent discovery locations: %s", len(cGroup), strings.Join(assets, ", ")))
		}

		// Evaluate Reconciliation Classification
		re.classifyCandidate(&item)

		report.Items = append(report.Items, item)

		// Aggregate report counters
		switch item.Classification {
		case ClassificationDocumentedMatch:
			report.TotalDocumentedMatches++
		case ClassificationUndocumentedCandidate:
			report.TotalUndocumentedCandidates++
			report.ShadowSurface = append(report.ShadowSurface, item)
			if len(item.SensitiveHits) > 0 {
				report.TotalSensitiveShadowRoutes++
			}
		case ClassificationAmbiguousMatch:
			report.TotalAmbiguousMatches++
			report.ShadowSurface = append(report.ShadowSurface, item)
			if len(item.SensitiveHits) > 0 {
				report.TotalSensitiveShadowRoutes++
			}
		case ClassificationIncompleteEvidence:
			report.TotalIncompleteEvidence++
		}
	}

	// Sort ShadowSurface by Priority (Critical first, then High, then Standard, then Low)
	sort.Slice(report.ShadowSurface, func(i, j int) bool {
		rankI := priorityRank(report.ShadowSurface[i].Priority)
		rankJ := priorityRank(report.ShadowSurface[j].Priority)
		if rankI != rankJ {
			return rankI < rankJ
		}
		return report.ShadowSurface[i].CanonicalPath < report.ShadowSurface[j].CanonicalPath
	})

	return report
}

// classifyCandidate determines match classification, rationale, and shadow surface priority.
func (re *ReconciliationEngine) classifyCandidate(item *ReconciliationItem) {
	canonicalPath := item.CanonicalPath
	candMethod := item.Method

	// Check if specifications were provided and parsed successfully
	if len(re.allSpecs) == 0 {
		item.Classification = ClassificationIncompleteEvidence
		item.MatchRationale = "No API specification provided; topology reconciliation cannot confirm whether routes are documented"
		item.Priority = PriorityIncomplete
		item.PriorityRationale = "Baseline specification missing; candidate status cannot be established without documentation"
		return
	}

	allMalformed := true
	for _, spec := range re.allSpecs {
		if spec.Format != "MALFORMED" && spec.Format != "UNSUPPORTED" {
			allMalformed = false
			break
		}
	}
	if allMalformed {
		item.Classification = ClassificationUnsupportedOrUnparsed
		item.MatchRationale = "Supplied API specification(s) could not be parsed or are unsupported; baseline is unavailable"
		item.Priority = PriorityIncomplete
		item.PriorityRationale = "Unparsed specification baseline prevents authoritative documentation verification"
		return
	}

	// If candidate was inferred via weak string concatenation or heuristic without confirmed method
	if item.DiscoveryConfidence == string(crawler.ConfidenceHeuristic) {
		// If it happens to match a documented path exactly, record match; otherwise mark incomplete evidence
		if matches, ok := re.primaryIndex[fmt.Sprintf("%s:%s", candMethod, canonicalPath)]; ok && len(matches) > 0 {
			re.setDocumentedMatch(item, matches)
			return
		}
		item.Classification = ClassificationIncompleteEvidence
		item.MatchRationale = "Candidate discovered through weak heuristic evidence; insufficient proof to confirm undocumented shadow status"
		item.Priority = PriorityLowShadow
		item.PriorityRationale = "Low discovery confidence requires analyst triage before active verification"
		return
	}

	// Case 1: Unknown HTTP Method
	if candMethod == "UNKNOWN" {
		if pathMatches, ok := re.pathIndex[canonicalPath]; ok && len(pathMatches) > 0 {
			var methods []string
			seenMethod := make(map[string]bool)
			for _, pm := range pathMatches {
				if !seenMethod[pm.Method] {
					seenMethod[pm.Method] = true
					methods = append(methods, pm.Method)
				}
			}
			item.Classification = ClassificationAmbiguousMatch
			item.AmbiguousMatches = pathMatches
			item.MatchRationale = fmt.Sprintf("Path %s is documented for method(s) %s, but discovered HTTP method is UNKNOWN; exact operation is ambiguous", canonicalPath, strings.Join(methods, ", "))
			item.Priority = PriorityAmbiguous
			item.PriorityRationale = "Ambiguous operation match: method must be confirmed before determining shadow status"
			return
		}

		// Undocumented path with unknown method
		item.Classification = ClassificationUndocumentedCandidate
		item.MatchRationale = fmt.Sprintf("Path %s does not match any documented path across API specifications", canonicalPath)
		re.assignShadowPriority(item)
		return
	}

	// Case 2: Concrete HTTP Method
	primaryKey := fmt.Sprintf("%s:%s", candMethod, canonicalPath)
	exactMatches, hasExact := re.primaryIndex[primaryKey]

	if hasExact && len(exactMatches) > 0 {
		// Check for multi-specification conflicts
		if len(exactMatches) > 1 && hasConflictingSpecDefinitions(exactMatches) {
			item.Classification = ClassificationAmbiguousMatch
			item.AmbiguousMatches = exactMatches
			item.MatchRationale = fmt.Sprintf("Operation %s %s matches conflicting declarations across multiple API specifications", candMethod, canonicalPath)
			item.Priority = PriorityAmbiguous
			item.PriorityRationale = "Conflicting multi-specification declarations require specification reconciliation"
			return
		}

		re.setDocumentedMatch(item, exactMatches)
		return
	}

	// No exact method match: check if path is documented under DIFFERENT methods
	if pathMatches, hasPath := re.pathIndex[canonicalPath]; hasPath && len(pathMatches) > 0 {
		var docMethods []string
		for _, pm := range pathMatches {
			docMethods = append(docMethods, pm.Method)
		}
		item.Classification = ClassificationUndocumentedCandidate
		item.MatchRationale = fmt.Sprintf("Path %s is documented under method(s) %s, but operation %s %s is undocumented in API specifications", canonicalPath, strings.Join(docMethods, ", "), candMethod, canonicalPath)
		item.AmbiguousMatches = pathMatches
		re.assignShadowPriority(item)
		return
	}

	// Entirely undocumented path and method
	item.Classification = ClassificationUndocumentedCandidate
	item.MatchRationale = fmt.Sprintf("Operation %s %s is undocumented across all parsed API specifications", candMethod, canonicalPath)
	re.assignShadowPriority(item)
}

func (re *ReconciliationEngine) setDocumentedMatch(item *ReconciliationItem, matches []DocumentedOperation) {
	op := matches[0]
	item.Classification = ClassificationDocumentedMatch
	item.MatchedSpec = op.SpecTitle
	item.MatchedOperationID = op.OperationID
	item.MatchedOperation = &op
	item.MatchRationale = fmt.Sprintf("Exact match on %s %s in specification %q", op.Method, op.CanonicalPath, op.SpecTitle)
	item.Priority = PriorityDocumented
	item.PriorityRationale = "Operation is explicitly declared and documented in API contract"
}

// assignShadowPriority calculates shadow prioritization based on sensitive identifiers,
// HTTP methods, and discovery confidence.
func (re *ReconciliationEngine) assignShadowPriority(item *ReconciliationItem) {
	hasPathSensitive := false
	for _, hit := range item.SensitiveHits {
		if hit.Location == "PATH" {
			hasPathSensitive = true
			break
		}
	}

	isMutation := item.Method == "POST" || item.Method == "PUT" || item.Method == "DELETE" || item.Method == "PATCH"

	switch {
	case hasPathSensitive && item.DiscoveryConfidence == string(crawler.ConfidenceConfirmed):
		item.Priority = PriorityCriticalShadow
		item.PriorityRationale = "High-confidence undocumented route exposing authorization-boundary identifier in path parameter"

	case hasPathSensitive || isMutation || len(item.SensitiveHits) > 0:
		item.Priority = PriorityHighShadow
		if isMutation {
			item.PriorityRationale = "High-priority undocumented mutation operation (state-changing API surface)"
		} else {
			item.PriorityRationale = "High-priority undocumented route involving sensitive authorization identifiers"
		}

	case item.DiscoveryConfidence == string(crawler.ConfidenceInferred):
		item.Priority = PriorityLowShadow
		item.PriorityRationale = "Inferred undocumented route candidate requiring manual endpoint verification"

	default:
		item.Priority = PriorityStandardShadow
		item.PriorityRationale = "Undocumented read operation discovered in client bundle without sensitive path parameters"
	}
}

func hasConflictingSpecDefinitions(matches []DocumentedOperation) bool {
	firstSpec := matches[0].SpecSource
	for _, m := range matches[1:] {
		if m.SpecSource != firstSpec && (m.OperationID != matches[0].OperationID || len(m.Parameters) != len(matches[0].Parameters)) {
			return true
		}
	}
	return false
}

func mergeSensitiveHits(a, b []SensitiveIdentifierHit) []SensitiveIdentifierHit {
	seen := make(map[string]bool)
	var merged []SensitiveIdentifierHit

	for _, h := range append(a, b...) {
		key := fmt.Sprintf("%s|%s|%s", h.Type, h.MatchedTerm, h.Location)
		if !seen[key] {
			seen[key] = true
			merged = append(merged, h)
		}
	}
	return merged
}

func priorityRank(p ShadowPriority) int {
	switch p {
	case PriorityCriticalShadow:
		return 1
	case PriorityHighShadow:
		return 2
	case PriorityStandardShadow:
		return 3
	case PriorityLowShadow:
		return 4
	case PriorityAmbiguous:
		return 5
	case PriorityIncomplete:
		return 6
	case PriorityDocumented:
		return 7
	default:
		return 8
	}
}
