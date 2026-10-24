package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// DriftClassification categorizes the structural, semantic, or reachability shift observed on an API route.
type DriftClassification string

const (
	ClassificationNewShadowRoute           DriftClassification = "NEW_SHADOW_ROUTE"
	ClassificationRemovedRoute             DriftClassification = "REMOVED_ROUTE"
	ClassificationMethodChange             DriftClassification = "METHOD_CHANGE"
	ClassificationParameterShapeChange     DriftClassification = "PARAMETER_SHAPE_CHANGE"
	ClassificationSensitiveIdentifierChange DriftClassification = "SENSITIVE_IDENTIFIER_CHANGE"
	ClassificationDocumentationStatusChange DriftClassification = "DOCUMENTATION_STATUS_CHANGE"
	ClassificationReachabilityChange       DriftClassification = "REACHABILITY_CHANGE"
	ClassificationProbeClassificationChange DriftClassification = "PROBE_CLASSIFICATION_CHANGE"
	ClassificationEvidenceConfidenceChange DriftClassification = "EVIDENCE_CONFIDENCE_CHANGE"
	ClassificationBaselineMissing          DriftClassification = "BASELINE_MISSING"
	ClassificationBaselineIncompatible     DriftClassification = "BASELINE_INCOMPATIBLE"
	ClassificationSnapshotIncomplete       DriftClassification = "SNAPSHOT_INCOMPLETE"
)

// DriftPriority defines the triage urgency of a detected temporal drift.
type DriftPriority string

const (
	PriorityCritical DriftPriority = "CRITICAL"
	PriorityHigh     DriftPriority = "HIGH"
	PriorityMedium   DriftPriority = "MEDIUM"
	PriorityLow      DriftPriority = "LOW"
	PriorityInfo     DriftPriority = "INFO"
)

// PriorityRank maps priority string to numeric rank for sorting.
func PriorityRank(p DriftPriority) int {
	switch p {
	case PriorityCritical:
		return 5
	case PriorityHigh:
		return 4
	case PriorityMedium:
		return 3
	case PriorityLow:
		return 2
	case PriorityInfo:
		return 1
	default:
		return 0
	}
}

// DriftEvent models an actionable, auditable change detected between an API surface baseline and a current snapshot.
type DriftEvent struct {
	ID                   string              `json:"id"`
	TargetID             string              `json:"target_id"`
	BaselineSnapshotID   string              `json:"baseline_snapshot_id"`
	CurrentSnapshotID    string              `json:"current_snapshot_id"`
	Classification       DriftClassification `json:"classification"`
	CanonicalRoute       string              `json:"canonical_route"`
	Method               string              `json:"method,omitempty"`
	PreviousValue        string              `json:"previous_value,omitempty"`
	CurrentValue         string              `json:"current_value,omitempty"`
	SensitiveIdentifiers []string            `json:"sensitive_identifiers,omitempty"`
	Provenance           string              `json:"provenance,omitempty"`
	DetectedAt           time.Time           `json:"detected_at"`
	Priority             DriftPriority       `json:"priority"`
	PriorityRationale    string              `json:"priority_rationale"`
	Confidence           string              `json:"confidence"`
	IsComplete           bool                `json:"is_complete"`
	SuggestedAction      string              `json:"suggested_action"`
}

// ComputeEventDeduplicationKey generates a stable SHA-256 deduplication key for an event.
func ComputeEventDeduplicationKey(targetID string, class DriftClassification, route, method, detail string) string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s",
		strings.TrimSpace(targetID),
		class,
		strings.ToLower(strings.TrimSpace(route)),
		strings.ToUpper(strings.TrimSpace(method)),
		strings.TrimSpace(detail),
	)
	h := sha256.Sum256([]byte(raw))
	return "evt_" + hex.EncodeToString(h[:12])
}

// DriftReport summarizes all temporal changes detected between a baseline and current snapshot.
type DriftReport struct {
	TargetID           string                    `json:"target_id"`
	BaselineSnapshotID string                    `json:"baseline_snapshot_id"`
	CurrentSnapshotID  string                    `json:"current_snapshot_id"`
	ComparedAt         time.Time                 `json:"compared_at"`
	TotalEvents        int                       `json:"total_events"`
	Events             []DriftEvent              `json:"events"`
	Summary            map[DriftClassification]int `json:"summary"`
	Warnings           []string                  `json:"warnings,omitempty"`
	HasBaseline        bool                      `json:"has_baseline"`
	IsCompatible       bool                      `json:"is_compatible"`
}

// CompareSnapshots analyzes temporal differences between an authoritative baseline and a current snapshot.
// It enforces all P14.5 conservative evidence boundaries and returns deterministic results.
func CompareSnapshots(baseline, current *Snapshot) *DriftReport {
	now := time.Now().UTC()
	rep := &DriftReport{
		ComparedAt:   now,
		Summary:      make(map[DriftClassification]int),
		HasBaseline:  baseline != nil,
		IsCompatible: true,
	}

	if current != nil {
		rep.TargetID = current.TargetID
		rep.CurrentSnapshotID = current.ID
	} else if baseline != nil {
		rep.TargetID = baseline.TargetID
	}

	// 1. Missing baseline check
	if baseline == nil {
		rep.HasBaseline = false
		if current != nil {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("No prior baseline exists for target %q; current snapshot established as initial baseline", current.TargetID))
		}
		evt := DriftEvent{
			ID:                 ComputeEventDeduplicationKey(rep.TargetID, ClassificationBaselineMissing, "*", "*", "initial_baseline"),
			TargetID:           rep.TargetID,
			CurrentSnapshotID:  rep.CurrentSnapshotID,
			Classification:     ClassificationBaselineMissing,
			CanonicalRoute:     "*",
			DetectedAt:         now,
			Priority:           PriorityInfo,
			PriorityRationale:  "Initial baseline established; zero drift events generated on initial run",
			Confidence:         "HIGH",
			IsComplete:         current != nil && current.IsComplete,
			SuggestedAction:    "Monitor future runs against this baseline for API surface changes.",
		}
		rep.Events = append(rep.Events, evt)
		rep.Summary[ClassificationBaselineMissing]++
		rep.TotalEvents = len(rep.Events)
		return rep
	}

	rep.BaselineSnapshotID = baseline.ID

	// 2. Schema compatibility check
	if current != nil && baseline.SchemaVersion != current.SchemaVersion {
		rep.IsCompatible = false
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("Baseline schema version (%d) is incompatible with current snapshot (%d)", baseline.SchemaVersion, current.SchemaVersion))
		evt := DriftEvent{
			ID:                 ComputeEventDeduplicationKey(rep.TargetID, ClassificationBaselineIncompatible, "*", "*", "schema_mismatch"),
			TargetID:           rep.TargetID,
			BaselineSnapshotID: rep.BaselineSnapshotID,
			CurrentSnapshotID:  rep.CurrentSnapshotID,
			Classification:     ClassificationBaselineIncompatible,
			CanonicalRoute:     "*",
			PreviousValue:      fmt.Sprintf("schema_v%d", baseline.SchemaVersion),
			CurrentValue:       fmt.Sprintf("schema_v%d", current.SchemaVersion),
			DetectedAt:         now,
			Priority:           PriorityHigh,
			PriorityRationale:  "Incompatible snapshot schemas prevent accurate structural comparison",
			Confidence:         "HIGH",
			IsComplete:         false,
			SuggestedAction:    "Reset baseline using 'felix monitor baseline --reset' to adopt the new schema format.",
		}
		rep.Events = append(rep.Events, evt)
		rep.Summary[ClassificationBaselineIncompatible]++
		rep.TotalEvents = len(rep.Events)
		return rep
	}

	if current == nil {
		rep.Warnings = append(rep.Warnings, "Current snapshot is nil; comparison aborted")
		return rep
	}

	// 3. Completeness warning
	if !current.IsComplete || current.Truncated {
		rep.Warnings = append(rep.Warnings, "Current scan is incomplete or truncated; route removal detections are strictly suppressed to avoid false alarms")
		evt := DriftEvent{
			ID:                 ComputeEventDeduplicationKey(rep.TargetID, ClassificationSnapshotIncomplete, "*", "*", "scan_incomplete"),
			TargetID:           rep.TargetID,
			BaselineSnapshotID: rep.BaselineSnapshotID,
			CurrentSnapshotID:  rep.CurrentSnapshotID,
			Classification:     ClassificationSnapshotIncomplete,
			CanonicalRoute:     "*",
			DetectedAt:         now,
			Priority:           PriorityMedium,
			PriorityRationale:  "Scan terminated early or reached bounds; temporal completeness compromised",
			Confidence:         "MEDIUM",
			IsComplete:         false,
			SuggestedAction:    "Investigate scan timeouts or collection limits and rerun discovery.",
		}
		rep.Events = append(rep.Events, evt)
		rep.Summary[ClassificationSnapshotIncomplete]++
	}

	// Index baseline routes by identity key
	baseMap := make(map[string]SurfaceRoute)
	for _, r := range baseline.Routes {
		baseMap[r.IdentityKey()] = r
	}

	// Index current routes by identity key
	currMap := make(map[string]SurfaceRoute)
	for _, r := range current.Routes {
		currMap[r.IdentityKey()] = r
	}

	// 4. Evaluate routes present in current snapshot
	for key, currRoute := range currMap {
		baseRoute, existsInBaseline := baseMap[key]

		if !existsInBaseline {
			// Newly observed route
			methodStr := strings.Join(currRoute.Methods, ",")
			if methodStr == "" {
				methodStr = "UNKNOWN"
			}

			priority := PriorityMedium
			rationale := "Newly discovered API endpoint not present in baseline"

			if currRoute.HasSensitiveIdentifiers() {
				priority = PriorityCritical
				rationale = fmt.Sprintf("Newly discovered undocumented endpoint with sensitive parameter boundaries (%s)", strings.Join(currRoute.SensitiveIdentifiers, ", "))
			} else if hasMutatingMethod(currRoute.Methods) || currRoute.Reachability == ReachabilityConfirmed {
				priority = PriorityHigh
				rationale = "Newly discovered undocumented endpoint with mutating capability or verified live reachability"
			}

			evt := DriftEvent{
				ID:                   ComputeEventDeduplicationKey(rep.TargetID, ClassificationNewShadowRoute, currRoute.CanonicalPath, methodStr, "new"),
				TargetID:             rep.TargetID,
				BaselineSnapshotID:   rep.BaselineSnapshotID,
				CurrentSnapshotID:    rep.CurrentSnapshotID,
				Classification:       ClassificationNewShadowRoute,
				CanonicalRoute:       currRoute.CanonicalPath,
				Method:               methodStr,
				PreviousValue:        "[ABSENT_IN_BASELINE]",
				CurrentValue:         fmt.Sprintf("methods=%s doc=%s reach=%s", methodStr, currRoute.DocumentationStatus, currRoute.Reachability),
				SensitiveIdentifiers: currRoute.SensitiveIdentifiers,
				Provenance:           currRoute.OriginatingAsset,
				DetectedAt:           now,
				Priority:             priority,
				PriorityRationale:    rationale,
				Confidence:           currRoute.DiscoveryConfidence,
				IsComplete:           current.IsComplete,
				SuggestedAction:      "Verify whether route is authorized, whether it enforces authentication, and document in API specification.",
			}
			if evt.Confidence == "" {
				evt.Confidence = "HIGH"
			}
			rep.Events = append(rep.Events, evt)
			rep.Summary[ClassificationNewShadowRoute]++
			continue
		}

		// Route exists in both: compare properties
		compareExistingRoute(rep, baseRoute, currRoute, now, current.IsComplete)
	}

	// 5. Evaluate route removals (STRICTLY SUPPRESSED if current scan is incomplete)
	if current.IsComplete && !current.Truncated {
		for key, baseRoute := range baseMap {
			if _, existsInCurrent := currMap[key]; !existsInCurrent {
				methodStr := strings.Join(baseRoute.Methods, ",")
				evt := DriftEvent{
					ID:                 ComputeEventDeduplicationKey(rep.TargetID, ClassificationRemovedRoute, baseRoute.CanonicalPath, methodStr, "removed"),
					TargetID:           rep.TargetID,
					BaselineSnapshotID: rep.BaselineSnapshotID,
					CurrentSnapshotID:  rep.CurrentSnapshotID,
					Classification:     ClassificationRemovedRoute,
					CanonicalRoute:     baseRoute.CanonicalPath,
					Method:             methodStr,
					PreviousValue:      fmt.Sprintf("methods=%s doc=%s", methodStr, baseRoute.DocumentationStatus),
					CurrentValue:       "[REMOVED_OR_UNOBSERVED]",
					Provenance:         baseRoute.OriginatingAsset,
					DetectedAt:         now,
					Priority:           PriorityLow,
					PriorityRationale:  "Endpoint observed in baseline was not discovered in complete scan",
					Confidence:         "MEDIUM",
					IsComplete:         true,
					SuggestedAction:    "Confirm whether endpoint was intentionally deprecated or decommissioned.",
				}
				rep.Events = append(rep.Events, evt)
				rep.Summary[ClassificationRemovedRoute]++
			}
		}
	}

	// 6. Stably sort events deterministically
	sort.SliceStable(rep.Events, func(i, j int) bool {
		pi := PriorityRank(rep.Events[i].Priority)
		pj := PriorityRank(rep.Events[j].Priority)
		if pi != pj {
			return pi > pj // Higher priority first
		}
		if rep.Events[i].CanonicalRoute != rep.Events[j].CanonicalRoute {
			return rep.Events[i].CanonicalRoute < rep.Events[j].CanonicalRoute
		}
		return rep.Events[i].Classification < rep.Events[j].Classification
	})

	rep.TotalEvents = len(rep.Events)
	return rep
}

// compareExistingRoute inspects changes in methods, parameters, sensitivity, doc status, and reachability.
func compareExistingRoute(rep *DriftReport, base, curr SurfaceRoute, now time.Time, isComplete bool) {
	route := curr.CanonicalPath

	// A. Method changes
	baseMethods := formatSortedMethods(base.Methods)
	currMethods := formatSortedMethods(curr.Methods)
	if baseMethods != currMethods {
		priority := PriorityMedium
		rationale := fmt.Sprintf("Supported HTTP methods changed from [%s] to [%s]", baseMethods, currMethods)
		if hasMutatingMethod(curr.Methods) && !hasMutatingMethod(base.Methods) {
			priority = PriorityHigh
			rationale = fmt.Sprintf("Mutating HTTP method added to endpoint: previously [%s], now [%s]", baseMethods, currMethods)
		}
		evt := DriftEvent{
			ID:                 ComputeEventDeduplicationKey(rep.TargetID, ClassificationMethodChange, route, currMethods, baseMethods),
			TargetID:           rep.TargetID,
			BaselineSnapshotID: rep.BaselineSnapshotID,
			CurrentSnapshotID:  rep.CurrentSnapshotID,
			Classification:     ClassificationMethodChange,
			CanonicalRoute:     route,
			Method:             currMethods,
			PreviousValue:      baseMethods,
			CurrentValue:       currMethods,
			DetectedAt:         now,
			Priority:           priority,
			PriorityRationale:  rationale,
			Confidence:         "HIGH",
			IsComplete:         isComplete,
			SuggestedAction:    "Verify that new methods are properly guarded by authorization handlers.",
		}
		rep.Events = append(rep.Events, evt)
		rep.Summary[ClassificationMethodChange]++
	}

	// B. Parameter shape changes
	baseParams := strings.Join(base.ParameterShapes, ",")
	currParams := strings.Join(curr.ParameterShapes, ",")
	if baseParams != currParams {
		evt := DriftEvent{
			ID:                 ComputeEventDeduplicationKey(rep.TargetID, ClassificationParameterShapeChange, route, currMethods, currParams),
			TargetID:           rep.TargetID,
			BaselineSnapshotID: rep.BaselineSnapshotID,
			CurrentSnapshotID:  rep.CurrentSnapshotID,
			Classification:     ClassificationParameterShapeChange,
			CanonicalRoute:     route,
			Method:             currMethods,
			PreviousValue:      baseParams,
			CurrentValue:       currParams,
			DetectedAt:         now,
			Priority:           PriorityMedium,
			PriorityRationale:  "Endpoint parameter schema changed between scans",
			Confidence:         "HIGH",
			IsComplete:         isComplete,
			SuggestedAction:    "Review updated parameter schema for injection or mass-assignment risks.",
		}
		rep.Events = append(rep.Events, evt)
		rep.Summary[ClassificationParameterShapeChange]++
	}

	// C. Sensitive identifier changes
	baseSens := strings.Join(base.SensitiveIdentifiers, ",")
	currSens := strings.Join(curr.SensitiveIdentifiers, ",")
	if baseSens != currSens {
		priority := PriorityHigh
		rationale := fmt.Sprintf("Sensitive identifier boundary changed: previously [%s], now [%s]", baseSens, currSens)
		if len(curr.SensitiveIdentifiers) > len(base.SensitiveIdentifiers) {
			priority = PriorityCritical
			rationale = fmt.Sprintf("New sensitive identifier observed in endpoint parameters: [%s]", currSens)
		}
		evt := DriftEvent{
			ID:                   ComputeEventDeduplicationKey(rep.TargetID, ClassificationSensitiveIdentifierChange, route, currMethods, currSens),
			TargetID:             rep.TargetID,
			BaselineSnapshotID:   rep.BaselineSnapshotID,
			CurrentSnapshotID:    rep.CurrentSnapshotID,
			Classification:       ClassificationSensitiveIdentifierChange,
			CanonicalRoute:       route,
			Method:               currMethods,
			PreviousValue:        baseSens,
			CurrentValue:         currSens,
			SensitiveIdentifiers: curr.SensitiveIdentifiers,
			DetectedAt:           now,
			Priority:             priority,
			PriorityRationale:    rationale,
			Confidence:           "HIGH",
			IsComplete:           isComplete,
			SuggestedAction:      "Audit object-level authorization (BOLA) rules for newly exposed sensitive identifiers.",
		}
		rep.Events = append(rep.Events, evt)
		rep.Summary[ClassificationSensitiveIdentifierChange]++
	}

	// D. Documentation status change
	if base.DocumentationStatus != curr.DocumentationStatus && curr.DocumentationStatus != "" {
		priority := PriorityInfo
		rationale := fmt.Sprintf("Documentation classification changed from %s to %s", base.DocumentationStatus, curr.DocumentationStatus)
		if curr.DocumentationStatus == DocStatusUndocumented && base.DocumentationStatus == DocStatusDocumented {
			priority = PriorityHigh
			rationale = "Previously documented endpoint is no longer declared in updated specification"
		}
		evt := DriftEvent{
			ID:                 ComputeEventDeduplicationKey(rep.TargetID, ClassificationDocumentationStatusChange, route, currMethods, curr.DocumentationStatus),
			TargetID:           rep.TargetID,
			BaselineSnapshotID: rep.BaselineSnapshotID,
			CurrentSnapshotID:  rep.CurrentSnapshotID,
			Classification:     ClassificationDocumentationStatusChange,
			CanonicalRoute:     route,
			Method:             currMethods,
			PreviousValue:      base.DocumentationStatus,
			CurrentValue:       curr.DocumentationStatus,
			DetectedAt:         now,
			Priority:           priority,
			PriorityRationale:  rationale,
			Confidence:         "HIGH",
			IsComplete:         isComplete,
			SuggestedAction:    "Reconcile updated API specification against active routing tables.",
		}
		rep.Events = append(rep.Events, evt)
		rep.Summary[ClassificationDocumentationStatusChange]++
	}

	// E. Reachability change
	if base.Reachability != curr.Reachability && curr.Reachability != "" && base.Reachability != "" {
		evt := DriftEvent{
			ID:                 ComputeEventDeduplicationKey(rep.TargetID, ClassificationReachabilityChange, route, currMethods, curr.Reachability),
			TargetID:           rep.TargetID,
			BaselineSnapshotID: rep.BaselineSnapshotID,
			CurrentSnapshotID:  rep.CurrentSnapshotID,
			Classification:     ClassificationReachabilityChange,
			CanonicalRoute:     route,
			Method:             currMethods,
			PreviousValue:      base.Reachability,
			CurrentValue:       curr.Reachability,
			DetectedAt:         now,
			Priority:           PriorityMedium,
			PriorityRationale:  fmt.Sprintf("Empirical network reachability shifted from %s to %s", base.Reachability, curr.Reachability),
			Confidence:         "HIGH",
			IsComplete:         isComplete,
			SuggestedAction:    "Inspect gateway routing and firewall rules for route exposure shifts.",
		}
		rep.Events = append(rep.Events, evt)
		rep.Summary[ClassificationReachabilityChange]++
	}

	// F. Probe classification change (e.g. 401 to 200)
	if base.ProbeStatus != curr.ProbeStatus && curr.ProbeStatus != "" && base.ProbeStatus != "" {
		priority := PriorityMedium
		rationale := fmt.Sprintf("Live probe behavior transitioned from %s to %s", base.ProbeStatus, curr.ProbeStatus)

		if strings.Contains(base.ProbeStatus, "AUTHENTICATION") && strings.Contains(curr.ProbeStatus, "REACHABLE") {
			priority = PriorityHigh
			rationale = "Previously authentication-enforced route responded reachable without challenge; warrants access-control investigation (does not prove exploitability)"
		}

		evt := DriftEvent{
			ID:                 ComputeEventDeduplicationKey(rep.TargetID, ClassificationProbeClassificationChange, route, currMethods, curr.ProbeStatus),
			TargetID:           rep.TargetID,
			BaselineSnapshotID: rep.BaselineSnapshotID,
			CurrentSnapshotID:  rep.CurrentSnapshotID,
			Classification:     ClassificationProbeClassificationChange,
			CanonicalRoute:     route,
			Method:             currMethods,
			PreviousValue:      base.ProbeStatus,
			CurrentValue:       curr.ProbeStatus,
			DetectedAt:         now,
			Priority:           priority,
			PriorityRationale:  rationale,
			Confidence:         "MEDIUM",
			IsComplete:         isComplete,
			SuggestedAction:    "Perform controlled manual verification to evaluate authorization middleware enforcement.",
		}
		rep.Events = append(rep.Events, evt)
		rep.Summary[ClassificationProbeClassificationChange]++
	}

	// G. Evidence confidence change
	if base.DiscoveryConfidence != curr.DiscoveryConfidence && curr.DiscoveryConfidence != "" && base.DiscoveryConfidence != "" {
		evt := DriftEvent{
			ID:                 ComputeEventDeduplicationKey(rep.TargetID, ClassificationEvidenceConfidenceChange, route, currMethods, curr.DiscoveryConfidence),
			TargetID:           rep.TargetID,
			BaselineSnapshotID: rep.BaselineSnapshotID,
			CurrentSnapshotID:  rep.CurrentSnapshotID,
			Classification:     ClassificationEvidenceConfidenceChange,
			CanonicalRoute:     route,
			Method:             currMethods,
			PreviousValue:      base.DiscoveryConfidence,
			CurrentValue:       curr.DiscoveryConfidence,
			DetectedAt:         now,
			Priority:           PriorityInfo,
			PriorityRationale:  fmt.Sprintf("Evidence extraction confidence shifted from %s to %s", base.DiscoveryConfidence, curr.DiscoveryConfidence),
			Confidence:         curr.DiscoveryConfidence,
			IsComplete:         isComplete,
			SuggestedAction:    "Review source bundle analysis for clearer route confirmation.",
		}
		rep.Events = append(rep.Events, evt)
		rep.Summary[ClassificationEvidenceConfidenceChange]++
	}
}

func hasMutatingMethod(methods []string) bool {
	for _, m := range methods {
		u := strings.ToUpper(strings.TrimSpace(m))
		if u == "POST" || u == "PUT" || u == "DELETE" || u == "PATCH" {
			return true
		}
	}
	return false
}

func formatSortedMethods(methods []string) string {
	var clean []string
	seen := make(map[string]bool)
	for _, m := range methods {
		u := strings.ToUpper(strings.TrimSpace(m))
		if u != "" && !seen[u] {
			clean = append(clean, u)
			seen[u] = true
		}
	}
	sort.Strings(clean)
	return strings.Join(clean, ",")
}
