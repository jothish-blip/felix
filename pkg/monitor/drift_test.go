package monitor

import (
	"fmt"
	"testing"
	"time"
)

func newSnapshotWithRoutes(targetID string, isComplete bool, routes ...SurfaceRoute) *Snapshot {
	return &Snapshot{
		ID:            fmt.Sprintf("snap_%d", time.Now().UnixNano()),
		SchemaVersion: CurrentSnapshotSchemaVersion,
		TargetID:      targetID,
		CollectedAt:   time.Now().UTC(),
		IsComplete:    isComplete,
		Routes:        routes,
	}
}

// 11. New Undocumented Route: Detects newly observed shadow route and applies sensitive boundary priority
func TestDriftComparator_NewUndocumentedRoute(t *testing.T) {
	targetID := "tenant-alpha"

	baseRoute := SurfaceRoute{
		CanonicalPath:       "/api/v1/health",
		Methods:             []string{"GET"},
		DocumentationStatus: DocStatusDocumented,
		Reachability:        ReachabilityConfirmed,
	}
	baseline := newSnapshotWithRoutes(targetID, true, baseRoute)

	// Current snapshot introduces a new undocumented route with tenant_id parameter
	shadowRoute := SurfaceRoute{
		CanonicalPath:        "/api/v1/tenants/{tenant_id}/export",
		RawPath:              "/api/v1/tenants/alpha/export",
		Methods:              []string{"POST"},
		DocumentationStatus:  DocStatusUndocumented,
		SensitiveIdentifiers: []string{"TENANT_ID"},
		Reachability:         ReachabilityConfirmed,
		DiscoveryConfidence:  "CONFIRMED",
	}
	current := newSnapshotWithRoutes(targetID, true, baseRoute, shadowRoute)

	rep := CompareSnapshots(baseline, current)
	if rep.TotalEvents != 1 {
		t.Fatalf("expected 1 drift event, got %d", rep.TotalEvents)
	}

	evt := rep.Events[0]
	if evt.Classification != ClassificationNewShadowRoute {
		t.Errorf("expected NEW_SHADOW_ROUTE, got %s", evt.Classification)
	}
	// Route has TENANT_ID and POST -> Priority CRITICAL
	if evt.Priority != PriorityCritical {
		t.Errorf("expected CRITICAL priority for shadow route with sensitive identifier, got %s", evt.Priority)
	}
	if len(evt.SensitiveIdentifiers) != 1 || evt.SensitiveIdentifiers[0] != "TENANT_ID" {
		t.Errorf("expected sensitive identifier TENANT_ID, got %v", evt.SensitiveIdentifiers)
	}
}

// 12. Removed Route: Observed when complete scan no longer discovers a baseline route
func TestDriftComparator_RemovedRouteCompleteOnly(t *testing.T) {
	targetID := "tenant-beta"

	r1 := SurfaceRoute{CanonicalPath: "/api/v1/active", Methods: []string{"GET"}}
	r2 := SurfaceRoute{CanonicalPath: "/api/v1/deprecated", Methods: []string{"GET"}}

	baseline := newSnapshotWithRoutes(targetID, true, r1, r2)
	current := newSnapshotWithRoutes(targetID, true, r1) // r2 missing in complete scan

	rep := CompareSnapshots(baseline, current)
	if rep.TotalEvents != 1 {
		t.Fatalf("expected 1 drift event, got %d", rep.TotalEvents)
	}

	evt := rep.Events[0]
	if evt.Classification != ClassificationRemovedRoute {
		t.Errorf("expected REMOVED_ROUTE, got %s", evt.Classification)
	}
	if evt.CanonicalRoute != "/api/v1/deprecated" {
		t.Errorf("expected removed route /api/v1/deprecated, got %s", evt.CanonicalRoute)
	}
}

// 13. Incomplete Scan Suppresses Removals: Incomplete scan must NOT generate false REMOVED_ROUTE events
func TestDriftComparator_IncompleteScanSuppressesRemovals(t *testing.T) {
	targetID := "tenant-gamma"

	r1 := SurfaceRoute{CanonicalPath: "/api/v1/users", Methods: []string{"GET"}}
	r2 := SurfaceRoute{CanonicalPath: "/api/v1/orders", Methods: []string{"GET"}}

	baseline := newSnapshotWithRoutes(targetID, true, r1, r2)

	// Current snapshot only observed r1, BUT IsComplete is FALSE (e.g. scan timed out)
	currentIncomplete := newSnapshotWithRoutes(targetID, false, r1)

	rep := CompareSnapshots(baseline, currentIncomplete)

	// Should record SNAPSHOT_INCOMPLETE warning event, but ZERO REMOVED_ROUTE events!
	if rep.Summary[ClassificationRemovedRoute] != 0 {
		t.Errorf("expected 0 REMOVED_ROUTE events on incomplete scan, got %d", rep.Summary[ClassificationRemovedRoute])
	}
	if rep.Summary[ClassificationSnapshotIncomplete] != 1 {
		t.Errorf("expected 1 SNAPSHOT_INCOMPLETE event, got %d", rep.Summary[ClassificationSnapshotIncomplete])
	}
}

// 14. Method Change: Detects added or removed HTTP methods on existing routes
func TestDriftComparator_MethodChange(t *testing.T) {
	targetID := "tenant-delta"

	baseRoute := SurfaceRoute{
		CanonicalPath: "/api/v1/documents/{id}",
		Methods:       []string{"GET"},
	}
	baseline := newSnapshotWithRoutes(targetID, true, baseRoute)

	// Route now supports POST and DELETE as well
	currRoute := SurfaceRoute{
		CanonicalPath: "/api/v1/documents/{id}",
		Methods:       []string{"DELETE", "GET", "POST"},
	}
	current := newSnapshotWithRoutes(targetID, true, currRoute)

	rep := CompareSnapshots(baseline, current)
	if rep.TotalEvents != 1 {
		t.Fatalf("expected 1 drift event, got %d", rep.TotalEvents)
	}

	evt := rep.Events[0]
	if evt.Classification != ClassificationMethodChange {
		t.Errorf("expected METHOD_CHANGE, got %s", evt.Classification)
	}
	if evt.Priority != PriorityHigh {
		t.Errorf("expected HIGH priority for mutating method addition, got %s", evt.Priority)
	}
	if evt.PreviousValue != "GET" || evt.CurrentValue != "DELETE,GET,POST" {
		t.Errorf("unexpected method shift: %s -> %s", evt.PreviousValue, evt.CurrentValue)
	}
}

// 15. Parameter Shape Change: Detects additions or modifications in parameter schemas
func TestDriftComparator_ParameterShapeChange(t *testing.T) {
	targetID := "tenant-echo"

	baseRoute := SurfaceRoute{
		CanonicalPath:   "/api/v1/search",
		Methods:         []string{"GET"},
		ParameterShapes: []string{"q"},
	}
	baseline := newSnapshotWithRoutes(targetID, true, baseRoute)

	currRoute := SurfaceRoute{
		CanonicalPath:   "/api/v1/search",
		Methods:         []string{"GET"},
		ParameterShapes: []string{"filter", "limit", "q"},
	}
	current := newSnapshotWithRoutes(targetID, true, currRoute)

	rep := CompareSnapshots(baseline, current)
	if rep.TotalEvents != 1 {
		t.Fatalf("expected 1 drift event, got %d", rep.TotalEvents)
	}

	evt := rep.Events[0]
	if evt.Classification != ClassificationParameterShapeChange {
		t.Errorf("expected PARAMETER_SHAPE_CHANGE, got %s", evt.Classification)
	}
}

// 16. Sensitive Identifier Change: Detects addition of authorization-boundary parameters (USER_ID, ROLE, etc.)
func TestDriftComparator_SensitiveIdentifierChange(t *testing.T) {
	targetID := "tenant-foxtrot"

	baseRoute := SurfaceRoute{
		CanonicalPath:        "/api/v1/profile",
		Methods:              []string{"GET"},
		SensitiveIdentifiers: []string{},
	}
	baseline := newSnapshotWithRoutes(targetID, true, baseRoute)

	currRoute := SurfaceRoute{
		CanonicalPath:        "/api/v1/profile",
		Methods:              []string{"GET"},
		SensitiveIdentifiers: []string{"ROLE", "USER_ID"},
	}
	current := newSnapshotWithRoutes(targetID, true, currRoute)

	rep := CompareSnapshots(baseline, current)
	if rep.TotalEvents != 1 {
		t.Fatalf("expected 1 drift event, got %d", rep.TotalEvents)
	}

	evt := rep.Events[0]
	if evt.Classification != ClassificationSensitiveIdentifierChange {
		t.Errorf("expected SENSITIVE_IDENTIFIER_CHANGE, got %s", evt.Classification)
	}
	if evt.Priority != PriorityCritical {
		t.Errorf("expected CRITICAL priority for newly added sensitive parameters, got %s", evt.Priority)
	}
}

// 17. Documentation Status Transition: Detects route moving from documented to undocumented
func TestDriftComparator_DocumentationStatusChange(t *testing.T) {
	targetID := "tenant-golf"

	baseRoute := SurfaceRoute{
		CanonicalPath:       "/api/v1/billing",
		Methods:             []string{"GET"},
		DocumentationStatus: DocStatusDocumented,
	}
	baseline := newSnapshotWithRoutes(targetID, true, baseRoute)

	currRoute := SurfaceRoute{
		CanonicalPath:       "/api/v1/billing",
		Methods:             []string{"GET"},
		DocumentationStatus: DocStatusUndocumented,
	}
	current := newSnapshotWithRoutes(targetID, true, currRoute)

	rep := CompareSnapshots(baseline, current)
	if rep.TotalEvents != 1 {
		t.Fatalf("expected 1 drift event, got %d", rep.TotalEvents)
	}

	evt := rep.Events[0]
	if evt.Classification != ClassificationDocumentationStatusChange {
		t.Errorf("expected DOCUMENTATION_STATUS_CHANGE, got %s", evt.Classification)
	}
	if evt.Priority != PriorityHigh {
		t.Errorf("expected HIGH priority when documented endpoint is dropped from spec, got %s", evt.Priority)
	}
}

// 18. Reachability Transition: Detects live network reachability changes
func TestDriftComparator_ReachabilityChange(t *testing.T) {
	targetID := "tenant-hotel"

	baseRoute := SurfaceRoute{
		CanonicalPath: "/api/v1/internal",
		Methods:       []string{"GET"},
		Reachability:  ReachabilityUnconfirmed,
	}
	baseline := newSnapshotWithRoutes(targetID, true, baseRoute)

	currRoute := SurfaceRoute{
		CanonicalPath: "/api/v1/internal",
		Methods:       []string{"GET"},
		Reachability:  ReachabilityConfirmed,
	}
	current := newSnapshotWithRoutes(targetID, true, currRoute)

	rep := CompareSnapshots(baseline, current)
	if rep.TotalEvents != 1 {
		t.Fatalf("expected 1 drift event, got %d", rep.TotalEvents)
	}

	evt := rep.Events[0]
	if evt.Classification != ClassificationReachabilityChange {
		t.Errorf("expected REACHABILITY_CHANGE, got %s", evt.Classification)
	}
}

// 19. Probe Classification Change: 401 AUTHENTICATION_REQUIRED to 200 REACHABLE triggers investigation
func TestDriftComparator_ProbeClassificationChange(t *testing.T) {
	targetID := "tenant-india"

	baseRoute := SurfaceRoute{
		CanonicalPath: "/api/v1/admin/dashboard",
		Methods:       []string{"GET"},
		ProbeStatus:   "AUTHENTICATION_REQUIRED",
	}
	baseline := newSnapshotWithRoutes(targetID, true, baseRoute)

	currRoute := SurfaceRoute{
		CanonicalPath: "/api/v1/admin/dashboard",
		Methods:       []string{"GET"},
		ProbeStatus:   "REACHABLE",
	}
	current := newSnapshotWithRoutes(targetID, true, currRoute)

	rep := CompareSnapshots(baseline, current)
	if rep.TotalEvents != 1 {
		t.Fatalf("expected 1 drift event, got %d", rep.TotalEvents)
	}

	evt := rep.Events[0]
	if evt.Classification != ClassificationProbeClassificationChange {
		t.Errorf("expected PROBE_CLASSIFICATION_CHANGE, got %s", evt.Classification)
	}
	if evt.Priority != PriorityHigh {
		t.Errorf("expected HIGH priority for authentication drop, got %s", evt.Priority)
	}
}

// 20. Evidence Confidence Change: Detects elevation or degradation in extraction confidence
func TestDriftComparator_EvidenceConfidenceChange(t *testing.T) {
	targetID := "tenant-juliet"

	baseRoute := SurfaceRoute{
		CanonicalPath:       "/api/v1/metrics",
		Methods:             []string{"GET"},
		DiscoveryConfidence: "HEURISTIC",
	}
	baseline := newSnapshotWithRoutes(targetID, true, baseRoute)

	currRoute := SurfaceRoute{
		CanonicalPath:       "/api/v1/metrics",
		Methods:             []string{"GET"},
		DiscoveryConfidence: "CONFIRMED",
	}
	current := newSnapshotWithRoutes(targetID, true, currRoute)

	rep := CompareSnapshots(baseline, current)
	if rep.TotalEvents != 1 {
		t.Fatalf("expected 1 drift event, got %d", rep.TotalEvents)
	}

	evt := rep.Events[0]
	if evt.Classification != ClassificationEvidenceConfidenceChange {
		t.Errorf("expected EVIDENCE_CONFIDENCE_CHANGE, got %s", evt.Classification)
	}
}

// 21. Equivalent Routes Normalization & Distinct Versions:
// Normalizes case & trailing slash, while strictly distinguishing different API versions (/v1 vs /v2)
func TestDriftComparator_EquivalentRoutesAndDistinctVersions(t *testing.T) {
	targetID := "tenant-kilo"

	rV1 := SurfaceRoute{CanonicalPath: "/api/v1/users/{id}", Methods: []string{"GET"}}
	rV2 := SurfaceRoute{CanonicalPath: "/api/v2/users/{id}", Methods: []string{"GET"}}

	baseline := newSnapshotWithRoutes(targetID, true, rV1, rV2)

	// Current snapshot has identical v1 and v2, but with equivalent case/formatting
	rV1Equiv := SurfaceRoute{CanonicalPath: "/api/v1/users/{id}", Methods: []string{"GET"}}
	rV2Equiv := SurfaceRoute{CanonicalPath: "/api/v2/users/{id}", Methods: []string{"GET"}}

	current := newSnapshotWithRoutes(targetID, true, rV1Equiv, rV2Equiv)

	rep := CompareSnapshots(baseline, current)
	if rep.TotalEvents != 0 {
		t.Errorf("expected 0 drift events for equivalent routes, got %d: %+v", rep.TotalEvents, rep.Events)
	}
}

// 22. Determinism & Zero Drift on Identical Snapshots
func TestDriftComparator_IdenticalSnapshotsDeterministicZeroDrift(t *testing.T) {
	targetID := "tenant-lima"

	r1 := SurfaceRoute{CanonicalPath: "/api/v1/feed", Methods: []string{"GET"}, DocumentationStatus: DocStatusDocumented}
	r2 := SurfaceRoute{CanonicalPath: "/api/v1/status", Methods: []string{"GET"}, DocumentationStatus: DocStatusDocumented}

	snapA := newSnapshotWithRoutes(targetID, true, r1, r2)
	snapB := newSnapshotWithRoutes(targetID, true, r2, r1) // Permuted order

	rep := CompareSnapshots(snapA, snapB)
	if rep.TotalEvents != 0 {
		t.Errorf("expected zero drift for identical snapshot contents, got %d events", rep.TotalEvents)
	}
}
