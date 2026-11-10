package commercial

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"felix/pkg/assessment"
)

// DriftEventType categorizes the nature of observed attack surface change.
type DriftEventType string

const (
	DriftTypeNewRoute           DriftEventType = "NEW_ROUTE"
	DriftTypeRemovedRoute       DriftEventType = "REMOVED_ROUTE"
	DriftTypeNewQueryParam      DriftEventType = "NEW_QUERY_PARAM"
	DriftTypeCookieSecurity     DriftEventType = "COOKIE_SECURITY_DRIFT"
	DriftTypeAuthBoundary       DriftEventType = "AUTH_BOUNDARY_DRIFT"
	DriftTypeBOLABoundary       DriftEventType = "BOLA_BOUNDARY_DRIFT"
	DriftTypeNewFinding         DriftEventType = "NEW_FINDING"
	DriftTypeFindingStatusChange DriftEventType = "FINDING_STATUS_CHANGE"
	DriftTypeFindingResolved    DriftEventType = "FINDING_RESOLVED"
)

// RouteDetail captures normalized endpoint route metadata.
type RouteDetail struct {
	Method         string `json:"method"`
	Path           string `json:"path"`
	Classification string `json:"classification,omitempty"`
	Authenticated  bool   `json:"authenticated"`
}

// CookieDetail captures security flags for a session or application cookie.
type CookieDetail struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	SameSite string `json:"same_site,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Path     string `json:"path,omitempty"`
}

// AuthBoundaryDetail represents authentication requirement for an endpoint.
type AuthBoundaryDetail struct {
	Route        string   `json:"route"`
	RequiresAuth bool     `json:"requires_auth"`
	AllowedRoles []string `json:"allowed_roles,omitempty"`
}

// BOLABoundaryDetail represents object reference or authorization parameter boundaries.
type BOLABoundaryDetail struct {
	Route         string   `json:"route"`
	IDParameters  []string `json:"id_parameters"`
	ResourceTypes []string `json:"resource_types,omitempty"`
}

// FindingSnapshot represents finding state captured at assessment completion.
type FindingSnapshot struct {
	ID                 string                           `json:"id"`
	Fingerprint        string                           `json:"fingerprint"`
	Title              string                           `json:"title"`
	Severity           string                           `json:"severity"`
	Category           string                           `json:"category"`
	TargetURL          string                           `json:"target_url"`
	Status             string                           `json:"status"` // VERIFIED_DEFECT, POTENTIAL, UNVERIFIED, CONFIRMED
	VerificationStatus string                           `json:"verification_status,omitempty"`
	SignedEvidence     *assessment.SignedEvidenceRecord `json:"signed_evidence,omitempty"`
	AttestationLetter  *assessment.AttestationLetter    `json:"attestation_letter,omitempty"`
}

// AttackSurfaceSnapshot encapsulates the entire state of an audited target application.
type AttackSurfaceSnapshot struct {
	AssessmentID   string                         `json:"assessment_id"`
	ClientID       string                         `json:"client_id"`
	Timestamp      time.Time                      `json:"timestamp"`
	Routes         map[string]RouteDetail         `json:"routes"`          // Key: "METHOD:PATH"
	QueryParams    map[string][]string            `json:"query_params"`   // Key: "METHOD:PATH" -> list of param names
	Cookies        map[string]CookieDetail        `json:"cookies"`         // Key: cookie name
	AuthBoundaries map[string]AuthBoundaryDetail  `json:"auth_boundaries"` // Key: "METHOD:PATH"
	BOLABoundaries map[string]BOLABoundaryDetail  `json:"bola_boundaries"` // Key: "METHOD:PATH"
	Findings       map[string]FindingSnapshot     `json:"findings"`        // Key: Fingerprint
}

// NewAttackSurfaceSnapshot constructs an initialized empty snapshot.
func NewAttackSurfaceSnapshot(assessmentID, clientID string, ts time.Time) *AttackSurfaceSnapshot {
	return &AttackSurfaceSnapshot{
		AssessmentID:   assessmentID,
		ClientID:       clientID,
		Timestamp:      ts,
		Routes:         make(map[string]RouteDetail),
		QueryParams:    make(map[string][]string),
		Cookies:        make(map[string]CookieDetail),
		AuthBoundaries: make(map[string]AuthBoundaryDetail),
		BOLABoundaries: make(map[string]BOLABoundaryDetail),
		Findings:       make(map[string]FindingSnapshot),
	}
}

// DriftEvent represents an immutable, structured record of attack surface or security posture change.
type DriftEvent struct {
	ID                string         `json:"id"`
	Type              DriftEventType `json:"type"`
	Severity          string         `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Entity            string         `json:"entity"`
	BeforeState       string         `json:"before_state,omitempty"`
	AfterState        string         `json:"after_state,omitempty"`
	Details           string         `json:"details"`
	EvidenceReference string         `json:"evidence_reference,omitempty"`
}

// DriftReport compiles all drift events discovered by comparing a baseline and current assessment.
type DriftReport struct {
	ID                        string       `json:"id"`
	ScheduleID                string       `json:"schedule_id"`
	BaselineAssessmentID      string       `json:"baseline_assessment_id"`
	CurrentAssessmentID       string       `json:"current_assessment_id"`
	CreatedAt                 time.Time    `json:"created_at"`
	SummaryHeadline           string       `json:"summary_headline"`
	TotalDriftEvents          int          `json:"total_drift_events"`
	NewRoutesCount            int          `json:"new_routes_count"`
	RemovedRoutesCount        int          `json:"removed_routes_count"`
	NewQueryParamsCount       int          `json:"new_query_params_count"`
	CookieDriftCount          int          `json:"cookie_drift_count"`
	AuthBoundaryDriftCount    int          `json:"auth_boundary_drift_count"`
	BOLABoundaryDriftCount    int          `json:"bola_boundary_drift_count"`
	NewFindingsCount          int          `json:"new_findings_count"`
	NewlyVerifiedDefectsCount int          `json:"newly_verified_defects_count"`
	ResolvedFindingsCount     int          `json:"resolved_findings_count"`
	DriftEvents               []DriftEvent `json:"drift_events"`
}

// DriftEngine performs deterministic differential comparison across attack surface snapshots.
type DriftEngine struct{}

// NewDriftEngine constructs an initialized DriftEngine.
func NewDriftEngine() *DriftEngine {
	return &DriftEngine{}
}

// Compare computes deterministic attack surface drift between baseline and current snapshots.
func (e *DriftEngine) Compare(scheduleID string, baseline, current *AttackSurfaceSnapshot) (*DriftReport, error) {
	if current == nil {
		return nil, fmt.Errorf("cpaas: current snapshot cannot be nil")
	}

	now := time.Now().UTC()
	reportID := fmt.Sprintf("drf_%s_%d", scheduleID, now.UnixNano())

	baseID := ""
	if baseline != nil {
		baseID = baseline.AssessmentID
	}

	report := &DriftReport{
		ID:                   reportID,
		ScheduleID:           scheduleID,
		BaselineAssessmentID: baseID,
		CurrentAssessmentID:  current.AssessmentID,
		CreatedAt:            now,
		DriftEvents:          make([]DriftEvent, 0),
	}

	// 1. Initial Assessment (No baseline exists yet)
	if baseline == nil {
		report.SummaryHeadline = fmt.Sprintf("Baseline assessment established with %d routes and %d findings", len(current.Routes), len(current.Findings))
		// For initial assessment, record new routes and findings
		for k, r := range current.Routes {
			report.DriftEvents = append(report.DriftEvents, DriftEvent{
				ID:          generateEventID(DriftTypeNewRoute, k),
				Type:        DriftTypeNewRoute,
				Severity:    "INFO",
				Entity:      fmt.Sprintf("%s %s", r.Method, r.Path),
				AfterState:  "DISCOVERED",
				Details:     fmt.Sprintf("Initial discovery of route %s %s", r.Method, r.Path),
			})
			report.NewRoutesCount++
		}
		for _, f := range current.Findings {
			isVerified := f.Status == "VERIFIED_DEFECT"
			sev := f.Severity
			if !isVerified && (sev == "CRITICAL" || sev == "HIGH") {
				sev = "MEDIUM" // unverified findings do not trigger high alerts
			}
			report.DriftEvents = append(report.DriftEvents, DriftEvent{
				ID:                generateEventID(DriftTypeNewFinding, f.Fingerprint),
				Type:              DriftTypeNewFinding,
				Severity:          sev,
				Entity:            f.Title,
				AfterState:        f.Status,
				Details:           fmt.Sprintf("Initial finding %q at %s (status: %s)", f.Title, f.TargetURL, f.Status),
				EvidenceReference: f.Fingerprint,
			})
			report.NewFindingsCount++
			if isVerified {
				report.NewlyVerifiedDefectsCount++
			}
		}

		sortDriftEvents(report.DriftEvents)
		report.TotalDriftEvents = len(report.DriftEvents)
		return report, nil
	}

	// 2. Route Drift (New & Removed Routes)
	for k, curRoute := range current.Routes {
		if _, exists := baseline.Routes[k]; !exists {
			report.DriftEvents = append(report.DriftEvents, DriftEvent{
				ID:          generateEventID(DriftTypeNewRoute, k),
				Type:        DriftTypeNewRoute,
				Severity:    "INFO",
				Entity:      fmt.Sprintf("%s %s", curRoute.Method, curRoute.Path),
				BeforeState: "NOT_PRESENT",
				AfterState:  "EXPOSED",
				Details:     fmt.Sprintf("Newly exposed route detected: %s %s", curRoute.Method, curRoute.Path),
			})
			report.NewRoutesCount++
		}
	}
	for k, baseRoute := range baseline.Routes {
		if _, exists := current.Routes[k]; !exists {
			report.DriftEvents = append(report.DriftEvents, DriftEvent{
				ID:          generateEventID(DriftTypeRemovedRoute, k),
				Type:        DriftTypeRemovedRoute,
				Severity:    "INFO",
				Entity:      fmt.Sprintf("%s %s", baseRoute.Method, baseRoute.Path),
				BeforeState: "EXPOSED",
				AfterState:  "REMOVED",
				Details:     fmt.Sprintf("Previously exposed route no longer reachable: %s %s", baseRoute.Method, baseRoute.Path),
			})
			report.RemovedRoutesCount++
		}
	}

	// 3. Query Parameter Drift
	for routeKey, curParams := range current.QueryParams {
		baseParams, exists := baseline.QueryParams[routeKey]
		baseSet := make(map[string]struct{})
		if exists {
			for _, p := range baseParams {
				baseSet[strings.ToLower(p)] = struct{}{}
			}
		}
		for _, p := range curParams {
			pClean := strings.ToLower(p)
			if _, ok := baseSet[pClean]; !ok {
				entity := fmt.Sprintf("%s?%s", routeKey, p)
				report.DriftEvents = append(report.DriftEvents, DriftEvent{
					ID:          generateEventID(DriftTypeNewQueryParam, entity),
					Type:        DriftTypeNewQueryParam,
					Severity:    "LOW",
					Entity:      entity,
					BeforeState: "PARAM_ABSENT",
					AfterState:  "PARAM_ACCEPTED",
					Details:     fmt.Sprintf("New query parameter %q accepted on route %s", p, routeKey),
				})
				report.NewQueryParamsCount++
			}
		}
	}

	// 4. Cookie Configuration Drift
	for name, curCookie := range current.Cookies {
		baseCookie, exists := baseline.Cookies[name]
		if !exists {
			report.DriftEvents = append(report.DriftEvents, DriftEvent{
				ID:          generateEventID(DriftTypeCookieSecurity, name),
				Type:        DriftTypeCookieSecurity,
				Severity:    "INFO",
				Entity:      name,
				BeforeState: "ABSENT",
				AfterState:  fmt.Sprintf("HttpOnly=%v,Secure=%v,SameSite=%s", curCookie.HttpOnly, curCookie.Secure, curCookie.SameSite),
				Details:     fmt.Sprintf("New cookie observed: %s", name),
			})
			report.CookieDriftCount++
			continue
		}

		// Security degradation checks
		degraded := false
		var degradations []string
		if baseCookie.HttpOnly && !curCookie.HttpOnly {
			degraded = true
			degradations = append(degradations, "HttpOnly flag removed")
		}
		if baseCookie.Secure && !curCookie.Secure {
			degraded = true
			degradations = append(degradations, "Secure flag removed")
		}
		if degraded {
			report.DriftEvents = append(report.DriftEvents, DriftEvent{
				ID:          generateEventID(DriftTypeCookieSecurity, name+"_degraded"),
				Type:        DriftTypeCookieSecurity,
				Severity:    "MEDIUM",
				Entity:      name,
				BeforeState: fmt.Sprintf("HttpOnly=%v,Secure=%v", baseCookie.HttpOnly, baseCookie.Secure),
				AfterState:  fmt.Sprintf("HttpOnly=%v,Secure=%v", curCookie.HttpOnly, curCookie.Secure),
				Details:     fmt.Sprintf("Cookie security posture degraded on %s: %s", name, strings.Join(degradations, ", ")),
			})
			report.CookieDriftCount++
		}
	}

	// 5. Authentication Boundary Drift
	for routeKey, curAuth := range current.AuthBoundaries {
		baseAuth, exists := baseline.AuthBoundaries[routeKey]
		if exists && baseAuth.RequiresAuth && !curAuth.RequiresAuth {
			// CRITICAL/HIGH: An endpoint that required authentication is now public!
			report.DriftEvents = append(report.DriftEvents, DriftEvent{
				ID:          generateEventID(DriftTypeAuthBoundary, routeKey),
				Type:        DriftTypeAuthBoundary,
				Severity:    "HIGH",
				Entity:      routeKey,
				BeforeState: "AUTHENTICATED",
				AfterState:  "UNAUTHENTICATED",
				Details:     fmt.Sprintf("Authentication boundary dropped on route %s: previously required auth, now publicly accessible", routeKey),
			})
			report.AuthBoundaryDriftCount++
		}
	}

	// 6. BOLA / IDOR Boundary Drift
	for routeKey, curBOLA := range current.BOLABoundaries {
		baseBOLA, exists := baseline.BOLABoundaries[routeKey]
		baseIDSet := make(map[string]struct{})
		if exists {
			for _, idp := range baseBOLA.IDParameters {
				baseIDSet[strings.ToLower(idp)] = struct{}{}
			}
		}
		for _, curIDP := range curBOLA.IDParameters {
			if _, ok := baseIDSet[strings.ToLower(curIDP)]; !ok {
				entity := fmt.Sprintf("%s:%s", routeKey, curIDP)
				report.DriftEvents = append(report.DriftEvents, DriftEvent{
					ID:          generateEventID(DriftTypeBOLABoundary, entity),
					Type:        DriftTypeBOLABoundary,
					Severity:    "HIGH",
					Entity:      entity,
					BeforeState: "NO_OBJECT_ID",
					AfterState:  fmt.Sprintf("OBJECT_ID_EXPOSED(%s)", curIDP),
					Details:     fmt.Sprintf("New object identifier parameter %q exposed on %s (potential BOLA boundary change)", curIDP, routeKey),
				})
				report.BOLABoundaryDriftCount++
			}
		}
	}

	// 7. Finding Drift & Status Changes
	for fp, curFinding := range current.Findings {
		baseFinding, exists := baseline.Findings[fp]
		if !exists {
			// Newly discovered finding
			isVerified := curFinding.Status == "VERIFIED_DEFECT"
			sev := curFinding.Severity
			report.DriftEvents = append(report.DriftEvents, DriftEvent{
				ID:                generateEventID(DriftTypeNewFinding, fp),
				Type:              DriftTypeNewFinding,
				Severity:          sev,
				Entity:            curFinding.Title,
				BeforeState:       "NOT_PRESENT",
				AfterState:        curFinding.Status,
				Details:           fmt.Sprintf("New finding identified: %s at %s (severity: %s, status: %s)", curFinding.Title, curFinding.TargetURL, curFinding.Severity, curFinding.Status),
				EvidenceReference: fp,
			})
			report.NewFindingsCount++
			if isVerified {
				report.NewlyVerifiedDefectsCount++
			}
		} else if baseFinding.Status != curFinding.Status {
			// Status transition occurred
			isVerifiedNow := curFinding.Status == "VERIFIED_DEFECT"
			wasVerified := baseFinding.Status == "VERIFIED_DEFECT"

			sev := curFinding.Severity
			if isVerifiedNow && !wasVerified {
				sev = "HIGH"
			}

			report.DriftEvents = append(report.DriftEvents, DriftEvent{
				ID:                generateEventID(DriftTypeFindingStatusChange, fp),
				Type:              DriftTypeFindingStatusChange,
				Severity:          sev,
				Entity:            curFinding.Title,
				BeforeState:       baseFinding.Status,
				AfterState:        curFinding.Status,
				Details:           fmt.Sprintf("Finding status transitioned from %s to %s: %s", baseFinding.Status, curFinding.Status, curFinding.Title),
				EvidenceReference: fp,
			})
			if isVerifiedNow && !wasVerified {
				report.NewlyVerifiedDefectsCount++
			}
		}
	}

	// 8. Resolved Findings (Present in baseline, missing in current or status remediated)
	for fp, baseFinding := range baseline.Findings {
		curFinding, exists := current.Findings[fp]
		if !exists || curFinding.Status == "REMEDIATED_VERIFIED" || curFinding.Status == "RESOLVED" {
			report.DriftEvents = append(report.DriftEvents, DriftEvent{
				ID:                generateEventID(DriftTypeFindingResolved, fp),
				Type:              DriftTypeFindingResolved,
				Severity:          "INFO",
				Entity:            baseFinding.Title,
				BeforeState:       baseFinding.Status,
				AfterState:        "RESOLVED",
				Details:           fmt.Sprintf("Finding resolved or no longer detected: %s", baseFinding.Title),
				EvidenceReference: fp,
			})
			report.ResolvedFindingsCount++
		}
	}

	// Sort events deterministically
	sortDriftEvents(report.DriftEvents)
	report.TotalDriftEvents = len(report.DriftEvents)

	headlineParts := []string{}
	if report.NewRoutesCount > 0 {
		headlineParts = append(headlineParts, fmt.Sprintf("+%d routes", report.NewRoutesCount))
	}
	if report.RemovedRoutesCount > 0 {
		headlineParts = append(headlineParts, fmt.Sprintf("-%d routes", report.RemovedRoutesCount))
	}
	if report.NewQueryParamsCount > 0 {
		headlineParts = append(headlineParts, fmt.Sprintf("+%d query params", report.NewQueryParamsCount))
	}
	if report.CookieDriftCount > 0 {
		headlineParts = append(headlineParts, fmt.Sprintf("%d cookie changes", report.CookieDriftCount))
	}
	if report.AuthBoundaryDriftCount > 0 {
		headlineParts = append(headlineParts, fmt.Sprintf("%d auth boundary shifts", report.AuthBoundaryDriftCount))
	}
	if report.BOLABoundaryDriftCount > 0 {
		headlineParts = append(headlineParts, fmt.Sprintf("%d BOLA boundary shifts", report.BOLABoundaryDriftCount))
	}
	if report.NewlyVerifiedDefectsCount > 0 {
		headlineParts = append(headlineParts, fmt.Sprintf("CRITICAL: %d new VERIFIED_DEFECT findings", report.NewlyVerifiedDefectsCount))
	}

	if len(headlineParts) == 0 {
		report.SummaryHeadline = "Attack surface baseline stable; zero drift detected"
	} else {
		report.SummaryHeadline = fmt.Sprintf("Attack Surface Drift Detected: %s", strings.Join(headlineParts, ", "))
	}

	return report, nil
}

func generateEventID(typ DriftEventType, entity string) string {
	raw := fmt.Sprintf("%s:%s", typ, strings.ToLower(strings.TrimSpace(entity)))
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("devt_%s", hex.EncodeToString(h[:8]))
}

func sortDriftEvents(events []DriftEvent) {
	sort.Slice(events, func(i, j int) bool {
		if events[i].Type != events[j].Type {
			return events[i].Type < events[j].Type
		}
		if events[i].Severity != events[j].Severity {
			return events[i].Severity < events[j].Severity
		}
		return events[i].Entity < events[j].Entity
	})
}
