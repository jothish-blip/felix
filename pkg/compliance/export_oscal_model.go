package compliance

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// CurrentOSCALVersion defines the authoritative NIST OSCAL specification version supported.
const CurrentOSCALVersion = "1.1.0"

// OSCALProperty represents an OSCAL name/value pair with optional namespace and class.
type OSCALProperty struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Ns      string `json:"ns,omitempty"`
	Class   string `json:"class,omitempty"`
	Remarks string `json:"remarks,omitempty"`
}

// OSCALLink represents an external link or URI reference in OSCAL.
type OSCALLink struct {
	Href      string `json:"href"`
	Rel       string `json:"rel,omitempty"`
	MediaType string `json:"media-type,omitempty"`
	Text      string `json:"text,omitempty"`
}

// OSCALRole defines a participant or system role in an OSCAL document.
type OSCALRole struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
}

// OSCALParty defines an organization or person party in an OSCAL document.
type OSCALParty struct {
	UUID      string `json:"uuid"`
	Type      string `json:"type"` // "organization" or "person" per NIST OSCAL v1.1.0 schema
	Name      string `json:"name"`
	ShortName string `json:"short-name,omitempty"`
}

// OSCALMetadata represents the standard header section for all OSCAL models.
type OSCALMetadata struct {
	Title        string          `json:"title"`
	Published    time.Time       `json:"published"`
	LastModified time.Time       `json:"last-modified"`
	Version      string          `json:"version"`
	OSCALVersion string          `json:"oscal-version"`
	Roles        []OSCALRole     `json:"roles,omitempty"`
	Parties      []OSCALParty    `json:"parties,omitempty"`
	Props        []OSCALProperty `json:"props,omitempty"`
	Links        []OSCALLink     `json:"links,omitempty"`
	Remarks      string          `json:"remarks,omitempty"`
}

// OSCALImportAssessmentPlan references the assessment plan or catalog driving the assessment.
type OSCALImportAssessmentPlan struct {
	Href    string `json:"href"`
	Remarks string `json:"remarks,omitempty"`
}

// OSCALControlSelection represents controls selected for evaluation.
type OSCALControlSelection struct {
	IncludeControls []OSCALControlRef `json:"include-controls,omitempty"`
	IncludeAll      *struct{}         `json:"include-all,omitempty"`
}

// OSCALControlRef identifies a specific control in reviewed controls.
type OSCALControlRef struct {
	ControlID string `json:"control-id"`
}

// OSCALSelectObjective specifies an objective identifier within an objective selection.
type OSCALSelectObjective struct {
	ObjectiveID string `json:"objective-id"`
}

// OSCALControlObjectiveSelection captures the evaluation outcome for a specific control requirement or objective.
type OSCALControlObjectiveSelection struct {
	Description       string                 `json:"description,omitempty"`
	Props             []OSCALProperty        `json:"props,omitempty"`
	IncludeObjectives []OSCALSelectObjective `json:"include-objectives,omitempty"`
	Remarks           string                 `json:"remarks,omitempty"`
}

// OSCALReviewedControls organizes reviewed controls and their assessed objective satisfaction states.
type OSCALReviewedControls struct {
	ControlSelections          []OSCALControlSelection          `json:"control-selections"`
	ControlObjectiveSelections []OSCALControlObjectiveSelection `json:"control-objective-selections,omitempty"`
	Remarks                    string                           `json:"remarks,omitempty"`
}

// OSCALObservationOrigin represents the origin or agent that produced an observation.
type OSCALObservationOrigin struct {
	Actors []OSCALActor `json:"actors"`
}

// OSCALActor represents a tool or assessor party acting in an observation.
type OSCALActor struct {
	Type      string `json:"type"` // "tool", "assessor"
	ActorUUID string `json:"actor-uuid"`
}

// OSCALSubject represents the assessment target or component observed.
type OSCALSubject struct {
	SubjectUUID string `json:"subject-uuid"`
	Type        string `json:"type"` // "component", "inventory-item", "location", "party", "user", "resource"
	Title       string `json:"title,omitempty"`
}

// OSCALRelevantEvidence represents attached or linked evidence files.
type OSCALRelevantEvidence struct {
	Href        string `json:"href"`
	Description string `json:"description"`
}

// OSCALObservation represents empirical technical evidence collected during assessment.
type OSCALObservation struct {
	UUID             string                   `json:"uuid"`
	Title            string                   `json:"title"`
	Description      string                   `json:"description"`
	Methods          []string                 `json:"methods"` // "EXAMINE", "TEST", "INTERVIEW"
	Types            []string                 `json:"types"`   // "evidence", "finding-observation"
	Origins          []OSCALObservationOrigin `json:"origins,omitempty"`
	Subjects         []OSCALSubject           `json:"subjects,omitempty"`
	RelevantEvidence []OSCALRelevantEvidence  `json:"relevant-evidence,omitempty"`
	Collected        time.Time                `json:"collected"`
	Props            []OSCALProperty          `json:"props,omitempty"`
	Remarks          string                   `json:"remarks,omitempty"`
}

// OSCALFindingStatus specifies the assessor's conclusion on an objective.
type OSCALFindingStatus struct {
	State   string `json:"state"`            // "satisfied" or "not-satisfied" per NIST OSCAL v1.1.0 schema
	Reason  string `json:"reason,omitempty"` // "pass", "fail", "other"
	Remarks string `json:"remarks,omitempty"`
}

// OSCALFindingTarget identifies the specific control statement or objective targeted by a finding.
type OSCALFindingTarget struct {
	Type        string             `json:"type"` // "statement-id", "objective-id" per NIST OSCAL v1.1.0 schema
	TargetID    string             `json:"target-id"`
	Title       string             `json:"title,omitempty"`
	Description string             `json:"description,omitempty"`
	Status      OSCALFindingStatus `json:"status"`
	Props       []OSCALProperty    `json:"props,omitempty"`
	Remarks     string             `json:"remarks,omitempty"`
}

// OSCALObservationRef links a finding to its supporting observation.
type OSCALObservationRef struct {
	ObservationUUID string `json:"observation-uuid"`
}

// OSCALFinding represents a non-conformity, vulnerability, or exposure mapped to controls.
type OSCALFinding struct {
	UUID                string                `json:"uuid"`
	Title               string                `json:"title"`
	Description         string                `json:"description"`
	Target              OSCALFindingTarget    `json:"target"`
	RelatedObservations []OSCALObservationRef `json:"related-observations,omitempty"`
	Props               []OSCALProperty       `json:"props,omitempty"`
	Remarks             string                `json:"remarks,omitempty"`
}

// OSCALResult represents the findings and control evaluation results of an assessment activity.
type OSCALResult struct {
	UUID             string                `json:"uuid"`
	Title            string                `json:"title"`
	Description      string                `json:"description"`
	Start            time.Time             `json:"start"`
	End              time.Time             `json:"end"`
	Props            []OSCALProperty       `json:"props,omitempty"`
	ReviewedControls OSCALReviewedControls `json:"reviewed-controls"`
	Observations     []OSCALObservation    `json:"observations,omitempty"`
	Findings         []OSCALFinding        `json:"findings,omitempty"`
	Remarks          string                `json:"remarks,omitempty"`
}

// OSCALAssessmentResults encapsulates the complete NIST OSCAL Assessment Results model.
type OSCALAssessmentResults struct {
	UUID     string                    `json:"uuid"`
	Metadata OSCALMetadata             `json:"metadata"`
	ImportAP OSCALImportAssessmentPlan `json:"import-ap"`
	Results  []OSCALResult             `json:"results"`
}

// OSCALAssessmentResultsDocument is the root JSON wrapper for the official OSCAL Assessment Results schema.
type OSCALAssessmentResultsDocument struct {
	AssessmentResults OSCALAssessmentResults `json:"assessment-results"`
}

// ============================================================================
// OSCAL PLAN OF ACTION AND MILESTONES (POA&M) MODEL
// ============================================================================

// OSCALImportSSP references the system security plan in an OSCAL POA&M document.
type OSCALImportSSP struct {
	Href string `json:"href"`
}

// OSCALSystemID identifies the system associated with a POA&M document.
type OSCALSystemID struct {
	IdentifierType string `json:"identifier-type,omitempty"`
	ID             string `json:"id"`
}

// OSCALFindingRef links a POA&M item to an assessment finding.
type OSCALFindingRef struct {
	FindingUUID string `json:"finding-uuid"`
}

// OSCALPOAMItem represents a single remediation work item in the POA&M register.
type OSCALPOAMItem struct {
	UUID                string                   `json:"uuid,omitempty"`
	Title               string                   `json:"title"`
	Description         string                   `json:"description"`
	Props               []OSCALProperty          `json:"props,omitempty"`
	Links               []OSCALLink              `json:"links,omitempty"`
	Origins             []OSCALObservationOrigin `json:"origins,omitempty"`
	RelatedFindings     []OSCALFindingRef        `json:"related-findings,omitempty"`
	RelatedObservations []OSCALObservationRef    `json:"related-observations,omitempty"`
	Remarks             string                   `json:"remarks,omitempty"`
}

// OSCALPOAM encapsulates the complete NIST OSCAL Plan of Action and Milestones model.
type OSCALPOAM struct {
	UUID      string          `json:"uuid"`
	Metadata  OSCALMetadata   `json:"metadata"`
	ImportSSP OSCALImportSSP  `json:"import-ssp"`
	SystemID  OSCALSystemID   `json:"system-id"`
	POAMItems []OSCALPOAMItem `json:"poam-items"`
}

// OSCALPOAMDocument is the root JSON wrapper for the official OSCAL POA&M schema.
type OSCALPOAMDocument struct {
	PlanOfActionAndMilestones OSCALPOAM `json:"plan-of-action-and-milestones"`
}

// ============================================================================
// DETERMINISTIC UUID GENERATION HELPERS
// ============================================================================

var felixOSCALNamespace = uuid.MustParse("7a4b8392-4d2b-4e67-9bf4-11e2f388910a")

// DeterministicOSCALUUID creates a consistent UUIDv5 string from a domain-specific key.
func DeterministicOSCALUUID(key string) string {
	return uuid.NewSHA1(felixOSCALNamespace, []byte(key)).String()
}

// ToJSON serializes the OSCAL Assessment Results document to compact JSON.
func (doc *OSCALAssessmentResultsDocument) ToJSON() ([]byte, error) {
	return json.Marshal(doc)
}

// ToPrettyJSON serializes the OSCAL Assessment Results document to formatted JSON.
func (doc *OSCALAssessmentResultsDocument) ToPrettyJSON() ([]byte, error) {
	return json.MarshalIndent(doc, "", "  ")
}

// ToJSON serializes the OSCAL POA&M document to compact JSON.
func (doc *OSCALPOAMDocument) ToJSON() ([]byte, error) {
	return json.Marshal(doc)
}

// ToPrettyJSON serializes the OSCAL POA&M document to formatted JSON.
func (doc *OSCALPOAMDocument) ToPrettyJSON() ([]byte, error) {
	return json.MarshalIndent(doc, "", "  ")
}
