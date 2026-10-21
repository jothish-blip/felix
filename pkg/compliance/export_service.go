package compliance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ExportRequest specifies parameters for generating compliance exports.
type ExportRequest struct {
	AssessmentID       string
	CatalogID          string
	CatalogPath        string
	Catalog            *ControlCatalog
	MappingRuleSetID   string
	MappingPath        string
	MappingRuleSet     *MappingRuleSet
	Dossier            *ComplianceDossier
	Format             ExportFormat
	IncludeRemediation bool
	IncludeSLA         bool
	IncludeMTTR        bool
	StrictIntegrity    bool
	KeyProvider        KeyProvider
	FelixVersion       string
	SourceRevision     string
}

// ExportService coordinates the conversion of compliance assessment records into normalized JSON and OSCAL models.
type ExportService struct {
	store          ComplianceStore
	clock          Clock
	dossierService *DossierService
}

// NewExportService initializes a new ExportService.
func NewExportService(store ComplianceStore, clock Clock) *ExportService {
	if clock == nil {
		clock = &RealClock{}
	}
	return &ExportService{
		store:          store,
		clock:          clock,
		dossierService: NewDossierService(store, clock),
	}
}

// resolveDossier acquires a validated ComplianceDossier either from the request directly or via DossierService.
func (s *ExportService) resolveDossier(ctx context.Context, req ExportRequest) (*ComplianceDossier, error) {
	if req.Dossier != nil {
		if req.StrictIntegrity {
			if len(req.Dossier.Integrity.IntegrityFailures) > 0 {
				return nil, fmt.Errorf("%w: source dossier contains integrity failures", ErrIntegrityMismatch)
			}
			if req.Dossier.Integrity.CoverageStatus == "PARTIAL" || req.Dossier.Integrity.CoverageStatus == "LIMITED" {
				return nil, fmt.Errorf("%w: source dossier exhibits incomplete or unverified coverage status (%s)",
					ErrIntegrityMismatch, req.Dossier.Integrity.CoverageStatus)
			}
		}
		if err := ValidateDossier(req.Dossier); err != nil {
			return nil, fmt.Errorf("provided source dossier failed validation: %w", err)
		}
		return req.Dossier, nil
	}

	cleanAssID := strings.TrimSpace(req.AssessmentID)
	cleanCatID := strings.TrimSpace(req.CatalogID)
	if cleanAssID == "" {
		return nil, errors.New("missing required assessment identifier for export")
	}
	if cleanCatID == "" && strings.TrimSpace(req.CatalogPath) == "" {
		return nil, errors.New("missing required catalog identifier or path for export")
	}

	dossierReq := GenerateDossierRequest{
		AssessmentID:       cleanAssID,
		CatalogID:          cleanCatID,
		CatalogPath:        req.CatalogPath,
		Catalog:            req.Catalog,
		MappingRuleSetID:   req.MappingRuleSetID,
		MappingPath:        req.MappingPath,
		MappingRuleSet:     req.MappingRuleSet,
		IncludeRemediation: req.IncludeRemediation,
		IncludeSLA:         req.IncludeSLA,
		IncludeMTTR:        req.IncludeMTTR,
		StrictIntegrity:    req.StrictIntegrity,
		KeyProvider:        req.KeyProvider,
		FelixVersion:       req.FelixVersion,
		SourceRevision:     req.SourceRevision,
	}

	return s.dossierService.GenerateDossier(ctx, dossierReq)
}

// GenerateNormalizedExport produces a versioned NormalizedComplianceExport document.
func (s *ExportService) GenerateNormalizedExport(ctx context.Context, req ExportRequest) (*NormalizedComplianceExport, error) {
	dossier, err := s.resolveDossier(ctx, req)
	if err != nil {
		return nil, err
	}

	now := s.clock.Now().UTC()
	ver := req.FelixVersion
	if ver == "" {
		ver = dossier.Identity.FelixVersion
	}
	if ver == "" {
		ver = "2.0.0"
	}

	rev := req.SourceRevision
	if rev == "" {
		rev = dossier.Identity.SourceRevision
	}

	controls := make([]ExportControlRecord, len(dossier.Controls))
	for i, c := range dossier.Controls {
		controls[i] = ExportControlRecord{
			ControlID:                   c.ControlID,
			Title:                       c.ControlTitle,
			CatalogID:                   c.CatalogID,
			CatalogVersion:              c.CatalogVersion,
			Category:                    c.Category,
			Severity:                    c.Severity,
			EvaluationState:             c.EvaluationState,
			Rationale:                   c.Rationale,
			RequirementsEvaluated:       append([]string{}, c.RequirementsEvaluated...),
			SupportingEvidence:          append([]string{}, c.SupportingEvidence...),
			ContradictingEvidence:       append([]string{}, c.ContradictingEvidence...),
			MissingOrUnverifiedEvidence: append([]string{}, c.MissingOrUnverifiedEvidence...),
			MappedFindings:              append([]DossierMappedFindingRef{}, c.MappedFindings...),
			Remediation:                 c.Remediation,
			Limitations:                 append([]string{}, c.Limitations...),
			Errors:                      append([]string{}, c.Errors...),
		}
	}

	findings := make([]ExportFindingRecord, len(dossier.Findings))
	for i, f := range dossier.Findings {
		findings[i] = ExportFindingRecord{
			FindingID:            f.FindingID,
			FindingSource:        f.FindingSource,
			RuleID:               f.RuleID,
			Title:                f.Title,
			Severity:             f.Severity,
			Category:             f.Category,
			AssessmentID:         f.AssessmentID,
			ExecutionID:          f.ExecutionID,
			AssociatedControlIDs: append([]string{}, f.AssociatedControlIDs...),
			MappingRelationships: append([]DossierFindingMappingRelationship{}, f.MappingRelationships...),
			EvidenceReferenceIDs: append([]string{}, f.EvidenceReferenceIDs...),
			RemediationRecordID:  f.RemediationRecordID,
		}
	}

	evidence := make([]ExportEvidenceRecord, len(dossier.Evidence))
	for i, e := range dossier.Evidence {
		evidence[i] = ExportEvidenceRecord{
			EvidenceID:         e.EvidenceID,
			ControlID:          e.ControlID,
			FindingID:          e.FindingID,
			EvaluationID:       e.EvaluationID,
			EvidenceType:       e.EvidenceType,
			ReferenceID:        e.ReferenceID,
			Source:             e.Source,
			Description:        e.Description,
			VerificationStatus: e.VerificationStatus,
			Verified:           e.Verified,
		}
	}

	remediations := make([]ExportRemediationRecord, len(dossier.Remediation))
	for i, r := range dossier.Remediation {
		remediations[i] = ExportRemediationRecord{
			RemediationID:            r.RemediationID,
			FindingID:                r.FindingID,
			ControlID:                r.ControlID,
			Status:                   r.Status,
			Severity:                 r.Severity,
			AssignedAt:               r.AssignedAt,
			SLAStartTime:             r.SLAStartTime,
			Deadline:                 r.Deadline,
			IsOverdue:                r.IsOverdue,
			CompletedAt:              r.CompletedAt,
			ReopenCount:              r.ReopenCount,
			RiskAccepted:             r.RiskAccepted,
			RiskAcceptanceRationale:  r.RiskAcceptanceRationale,
			RiskAcceptanceApprovedBy: r.RiskAcceptanceApprovedBy,
			PolicyID:                 r.PolicyID,
			PolicyVersion:            r.PolicyVersion,
			VerifiedCompletion:       r.VerifiedCompletion,
		}
	}

	exp := &NormalizedComplianceExport{
		SchemaVersion: CurrentNormalizedExportSchemaVersion,
		ExportMetadata: ExportMetadata{
			ExportID:            fmt.Sprintf("export:%s:%s", dossier.Identity.AssessmentID, ExportFormatNormalizedJSON),
			ExportedAt:          now,
			Format:              ExportFormatNormalizedJSON,
			FelixVersion:        ver,
			SourceRevision:      rev,
			SourceDossierID:     dossier.Identity.DossierID,
			SourceDossierDigest: dossier.LogicalDigest,
			GenerationMode:      dossier.Identity.GenerationMode,
			CompletenessStatus:  dossier.Identity.CompletenessStatus,
		},
		Assessment: ExportAssessmentDetails{
			AssessmentID:            dossier.Identity.AssessmentID,
			ExecutionID:             dossier.Identity.ExecutionID,
			EvaluatedAt:             dossier.Identity.GeneratedAt,
			OverallStatus:           dossier.Summary.OverallStatus,
			CompletionStatus:        dossier.Summary.CompletionStatus,
			ApplicablePolicyID:      dossier.Identity.ApplicablePolicyID,
			ApplicablePolicyVersion: dossier.Identity.ApplicablePolicyVersion,
		},
		Catalog: ExportCatalogDetails{
			CatalogID:      dossier.Identity.CatalogID,
			CatalogVersion: dossier.Identity.CatalogVersion,
			CatalogDigest:  dossier.Identity.CatalogDigest,
			TotalControls:  dossier.Summary.TotalControls,
		},
		Mapping: ExportMappingDetails{
			MappingRuleSetID:      dossier.Identity.MappingRuleSetID,
			MappingRuleSetVersion: dossier.Identity.MappingRuleSetVersion,
			MappingRuleSetDigest:  dossier.Identity.MappingRuleSetDigest,
			TotalRules:            dossier.Summary.MappedFindings,
		},
		Summary: ExportSummaryDetails{
			TotalControls:              dossier.Summary.TotalControls,
			CompliantCount:             dossier.Summary.CompliantCount,
			NonCompliantCount:          dossier.Summary.NonCompliantCount,
			PartiallyCompliantCount:    dossier.Summary.PartiallyCompliantCount,
			NotAssessedCount:           dossier.Summary.NotAssessedCount,
			InsufficientEvidenceCount:  dossier.Summary.InsufficientEvidenceCount,
			NotApplicableCount:         dossier.Summary.NotApplicableCount,
			ErrorCount:                 dossier.Summary.ErrorCount,
			ApplicableControls:         dossier.Summary.ApplicableControls,
			AssessedControls:           dossier.Summary.AssessedControls,
			TotalFindings:              dossier.Summary.TotalFindings,
			MappedFindings:             dossier.Summary.MappedFindings,
			UnmappedFindings:           dossier.Summary.UnmappedFindings,
			TotalEvidenceLinks:         dossier.Summary.TotalEvidenceLinks,
			SupportingEvidenceCount:    dossier.Summary.SupportingEvidenceCount,
			ContradictingEvidenceCount: dossier.Summary.ContradictingEvidenceCount,
			VerifiedEvidenceCount:      dossier.Summary.VerifiedEvidenceCount,
			UnverifiedEvidenceCount:    dossier.Summary.UnverifiedEvidenceCount,
			TotalRemediations:          dossier.Summary.TotalRemediations,
			OpenRemediations:           dossier.Summary.OpenRemediations,
			InProgressRemediations:     dossier.Summary.InProgressRemediations,
			RemediatedCount:            dossier.Summary.RemediatedCount,
			AcceptedRiskCount:          dossier.Summary.AcceptedRiskCount,
			ReopenedCount:              dossier.Summary.ReopenedCount,
			OverdueRemediations:        dossier.Summary.OverdueRemediations,
			SLAPerformance:             dossier.Summary.SLAPerformance,
			MTTRSummary:                dossier.Summary.MTTRSummary,
		},
		Controls:    controls,
		Findings:    findings,
		Evidence:    evidence,
		Remediation: remediations,
		Integrity: ExportIntegrityDetails{
			VerifiedSourceRecords:      append([]string{}, dossier.Integrity.VerifiedSourceRecords...),
			UnverifiedLegacyRecords:    append([]string{}, dossier.Integrity.UnverifiedLegacyRecords...),
			IntegrityFailures:          append([]string{}, dossier.Integrity.IntegrityFailures...),
			CoverageStatus:             dossier.Integrity.CoverageStatus,
			EvaluationIntegrityStatus:  dossier.Integrity.EvaluationIntegrityStatus,
			RemediationIntegrityStatus: dossier.Integrity.RemediationIntegrityStatus,
			LimitationsNotice:          dossier.Integrity.LimitationsNotice,
			AuthenticityStatement:      dossier.Integrity.DossierAuthenticityStatement,
		},
		Limitations:           append([]string{}, dossier.Summary.Limitations...),
		StructuredLimitations: append([]ComplianceLimitation{}, dossier.StructuredLimitations...),
		CoverageBasis:         dossier.CoverageBasis,
	}

	exp.LogicalDigest = ComputeNormalizedExportDigest(exp)

	if err := ValidateNormalizedExport(exp); err != nil {
		return nil, fmt.Errorf("generated normalized export failed validation: %w", err)
	}

	return exp, nil
}

// GenerateOSCALAssessmentResults produces a NIST OSCAL v1.1.0 Assessment Results document.
func (s *ExportService) GenerateOSCALAssessmentResults(ctx context.Context, req ExportRequest) (*OSCALAssessmentResultsDocument, error) {
	dossier, err := s.resolveDossier(ctx, req)
	if err != nil {
		return nil, err
	}

	now := s.clock.Now().UTC()
	assID := dossier.Identity.AssessmentID
	catID := dossier.Identity.CatalogID

	// 1. Build Metadata
	docUUID := DeterministicOSCALUUID("ar:" + assID + ":" + catID)
	resultUUID := DeterministicOSCALUUID("result:" + assID)
	partyUUID := DeterministicOSCALUUID("party:felix-cli")

	metadataProps := []OSCALProperty{
		{Name: "assessment-id", Value: assID},
		{Name: "catalog-id", Value: catID},
		{Name: "source-dossier-id", Value: dossier.Identity.DossierID},
		{Name: "source-dossier-digest", Value: dossier.LogicalDigest},
		{Name: "generation-mode", Value: string(dossier.Identity.GenerationMode)},
		{Name: "completeness-status", Value: string(dossier.Identity.CompletenessStatus)},
		{Name: "overall-status", Value: dossier.Summary.OverallStatus},
		{Name: "coverage-status", Value: dossier.Integrity.CoverageStatus},
		{Name: "evaluation-integrity-status", Value: string(dossier.Integrity.EvaluationIntegrityStatus)},
	}

	if dossier.Identity.ExecutionID != "" {
		metadataProps = append(metadataProps, OSCALProperty{Name: "execution-id", Value: dossier.Identity.ExecutionID})
	}
	if dossier.Identity.CatalogVersion != "" {
		metadataProps = append(metadataProps, OSCALProperty{Name: "catalog-version", Value: dossier.Identity.CatalogVersion})
	}
	if dossier.Identity.CatalogDigest != "" {
		metadataProps = append(metadataProps, OSCALProperty{Name: "catalog-digest", Value: dossier.Identity.CatalogDigest})
	}
	if dossier.Identity.MappingRuleSetID != "" {
		metadataProps = append(metadataProps, OSCALProperty{Name: "mapping-ruleset-id", Value: dossier.Identity.MappingRuleSetID})
	}

	metadataProps = append(metadataProps,
		OSCALProperty{Name: "formal-certification-disclaimer", Value: FormalCertificationDisclaimer()},
		OSCALProperty{Name: "assessed-controls", Value: fmt.Sprintf("%d", dossier.Summary.AssessedControls)},
		OSCALProperty{Name: "applicable-controls", Value: fmt.Sprintf("%d", dossier.Summary.ApplicableControls)},
	)

	for _, lim := range dossier.StructuredLimitations {
		metadataProps = append(metadataProps, OSCALProperty{
			Name:    "felix-limitation",
			Value:   lim.ID,
			Ns:      "https://felix.security/oscal/props",
			Class:   string(lim.Severity),
			Remarks: fmt.Sprintf("%s: %s", lim.Title, lim.Description),
		})
	}

	metadataRemarks := "Assessment plan derived from FELIX automated control evaluation"
	if dossier.Summary.NotApplicableCount > 0 || dossier.Summary.ErrorCount > 0 ||
		dossier.Summary.InsufficientEvidenceCount > 0 || dossier.Summary.NotAssessedCount > 0 {
		metadataRemarks += fmt.Sprintf(". Notice: Assessment contains non-binary states (%d not-applicable, %d error, %d insufficient-evidence, %d not-assessed) mapped to 'not-satisfied' with reason 'other' per NIST OSCAL v1.1.0 schema specification constraints. Inspect 'felix-evaluation-state' property for exact semantic state.",
			dossier.Summary.NotApplicableCount, dossier.Summary.ErrorCount,
			dossier.Summary.InsufficientEvidenceCount, dossier.Summary.NotAssessedCount)
	}

	metadata := OSCALMetadata{
		Title:        fmt.Sprintf("FELIX Compliance Assessment Results - %s (%s)", assID, catID),
		Published:    dossier.Identity.GeneratedAt,
		LastModified: now,
		Version:      "1.0.0",
		OSCALVersion: CurrentOSCALVersion,
		Roles: []OSCALRole{
			{ID: "assessor", Title: "Automated Cybersecurity Assessor"},
		},
		Parties: []OSCALParty{
			{
				UUID:      partyUUID,
				Type:      "organization",
				Name:      "FELIX Security Assessment Platform",
				ShortName: "felix",
			},
		},
		Props:   metadataProps,
		Remarks: metadataRemarks,
		Links: []OSCALLink{
			{
				Href: fmt.Sprintf("#catalog-%s", catID),
				Rel:  "assessment-catalog",
			},
		},
	}

	// 2. Build Reviewed Controls and Objectives
	var (
		includeControls []OSCALControlRef
		objectives      []OSCALControlObjectiveSelection
	)

	ctrlStateMap := make(map[string]EvaluationState)
	for _, c := range dossier.Controls {
		ctrlStateMap[c.ControlID] = c.EvaluationState
	}

	for _, c := range dossier.Controls {
		includeControls = append(includeControls, OSCALControlRef{ControlID: c.ControlID})

		objProps := []OSCALProperty{
			{Name: "status", Value: oscalObjectiveState(c.EvaluationState)},
			{Name: "reason", Value: oscalObjectiveReason(c.EvaluationState)},
			{Name: "felix-evaluation-state", Value: string(c.EvaluationState)},
			{Name: "control-id", Value: c.ControlID},
			{Name: "catalog-id", Value: c.CatalogID},
		}
		if c.CatalogVersion != "" {
			objProps = append(objProps, OSCALProperty{Name: "catalog-version", Value: c.CatalogVersion})
		}
		if c.Category != "" {
			objProps = append(objProps, OSCALProperty{Name: "category", Value: c.Category})
		}

		remarks := c.Rationale
		if len(c.Limitations) > 0 {
			remarks += fmt.Sprintf(" [Limitations: %s]", strings.Join(c.Limitations, "; "))
		}
		switch c.EvaluationState {
		case StateNotApplicable:
			remarks += " [OSCAL Mapping Notice: not_applicable mapped to not-satisfied with reason 'other' per OSCAL v1.1.0 schema constraints; requirement is out-of-scope/not-applicable, not a verified failure]"
		case StateError:
			remarks += " [OSCAL Mapping Notice: error mapped to not-satisfied with reason 'other' per OSCAL v1.1.0 schema constraints; evaluation encountered execution error, not a verified control failure]"
		case StateInsufficientEvidence:
			remarks += " [OSCAL Mapping Notice: insufficient_evidence mapped to not-satisfied with reason 'other' per OSCAL v1.1.0 schema constraints; evidence was inconclusive, not a verified control failure]"
		case StateNotAssessed:
			remarks += " [OSCAL Mapping Notice: not_assessed mapped to not-satisfied with reason 'other' per OSCAL v1.1.0 schema constraints; control was unassessed]"
		case StatePartiallyCompliant:
			remarks += " [OSCAL Mapping Notice: partially_compliant mapped to not-satisfied with reason 'fail' per OSCAL v1.1.0 schema constraints; partial requirements met]"
		}

		objectives = append(objectives, OSCALControlObjectiveSelection{
			Description: fmt.Sprintf("Evaluation of control %s (%s)", c.ControlID, c.ControlTitle),
			Props:       objProps,
			IncludeObjectives: []OSCALSelectObjective{
				{ObjectiveID: fmt.Sprintf("%s_obj", strings.ToLower(c.ControlID))},
			},
			Remarks: remarks,
		})
	}

	reviewedControls := OSCALReviewedControls{
		ControlSelections: []OSCALControlSelection{
			{IncludeControls: includeControls},
		},
		ControlObjectiveSelections: objectives,
		Remarks:                    fmt.Sprintf("Total reviewed controls: %d across catalog %s", len(dossier.Controls), catID),
	}

	// 3. Build Observations from Evidence Register
	var observations []OSCALObservation
	findingToObsMap := make(map[string][]string) // findingID -> []observationUUID

	for _, e := range dossier.Evidence {
		obsUUID := DeterministicOSCALUUID("obs:" + e.EvidenceID + ":" + e.ControlID)
		if e.FindingID != "" {
			findingToObsMap[e.FindingID] = append(findingToObsMap[e.FindingID], obsUUID)
		}

		obsProps := []OSCALProperty{
			{Name: "evidence-id", Value: e.EvidenceID},
			{Name: "control-id", Value: e.ControlID},
			{Name: "verification-status", Value: e.VerificationStatus},
			{Name: "verified", Value: fmt.Sprintf("%t", e.Verified)},
		}
		if e.FindingID != "" {
			obsProps = append(obsProps, OSCALProperty{Name: "finding-id", Value: e.FindingID})
		}
		if e.ReferenceID != "" {
			obsProps = append(obsProps, OSCALProperty{Name: "reference-id", Value: e.ReferenceID})
		}

		obs := OSCALObservation{
			UUID:        obsUUID,
			Title:       fmt.Sprintf("Evidence link %s for control %s", e.EvidenceID, e.ControlID),
			Description: e.Description,
			Methods:     []string{"EXAMINE", "TEST"},
			Types:       []string{"finding"},
			Origins: []OSCALObservationOrigin{
				{Actors: []OSCALActor{{Type: "tool", ActorUUID: partyUUID}}},
			},
			Collected: dossier.Identity.GeneratedAt,
			Props:     obsProps,
			Remarks:   fmt.Sprintf("Evidence Type: %s, Source: %s", e.EvidenceType, e.Source),
		}
		observations = append(observations, obs)
	}

	// 4. Build Findings from Findings Register
	var findings []OSCALFinding
	for _, f := range dossier.Findings {
		findingUUID := DeterministicOSCALUUID("finding:" + f.FindingID + ":" + assID)

		targetID := "unmapped"
		if len(f.AssociatedControlIDs) > 0 {
			targetID = f.AssociatedControlIDs[0]
		}

		findingEvalState := StateNonCompliant
		if len(f.AssociatedControlIDs) > 0 {
			if st, ok := ctrlStateMap[f.AssociatedControlIDs[0]]; ok {
				findingEvalState = st
			}
		}

		var relObs []OSCALObservationRef
		for _, obsUUID := range findingToObsMap[f.FindingID] {
			relObs = append(relObs, OSCALObservationRef{ObservationUUID: obsUUID})
		}

		findingProps := []OSCALProperty{
			{Name: "finding-id", Value: f.FindingID},
			{Name: "severity", Value: f.Severity},
			{Name: "assessment-id", Value: f.AssessmentID},
		}
		if f.RuleID != "" {
			findingProps = append(findingProps, OSCALProperty{Name: "rule-id", Value: f.RuleID})
		}
		if f.Category != "" {
			findingProps = append(findingProps, OSCALProperty{Name: "category", Value: f.Category})
		}
		if f.FindingSource != "" {
			findingProps = append(findingProps, OSCALProperty{Name: "finding-source", Value: f.FindingSource})
		}

		finding := OSCALFinding{
			UUID:  findingUUID,
			Title: f.Title,
			Description: fmt.Sprintf("Security finding %s (%s, severity: %s) mapped to controls %s",
				f.FindingID, f.RuleID, f.Severity, strings.Join(f.AssociatedControlIDs, ", ")),
			Target: OSCALFindingTarget{
				Type:     "objective-id",
				TargetID: fmt.Sprintf("%s_obj", strings.ToLower(targetID)),
				Title:    fmt.Sprintf("Objective status for %s", targetID),
				Status: OSCALFindingStatus{
					State:   oscalObjectiveState(findingEvalState),
					Reason:  oscalObjectiveReason(findingEvalState),
					Remarks: fmt.Sprintf("Assessment finding %s identified on control %s (state: %s)", f.FindingID, targetID, findingEvalState),
				},
				Props: []OSCALProperty{
					{Name: "felix-evaluation-state", Value: string(findingEvalState)},
					{Name: "control-id", Value: targetID},
				},
			},
			RelatedObservations: relObs,
			Props:               findingProps,
			Remarks:             fmt.Sprintf("Remediation Record: %s", f.RemediationRecordID),
		}
		findings = append(findings, finding)
	}

	// 5. Assemble Result Record
	var resultRemarks []string
	if strings.TrimSpace(dossier.Integrity.LimitationsNotice) != "" {
		resultRemarks = append(resultRemarks, dossier.Integrity.LimitationsNotice)
	}
	if dossier.Summary.NotApplicableCount > 0 || dossier.Summary.ErrorCount > 0 ||
		dossier.Summary.InsufficientEvidenceCount > 0 || dossier.Summary.NotAssessedCount > 0 ||
		dossier.Summary.PartiallyCompliantCount > 0 {
		resultRemarks = append(resultRemarks, fmt.Sprintf(
			"OSCAL v1.1.0 Binary State Model Limitation: Downstream consumers that ignore the 'felix-evaluation-state' property cannot natively distinguish verified non-compliance from non-failure states (%d not-applicable, %d error, %d insufficient-evidence, %d not-assessed, %d partially-compliant). In OSCAL v1.1.0, these states are mapped to 'not-satisfied' with reason 'other' (or 'fail' for partial compliance) to strictly maintain schema validity without falsely reporting compliance.",
			dossier.Summary.NotApplicableCount, dossier.Summary.ErrorCount,
			dossier.Summary.InsufficientEvidenceCount, dossier.Summary.NotAssessedCount,
			dossier.Summary.PartiallyCompliantCount,
		))
	}

	resultRecord := OSCALResult{
		UUID:        resultUUID,
		Title:       fmt.Sprintf("Assessment Activity %s Result", assID),
		Description: fmt.Sprintf("Evaluated %d controls: %d compliant, %d non-compliant", dossier.Summary.TotalControls, dossier.Summary.CompliantCount, dossier.Summary.NonCompliantCount),
		Start:       dossier.Identity.GeneratedAt,
		End:         now,
		Props: []OSCALProperty{
			{Name: "total-controls", Value: fmt.Sprintf("%d", dossier.Summary.TotalControls)},
			{Name: "compliant-count", Value: fmt.Sprintf("%d", dossier.Summary.CompliantCount)},
			{Name: "non-compliant-count", Value: fmt.Sprintf("%d", dossier.Summary.NonCompliantCount)},
			{Name: "partially-compliant-count", Value: fmt.Sprintf("%d", dossier.Summary.PartiallyCompliantCount)},
			{Name: "insufficient-evidence-count", Value: fmt.Sprintf("%d", dossier.Summary.InsufficientEvidenceCount)},
			{Name: "not-assessed-count", Value: fmt.Sprintf("%d", dossier.Summary.NotAssessedCount)},
			{Name: "not-applicable-count", Value: fmt.Sprintf("%d", dossier.Summary.NotApplicableCount)},
			{Name: "error-count", Value: fmt.Sprintf("%d", dossier.Summary.ErrorCount)},
			{Name: "total-findings", Value: fmt.Sprintf("%d", dossier.Summary.TotalFindings)},
			{Name: "total-evidence-links", Value: fmt.Sprintf("%d", dossier.Summary.TotalEvidenceLinks)},
		},
		ReviewedControls: reviewedControls,
		Observations:     observations,
		Findings:         findings,
		Remarks:          strings.Join(resultRemarks, " | "),
	}

	doc := &OSCALAssessmentResultsDocument{
		AssessmentResults: OSCALAssessmentResults{
			UUID:     docUUID,
			Metadata: metadata,
			ImportAP: OSCALImportAssessmentPlan{
				Href:    fmt.Sprintf("#assessment-plan-%s", catID),
				Remarks: "Assessment plan derived from FELIX automated control evaluation",
			},
			Results: []OSCALResult{resultRecord},
		},
	}

	if err := ValidateOSCALAssessmentResults(doc); err != nil {
		return nil, fmt.Errorf("generated OSCAL Assessment Results failed validation: %w", err)
	}

	return doc, nil
}

// GenerateOSCALPOAM produces a NIST OSCAL v1.1.0 Plan of Action and Milestones document.
func (s *ExportService) GenerateOSCALPOAM(ctx context.Context, req ExportRequest) (*OSCALPOAMDocument, error) {
	dossier, err := s.resolveDossier(ctx, req)
	if err != nil {
		return nil, err
	}

	now := s.clock.Now().UTC()
	assID := dossier.Identity.AssessmentID
	poamUUID := DeterministicOSCALUUID("poam:" + assID)
	partyUUID := DeterministicOSCALUUID("party:felix-cli")

	metadataProps := []OSCALProperty{
		{Name: "assessment-id", Value: assID},
		{Name: "total-remediations", Value: fmt.Sprintf("%d", len(dossier.Remediation))},
		{Name: "open-remediations", Value: fmt.Sprintf("%d", dossier.Summary.OpenRemediations)},
		{Name: "overdue-remediations", Value: fmt.Sprintf("%d", dossier.Summary.OverdueRemediations)},
		{Name: "remediation-integrity-status", Value: string(dossier.Integrity.RemediationIntegrityStatus)},
	}

	metadata := OSCALMetadata{
		Title:        fmt.Sprintf("FELIX Compliance Remediation Plan of Action and Milestones - %s", assID),
		Published:    dossier.Identity.GeneratedAt,
		LastModified: now,
		Version:      "1.0.0",
		OSCALVersion: CurrentOSCALVersion,
		Roles: []OSCALRole{
			{ID: "remediator", Title: "Remediation Lead / Security Engineer"},
		},
		Parties: []OSCALParty{
			{
				UUID:      partyUUID,
				Type:      "organization",
				Name:      "FELIX Security Assessment Platform",
				ShortName: "felix",
			},
		},
		Props: metadataProps,
	}

	var poamItems []OSCALPOAMItem
	for _, r := range dossier.Remediation {
		itemUUID := DeterministicOSCALUUID("poam-item:" + r.RemediationID)
		findingUUID := DeterministicOSCALUUID("finding:" + r.FindingID + ":" + assID)

		itemProps := []OSCALProperty{
			{Name: "remediation-id", Value: r.RemediationID},
			{Name: "finding-id", Value: r.FindingID},
			{Name: "control-id", Value: r.ControlID},
			{Name: "status", Value: string(r.Status)},
			{Name: "severity", Value: r.Severity},
			{Name: "is-overdue", Value: fmt.Sprintf("%t", r.IsOverdue)},
			{Name: "reopen-count", Value: fmt.Sprintf("%d", r.ReopenCount)},
			{Name: "risk-accepted", Value: fmt.Sprintf("%t", r.RiskAccepted)},
			{Name: "verified-completion", Value: fmt.Sprintf("%t", r.VerifiedCompletion)},
		}

		if r.RiskAccepted {
			if r.RiskAcceptanceRationale != "" {
				itemProps = append(itemProps, OSCALProperty{Name: "risk-acceptance-rationale", Value: r.RiskAcceptanceRationale})
			}
			if r.RiskAcceptanceApprovedBy != "" {
				itemProps = append(itemProps, OSCALProperty{Name: "risk-acceptance-approver", Value: r.RiskAcceptanceApprovedBy})
			}
		}

		if r.PolicyID != "" {
			itemProps = append(itemProps, OSCALProperty{Name: "sla-policy-id", Value: r.PolicyID})
		}
		if r.PolicyVersion != "" {
			itemProps = append(itemProps, OSCALProperty{Name: "sla-policy-version", Value: r.PolicyVersion})
		}

		if !r.Deadline.IsZero() {
			itemProps = append(itemProps, OSCALProperty{Name: "scheduled-completion-date", Value: r.Deadline.Format(time.RFC3339)})
		}
		if r.CompletedAt != nil {
			itemProps = append(itemProps, OSCALProperty{Name: "actual-completion-date", Value: r.CompletedAt.Format(time.RFC3339)})
		}

		item := OSCALPOAMItem{
			UUID:        itemUUID,
			Title:       fmt.Sprintf("Remediation item %s: Finding %s on Control %s", r.RemediationID, r.FindingID, r.ControlID),
			Description: fmt.Sprintf("Remediation lifecycle record for finding %s affecting control %s with severity %s", r.FindingID, r.ControlID, r.Severity),
			Props:       itemProps,
			RelatedFindings: []OSCALFindingRef{
				{FindingUUID: findingUUID},
			},
			Remarks: fmt.Sprintf("Assigned: %s, SLA Start: %s", r.AssignedAt.Format(time.RFC3339), r.SLAStartTime.Format(time.RFC3339)),
		}
		poamItems = append(poamItems, item)
	}

	doc := &OSCALPOAMDocument{
		PlanOfActionAndMilestones: OSCALPOAM{
			UUID:      poamUUID,
			Metadata:  metadata,
			ImportSSP: OSCALImportSSP{Href: "#ssp-felix-default"},
			SystemID:  OSCALSystemID{IdentifierType: "https://felix.security", ID: assID},
			POAMItems: poamItems,
		},
	}

	if err := ValidateOSCALPOAM(doc); err != nil {
		return nil, fmt.Errorf("generated OSCAL POA&M failed validation: %w", err)
	}

	return doc, nil
}

// oscalObjectiveState maps a FELIX evaluation state to the official OSCAL objective-status state enum.
// The official OSCAL v1.1.0 schema strictly permits ONLY "satisfied" and "not-satisfied".
// Under no circumstances may insufficient evidence, partial compliance, or unassessed controls be converted to "satisfied".
func oscalObjectiveState(state EvaluationState) string {
	switch state {
	case StateCompliant:
		return "satisfied"
	default:
		// StateNonCompliant, StatePartiallyCompliant, StateInsufficientEvidence, StateNotAssessed, StateNotApplicable, StateError
		// All map to "not-satisfied" in official NIST OSCAL schema.
		return "not-satisfied"
	}
}

// oscalObjectiveReason maps a FELIX evaluation state to the official OSCAL objective-status reason enum ("pass", "fail", "other").
func oscalObjectiveReason(state EvaluationState) string {
	switch state {
	case StateCompliant:
		return "pass"
	case StateNonCompliant, StatePartiallyCompliant:
		return "fail"
	default:
		return "other"
	}
}
