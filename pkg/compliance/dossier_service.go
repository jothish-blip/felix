package compliance

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"felix/pkg/report"
)

// DossierService coordinates the evidence-backed assembly of compliance dossiers.
type DossierService struct {
	store       ComplianceStore
	clock       Clock
	mttrService *MTTRService
}

// NewDossierService initializes a new DossierService with the specified store and clock.
func NewDossierService(store ComplianceStore, clock Clock) *DossierService {
	if clock == nil {
		clock = &RealClock{}
	}
	return &DossierService{
		store:       store,
		clock:       clock,
		mttrService: NewMTTRService(store, clock),
	}
}

// GenerateDossierRequest specifies the parameters and scope for generating a compliance dossier snapshot.
type GenerateDossierRequest struct {
	AssessmentID       string
	CatalogID          string
	CatalogPath        string
	Catalog            *ControlCatalog
	MappingRuleSetID   string
	MappingPath        string
	MappingRuleSet     *MappingRuleSet
	Findings           []report.Finding
	IncludeRemediation bool
	IncludeSLA         bool
	IncludeMTTR        bool
	StrictIntegrity    bool
	KeyProvider        KeyProvider
	FelixVersion       string
	SourceRevision     string
}

// GenerateDossier generates an evidence-backed, reproducible compliance dossier from stored assessment data.
func (s *DossierService) GenerateDossier(ctx context.Context, req GenerateDossierRequest) (*ComplianceDossier, error) {
	if s.store == nil {
		return nil, errors.New("compliance store is not initialized")
	}

	cleanAssID := strings.TrimSpace(req.AssessmentID)
	if cleanAssID == "" {
		return nil, errors.New("assessment_id is required to generate a compliance dossier")
	}

	cleanCatID := strings.TrimSpace(req.CatalogID)
	if cleanCatID == "" && req.Catalog != nil {
		cleanCatID = req.Catalog.ID
	}
	if cleanCatID == "" {
		return nil, errors.New("catalog_id or a valid ControlCatalog is required to generate a compliance dossier")
	}

	now := s.clock.Now().UTC()

	// 1. Retrieve the stored evaluation result
	evalRes, err := s.store.GetEvaluationResult(cleanAssID, cleanCatID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("%w: evaluation result not found for assessment %q catalog %q", ErrNotFound, cleanAssID, cleanCatID)
		}
		return nil, fmt.Errorf("failed retrieving evaluation result for dossier: %w", err)
	}
	if evalRes == nil {
		return nil, fmt.Errorf("%w: evaluation result not found for assessment %q catalog %q", ErrNotFound, cleanAssID, cleanCatID)
	}

	// 2. Resolve and validate the ControlCatalog
	catalog := req.Catalog
	if catalog == nil && req.CatalogPath != "" {
		loadedCat, loadErr := LoadCatalog(req.CatalogPath)
		if loadErr != nil {
			return nil, fmt.Errorf("failed loading catalog from %q: %w", req.CatalogPath, loadErr)
		}
		catalog = loadedCat
	}

	var (
		limitations       []string
		verifiedRecords   []string
		legacyRecords     []string
		integrityFailures []string
		coverageStatus    = "COMPLETE"
	)

	if catalog != nil {
		if evalRes.CatalogIdentity != "" && catalog.Identity() != "" &&
			!strings.EqualFold(evalRes.CatalogIdentity, catalog.Identity()) {
			if req.StrictIntegrity {
				return nil, fmt.Errorf("%w: catalog identity mismatch: evaluation targets %q, provided catalog is %q",
					ErrIntegrityMismatch, evalRes.CatalogIdentity, catalog.Identity())
			}
			limitations = append(limitations, fmt.Sprintf("catalog version mismatch: evaluation targets %s, provided catalog is %s",
				evalRes.CatalogIdentity, catalog.Identity()))
			coverageStatus = "PARTIAL"
		}
		catDigest := catalog.Digest()
		if catDigest != "" && evalRes.CatalogDigest != "" &&
			!strings.EqualFold(evalRes.CatalogDigest, catDigest) {
			if req.StrictIntegrity {
				return nil, fmt.Errorf("%w: catalog digest mismatch: evaluation targets %q, provided catalog is %q",
					ErrIntegrityMismatch, evalRes.CatalogDigest, catDigest)
			}
			limitations = append(limitations, fmt.Sprintf("catalog digest mismatch: evaluation targets %s, provided catalog is %s",
				evalRes.CatalogDigest, catDigest))
			coverageStatus = "PARTIAL"
		}
	}

	mappingRuleSet := req.MappingRuleSet
	if mappingRuleSet == nil && req.MappingPath != "" {
		loadedRules, loadErr := LoadMappingRuleSet(req.MappingPath)
		if loadErr != nil {
			return nil, fmt.Errorf("failed loading mapping ruleset from %q: %w", req.MappingPath, loadErr)
		}
		mappingRuleSet = loadedRules
	}

	if mappingRuleSet != nil {
		if evalRes.MappingRuleSetIdentity != "" && mappingRuleSet.Identity() != "" &&
			!strings.EqualFold(evalRes.MappingRuleSetIdentity, mappingRuleSet.Identity()) {
			if req.StrictIntegrity {
				return nil, fmt.Errorf("%w: mapping ruleset identity mismatch: evaluation targets %q, provided ruleset is %q",
					ErrIntegrityMismatch, evalRes.MappingRuleSetIdentity, mappingRuleSet.Identity())
			}
			limitations = append(limitations, fmt.Sprintf("mapping ruleset version mismatch: evaluation targets %s, provided ruleset is %s",
				evalRes.MappingRuleSetIdentity, mappingRuleSet.Identity()))
			coverageStatus = "PARTIAL"
		}
		rulesetDigest := mappingRuleSet.Digest()
		if rulesetDigest != "" && evalRes.MappingRuleSetDigest != "" &&
			!strings.EqualFold(evalRes.MappingRuleSetDigest, rulesetDigest) {
			if req.StrictIntegrity {
				return nil, fmt.Errorf("%w: mapping ruleset digest mismatch: evaluation targets %q, provided ruleset is %q",
					ErrIntegrityMismatch, evalRes.MappingRuleSetDigest, rulesetDigest)
			}
			limitations = append(limitations, fmt.Sprintf("mapping ruleset digest mismatch: evaluation targets %s, provided ruleset is %s",
				evalRes.MappingRuleSetDigest, rulesetDigest))
			coverageStatus = "PARTIAL"
		}
	}

	if req.MappingRuleSetID != "" && evalRes.MappingRuleSetIdentity != "" &&
		!strings.EqualFold(evalRes.MappingRuleSetIdentity, req.MappingRuleSetID) {
		if req.StrictIntegrity {
			return nil, fmt.Errorf("%w: mapping ruleset ID mismatch: evaluation targets %q, requested %q",
				ErrIntegrityMismatch, evalRes.MappingRuleSetIdentity, req.MappingRuleSetID)
		}
		limitations = append(limitations, fmt.Sprintf("mapping ruleset ID mismatch: evaluation targets %s, requested %s",
			evalRes.MappingRuleSetIdentity, req.MappingRuleSetID))
		coverageStatus = "PARTIAL"
	}

	knownControls := make(map[string]Control)
	if catalog != nil {
		for _, c := range catalog.Controls {
			knownControls[c.ID] = c
		}
	}

	// 3. Verify Evaluation Content Integrity
	verRes, verErr := s.store.VerifyEvaluationIntegrity(cleanAssID, cleanCatID, req.KeyProvider)
	evalStatus := StatusUnverifiedLegacy
	if verErr != nil {
		if errors.Is(verErr, ErrIntegrityMismatch) || (verRes != nil && verRes.Status == StatusIntegrityMismatch) {
			evalStatus = StatusIntegrityMismatch
			if req.StrictIntegrity {
				return nil, fmt.Errorf("%w: underlying evaluation %s:%s failed integrity verification", ErrIntegrityMismatch, cleanAssID, cleanCatID)
			}
			integrityFailures = append(integrityFailures, fmt.Sprintf("evaluation %s:%s: integrity mismatch (%v)", cleanAssID, cleanCatID, verErr))
			coverageStatus = "PARTIAL"
			limitations = append(limitations, fmt.Sprintf("source evaluation %s:%s exhibits integrity mismatch; data may be unverified or tampered", cleanAssID, cleanCatID))
		} else {
			evalStatus = StatusOperationalFailure
			limitations = append(limitations, fmt.Sprintf("operational error verifying evaluation integrity: %v", verErr))
			coverageStatus = "LIMITED"
		}
	} else if verRes != nil {
		evalStatus = verRes.Status
		if verRes.Status == StatusIntegrityMismatch {
			if req.StrictIntegrity {
				return nil, fmt.Errorf("%w: underlying evaluation %s:%s failed integrity verification: %v", ErrIntegrityMismatch, cleanAssID, cleanCatID, verRes.Violations)
			}
			integrityFailures = append(integrityFailures, fmt.Sprintf("evaluation %s:%s: %v", cleanAssID, cleanCatID, verRes.Violations))
			coverageStatus = "PARTIAL"
			limitations = append(limitations, fmt.Sprintf("source evaluation %s:%s failed integrity checks: %v", cleanAssID, cleanCatID, verRes.Violations))
		} else if verRes.Status == StatusUnverifiedLegacy {
			legacyRecords = append(legacyRecords, fmt.Sprintf("evaluation %s:%s (legacy record without integrity metadata)", cleanAssID, cleanCatID))
			limitations = append(limitations, fmt.Sprintf("source evaluation %s:%s is an unverified legacy record", cleanAssID, cleanCatID))
		} else if verRes.Status == StatusVerified || verRes.Status == StatusIntegrityOnly {
			verifiedRecords = append(verifiedRecords, fmt.Sprintf("evaluation %s:%s (status: %s)", cleanAssID, cleanCatID, verRes.Status))
		}
	}

	// 4. Assemble Control Results and Evidence Register
	var (
		controls        []DossierControlResult
		evidenceEntries []DossierEvidenceEntry
		findingRefMap   = make(map[string][]string) // findingID -> []controlID
		findingObjMap   = make(map[string]*DossierFindingEntry)
	)

	// Pre-index provided findings
	for _, f := range req.Findings {
		fID := strings.TrimSpace(f.ID)
		if fID == "" {
			continue
		}

		// Cross-assessment or cross-execution check on findings if provenance is provided
		if f.Provenance != nil {
			if f.Provenance.AssessmentID != "" && f.Provenance.AssessmentID != cleanAssID {
				if req.StrictIntegrity {
					return nil, fmt.Errorf("%w: finding %s references cross-assessment %q (expected %q)",
						ErrIntegrityMismatch, fID, f.Provenance.AssessmentID, cleanAssID)
				}
				limitations = append(limitations, fmt.Sprintf("finding %s exhibits cross-assessment reference (%s != %s)", fID, f.Provenance.AssessmentID, cleanAssID))
				coverageStatus = "PARTIAL"
				integrityFailures = append(integrityFailures, fmt.Sprintf("finding %s: cross-assessment (%s != %s)", fID, f.Provenance.AssessmentID, cleanAssID))
				continue
			}
			if f.Provenance.ExecutionID != "" && evalRes.ExecutionID != "" && f.Provenance.ExecutionID != evalRes.ExecutionID {
				if req.StrictIntegrity {
					return nil, fmt.Errorf("%w: finding %s references cross-execution %q (expected %q)",
						ErrIntegrityMismatch, fID, f.Provenance.ExecutionID, evalRes.ExecutionID)
				}
				limitations = append(limitations, fmt.Sprintf("finding %s exhibits cross-execution reference (%s != %s)", fID, f.Provenance.ExecutionID, evalRes.ExecutionID))
				coverageStatus = "PARTIAL"
				integrityFailures = append(integrityFailures, fmt.Sprintf("finding %s: cross-execution (%s != %s)", fID, f.Provenance.ExecutionID, evalRes.ExecutionID))
				continue
			}
		}
		if f.EvidenceDetails.Provenance != nil {
			if f.EvidenceDetails.Provenance.AssessmentID != "" && f.EvidenceDetails.Provenance.AssessmentID != cleanAssID {
				if req.StrictIntegrity {
					return nil, fmt.Errorf("%w: finding %s evidence references cross-assessment %q (expected %q)",
						ErrIntegrityMismatch, fID, f.EvidenceDetails.Provenance.AssessmentID, cleanAssID)
				}
				limitations = append(limitations, fmt.Sprintf("finding %s evidence exhibits cross-assessment reference (%s != %s)", fID, f.EvidenceDetails.Provenance.AssessmentID, cleanAssID))
				coverageStatus = "PARTIAL"
				integrityFailures = append(integrityFailures, fmt.Sprintf("finding %s: cross-assessment evidence (%s != %s)", fID, f.EvidenceDetails.Provenance.AssessmentID, cleanAssID))
				continue
			}
			if f.EvidenceDetails.Provenance.ExecutionID != "" && evalRes.ExecutionID != "" && f.EvidenceDetails.Provenance.ExecutionID != evalRes.ExecutionID {
				if req.StrictIntegrity {
					return nil, fmt.Errorf("%w: finding %s evidence references cross-execution %q (expected %q)",
						ErrIntegrityMismatch, fID, f.EvidenceDetails.Provenance.ExecutionID, evalRes.ExecutionID)
				}
				limitations = append(limitations, fmt.Sprintf("finding %s evidence exhibits cross-execution reference (%s != %s)", fID, f.EvidenceDetails.Provenance.ExecutionID, evalRes.ExecutionID))
				coverageStatus = "PARTIAL"
				integrityFailures = append(integrityFailures, fmt.Sprintf("finding %s: cross-execution evidence (%s != %s)", fID, f.EvidenceDetails.Provenance.ExecutionID, evalRes.ExecutionID))
				continue
			}
		}

		entry := &DossierFindingEntry{
			FindingID:            fID,
			FindingSource:        f.Framework,
			RuleID:               f.RuleID,
			Title:                f.Title,
			Severity:             f.Severity,
			Category:             f.Category,
			AssessmentID:         cleanAssID,
			ExecutionID:          evalRes.ExecutionID,
			AssociatedControlIDs: []string{},
			EvidenceReferenceIDs: []string{},
		}
		findingObjMap[fID] = entry
	}

	for _, ce := range evalRes.Evaluations {
		ctrlResult := DossierControlResult{
			ControlID:             ce.ControlID,
			ControlTitle:          ce.ControlTitle,
			CatalogID:             ce.CatalogID,
			CatalogVersion:        ce.CatalogVersion,
			EvaluationState:       ce.State,
			Rationale:             ce.Rationale,
			SupportingEvidence:    append([]string{}, ce.SupportingEvidence...),
			ContradictingEvidence: append([]string{}, ce.ContradictingEvidence...),
			MappedFindings:        make([]DossierMappedFindingRef, 0),
		}

		if ctrlResult.CatalogID == "" {
			ctrlResult.CatalogID = evalRes.CatalogIdentity
		}

		// Enrich from known catalog if available
		if catalog != nil {
			kCtrl, ok := knownControls[ce.ControlID]
			if !ok {
				if req.StrictIntegrity {
					return nil, fmt.Errorf("%w: evaluation references control %q not found in catalog %q",
						ErrIntegrityMismatch, ce.ControlID, catalog.Identity())
				}
				limitations = append(limitations, fmt.Sprintf("control %s is not defined in catalog %s", ce.ControlID, catalog.Identity()))
				coverageStatus = "PARTIAL"
				integrityFailures = append(integrityFailures, fmt.Sprintf("control %s: unknown control in catalog %s", ce.ControlID, catalog.Identity()))
			} else {
				if ctrlResult.ControlTitle == "" {
					ctrlResult.ControlTitle = kCtrl.Title
				}
				ctrlResult.Category = kCtrl.Category
				ctrlResult.Severity = kCtrl.Severity
			}
		}

		if ce.Limitations != "" {
			ctrlResult.Limitations = append(ctrlResult.Limitations, ce.Limitations)
		}

		// Mapped findings
		for _, fid := range ce.FindingIDs {
			cleanFid := strings.TrimSpace(fid)
			if cleanFid == "" {
				continue
			}

			// Validate finding-to-control mapping against mappingRuleSet if provided
			if mappingRuleSet != nil {
				fEntry, hasFinding := findingObjMap[cleanFid]
				if hasFinding && (fEntry.RuleID != "" || fEntry.Category != "") {
					hasRuleForFinding := false
					ruleTargetsThisControl := false
					for _, r := range mappingRuleSet.Rules {
						matchesRule := (r.SourceRuleID != "" && r.SourceRuleID == fEntry.RuleID)
						matchesCat := (r.SourceCategory != "" && fEntry.Category != "" && strings.EqualFold(r.SourceCategory, fEntry.Category))
						if matchesRule || matchesCat {
							hasRuleForFinding = true
							if r.TargetControlID == ce.ControlID {
								ruleTargetsThisControl = true
								break
							}
						}
					}
					if hasRuleForFinding && !ruleTargetsThisControl {
						if req.StrictIntegrity {
							return nil, fmt.Errorf("%w: finding %s (rule %q) is linked to wrong control %q according to mapping ruleset",
								ErrIntegrityMismatch, cleanFid, fEntry.RuleID, ce.ControlID)
						}
						limitations = append(limitations, fmt.Sprintf("finding %s linked to wrong control %s (contradicts mapping ruleset)", cleanFid, ce.ControlID))
						coverageStatus = "PARTIAL"
						integrityFailures = append(integrityFailures, fmt.Sprintf("finding %s: mismatched control %s", cleanFid, ce.ControlID))
						continue
					}
				}
			}

			mappedRef := DossierMappedFindingRef{
				FindingID:    cleanFid,
				Relationship: RelationshipDirect,
			}

			if fEntry, ok := findingObjMap[cleanFid]; ok {
				mappedRef.FindingRuleID = fEntry.RuleID
				mappedRef.FindingTitle = fEntry.Title
				mappedRef.FindingSeverity = fEntry.Severity
			}
			ctrlResult.MappedFindings = append(ctrlResult.MappedFindings, mappedRef)

			findingRefMap[cleanFid] = append(findingRefMap[cleanFid], ce.ControlID)
		}

		// Query durable evidence links for this evaluation
		evLinks, evErr := s.store.GetEvaluationEvidence(ce.EvaluationID)
		if evErr == nil && len(evLinks) > 0 {
			for _, l := range evLinks {
				// Cross-assessment check: reject or exclude evidence belonging to a different assessment
				if l.AssessmentID != "" && l.AssessmentID != cleanAssID {
					if req.StrictIntegrity {
						return nil, fmt.Errorf("%w: evidence link %s references cross-assessment %q (expected %q)",
							ErrIntegrityMismatch, l.ID, l.AssessmentID, cleanAssID)
					}
					limitations = append(limitations, fmt.Sprintf("excluded evidence link %s: cross-assessment reference to %s", l.ID, l.AssessmentID))
					coverageStatus = "PARTIAL"
					integrityFailures = append(integrityFailures, fmt.Sprintf("evidence link %s: cross-assessment reference %s", l.ID, l.AssessmentID))
					continue
				}
				// Cross-control check: reject or exclude evidence belonging to a different control
				if l.ControlID != "" && l.ControlID != ce.ControlID {
					if req.StrictIntegrity {
						return nil, fmt.Errorf("%w: evidence link %s references control %q under evaluation for control %q",
							ErrIntegrityMismatch, l.ID, l.ControlID, ce.ControlID)
					}
					limitations = append(limitations, fmt.Sprintf("excluded evidence link %s: control mismatch (references %s under %s)", l.ID, l.ControlID, ce.ControlID))
					coverageStatus = "PARTIAL"
					integrityFailures = append(integrityFailures, fmt.Sprintf("evidence link %s: control mismatch (%s != %s)", l.ID, l.ControlID, ce.ControlID))
					continue
				}

				verStatus := "UNVERIFIED"
				isVer := false
				if evalStatus == StatusVerified || evalStatus == StatusIntegrityOnly {
					verStatus = "VERIFIED"
					isVer = true
				} else if evalStatus == StatusIntegrityMismatch {
					verStatus = "INTEGRITY_MISMATCH"
				}

				evEntry := DossierEvidenceEntry{
					EvidenceID:         l.ID,
					EvidenceType:       l.EvidenceType,
					ReferenceID:        l.ReferenceID,
					Source:             "database_evidence_link",
					Description:        l.Detail,
					ControlID:          ce.ControlID,
					EvaluationID:       ce.EvaluationID,
					VerificationStatus: verStatus,
					Verified:           isVer,
				}
				evidenceEntries = append(evidenceEntries, evEntry)
			}
		}

		controls = append(controls, ctrlResult)
	}

	// 5. Assemble Findings Register
	var findingEntries []DossierFindingEntry
	for fID, ctrlIDs := range findingRefMap {
		fEntry, ok := findingObjMap[fID]
		if !ok {
			fEntry = &DossierFindingEntry{
				FindingID:            fID,
				Title:                fmt.Sprintf("Finding %s", fID),
				Severity:             "MEDIUM",
				AssessmentID:         cleanAssID,
				ExecutionID:          evalRes.ExecutionID,
				AssociatedControlIDs: []string{},
			}
			findingObjMap[fID] = fEntry
		}

		// Merge associated control IDs
		allCtrls := append(fEntry.AssociatedControlIDs, ctrlIDs...)
		sort.Strings(allCtrls)
		uniqueCtrls := make([]string, 0, len(allCtrls))
		for _, c := range allCtrls {
			if len(uniqueCtrls) == 0 || uniqueCtrls[len(uniqueCtrls)-1] != c {
				uniqueCtrls = append(uniqueCtrls, c)
			}
		}
		fEntry.AssociatedControlIDs = uniqueCtrls

		// Add mapping relationships
		for _, c := range uniqueCtrls {
			fEntry.MappingRelationships = append(fEntry.MappingRelationships, DossierFindingMappingRelationship{
				ControlID:    c,
				Relationship: RelationshipDirect,
			})
		}
	}

	for _, entry := range findingObjMap {
		findingEntries = append(findingEntries, *entry)
	}

	// 6. Assemble Remediation & SLA Register (if requested)
	var (
		remediationEntries []DossierRemediationEntry
		remIntegrityStatus = StatusUnverifiedLegacy
		slaPerfMetrics     *SLAPerformanceMetrics
		mttrSnapshot       *MTTRSummarySnapshot
	)

	if req.IncludeRemediation || req.IncludeSLA || req.IncludeMTTR {
		validControlFindings := make(map[string]map[string]bool)
		for _, ce := range evalRes.Evaluations {
			if _, ok := validControlFindings[ce.ControlID]; !ok {
				validControlFindings[ce.ControlID] = make(map[string]bool)
			}
			for _, fid := range ce.FindingIDs {
				validControlFindings[ce.ControlID][strings.TrimSpace(fid)] = true
			}
		}

		remRecords, _, remErr := s.store.ListRemediationRecordsWithHistory(RemediationFilter{
			AssessmentID: cleanAssID,
		})
		if remErr == nil && len(remRecords) > 0 {
			for _, rec := range remRecords {
				// Cross-assessment check: reject or exclude remediation belonging to a different assessment
				if rec.AssessmentID != "" && rec.AssessmentID != cleanAssID {
					if req.StrictIntegrity {
						return nil, fmt.Errorf("%w: remediation record %s references cross-assessment %q (expected %q)",
							ErrIntegrityMismatch, rec.ID, rec.AssessmentID, cleanAssID)
					}
					limitations = append(limitations, fmt.Sprintf("excluded remediation record %s: cross-assessment reference to %s", rec.ID, rec.AssessmentID))
					coverageStatus = "PARTIAL"
					integrityFailures = append(integrityFailures, fmt.Sprintf("remediation %s: cross-assessment (%s != %s)", rec.ID, rec.AssessmentID, cleanAssID))
					continue
				}

				// Unrelated control / finding check
				if rec.ControlID != "" {
					findingsForCtrl, ctrlExists := validControlFindings[rec.ControlID]
					if !ctrlExists {
						if req.StrictIntegrity {
							return nil, fmt.Errorf("%w: remediation record %s references control %q which does not exist in evaluation",
								ErrIntegrityMismatch, rec.ID, rec.ControlID)
						}
						limitations = append(limitations, fmt.Sprintf("excluded remediation record %s: references unassessed control %s", rec.ID, rec.ControlID))
						coverageStatus = "PARTIAL"
						integrityFailures = append(integrityFailures, fmt.Sprintf("remediation %s: unassessed control %s", rec.ID, rec.ControlID))
						continue
					}
					if rec.FindingID != "" && len(findingsForCtrl) > 0 && !findingsForCtrl[rec.FindingID] {
						if req.StrictIntegrity {
							return nil, fmt.Errorf("%w: remediation record %s references finding %q not evaluated under control %q",
								ErrIntegrityMismatch, rec.ID, rec.FindingID, rec.ControlID)
						}
						limitations = append(limitations, fmt.Sprintf("excluded remediation record %s: references finding %s not associated with control %s", rec.ID, rec.FindingID, rec.ControlID))
						coverageStatus = "PARTIAL"
						integrityFailures = append(integrityFailures, fmt.Sprintf("remediation %s: unrelated finding %s under control %s", rec.ID, rec.FindingID, rec.ControlID))
						continue
					}
				}

				// Verify remediation integrity
				remVer, verErr := s.store.VerifyRemediationIntegrity(rec.ID, req.KeyProvider)
				if verErr != nil || (remVer != nil && remVer.Status == StatusIntegrityMismatch) {
					if req.StrictIntegrity {
						return nil, fmt.Errorf("%w: remediation record %s failed integrity verification", ErrIntegrityMismatch, rec.ID)
					}
					integrityFailures = append(integrityFailures, fmt.Sprintf("remediation %s: integrity mismatch", rec.ID))
					coverageStatus = "PARTIAL"
					limitations = append(limitations, fmt.Sprintf("remediation record %s exhibits integrity tampering", rec.ID))
					remIntegrityStatus = StatusIntegrityMismatch
				} else if remVer != nil && remVer.Status == StatusVerified {
					verifiedRecords = append(verifiedRecords, fmt.Sprintf("remediation %s (verified)", rec.ID))
					if remIntegrityStatus != StatusIntegrityMismatch {
						remIntegrityStatus = StatusVerified
					}
				} else {
					legacyRecords = append(legacyRecords, fmt.Sprintf("remediation %s (legacy unverified)", rec.ID))
				}

				isOverdue := false
				if (rec.Status == RemediationStatusOpen || rec.Status == RemediationStatusInProgress || rec.Status == RemediationStatusReopened) &&
					!rec.Deadline.IsZero() && now.After(rec.Deadline.UTC()) {
					isOverdue = true
				}

				remEntry := DossierRemediationEntry{
					RemediationID:      rec.ID,
					FindingID:          rec.FindingID,
					ControlID:          rec.ControlID,
					Status:             rec.Status,
					Severity:           rec.Severity,
					AssignedAt:         rec.AssignedAt,
					SLAStartTime:       rec.SLAStartTime,
					Deadline:           rec.Deadline,
					IsOverdue:          isOverdue,
					CompletedAt:        rec.CompletedAt,
					ReopenCount:        rec.ReopenCount,
					PolicyID:           rec.PolicyID,
					PolicyVersion:      rec.PolicyVersion,
					VerifiedCompletion: rec.Status == RemediationStatusRemediated && rec.CompletedAt != nil,
				}

				if rec.RiskAcceptance != nil {
					remEntry.RiskAccepted = true
					remEntry.RiskAcceptanceRationale = rec.RiskAcceptance.Rationale
					remEntry.RiskAcceptanceApprovedBy = rec.RiskAcceptance.Author
				}

				remediationEntries = append(remediationEntries, remEntry)

				// Attach remediation summary to corresponding control result
				for i := range controls {
					if controls[i].ControlID == rec.ControlID {
						ctrlRem := &DossierControlRemediationSummary{
							RecordID:     rec.ID,
							Status:       rec.Status,
							Severity:     rec.Severity,
							IsOverdue:    isOverdue,
							CompletedAt:  rec.CompletedAt,
							RiskAccepted: rec.Status == RemediationStatusAcceptedRisk,
						}
						if !rec.Deadline.IsZero() {
							dl := rec.Deadline.UTC()
							ctrlRem.Deadline = &dl
							if rec.CompletedAt != nil {
								met := !rec.CompletedAt.After(dl)
								ctrlRem.MetSLA = &met
							}
						}
						controls[i].Remediation = ctrlRem
						break
					}
				}

				// Attach remediation record ID to corresponding finding entry
				for i := range findingEntries {
					if findingEntries[i].FindingID == rec.FindingID {
						findingEntries[i].RemediationRecordID = rec.ID
						break
					}
				}
			}
		}

		if req.IncludeMTTR || req.IncludeSLA {
			mttrRes, mttrErr := s.mttrService.CalculateMTTR(ctx, MTTRFilter{
				AssessmentID:    cleanAssID,
				KeyProvider:     req.KeyProvider,
				StrictIntegrity: req.StrictIntegrity,
			})
			if mttrErr == nil && mttrRes != nil {
				slaPerfMetrics = mttrRes.SLAPerformance
				mttrSnapshot = &MTTRSummarySnapshot{
					HasData:             mttrRes.HasData,
					CompletedEpisodes:   mttrRes.CompletedEpisodes,
					UniqueFindings:      mttrRes.UniqueFindings,
					MTTRString:          mttrRes.MTTRString,
					TotalDurationString: mttrRes.TotalDurationString,
					CoverageStatus:      mttrRes.CoverageStatus,
				}
			}
		}
	}

	// 7. Calculate Counts and Summary Aggregates
	var (
		compliantCount     int
		nonCompliantCount  int
		partiallyCompCount int
		notAssessedCount   int
		insuffEvCount      int
		notApplicableCount int
		errorCount         int
	)

	for _, c := range controls {
		switch c.EvaluationState {
		case StateCompliant:
			compliantCount++
		case StateNonCompliant:
			nonCompliantCount++
		case StatePartiallyCompliant:
			partiallyCompCount++
		case StateNotAssessed:
			notAssessedCount++
		case StateInsufficientEvidence:
			insuffEvCount++
		case StateNotApplicable:
			notApplicableCount++
		case StateError:
			errorCount++
		}
	}

	var (
		openRemCount     int
		inProgRemCount   int
		remedRemCount    int
		riskAccRemCount  int
		reopenedRemCount int
		overdueRemCount  int
	)

	for _, r := range remediationEntries {
		switch r.Status {
		case RemediationStatusOpen:
			openRemCount++
		case RemediationStatusInProgress:
			inProgRemCount++
		case RemediationStatusRemediated:
			remedRemCount++
		case RemediationStatusAcceptedRisk:
			riskAccRemCount++
		case RemediationStatusReopened:
			reopenedRemCount++
		}
		if r.IsOverdue {
			overdueRemCount++
		}
	}

	var (
		suppEvCount   int
		contraEvCount int
		verEvCount    int
		unverEvCount  int
	)

	for _, e := range evidenceEntries {
		if e.EvidenceType == "supporting" || e.EvidenceType == "positive" {
			suppEvCount++
		} else if e.EvidenceType == "contradicting" {
			contraEvCount++
		}
		if e.Verified {
			verEvCount++
		} else {
			unverEvCount++
		}
	}

	// Overall Assessment Status
	overallStatus := "COMPLETED"
	if len(controls) == 0 {
		overallStatus = "NOT_ASSESSED"
	} else if errorCount > 0 {
		overallStatus = "COMPLETED_WITH_ERRORS"
	}

	// Deterministic sorting of all lists
	sort.SliceStable(controls, func(i, j int) bool {
		return controls[i].ControlID < controls[j].ControlID
	})
	sort.SliceStable(findingEntries, func(i, j int) bool {
		return findingEntries[i].FindingID < findingEntries[j].FindingID
	})
	sort.SliceStable(evidenceEntries, func(i, j int) bool {
		if evidenceEntries[i].EvidenceID != evidenceEntries[j].EvidenceID {
			return evidenceEntries[i].EvidenceID < evidenceEntries[j].EvidenceID
		}
		return evidenceEntries[i].ControlID < evidenceEntries[j].ControlID
	})
	sort.SliceStable(remediationEntries, func(i, j int) bool {
		return remediationEntries[i].RemediationID < remediationEntries[j].RemediationID
	})
	sort.Strings(limitations)
	sort.Strings(verifiedRecords)
	sort.Strings(legacyRecords)
	sort.Strings(integrityFailures)

	genMode := DossierModeDefault
	if req.StrictIntegrity {
		genMode = DossierModeStrict
	}

	catVer := evalRes.CatalogIdentity
	if parts := strings.Split(evalRes.CatalogIdentity, ":"); len(parts) > 1 {
		catVer = parts[1]
	}

	mID := evalRes.MappingRuleSetIdentity
	mVer := ""
	mDigest := evalRes.MappingRuleSetDigest
	if mappingRuleSet != nil {
		if mID == "" {
			mID = mappingRuleSet.Identity()
		}
		mVer = mappingRuleSet.Version
		if mDigest == "" {
			mDigest = mappingRuleSet.Digest()
		}
	} else if strings.Contains(mID, ":") {
		parts := strings.Split(mID, ":")
		mVer = parts[1]
	}

	dossier := &ComplianceDossier{
		Identity: DossierIdentity{
			DossierID:             fmt.Sprintf("dossier:%s:%s", cleanAssID, cleanCatID),
			SchemaVersion:         CurrentDossierSchemaVersion,
			GeneratedAt:           now,
			AssessmentID:          cleanAssID,
			ExecutionID:           evalRes.ExecutionID,
			CatalogID:             cleanCatID,
			CatalogVersion:        catVer,
			CatalogDigest:         evalRes.CatalogDigest,
			MappingRuleSetID:      mID,
			MappingRuleSetVersion: mVer,
			MappingRuleSetDigest:  mDigest,
			FelixVersion:          req.FelixVersion,
			SourceRevision:        req.SourceRevision,
			GenerationMode:        genMode,
			CompletenessStatus:    DossierCompletenessStatus(coverageStatus),
		},
		Summary: DossierAssessmentSummary{
			OverallStatus:              overallStatus,
			CompletionStatus:           "COMPLETED",
			TotalControls:              len(controls),
			CompliantCount:             compliantCount,
			NonCompliantCount:          nonCompliantCount,
			PartiallyCompliantCount:    partiallyCompCount,
			NotAssessedCount:           notAssessedCount,
			InsufficientEvidenceCount:  insuffEvCount,
			NotApplicableCount:         notApplicableCount,
			ErrorCount:                 errorCount,
			ApplicableControls:         len(controls) - notApplicableCount,
			AssessedControls:           len(controls) - notAssessedCount,
			TotalFindings:              len(findingEntries),
			MappedFindings:             len(findingRefMap),
			UnmappedFindings:           len(findingEntries) - len(findingRefMap),
			TotalEvidenceLinks:         len(evidenceEntries),
			SupportingEvidenceCount:    suppEvCount,
			ContradictingEvidenceCount: contraEvCount,
			VerifiedEvidenceCount:      verEvCount,
			UnverifiedEvidenceCount:    unverEvCount,
			TotalRemediations:          len(remediationEntries),
			OpenRemediations:           openRemCount,
			InProgressRemediations:     inProgRemCount,
			RemediatedCount:            remedRemCount,
			AcceptedRiskCount:          riskAccRemCount,
			ReopenedCount:              reopenedRemCount,
			OverdueRemediations:        overdueRemCount,
			SLAPerformance:             slaPerfMetrics,
			MTTRSummary:                mttrSnapshot,
			Limitations:                limitations,
		},
		Controls:    controls,
		Findings:    findingEntries,
		Evidence:    evidenceEntries,
		Remediation: remediationEntries,
		Integrity: DossierIntegrityStatement{
			VerifiedSourceRecords:        verifiedRecords,
			UnverifiedLegacyRecords:      legacyRecords,
			IntegrityFailures:            integrityFailures,
			CoverageStatus:               coverageStatus,
			EvaluationIntegrityStatus:    evalStatus,
			RemediationIntegrityStatus:   remIntegrityStatus,
			LimitationsNotice:            EvaluationLimitationsNotice(),
			DossierAuthenticityStatement: DefaultDossierAuthenticityStatement(),
		},
	}

	// 7b. Populate structured limitations and explicit coverage basis
	covBasis := CalculateCoverageBasis(EvaluationSummary{
		TotalControls:             len(controls),
		CompliantCount:            compliantCount,
		NonCompliantCount:         nonCompliantCount,
		PartiallyCompliantCount:   partiallyCompCount,
		NotAssessedCount:          notAssessedCount,
		InsufficientEvidenceCount: insuffEvCount,
		NotApplicableCount:        notApplicableCount,
		ErrorCount:                errorCount,
		ApplicableControls:        len(controls) - notApplicableCount,
		AssessedControls:          len(controls) - notAssessedCount,
	})
	dossier.CoverageBasis = &covBasis
	dossier.StructuredLimitations = DeriveLimitationsFromDossier(dossier)

	// 8. Compute deterministic logical digest over non-volatile content
	dossier.LogicalDigest = ComputeDossierLogicalDigest(dossier)

	// 9. Semantic validation of the assembled dossier
	if err := ValidateDossier(dossier); err != nil {
		return nil, fmt.Errorf("generated dossier failed validation: %w", err)
	}

	return dossier, nil
}
