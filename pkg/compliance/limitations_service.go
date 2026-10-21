package compliance

import (
	"fmt"
	"sort"
	"strings"
)

// CalculateCoverageBasis computes the explicit mathematical coverage and compliance basis for an evaluation summary.
func CalculateCoverageBasis(sum EvaluationSummary) CoverageBasis {
	total := sum.TotalControls
	notApp := sum.NotApplicableCount
	applicable := total - notApp
	if applicable < 0 {
		applicable = 0
	}

	assessed := sum.AssessedControls
	if assessed == 0 && total > 0 {
		assessed = sum.CompliantCount + sum.NonCompliantCount + sum.PartiallyCompliantCount + sum.InsufficientEvidenceCount + sum.ErrorCount
	}
	if assessed > applicable {
		assessed = applicable
	}

	unassessed := applicable - assessed
	if unassessed < 0 {
		unassessed = 0
	}

	assessedPct := 0.0
	complianceRate := 0.0
	if applicable > 0 {
		assessedPct = (float64(assessed) / float64(applicable)) * 100.0
		complianceRate = (float64(sum.CompliantCount) / float64(applicable)) * 100.0
	}

	confidence := "COMPLETE"
	if unassessed > 0 || sum.InsufficientEvidenceCount > 0 || sum.ErrorCount > 0 {
		confidence = "PARTIAL"
	}
	if assessed == 0 {
		confidence = "LIMITED"
	}

	formula := "AssessedCoverage = Assessed / Applicable; ComplianceRate = Compliant / Applicable (Where Applicable = Total - NotApplicable)"
	denomDesc := fmt.Sprintf("%d applicable controls in evaluated scope (Total catalog controls: %d, Explicitly Not Applicable: %d)",
		applicable, total, notApp)

	return CoverageBasis{
		TotalCatalogControls:         total,
		ApplicableControls:           applicable,
		NotApplicableControls:        notApp,
		AssessedControls:             assessed,
		UnassessedControls:           unassessed,
		CompliantControls:            sum.CompliantCount,
		NonCompliantControls:         sum.NonCompliantCount,
		PartiallyCompliantControls:   sum.PartiallyCompliantCount,
		InsufficientEvidenceControls: sum.InsufficientEvidenceCount,
		ErrorControls:                sum.ErrorCount,
		AssessedCoveragePercent:      assessedPct,
		ComplianceRatePercent:        complianceRate,
		BasisFormula:                 formula,
		DenominatorDescription:       denomDesc,
		CoverageConfidence:           confidence,
		LimitationsSummary:           fmt.Sprintf("%d unassessed, %d insufficient evidence, %d error controls", unassessed, sum.InsufficientEvidenceCount, sum.ErrorCount),
	}
}

// DeriveLimitationsFromEvaluation extracts all empirical and declared limitations from an EvaluationResult.
func DeriveLimitationsFromEvaluation(eval *EvaluationResult, cat *ControlCatalog) []ComplianceLimitation {
	if eval == nil {
		return []ComplianceLimitation{
			{
				ID:          "LIM-EVAL-NIL",
				Category:    LimitationCategoryEvaluation,
				Severity:    LimitationSeverityCritical,
				Title:       "Nil Evaluation Result",
				Description: "No evaluation result was provided; compliance evaluation could not be performed.",
				Impacts:     []string{"coverage", "determination"},
			},
		}
	}

	var lims []ComplianceLimitation

	// 1. Always attach authoritative formal certification disclaimer
	lims = append(lims, ComplianceLimitation{
		ID:          "LIM-CERT-DISCLAIMER",
		Category:    LimitationCategoryCertification,
		Severity:    LimitationSeverityInfo,
		Title:       "Technical Evaluation Boundary Notice",
		Description: FormalCertificationDisclaimer(),
		Impacts:     []string{"determination"},
		Source:      "compliance_engine",
	})

	// 2. Control-by-control empirical limitations
	for _, ce := range eval.Evaluations {
		ctrlID := strings.TrimSpace(ce.ControlID)

		switch ce.State {
		case StateNotAssessed:
			lims = append(lims, ComplianceLimitation{
				ID:           "LIM-COV-UNASSESSED",
				Category:     LimitationCategoryCoverage,
				Severity:     LimitationSeverityWarning,
				Title:        fmt.Sprintf("Control %s is unassessed", ctrlID),
				Description:  fmt.Sprintf("Control %s was not evaluated in assessment %s. Absence of findings does NOT establish compliance.", ctrlID, eval.AssessmentID),
				AffectedItem: ctrlID,
				Impacts:      []string{"coverage", "determination"},
				Remediation:  "Configure and execute assessment tools, scans, or rules targeting this control requirement.",
				Source:       "evaluation_engine",
			})

		case StateInsufficientEvidence:
			lims = append(lims, ComplianceLimitation{
				ID:           "LIM-EVID-INSUFFICIENT",
				Category:     LimitationCategoryEvidence,
				Severity:     LimitationSeverityWarning,
				Title:        fmt.Sprintf("Control %s has insufficient evidence", ctrlID),
				Description:  fmt.Sprintf("Evidence for control %s is ambiguous or incomplete: %s", ctrlID, ce.Rationale),
				AffectedItem: ctrlID,
				Impacts:      []string{"confidence", "determination"},
				Remediation:  "Gather direct positive implementation evidence or unambiguous scan findings to establish compliance.",
				Source:       "evaluation_engine",
			})

		case StateNotApplicable:
			lims = append(lims, ComplianceLimitation{
				ID:           "LIM-SCOPE-NOTAPPLICABLE",
				Category:     LimitationCategoryScope,
				Severity:     LimitationSeverityInfo,
				Title:        fmt.Sprintf("Control %s is marked not applicable", ctrlID),
				Description:  fmt.Sprintf("Control %s was explicitly scoped out as not applicable: %s", ctrlID, ce.Rationale),
				AffectedItem: ctrlID,
				Impacts:      []string{"scope"},
				Source:       "evaluation_engine",
			})

		case StateError:
			lims = append(lims, ComplianceLimitation{
				ID:           "LIM-EVAL-ERROR",
				Category:     LimitationCategoryEvaluation,
				Severity:     LimitationSeverityCritical,
				Title:        fmt.Sprintf("Control %s evaluation failed with error", ctrlID),
				Description:  fmt.Sprintf("Execution error encountered while evaluating control %s: %s", ctrlID, ce.Rationale),
				AffectedItem: ctrlID,
				Impacts:      []string{"coverage", "confidence", "determination"},
				Remediation:  "Investigate execution failure, verify catalog and rule syntax, and rerun the assessment.",
				Source:       "evaluation_engine",
			})
		}

		if strings.TrimSpace(ce.Limitations) != "" {
			lims = append(lims, ComplianceLimitation{
				ID:           fmt.Sprintf("LIM-CTRL-%s", ctrlID),
				Category:     LimitationCategoryScope,
				Severity:     LimitationSeverityInfo,
				Title:        fmt.Sprintf("Declared scope limitation for control %s", ctrlID),
				Description:  strings.TrimSpace(ce.Limitations),
				AffectedItem: ctrlID,
				Impacts:      []string{"scope"},
				Source:       "control_evaluation",
			})
		}
	}

	// 3. Overall coverage and completeness limitations
	cov := CalculateCoverageBasis(eval.Summary)
	if cov.TotalCatalogControls > 0 && cov.AssessedControls == 0 {
		lims = append(lims, ComplianceLimitation{
			ID:          "LIM-COV-NONE",
			Category:    LimitationCategoryCoverage,
			Severity:    LimitationSeverityCritical,
			Title:       "Zero controls were assessed in this evaluation",
			Description: "No controls were evaluated against empirical evidence. A total lack of findings cannot imply compliance.",
			Impacts:     []string{"coverage", "determination"},
			Remediation: "Run assessment scanners and mapping rules against the target application.",
			Source:      "coverage_calculator",
		})
	} else if cov.UnassessedControls > 0 {
		lims = append(lims, ComplianceLimitation{
			ID:          "LIM-COV-INCOMPLETE",
			Category:    LimitationCategoryCoverage,
			Severity:    LimitationSeverityWarning,
			Title:       fmt.Sprintf("Incomplete assessment coverage: %d of %d applicable controls unassessed", cov.UnassessedControls, cov.ApplicableControls),
			Description: fmt.Sprintf("Evaluated coverage is %.1f%% (%d of %d applicable controls assessed). Remaining controls cannot be assumed compliant.", cov.AssessedCoveragePercent, cov.AssessedControls, cov.ApplicableControls),
			Impacts:     []string{"coverage", "determination"},
			Remediation: "Expand assessment scope to include remaining unassessed controls.",
			Source:      "coverage_calculator",
		})
	}

	if eval.Summary.ErrorCount > 0 {
		lims = append(lims, ComplianceLimitation{
			ID:          "LIM-EVAL-FAILURES",
			Category:    LimitationCategoryEvaluation,
			Severity:    LimitationSeverityCritical,
			Title:       fmt.Sprintf("%d control evaluation execution errors recorded", eval.Summary.ErrorCount),
			Description: "One or more controls could not be evaluated due to execution failures.",
			Impacts:     []string{"confidence", "determination"},
			Remediation: "Check diagnostic logs and retry evaluation.",
			Source:      "evaluation_engine",
		})
	}

	// 4. Catalog scope / procedural requirements limitation
	lims = append(lims, ComplianceLimitation{
		ID:          "LIM-REQ-PROCEDURAL",
		Category:    LimitationCategoryUnsupportedRequirement,
		Severity:    LimitationSeverityInfo,
		Title:       "Procedural and physical controls require organizational audit",
		Description: "FELIX evaluates automated technical vulnerabilities and configurations. Administrative policies, personnel screening, and physical security requirements cannot be verified purely via automated technical scans.",
		Impacts:     []string{"determination"},
		Source:      "methodology",
	})

	return DeduplicateAndSortLimitations(lims)
}

// DeriveLimitationsFromDossier extracts complete limitations from a ComplianceDossier snapshot.
func DeriveLimitationsFromDossier(dossier *ComplianceDossier) []ComplianceLimitation {
	if dossier == nil {
		return nil
	}

	var lims []ComplianceLimitation

	// 1. Inherit standard certification disclaimer
	lims = append(lims, ComplianceLimitation{
		ID:          "LIM-CERT-DISCLAIMER",
		Category:    LimitationCategoryCertification,
		Severity:    LimitationSeverityInfo,
		Title:       "Technical Evaluation Boundary Notice",
		Description: FormalCertificationDisclaimer(),
		Impacts:     []string{"determination"},
		Source:      "dossier_assembler",
	})

	// 2. Control-level limitations from dossier controls
	for _, c := range dossier.Controls {
		ctrlID := strings.TrimSpace(c.ControlID)

		switch c.EvaluationState {
		case StateNotAssessed:
			lims = append(lims, ComplianceLimitation{
				ID:           "LIM-COV-UNASSESSED",
				Category:     LimitationCategoryCoverage,
				Severity:     LimitationSeverityWarning,
				Title:        fmt.Sprintf("Control %s is unassessed", ctrlID),
				Description:  fmt.Sprintf("Control %s was not evaluated in assessment %s. Absence of findings does not establish compliance.", ctrlID, dossier.Identity.AssessmentID),
				AffectedItem: ctrlID,
				Impacts:      []string{"coverage", "determination"},
				Remediation:  "Execute test procedures targeting this control requirement.",
				Source:       "dossier_controls",
			})
		case StateInsufficientEvidence:
			lims = append(lims, ComplianceLimitation{
				ID:           "LIM-EVID-INSUFFICIENT",
				Category:     LimitationCategoryEvidence,
				Severity:     LimitationSeverityWarning,
				Title:        fmt.Sprintf("Control %s has insufficient evidence", ctrlID),
				Description:  fmt.Sprintf("Evidence for control %s is insufficient: %s", ctrlID, c.Rationale),
				AffectedItem: ctrlID,
				Impacts:      []string{"confidence", "determination"},
				Remediation:  "Collect additional positive implementation evidence.",
				Source:       "dossier_controls",
			})
		case StateNotApplicable:
			lims = append(lims, ComplianceLimitation{
				ID:           "LIM-SCOPE-NOTAPPLICABLE",
				Category:     LimitationCategoryScope,
				Severity:     LimitationSeverityInfo,
				Title:        fmt.Sprintf("Control %s marked not applicable", ctrlID),
				Description:  c.Rationale,
				AffectedItem: ctrlID,
				Impacts:      []string{"scope"},
				Source:       "dossier_controls",
			})
		case StateError:
			lims = append(lims, ComplianceLimitation{
				ID:           "LIM-EVAL-ERROR",
				Category:     LimitationCategoryEvaluation,
				Severity:     LimitationSeverityCritical,
				Title:        fmt.Sprintf("Control %s evaluation error", ctrlID),
				Description:  c.Rationale,
				AffectedItem: ctrlID,
				Impacts:      []string{"coverage", "confidence"},
				Remediation:  "Investigate execution error and rerun.",
				Source:       "dossier_controls",
			})
		}

		for _, l := range c.Limitations {
			if strings.TrimSpace(l) != "" {
				lims = append(lims, ComplianceLimitation{
					ID:           fmt.Sprintf("LIM-CTRL-%s", ctrlID),
					Category:     LimitationCategoryScope,
					Severity:     LimitationSeverityInfo,
					Title:        fmt.Sprintf("Control limitation for %s", ctrlID),
					Description:  l,
					AffectedItem: ctrlID,
					Impacts:      []string{"scope"},
					Source:       "dossier_controls",
				})
			}
		}
	}

	// 3. Completeness status
	if dossier.Identity.CompletenessStatus != DossierCompletenessComplete {
		lims = append(lims, ComplianceLimitation{
			ID:          "LIM-DOSSIER-COMPLETENESS",
			Category:    LimitationCategoryCoverage,
			Severity:    LimitationSeverityWarning,
			Title:       fmt.Sprintf("Dossier completeness status is %s", dossier.Identity.CompletenessStatus),
			Description: "The dossier represents a partial or limited assessment snapshot with unassessed controls, missing records, or unverified inputs.",
			Impacts:     []string{"coverage", "determination"},
			Remediation: "Ensure all controls in catalog scope are assessed and verified.",
			Source:      "dossier_integrity",
		})
	}

	// 4. Unmapped findings
	if dossier.Summary.UnmappedFindings > 0 {
		lims = append(lims, ComplianceLimitation{
			ID:          "LIM-MAP-UNMAPPED",
			Category:    LimitationCategoryMapping,
			Severity:    LimitationSeverityWarning,
			Title:       fmt.Sprintf("%d findings unmapped to controls", dossier.Summary.UnmappedFindings),
			Description: fmt.Sprintf("%d identified security weaknesses were not mapped to any control in catalog %s.", dossier.Summary.UnmappedFindings, dossier.Identity.CatalogID),
			Impacts:     []string{"coverage", "determination"},
			Remediation: "Update mapping ruleset to link observed findings to corresponding control requirements.",
			Source:      "mapping_engine",
		})
	}

	// 5. Integrity verification statement
	integ := dossier.Integrity
	if len(integ.IntegrityFailures) > 0 || integ.EvaluationIntegrityStatus == StatusIntegrityMismatch {
		lims = append(lims, ComplianceLimitation{
			ID:          "LIM-INT-MISMATCH",
			Category:    LimitationCategoryIntegrity,
			Severity:    LimitationSeverityCritical,
			Title:       "Cryptographic integrity mismatch detected in source records",
			Description: "Underlying evaluation or remediation records failed cryptographic hash/HMAC verification. Data may have been tampered with or corrupted.",
			Impacts:     []string{"integrity", "confidence", "determination"},
			Remediation: "Inspect database integrity records and verify key authenticity.",
			Source:      "store_integrity",
		})
	} else if len(integ.UnverifiedLegacyRecords) > 0 || integ.EvaluationIntegrityStatus == StatusUnverifiedLegacy {
		lims = append(lims, ComplianceLimitation{
			ID:          "LIM-INT-LEGACY",
			Category:    LimitationCategoryIntegrity,
			Severity:    LimitationSeverityWarning,
			Title:       "Evaluation record persisted without cryptographic HMAC signature",
			Description: "Source evaluation was persisted as a legacy record without cryptographic authenticity keys.",
			Impacts:     []string{"integrity"},
			Remediation: "Re-evaluate and save using a configured static or KMS KeyProvider.",
			Source:      "store_integrity",
		})
	} else if integ.EvaluationIntegrityStatus == StatusIntegrityOnly {
		lims = append(lims, ComplianceLimitation{
			ID:          "LIM-INT-UNAUTHENTICATED",
			Category:    LimitationCategoryIntegrity,
			Severity:    LimitationSeverityInfo,
			Title:       "Content integrity verified without cryptographic HMAC authenticity",
			Description: "Content digest matches stored database record, but authenticity tag was not verified with an HMAC key.",
			Impacts:     []string{"integrity"},
			Source:      "store_integrity",
		})
	}

	// 6. Overdue remediation SLAs
	if dossier.Summary.OverdueRemediations > 0 {
		lims = append(lims, ComplianceLimitation{
			ID:          "LIM-SLA-OVERDUE",
			Category:    LimitationCategoryEvidence,
			Severity:    LimitationSeverityWarning,
			Title:       fmt.Sprintf("%d remediation records are overdue", dossier.Summary.OverdueRemediations),
			Description: fmt.Sprintf("%d compliance finding remediations have exceeded their SLA target deadline.", dossier.Summary.OverdueRemediations),
			Impacts:     []string{"determination"},
			Remediation: "Prioritize and remediate overdue security findings according to SLA policy.",
			Source:      "sla_tracker",
		})
	}

	// 7. Re-parse existing raw string limitations in dossier
	for _, raw := range dossier.Summary.Limitations {
		clean := strings.TrimSpace(raw)
		if clean == "" {
			continue
		}
		cat := LimitationCategoryScope
		sev := LimitationSeverityWarning
		if strings.Contains(strings.ToLower(clean), "integrity") || strings.Contains(strings.ToLower(clean), "tamper") {
			cat = LimitationCategoryIntegrity
			sev = LimitationSeverityCritical
		} else if strings.Contains(strings.ToLower(clean), "mismatch") {
			cat = LimitationCategoryMapping
		}
		lims = append(lims, ComplianceLimitation{
			ID:          fmt.Sprintf("LIM-RAW-%d", len(lims)+1),
			Category:    cat,
			Severity:    sev,
			Title:       "Dossier Assembly Limitation",
			Description: clean,
			Impacts:     []string{"confidence"},
			Source:      "dossier_assembler",
		})
	}

	return DeduplicateAndSortLimitations(lims)
}

// DeduplicateAndSortLimitations deduplicates limitations by (ID, AffectedItem) and applies deterministic ordering:
// CRITICAL first, then WARNING, then INFO, then sorted by Category, ID, and AffectedItem.
func DeduplicateAndSortLimitations(lims []ComplianceLimitation) []ComplianceLimitation {
	seen := make(map[string]bool)
	var unique []ComplianceLimitation

	for _, l := range lims {
		key := fmt.Sprintf("%s:%s:%s", l.ID, l.AffectedItem, strings.TrimSpace(l.Description))
		if !seen[key] {
			seen[key] = true
			unique = append(unique, l)
		}
	}

	severityWeight := func(sev LimitationSeverity) int {
		switch sev {
		case LimitationSeverityCritical:
			return 1
		case LimitationSeverityWarning:
			return 2
		case LimitationSeverityInfo:
			return 3
		default:
			return 4
		}
	}

	sort.SliceStable(unique, func(i, j int) bool {
		wi, wj := severityWeight(unique[i].Severity), severityWeight(unique[j].Severity)
		if wi != wj {
			return wi < wj
		}
		if unique[i].Category != unique[j].Category {
			return unique[i].Category < unique[j].Category
		}
		if unique[i].ID != unique[j].ID {
			return unique[i].ID < unique[j].ID
		}
		return unique[i].AffectedItem < unique[j].AffectedItem
	})

	return unique
}
