package compliance

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"felix/pkg/report"
)

// MappingEngine coordinates the mapping of security findings to compliance catalog controls.
type MappingEngine struct {
	clock func() time.Time
}

// NewMappingEngine creates a new MappingEngine with default configuration.
func NewMappingEngine() *MappingEngine {
	return &MappingEngine{}
}

// WithClock configures a custom timestamp generator for deterministic testing.
func (e *MappingEngine) WithClock(fn func() time.Time) *MappingEngine {
	e.clock = fn
	return e
}

func (e *MappingEngine) now() time.Time {
	if e.clock != nil {
		return e.clock()
	}
	return time.Now().UTC().Truncate(time.Second)
}

// MapFindings executes finding-to-control mapping against the provided catalog and ruleset.
func (e *MappingEngine) MapFindings(catalog *ControlCatalog, ruleSet *MappingRuleSet, findings []report.Finding) (*MappingResult, error) {
	if catalog == nil {
		return nil, errors.New("control catalog cannot be nil")
	}
	if ruleSet == nil {
		return nil, errors.New("mapping rule set cannot be nil")
	}

	// Validate rule set compatibility against catalog
	if err := ValidateMappingRuleSet(ruleSet, catalog); err != nil {
		return nil, fmt.Errorf("invalid mapping rule set: %w", err)
	}

	result := &MappingResult{
		Mappings:               make([]FindingControlMapping, 0),
		Unmapped:               make([]UnmappedFinding, 0),
		CatalogIdentity:        catalog.Identity(),
		CatalogDigest:          catalog.Digest(),
		MappingRuleSetIdentity: ruleSet.Identity(),
		MappingRuleSetDigest:   ruleSet.Digest(),
		LimitationsNotice:      MappingLimitationsNotice(),
	}

	if len(findings) == 0 {
		result.Coverage = MappingCoverage{
			CatalogID:             catalog.ID,
			CatalogVersion:        catalog.Version,
			MappingRuleSetID:      ruleSet.ID,
			MappingRuleSetVersion: ruleSet.Version,
			ReferencedControls:    []string{},
		}
		return result, nil
	}

	currentTime := e.now()
	findingsWithMappings := make(map[string]int)
	refControlsMap := make(map[string]bool)
	ambiguousFindingsMap := make(map[string]bool)

	for idx, f := range findings {
		fID := strings.TrimSpace(f.ID)
		if fID == "" {
			fID = fmt.Sprintf("finding-%d", idx)
		}

		// Group matched rules by TargetControlID
		matchedByControl := make(map[string][]MappingRule)
		for _, rule := range ruleSet.Rules {
			if ruleMatchesFinding(&rule, &f, catalog) {
				tgtCtrl := strings.TrimSpace(rule.TargetControlID)
				matchedByControl[tgtCtrl] = append(matchedByControl[tgtCtrl], rule)
			}
		}

		if len(matchedByControl) == 0 {
			result.Unmapped = append(result.Unmapped, UnmappedFinding{
				FindingID: fID,
				RuleID:    f.RuleID,
				Category:  f.Category,
				Title:     f.Title,
				Severity:  f.Severity,
				Reason:    "no matching mapping rule for rule ID or category",
			})
			continue
		}

		// Has at least one mapping
		findingsWithMappings[fID] = 0

		for controlID, rulesForControl := range matchedByControl {
			if len(rulesForControl) > 1 {
				// Multiple rules matched for the same control - deterministic conflict resolution
				sort.SliceStable(rulesForControl, func(a, b int) bool {
					rA := rulesForControl[a]
					rB := rulesForControl[b]

					confA := rA.Confidence
					if confA == 0.0 {
						confA = 1.0
					}
					confB := rB.Confidence
					if confB == 0.0 {
						confB = 1.0
					}
					if confA != confB {
						return confA > confB
					}

					precA := relationshipPrecedence(rA.Relationship)
					precB := relationshipPrecedence(rB.Relationship)
					if precA != precB {
						return precA > precB
					}

					return rA.ID < rB.ID
				})

				// Check if there was an actual conflict (different relationships or confidences)
				firstRel := rulesForControl[0].Relationship
				firstConf := rulesForControl[0].Confidence
				hasActualConflict := false
				for _, otherRule := range rulesForControl[1:] {
					if otherRule.Relationship != firstRel || otherRule.Confidence != firstConf {
						hasActualConflict = true
						break
					}
				}
				if hasActualConflict {
					ambiguousFindingsMap[fID] = true
				}
			}

			bestRule := rulesForControl[0]
			hasEvidence, evLoc := evaluateEvidence(&f)
			conf := bestRule.Confidence
			if conf == 0.0 {
				conf = 1.0
			}
			rel, _ := CanonicalMappingRelationship(string(bestRule.Relationship))

			findingLoc := strings.TrimSpace(f.Endpoint)
			if findingLoc == "" {
				findingLoc = strings.TrimSpace(f.Target)
			}
			if findingLoc == "" {
				findingLoc = strings.TrimSpace(f.PrimaryAssetID)
			}

			mapping := FindingControlMapping{
				MappingID:          fmt.Sprintf("map:%s:%s:%s", fID, controlID, bestRule.ID),
				RuleID:             bestRule.ID,
				FindingID:          fID,
				FindingRuleID:      f.RuleID,
				FindingFingerprint: f.Fingerprint,
				FindingSeverity:    f.Severity,
				FindingLocation:    findingLoc,
				CatalogID:          catalog.ID,
				CatalogVersion:     catalog.Version,
				ControlID:          controlID,
				Relationship:       rel,
				Rationale:          bestRule.Rationale,
				Confidence:         conf,
				HasEvidence:        hasEvidence,
				EvidenceLocation:   evLoc,
				MappingVersion:     ruleSet.Version,
				CreatedAt:          currentTime,
			}

			result.Mappings = append(result.Mappings, mapping)
			findingsWithMappings[fID]++
			refControlsMap[controlID] = true
		}
	}

	// Deterministic sorting of Mappings
	sort.SliceStable(result.Mappings, func(i, j int) bool {
		mA := result.Mappings[i]
		mB := result.Mappings[j]
		if mA.FindingID != mB.FindingID {
			return mA.FindingID < mB.FindingID
		}
		if mA.CatalogID != mB.CatalogID {
			return mA.CatalogID < mB.CatalogID
		}
		if mA.ControlID != mB.ControlID {
			return mA.ControlID < mB.ControlID
		}
		if mA.Relationship != mB.Relationship {
			return mA.Relationship < mB.Relationship
		}
		return mA.RuleID < mB.RuleID
	})

	// Deterministic sorting of Unmapped
	sort.SliceStable(result.Unmapped, func(i, j int) bool {
		uA := result.Unmapped[i]
		uB := result.Unmapped[j]
		if uA.FindingID != uB.FindingID {
			return uA.FindingID < uB.FindingID
		}
		return uA.RuleID < uB.RuleID
	})

	// Calculate distinct coverage metrics
	totalFindings := len(findings)
	mappedFindings := len(findingsWithMappings)
	unmappedFindings := totalFindings - mappedFindings

	multiMappedFindings := 0
	for _, count := range findingsWithMappings {
		if count > 1 {
			multiMappedFindings++
		}
	}

	referencedControls := make([]string, 0, len(refControlsMap))
	for cID := range refControlsMap {
		referencedControls = append(referencedControls, cID)
	}
	sort.Strings(referencedControls)

	result.Coverage = MappingCoverage{
		TotalFindings:         totalFindings,
		MappedFindings:        mappedFindings,
		UnmappedFindings:      unmappedFindings,
		AmbiguousFindings:     len(ambiguousFindingsMap),
		TotalMappings:         len(result.Mappings),
		MultiMappedFindings:   multiMappedFindings,
		ReferencedControls:    referencedControls,
		CatalogID:             catalog.ID,
		CatalogVersion:        catalog.Version,
		MappingRuleSetID:      ruleSet.ID,
		MappingRuleSetVersion: ruleSet.Version,
	}

	return result, nil
}

// MapFindings is a convenience function that executes finding-to-control mapping using the default MappingEngine.
func MapFindings(catalog *ControlCatalog, ruleSet *MappingRuleSet, findings []report.Finding) (*MappingResult, error) {
	return NewMappingEngine().MapFindings(catalog, ruleSet, findings)
}

func ruleMatchesFinding(r *MappingRule, f *report.Finding, catalog *ControlCatalog) bool {
	if r == nil || f == nil {
		return false
	}

	// 1. Target catalog ID filter on rule
	if r.TargetCatalogID != "" && catalog != nil && strings.TrimSpace(catalog.ID) != "" {
		if !strings.EqualFold(strings.TrimSpace(r.TargetCatalogID), strings.TrimSpace(catalog.ID)) {
			return false
		}
	}

	// 2. Target catalog version filter on rule
	if r.TargetCatalogVersion != "" && r.TargetCatalogVersion != "*" && catalog != nil && strings.TrimSpace(catalog.Version) != "" {
		if !strings.EqualFold(strings.TrimSpace(r.TargetCatalogVersion), strings.TrimSpace(catalog.Version)) {
			return false
		}
	}

	// 3. Source matching criteria
	srcRule := strings.TrimSpace(r.SourceRuleID)
	srcCat := strings.TrimSpace(r.SourceCategory)
	fRule := strings.TrimSpace(f.RuleID)
	fCat := strings.TrimSpace(f.Category)

	if srcRule != "" && srcCat != "" {
		return strings.EqualFold(srcRule, fRule) && strings.EqualFold(srcCat, fCat)
	}
	if srcRule != "" {
		return strings.EqualFold(srcRule, fRule)
	}
	if srcCat != "" {
		return strings.EqualFold(srcCat, fCat)
	}

	return false
}

func relationshipPrecedence(r MappingRelationship) int {
	switch r {
	case RelationshipDirect:
		return 3
	case RelationshipPartialEvidence:
		return 2
	case RelationshipIndirect:
		return 1
	default:
		return 0
	}
}

func evaluateEvidence(f *report.Finding) (bool, string) {
	if f == nil {
		return false, ""
	}

	hasEvidence := false
	location := ""

	// Check direct evidence string
	if strings.TrimSpace(f.Evidence) != "" {
		hasEvidence = true
	}

	// Check EvidenceDetails
	if strings.TrimSpace(f.EvidenceDetails.Observation) != "" ||
		strings.TrimSpace(f.EvidenceDetails.ObservedBehavior) != "" ||
		strings.TrimSpace(f.EvidenceDetails.DetectionMethod) != "" ||
		(f.EvidenceDetails.Details != nil && len(f.EvidenceDetails.Details) > 0) ||
		f.EvidenceDetails.HTTPStatus > 0 {
		hasEvidence = true
	}

	// Check Verification evidence
	if strings.TrimSpace(f.Verification.Result) != "" ||
		strings.TrimSpace(f.Verification.SafeCurlCommand) != "" ||
		len(f.Verification.ReproductionSteps) > 0 {
		hasEvidence = true
	}

	// Extract evidence location if evidence exists
	if strings.TrimSpace(f.EvidenceDetails.Location) != "" {
		location = strings.TrimSpace(f.EvidenceDetails.Location)
		hasEvidence = true
	} else if strings.TrimSpace(f.Endpoint) != "" {
		location = strings.TrimSpace(f.Endpoint)
	} else if strings.TrimSpace(f.Target) != "" {
		location = strings.TrimSpace(f.Target)
	} else if strings.TrimSpace(f.PrimaryAssetID) != "" {
		location = strings.TrimSpace(f.PrimaryAssetID)
	}

	if !hasEvidence {
		return false, ""
	}

	return true, location
}
