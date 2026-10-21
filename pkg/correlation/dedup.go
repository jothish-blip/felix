package correlation

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"felix/pkg/discovery"
	"felix/pkg/report"
)

func init() {
	// Register the canonical Phase 6.4 deduplicator with pkg/report so all report generation
	// and summary pipelines automatically benefit from stable fingerprint deduplication.
	report.RegisterDeduplicator(DeduplicateFindings)
}

// -----------------------------------------------------------------------------
// Phase 6.4: Finding Deduplication Engine
// -----------------------------------------------------------------------------

// DeduplicationResult encapsulates the complete output of a finding deduplication pass.
type DeduplicationResult struct {
	CanonicalFindings []report.Finding  `json:"canonical_findings"` // Deduplicated canonical findings
	TotalInputCount   int               `json:"total_input_count"`   // Original count of findings before deduplication
	DeduplicatedCount int               `json:"deduplicated_count"` // Count of unique canonical findings
	DuplicateGroups   []DuplicateGroup  `json:"duplicate_groups"`   // Detailed metadata for each duplicate group
	DuplicateMap      map[string]string `json:"duplicate_map"`      // Mapping: duplicate finding ID -> canonical finding ID
}

// DuplicateGroup describes a group of findings that were consolidated into one canonical finding.
type DuplicateGroup struct {
	Fingerprint      string               `json:"fingerprint"`
	CanonicalID      string               `json:"canonical_id"`
	DuplicateIDs     []string             `json:"duplicate_ids"`
	Archetype        FingerprintArchetype `json:"archetype"`
	AssetKey         string               `json:"asset_key"`
	VulnerabilityKey string               `json:"vulnerability_key"`
	MergedSources    []string             `json:"merged_sources"`
	Reason           string               `json:"reason"`
}

// Deduplicator performs deterministic finding deduplication with provenance and evidence preservation.
type Deduplicator struct {
	inv *discovery.Inventory
}

// NewDeduplicator creates a new finding deduplicator.
func NewDeduplicator(inv *discovery.Inventory) *Deduplicator {
	return &Deduplicator{inv: inv}
}

// DeduplicateFindings performs canonical finding deduplication on a slice of findings.
func DeduplicateFindings(findings []report.Finding) []report.Finding {
	return NewDeduplicator(nil).DeduplicateFindings(findings)
}

// DeduplicateFindingsWithInventory performs canonical deduplication utilizing the assessment asset inventory.
func DeduplicateFindingsWithInventory(findings []report.Finding, inv *discovery.Inventory) DeduplicationResult {
	return NewDeduplicator(inv).Deduplicate(findings)
}

// DeduplicateFindings returns the deduplicated canonical finding slice directly.
func (d *Deduplicator) DeduplicateFindings(findings []report.Finding) []report.Finding {
	res := d.Deduplicate(findings)
	return res.CanonicalFindings
}

// Deduplicate executes the full deduplication pipeline, producing canonical findings,
// duplicate groupings, and an ID mapping for downstream relationship remapping.
func (d *Deduplicator) Deduplicate(findings []report.Finding) DeduplicationResult {
	if len(findings) == 0 {
		return DeduplicationResult{
			CanonicalFindings: []report.Finding{},
			TotalInputCount:   0,
			DeduplicatedCount: 0,
			DuplicateGroups:   []DuplicateGroup{},
			DuplicateMap:      make(map[string]string),
		}
	}

	dupMap := make(map[string]string, len(findings))

	// Step 1: Deterministically sort input findings by ID, Fingerprint, then Title
	// This ensures that input slice order CANNOT alter canonical selection or output ordering.
	sorted := make([]report.Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].ID != sorted[j].ID {
			return sorted[i].ID < sorted[j].ID
		}
		if sorted[i].Fingerprint != sorted[j].Fingerprint {
			return sorted[i].Fingerprint < sorted[j].Fingerprint
		}
		return sorted[i].Title < sorted[j].Title
	})

	// Step 2: Index findings into candidate duplicate groups using validated stable identity
	type groupEntry struct {
		key   string
		items []report.Finding
	}

	groupMap := make(map[string]*groupEntry)
	var groupKeys []string

	for _, rawF := range sorted {
		f := report.NormalizeFinding(rawF)

		var details FingerprintDetails
		if d.inv != nil {
			_, details = ComputeFingerprintWithInventory(f, d.inv)
		} else {
			details = ComputeFingerprintDetails(f, nil)
		}

		// Rule A: Ambiguous / incomplete findings missing explicit fingerprints NEVER merge
		if (details.IsAmbiguous || details.Archetype == ArchetypeAmbiguous) && strings.TrimSpace(rawF.Fingerprint) == "" {
			token := f.ID
			if token == "" {
				token = f.Title
			}
			f.Fingerprint = details.Value
			uniqueKey := fmt.Sprintf("ambiguous:%s:%s", cleanIdentityToken(token), f.Fingerprint)
			entry := &groupEntry{key: uniqueKey, items: []report.Finding{f}}
			groupMap[uniqueKey] = entry
			groupKeys = append(groupKeys, uniqueKey)
			continue
		}

		// Guarantee canonical v2 fingerprint
		EnsureFindingFingerprint(&f, TrustPolicyRecomputeIfLegacy)
		fp := f.Fingerprint

		if fp == "" {
			token := f.ID
			if token == "" {
				token = f.Title
			}
			uniqueKey := fmt.Sprintf("ambiguous:%s:empty", cleanIdentityToken(token))
			entry := &groupEntry{key: uniqueKey, items: []report.Finding{f}}
			groupMap[uniqueKey] = entry
			groupKeys = append(groupKeys, uniqueKey)
			continue
		}

		// Rule B: Enforce Tenant and Account boundary isolation
		tenantID, accountID := extractBoundaries(f)
		groupKey := fmt.Sprintf("%s|t:%s|a:%s", fp, tenantID, accountID)

		if entry, exists := groupMap[groupKey]; exists {
			// Compatibility safety check: ensure asset, vulnerability, and boundaries genuinely match
			if areFindingsCompatibleForMerge(entry.items[0], f) {
				entry.items = append(entry.items, f)
			} else {
				// Safety fallback: isolate if incompatible despite identical hash key
				isolateKey := fmt.Sprintf("%s:isolate:%s", groupKey, f.ID)
				entry := &groupEntry{key: isolateKey, items: []report.Finding{f}}
				groupMap[isolateKey] = entry
				groupKeys = append(groupKeys, isolateKey)
			}
		} else {
			entry := &groupEntry{key: groupKey, items: []report.Finding{f}}
			groupMap[groupKey] = entry
			groupKeys = append(groupKeys, groupKey)
		}
	}

	// Step 3: Process each duplicate group into a canonical finding with preserved evidence
	canonicalList := make([]report.Finding, 0, len(groupKeys))
	var duplicateGroups []DuplicateGroup

	for _, k := range groupKeys {
		entry := groupMap[k]
		items := entry.items

		if len(items) == 1 {
			// Single finding (no duplicates)
			single := items[0]
			if single.ScoreExplanation == nil || single.Score <= 0 {
				expl := report.ExplainFindingScore(single)
				single.Score = expl.Score
				single.ScoreExplanation = &expl
				if single.EvidenceDetails.Details == nil {
					single.EvidenceDetails.Details = make(map[string]string)
				}
				single.EvidenceDetails.Details["score_formula"] = expl.Formula
				single.EvidenceDetails.Details["score_rationale"] = expl.Rationale
			}
			dupMap[single.ID] = single.ID
			canonicalList = append(canonicalList, single)
			continue
		}

		// Multi-finding duplicate group:
		// 1. Sort items by objective authority to select canonical representative
		sort.Slice(items, func(i, j int) bool {
			return compareFindingAuthority(items[i], items[j]) > 0
		})

		canonical := items[0]
		dupMap[canonical.ID] = canonical.ID

		var mergedFindingIDs []string
		mergedSourcesMap := make(map[string]struct{})
		if canonical.Source != "" {
			mergedSourcesMap[canonical.Source] = struct{}{}
		}

		// 2. Merge all duplicates into canonical
		for _, dup := range items[1:] {
			dupMap[dup.ID] = canonical.ID
			mergedFindingIDs = append(mergedFindingIDs, dup.ID)
			if dup.Source != "" {
				mergedSourcesMap[dup.Source] = struct{}{}
			}

			mergeDuplicateIntoCanonical(&canonical, dup)
		}

		sort.Strings(mergedFindingIDs)
		var mergedSources []string
		for s := range mergedSourcesMap {
			mergedSources = append(mergedSources, s)
		}
		sort.Strings(mergedSources)

		// 3. Enrich canonical finding with audit traceability metadata
		if canonical.EvidenceDetails.Details == nil {
			canonical.EvidenceDetails.Details = make(map[string]string)
		}
		canonical.EvidenceDetails.Details["duplicate_count"] = strconv.Itoa(len(mergedFindingIDs))
		canonical.EvidenceDetails.Details["duplicate_finding_ids"] = strings.Join(mergedFindingIDs, ",")
		canonical.EvidenceDetails.Details["canonical_finding_id"] = canonical.ID
		if len(mergedSources) > 0 {
			canonical.EvidenceDetails.Details["merged_sources"] = strings.Join(mergedSources, ",")
		}

		// 4. Authoritatively reconcile risk score and explainability
		expl := report.ExplainFindingScore(canonical)
		canonical.Score = expl.Score
		canonical.ScoreExplanation = &expl
		canonical.EvidenceDetails.Details["score_formula"] = expl.Formula
		canonical.EvidenceDetails.Details["score_rationale"] = expl.Rationale

		canonicalList = append(canonicalList, canonical)

		// Record DuplicateGroup metadata
		var details FingerprintDetails
		if d.inv != nil {
			_, details = ComputeFingerprintWithInventory(canonical, d.inv)
		} else {
			details = ComputeFingerprintDetails(canonical, nil)
		}

		fpDisplay := canonical.Fingerprint
		if len(fpDisplay) > 16 {
			fpDisplay = fpDisplay[:16]
		}

		duplicateGroups = append(duplicateGroups, DuplicateGroup{
			Fingerprint:      canonical.Fingerprint,
			CanonicalID:      canonical.ID,
			DuplicateIDs:     mergedFindingIDs,
			Archetype:        details.Archetype,
			AssetKey:         details.AssetKey,
			VulnerabilityKey: details.VulnerabilityKey,
			MergedSources:    mergedSources,
			Reason:           fmt.Sprintf("Consolidated %d findings matching stable fingerprint %s", len(items), fpDisplay),
		})
	}

	// Step 4: Deterministically sort canonical findings using standard report prioritization
	prioritized := report.Prioritize(canonicalList)

	return DeduplicationResult{
		CanonicalFindings: prioritized,
		TotalInputCount:   len(findings),
		DeduplicatedCount: len(prioritized),
		DuplicateGroups:   duplicateGroups,
		DuplicateMap:      dupMap,
	}
}

// -----------------------------------------------------------------------------
// Compatibility & Authority Evaluation
// -----------------------------------------------------------------------------

// areFindingsCompatibleForMerge performs rigorous semantic checks to ensure findings can be safely consolidated.
func areFindingsCompatibleForMerge(f1, f2 report.Finding) bool {
	// 1. Boundary check: conflicting non-empty tenant or account IDs must never merge
	t1, a1 := extractBoundaries(f1)
	t2, a2 := extractBoundaries(f2)
	if t1 != "" && t2 != "" && t1 != t2 {
		return false
	}
	if a1 != "" && a2 != "" && a1 != a2 {
		return false
	}

	// 2. Archetype check: ambiguous findings must never merge
	arch1 := DetectArchetype(f1)
	arch2 := DetectArchetype(f2)
	if arch1 == ArchetypeAmbiguous || arch2 == ArchetypeAmbiguous {
		return false
	}
	if arch1 != arch2 {
		return false
	}

	// 3. Vulnerability type / rule compatibility
	vk1 := extractVulnerabilityKey(f1)
	vk2 := extractVulnerabilityKey(f2)
	if vk1 != "" && vk2 != "" && vk1 != vk2 {
		return false
	}

	return true
}

// compareFindingAuthority determines which finding in a duplicate group should serve as the canonical representative.
// Returns > 0 if a is more authoritative than b, < 0 if b is more authoritative, or 0 if equal.
func compareFindingAuthority(a, b report.Finding) int {
	// 1. Verification status rank: VERIFIED > DETECTED > NOT_VERIFIED > OBSERVED > NOT_EXPOSED
	rankVA := report.VerificationRank(a.Verification.Status)
	rankVB := report.VerificationRank(b.Verification.Status)
	if rankVA != rankVB {
		return rankVA - rankVB
	}

	// 2. Finding status rank: CONFIRMED > SUSPECTED > INCONCLUSIVE > NOT_TESTED > ERROR
	rankSA := report.FindingStatusRank(a.Status)
	rankSB := report.FindingStatusRank(b.Status)
	if rankSA != rankSB {
		return rankSA - rankSB
	}

	// 3. Analysis method: active verification is more authoritative than passive/static
	methodScoreA := 0
	if a.AnalysisMethod == report.AnalysisMethodActive && a.Verification.Status == report.VerificationVerified {
		methodScoreA = 2
	} else if a.AnalysisMethod == report.AnalysisMethodActive {
		methodScoreA = 1
	}
	methodScoreB := 0
	if b.AnalysisMethod == report.AnalysisMethodActive && b.Verification.Status == report.VerificationVerified {
		methodScoreB = 2
	} else if b.AnalysisMethod == report.AnalysisMethodActive {
		methodScoreB = 1
	}
	if methodScoreA != methodScoreB {
		return methodScoreA - methodScoreB
	}

	// 4. Severity rank: CRITICAL > HIGH > MEDIUM > LOW > INFO
	rankSevA := report.SeverityRank(a.Severity)
	rankSevB := report.SeverityRank(b.Severity)
	if rankSevA != rankSevB {
		return rankSevA - rankSevB
	}

	// 5. Confidence rank: HIGH > MEDIUM > LOW
	rankCA := report.ConfidenceRank(a.Confidence)
	rankCB := report.ConfidenceRank(b.Confidence)
	if rankCA != rankCB {
		return rankCA - rankCB
	}

	// 6. Evidence richness
	richnessA := evidenceRichness(a)
	richnessB := evidenceRichness(b)
	if richnessA != richnessB {
		return richnessA - richnessB
	}

	// 7. Deterministic tie-breakers: earlier Timestamp, then lexicographical ID
	if !a.Timestamp.IsZero() && !b.Timestamp.IsZero() && !a.Timestamp.Equal(b.Timestamp) {
		if a.Timestamp.Before(b.Timestamp) {
			return 1
		}
		return -1
	}

	if a.ID != b.ID {
		if a.ID < b.ID {
			return 1
		}
		return -1
	}

	return 0
}

// evidenceRichness computes a numeric weight indicating the depth of evidence attached to a finding.
func evidenceRichness(f report.Finding) int {
	r := 0
	if f.Verification.SafeCurlCommand != "" {
		r += 20
	}
	if len(f.Verification.ReproductionSteps) > 0 {
		r += len(f.Verification.ReproductionSteps) * 10
	}
	if f.EvidenceDetails.Observation != "" {
		r += len(f.EvidenceDetails.Observation)
	}
	if f.Evidence != "" {
		r += len(f.Evidence)
	}
	if len(f.EvidenceDetails.Details) > 0 {
		r += len(f.EvidenceDetails.Details) * 2
	}
	return r
}

// extractBoundaries retrieves tenant_id and account_id from finding details.
func extractBoundaries(f report.Finding) (string, string) {
	if f.EvidenceDetails.Details == nil {
		return "", ""
	}
	return strings.TrimSpace(f.EvidenceDetails.Details["tenant_id"]),
		strings.TrimSpace(f.EvidenceDetails.Details["account_id"])
}

func addAlternativeString(details map[string]string, key, val string) {
	val = strings.TrimSpace(val)
	if val == "" {
		return
	}
	var items []string
	if existing := details[key]; existing != "" {
		items = strings.Split(existing, " || ")
	}
	for _, it := range items {
		if it == val {
			return
		}
	}
	items = append(items, val)
	sort.Strings(items)
	details[key] = strings.Join(items, " || ")
}

// isBypassDemonstrated verifies whether a finding affirmatively proves an authentication bypass.
// HTTP 200 alone cannot establish an authentication bypass without affirmative evidence,
// bypass context, and absence of refutation.
func isBypassDemonstrated(f report.Finding) bool {
	if f.EvidenceDetails.HTTPStatus != 200 {
		return false
	}
	titleLower := strings.ToLower(f.Title)
	hasBypass := strings.Contains(titleLower, "bypass") || strings.Contains(titleLower, "unauthenticated")
	if !hasBypass {
		return false
	}
	hasEvidence := len(strings.TrimSpace(f.Evidence)) > 0 ||
		len(strings.TrimSpace(f.EvidenceDetails.Observation)) > 0 ||
		f.Verification.Status == report.VerificationVerified
	if !hasEvidence {
		return false
	}
	if f.Verification.Status == report.VerificationNotExposed {
		return false
	}
	return true
}

func addAlternativeStatus(details map[string]string, status int) {
	if status <= 0 {
		return
	}
	statusStr := strconv.Itoa(status)
	addAlternativeString(details, "alternative_http_statuses", statusStr)
}

func addTargetURL(details map[string]string, rawURL string) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return
	}
	tSet := make(map[string]struct{})
	if existing := details["associated_targets"]; existing != "" {
		for _, u := range strings.Split(existing, ",") {
			if u = strings.TrimSpace(u); u != "" {
				tSet[u] = struct{}{}
			}
		}
	}
	tSet[rawURL] = struct{}{}
	var urls []string
	for u := range tSet {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	details["associated_targets"] = strings.Join(urls, ", ")
}

// mergeDuplicateIntoCanonical safely incorporates evidence, assets, and metadata from dup into canonical.
func mergeDuplicateIntoCanonical(canonical *report.Finding, dup report.Finding) {
	// 1. Merge Evidence Observation text without duplicating substrings
	if dup.Evidence != "" && !strings.Contains(canonical.Evidence, dup.Evidence) {
		if canonical.Evidence == "" {
			canonical.Evidence = dup.Evidence
		} else {
			canonical.Evidence = canonical.Evidence + "; Also: " + dup.Evidence
		}
	}

	if canonical.EvidenceDetails.Observation == "" {
		canonical.EvidenceDetails.Observation = dup.EvidenceDetails.Observation
	} else if dup.EvidenceDetails.Observation != "" && !strings.Contains(canonical.EvidenceDetails.Observation, dup.EvidenceDetails.Observation) {
		canonical.EvidenceDetails.Observation = canonical.EvidenceDetails.Observation + "; Also: " + dup.EvidenceDetails.Observation
	}

	// 2. Merge Location
	if dup.EvidenceDetails.Location != "" && !strings.Contains(canonical.EvidenceDetails.Location, dup.EvidenceDetails.Location) {
		if canonical.EvidenceDetails.Location == "" {
			canonical.EvidenceDetails.Location = dup.EvidenceDetails.Location
		} else {
			canonical.EvidenceDetails.Location = canonical.EvidenceDetails.Location + ", " + dup.EvidenceDetails.Location
		}
	}

	// 3. Merge Negative Evidence
	if canonical.EvidenceDetails.NegativeEvidence == "" {
		canonical.EvidenceDetails.NegativeEvidence = dup.EvidenceDetails.NegativeEvidence
	} else if dup.EvidenceDetails.NegativeEvidence != "" && !strings.Contains(canonical.EvidenceDetails.NegativeEvidence, dup.EvidenceDetails.NegativeEvidence) {
		canonical.EvidenceDetails.NegativeEvidence = canonical.EvidenceDetails.NegativeEvidence + " " + dup.EvidenceDetails.NegativeEvidence
	}

	// 4. Merge Expected & Observed Behaviors
	if canonical.EvidenceDetails.ExpectedBehavior == "" && dup.EvidenceDetails.ExpectedBehavior != "" {
		canonical.EvidenceDetails.ExpectedBehavior = dup.EvidenceDetails.ExpectedBehavior
	} else if dup.EvidenceDetails.ExpectedBehavior != "" && !strings.Contains(canonical.EvidenceDetails.ExpectedBehavior, dup.EvidenceDetails.ExpectedBehavior) {
		canonical.EvidenceDetails.ExpectedBehavior = canonical.EvidenceDetails.ExpectedBehavior + "; " + dup.EvidenceDetails.ExpectedBehavior
	}
	if canonical.EvidenceDetails.ObservedBehavior == "" && dup.EvidenceDetails.ObservedBehavior != "" {
		canonical.EvidenceDetails.ObservedBehavior = dup.EvidenceDetails.ObservedBehavior
	} else if dup.EvidenceDetails.ObservedBehavior != "" && !strings.Contains(canonical.EvidenceDetails.ObservedBehavior, dup.EvidenceDetails.ObservedBehavior) {
		canonical.EvidenceDetails.ObservedBehavior = canonical.EvidenceDetails.ObservedBehavior + "; " + dup.EvidenceDetails.ObservedBehavior
	}

	// 5. Merge HTTP & Detection metadata
	if canonical.EvidenceDetails.HTTPStatus == 0 && dup.EvidenceDetails.HTTPStatus != 0 {
		canonical.EvidenceDetails.HTTPStatus = dup.EvidenceDetails.HTTPStatus
	} else if canonical.EvidenceDetails.HTTPStatus != 0 && dup.EvidenceDetails.HTTPStatus != 0 && canonical.EvidenceDetails.HTTPStatus != dup.EvidenceDetails.HTTPStatus {
		if canonical.EvidenceDetails.Details == nil {
			canonical.EvidenceDetails.Details = make(map[string]string)
		}
		addAlternativeStatus(canonical.EvidenceDetails.Details, dup.EvidenceDetails.HTTPStatus)
	}

	if canonical.EvidenceDetails.HTTPMethod == "" && dup.EvidenceDetails.HTTPMethod != "" {
		canonical.EvidenceDetails.HTTPMethod = dup.EvidenceDetails.HTTPMethod
	} else if canonical.EvidenceDetails.HTTPMethod != "" && dup.EvidenceDetails.HTTPMethod != "" && !strings.EqualFold(canonical.EvidenceDetails.HTTPMethod, dup.EvidenceDetails.HTTPMethod) {
		if canonical.EvidenceDetails.Details == nil {
			canonical.EvidenceDetails.Details = make(map[string]string)
		}
		addAlternativeString(canonical.EvidenceDetails.Details, "alternative_http_methods", dup.EvidenceDetails.HTTPMethod)
	}

	if canonical.EvidenceDetails.ContentType == "" && dup.EvidenceDetails.ContentType != "" {
		canonical.EvidenceDetails.ContentType = dup.EvidenceDetails.ContentType
	} else if canonical.EvidenceDetails.ContentType != "" && dup.EvidenceDetails.ContentType != "" && !strings.EqualFold(canonical.EvidenceDetails.ContentType, dup.EvidenceDetails.ContentType) {
		if canonical.EvidenceDetails.Details == nil {
			canonical.EvidenceDetails.Details = make(map[string]string)
		}
		addAlternativeString(canonical.EvidenceDetails.Details, "alternative_content_types", dup.EvidenceDetails.ContentType)
	}

	if canonical.EvidenceDetails.DetectionMethod == "" && dup.EvidenceDetails.DetectionMethod != "" {
		canonical.EvidenceDetails.DetectionMethod = dup.EvidenceDetails.DetectionMethod
	}
	if canonical.EvidenceDetails.DetectionStatus == "" && dup.EvidenceDetails.DetectionStatus != "" {
		canonical.EvidenceDetails.DetectionStatus = dup.EvidenceDetails.DetectionStatus
	}

	// Multi-target URL footprint preservation
	if dup.Target != "" && canonical.Target != "" && !strings.EqualFold(canonical.Target, dup.Target) {
		if canonical.EvidenceDetails.Details == nil {
			canonical.EvidenceDetails.Details = make(map[string]string)
		}
		addTargetURL(canonical.EvidenceDetails.Details, canonical.Target)
		addTargetURL(canonical.EvidenceDetails.Details, dup.Target)
	}

	// 6. Merge Evidence Provenance
	if canonical.Provenance == nil && dup.Provenance != nil {
		canonical.Provenance = dup.Provenance
		canonical.EvidenceDetails.Provenance = dup.Provenance
	} else if canonical.Provenance != nil && dup.Provenance != nil {
		if canonical.Provenance.AssetID == "" && dup.Provenance.AssetID != "" {
			canonical.Provenance.AssetID = dup.Provenance.AssetID
		}
		if canonical.Provenance.VerificationContext == "" && dup.Provenance.VerificationContext != "" {
			canonical.Provenance.VerificationContext = dup.Provenance.VerificationContext
		}
		canonical.EvidenceDetails.Provenance = canonical.Provenance
	}
	if dup.Provenance != nil && dup.Provenance.EvidenceID != "" {
		if canonical.EvidenceDetails.Details == nil {
			canonical.EvidenceDetails.Details = make(map[string]string)
		}
		evSet := make(map[string]struct{})
		if existing := canonical.EvidenceDetails.Details["merged_evidence_ids"]; existing != "" {
			for _, id := range strings.Split(existing, ",") {
				if id = strings.TrimSpace(id); id != "" {
					evSet[id] = struct{}{}
				}
			}
		} else if canonical.Provenance != nil && canonical.Provenance.EvidenceID != "" {
			evSet[canonical.Provenance.EvidenceID] = struct{}{}
		}
		evSet[dup.Provenance.EvidenceID] = struct{}{}
		var evIDs []string
		for id := range evSet {
			evIDs = append(evIDs, id)
		}
		sort.Strings(evIDs)
		canonical.EvidenceDetails.Details["merged_evidence_ids"] = strings.Join(evIDs, ",")
	}

	// 7. Merge Details map with field-specific semantics
	if len(dup.EvidenceDetails.Details) > 0 {
		if canonical.EvidenceDetails.Details == nil {
			canonical.EvidenceDetails.Details = make(map[string]string)
		}
		for k, v := range dup.EvidenceDetails.Details {
			if k == "score_formula" || k == "score_rationale" || k == "duplicate_finding_ids" || k == "duplicate_count" || k == "canonical_finding_id" {
				continue // Internal recomputed keys
			}
			oldV, has := canonical.EvidenceDetails.Details[k]


			switch k {
			// A. Test execution / coverage flags: if either detector tested it, the test was attempted
			case "unauth_bypass_tested":
				if oldV == "true" || v == "true" {
					canonical.EvidenceDetails.Details[k] = "true"
				} else {
					canonical.EvidenceDetails.Details[k] = "false"
				}
				continue

			// B. Positive Vulnerability Evidence Flags: affirmative leak proof is preserved
			case "cross_tenant", "cross_tenant_data_confirmed":
				if oldV == "true" || v == "true" {
					canonical.EvidenceDetails.Details[k] = "true"
				} else {
					canonical.EvidenceDetails.Details[k] = "false"
				}
				// Contradiction detection: check if tenant isolation was also claimed
				if (oldV == "true" || v == "true") && (canonical.EvidenceDetails.Details["isolation_verified"] == "true" || dup.EvidenceDetails.Details["isolation_verified"] == "true") {
					canonical.EvidenceDetails.Details["observation_conflict"] = "cross-tenant disclosure observed alongside tenant isolation claim"
					canonical.EvidenceDetails.Details["disputed_tenant_isolation"] = "true"
					canonical.EvidenceDetails.Details["isolation_verified"] = "false"
				}
				continue

			case "unescaped_reflection":
				// HTML/script execution context: if verified or proved, preserve "true"
				if oldV == "true" || v == "true" {
					canonical.EvidenceDetails.Details[k] = "true"
				} else {
					canonical.EvidenceDetails.Details[k] = "false"
				}
				// If unverified heuristics disagree on reflection escaping, record dispute
				if (oldV == "true" && v == "false") || (oldV == "false" && v == "true") {
					if canonical.Verification.Status != report.VerificationVerified {
						canonical.EvidenceDetails.Details["disputed_unescaped_reflection"] = "true"
						canonical.EvidenceDetails.Details["reflection_context_conflict"] = "divergent output encoding observed across detectors"
					}
				}
				continue

			case "isolation_verified":
				// Tenant isolation claim: check if a cross-tenant leak contradicts it
				hasCrossTenant := canonical.EvidenceDetails.Details["cross_tenant"] == "true" || dup.EvidenceDetails.Details["cross_tenant"] == "true" ||
					canonical.EvidenceDetails.Details["cross_tenant_data_confirmed"] == "true" || dup.EvidenceDetails.Details["cross_tenant_data_confirmed"] == "true"
				if hasCrossTenant {
					canonical.EvidenceDetails.Details["observation_conflict"] = "cross-tenant disclosure observed alongside tenant isolation claim"
					canonical.EvidenceDetails.Details["disputed_tenant_isolation"] = "true"
					canonical.EvidenceDetails.Details[k] = "false"
				} else if oldV == "true" || v == "true" {
					canonical.EvidenceDetails.Details[k] = "true"
				} else {
					canonical.EvidenceDetails.Details[k] = "false"
				}
				continue

			case "auth_required", "auth_enforced":
				// Defensive control requirement: NEVER blindly take "true" if unauthenticated bypass succeeded!
				bypassDemonstrated := isBypassDemonstrated(*canonical) || isBypassDemonstrated(dup)
				if bypassDemonstrated {
					canonical.EvidenceDetails.Details[k] = "false"
					canonical.EvidenceDetails.Details["disputed_"+k] = "true"
					canonical.EvidenceDetails.Details[k+"_contradiction"] = "conflicting observations: one detector observed authentication required while unauthenticated access succeeded on tested route"
				} else if (oldV == "true" && v == "false") || (oldV == "false" && v == "true") {
					canonical.EvidenceDetails.Details[k] = oldV
					canonical.EvidenceDetails.Details["disputed_"+k] = "true"
					canonical.EvidenceDetails.Details[k+"_contradiction"] = "conflicting observations between detectors regarding authentication requirement"
				} else if oldV == "true" || v == "true" {
					canonical.EvidenceDetails.Details[k] = "true"
				} else {
					canonical.EvidenceDetails.Details[k] = "false"
				}
				continue

			case "has_csp":
				if (oldV == "true" && v == "false") || (oldV == "false" && v == "true") {
					canonical.EvidenceDetails.Details[k] = oldV
					canonical.EvidenceDetails.Details["disputed_has_csp"] = "true"
					canonical.EvidenceDetails.Details["csp_divergence"] = "Content-Security-Policy header observed on some responses but absent on others"
				} else if oldV == "true" || v == "true" {
					canonical.EvidenceDetails.Details[k] = "true"
				} else {
					canonical.EvidenceDetails.Details[k] = "false"
				}
				continue

			case "is_defended":
				if (oldV == "true" && v == "false") || (oldV == "false" && v == "true") {
					canonical.EvidenceDetails.Details[k] = oldV
					canonical.EvidenceDetails.Details["disputed_is_defended"] = "true"
					canonical.EvidenceDetails.Details["defense_divergence"] = "conflicting defense status between detectors"
				} else if oldV == "true" || v == "true" {
					canonical.EvidenceDetails.Details[k] = "true"
				} else {
					canonical.EvidenceDetails.Details[k] = "false"
				}
				continue

			case "marker_found", "has_credentials", "negative_proof", "access_denied_confirmed", "baseline_accessible", "exploitable", "in_scope":
				if oldV == "true" || v == "true" {
					canonical.EvidenceDetails.Details[k] = "true"
				} else {
					canonical.EvidenceDetails.Details[k] = "false"
				}
				continue

			case "payload":
				// Keep canonical's payload as primary, and record alternative payloads
				var altPayloads []string
				if existing := canonical.EvidenceDetails.Details["additional_payloads"]; existing != "" {
					altPayloads = strings.Split(existing, " || ")
				}
				hasPayload := false
				for _, p := range altPayloads {
					if p == v {
						hasPayload = true
						break
					}
				}
				if !hasPayload && v != canonical.EvidenceDetails.Details["payload"] {
					altPayloads = append(altPayloads, v)
					sort.Strings(altPayloads)
					canonical.EvidenceDetails.Details["additional_payloads"] = strings.Join(altPayloads, " || ")
				}
				continue

			case "associated_targets":
				tSet := make(map[string]struct{})
				for _, t := range strings.Split(oldV, ",") {
					if t = strings.TrimSpace(t); t != "" {
						tSet[t] = struct{}{}
					}
				}
				for _, t := range strings.Split(v, ",") {
					if t = strings.TrimSpace(t); t != "" {
						tSet[t] = struct{}{}
					}
				}
				var urls []string
				for u := range tSet {
					urls = append(urls, u)
				}
				sort.Strings(urls)
				canonical.EvidenceDetails.Details["associated_targets"] = strings.Join(urls, ", ")
				continue

			case "associated_target_ids":
				tidSet := make(map[string]struct{})
				for _, tid := range strings.Split(oldV, ",") {
					if tid = strings.TrimSpace(tid); tid != "" {
						tidSet[tid] = struct{}{}
					}
				}
				for _, tid := range strings.Split(v, ",") {
					if tid = strings.TrimSpace(tid); tid != "" {
						tidSet[tid] = struct{}{}
					}
				}
				var tids []string
				for tid := range tidSet {
					tids = append(tids, tid)
				}
				sort.Strings(tids)
				canonical.EvidenceDetails.Details["associated_target_ids"] = strings.Join(tids, ",")
				canonical.EvidenceDetails.Details["target_id_count"] = strconv.Itoa(len(tids))
				continue

			case "owner_identity", "unauthorized_identity", "cookie_name", "parameter":
				if !has {
					canonical.EvidenceDetails.Details[k] = v
				} else if oldV != v {
					addAlternativeString(canonical.EvidenceDetails.Details, "alternative_"+k+"s", v)
				}
				continue

			default:
				if !has {
					canonical.EvidenceDetails.Details[k] = v
				} else if oldV != v && !strings.Contains(oldV, v) {
					canonical.EvidenceDetails.Details[k] = oldV + "; " + v
				}
			}
		}

		// Post-merge contradiction reconciliation
		if canonical.EvidenceDetails.Details["cross_tenant"] == "true" || canonical.EvidenceDetails.Details["cross_tenant_data_confirmed"] == "true" {
			if canonical.EvidenceDetails.Details["isolation_verified"] == "true" {
				canonical.EvidenceDetails.Details["observation_conflict"] = "cross-tenant disclosure observed alongside tenant isolation claim"
				canonical.EvidenceDetails.Details["disputed_tenant_isolation"] = "true"
				canonical.EvidenceDetails.Details["isolation_verified"] = "false"
			}
		}
		if isBypassDemonstrated(*canonical) || isBypassDemonstrated(dup) {
			if canonical.EvidenceDetails.Details["auth_required"] == "true" {
				canonical.EvidenceDetails.Details["auth_required"] = "false"
				canonical.EvidenceDetails.Details["disputed_auth_required"] = "true"
				canonical.EvidenceDetails.Details["auth_required_contradiction"] = "conflicting observations: one detector observed authentication required while unauthenticated access succeeded on tested route"
			}
		}
	}

	// 6. Merge PrimaryAssetID & AffectedAssetIDs
	if canonical.PrimaryAssetID == "" && dup.PrimaryAssetID != "" {
		canonical.PrimaryAssetID = dup.PrimaryAssetID
	}

	if len(dup.AffectedAssetIDs) > 0 {
		assetMap := make(map[string]struct{}, len(canonical.AffectedAssetIDs)+len(dup.AffectedAssetIDs))
		for _, a := range canonical.AffectedAssetIDs {
			assetMap[a] = struct{}{}
		}
		for _, a := range dup.AffectedAssetIDs {
			if _, has := assetMap[a]; !has {
				assetMap[a] = struct{}{}
				canonical.AffectedAssetIDs = append(canonical.AffectedAssetIDs, a)
			}
		}
		sort.Strings(canonical.AffectedAssetIDs)
	}

	// 7. Merge Verification SafeCurlCommand, ReproductionSteps, and Limitations
	if canonical.Verification.SafeCurlCommand == "" && dup.Verification.SafeCurlCommand != "" {
		canonical.Verification.SafeCurlCommand = dup.Verification.SafeCurlCommand
	}

	if len(dup.Verification.ReproductionSteps) > 0 {
		stepMap := make(map[string]struct{}, len(canonical.Verification.ReproductionSteps)+len(dup.Verification.ReproductionSteps))
		for _, s := range canonical.Verification.ReproductionSteps {
			stepMap[s] = struct{}{}
		}
		for _, s := range dup.Verification.ReproductionSteps {
			if _, has := stepMap[s]; !has {
				stepMap[s] = struct{}{}
				canonical.Verification.ReproductionSteps = append(canonical.Verification.ReproductionSteps, s)
			}
		}
	}

	if len(dup.Verification.Limitations) > 0 {
		limMap := make(map[string]struct{}, len(canonical.Verification.Limitations)+len(dup.Verification.Limitations))
		for _, l := range canonical.Verification.Limitations {
			limMap[l] = struct{}{}
		}
		for _, l := range dup.Verification.Limitations {
			if _, has := limMap[l]; !has {
				limMap[l] = struct{}{}
				canonical.Verification.Limitations = append(canonical.Verification.Limitations, l)
			}
		}
	}

	if canonical.Verification.Rationale == "" && dup.Verification.Rationale != "" {
		canonical.Verification.Rationale = dup.Verification.Rationale
	} else if dup.Verification.Rationale != "" && !strings.Contains(canonical.Verification.Rationale, dup.Verification.Rationale) {
		canonical.Verification.Rationale = canonical.Verification.Rationale + "; " + dup.Verification.Rationale
	}

	if dup.Verification.Result != "" && !strings.Contains(canonical.Verification.Result, dup.Verification.Result) {
		if canonical.Verification.Result == "" {
			canonical.Verification.Result = dup.Verification.Result
		} else {
			canonical.Verification.Result = canonical.Verification.Result + "; Note: " + dup.Verification.Result
		}
	}

	// 8. Merge RemediationAdvice
	if canonical.RemediationAdvice == nil && dup.RemediationAdvice != nil {
		canonical.RemediationAdvice = dup.RemediationAdvice
	} else if canonical.RemediationAdvice != nil && dup.RemediationAdvice != nil {
		for _, s := range dup.RemediationAdvice.Steps {
			has := false
			for _, es := range canonical.RemediationAdvice.Steps {
				if es == s {
					has = true
					break
				}
			}
			if !has {
				canonical.RemediationAdvice.Steps = append(canonical.RemediationAdvice.Steps, s)
			}
		}
		for _, r := range dup.RemediationAdvice.References {
			has := false
			for _, er := range canonical.RemediationAdvice.References {
				if er == r {
					has = true
					break
				}
			}
			if !has {
				canonical.RemediationAdvice.References = append(canonical.RemediationAdvice.References, r)
			}
		}
	}

	// 9. Timestamp span preservation (earliest timestamp)
	if !dup.Timestamp.IsZero() {
		if canonical.Timestamp.IsZero() || dup.Timestamp.Before(canonical.Timestamp) {
			canonical.Timestamp = dup.Timestamp
		}
	}
}

// -----------------------------------------------------------------------------
// Relationship & Attack Path Remapping
// -----------------------------------------------------------------------------

// RemapRelationships updates source and target finding references to point to canonical findings.
// Removes self-loops produced if both ends of an edge were merged into the same canonical finding.
func RemapRelationships(relationships []Relationship, dupMap map[string]string) []Relationship {
	if len(relationships) == 0 || len(dupMap) == 0 {
		return relationships
	}

	remapped := make([]Relationship, 0, len(relationships))
	seen := make(map[string]struct{})

	for _, rel := range relationships {
		rCopy := rel
		if canonSrc, ok := dupMap[rCopy.SourceFindingID]; ok {
			rCopy.SourceFindingID = canonSrc
		}
		if canonTgt, ok := dupMap[rCopy.TargetFindingID]; ok {
			rCopy.TargetFindingID = canonTgt
		}

		// Avoid self-loops if two findings in the same relationship were consolidated into one
		if rCopy.SourceFindingID == rCopy.TargetFindingID {
			continue
		}

		// Deduplicate identical relationships
		edgeKey := fmt.Sprintf("%s|%s|%s", rCopy.SourceFindingID, string(rCopy.Type), rCopy.TargetFindingID)
		if _, exists := seen[edgeKey]; !exists {
			seen[edgeKey] = struct{}{}
			remapped = append(remapped, rCopy)
		}
	}

	return remapped
}

// RemapAttackPaths updates node IDs and edges in attack paths to point to canonical findings.
func RemapAttackPaths(paths []AttackPath, dupMap map[string]string) []AttackPath {
	if len(paths) == 0 || len(dupMap) == 0 {
		return paths
	}

	remapped := make([]AttackPath, len(paths))
	for i, p := range paths {
		pCopy := p

		// Remap NodeIDs
		var newNodeIDs []string
		seenNodes := make(map[string]struct{})
		for _, nid := range pCopy.NodeIDs {
			targetID := nid
			if canon, ok := dupMap[nid]; ok {
				targetID = canon
			}
			if _, exists := seenNodes[targetID]; !exists {
				seenNodes[targetID] = struct{}{}
				newNodeIDs = append(newNodeIDs, targetID)
			}
		}
		pCopy.NodeIDs = newNodeIDs

		// Remap Nodes slice if present
		if len(pCopy.Nodes) > 0 {
			var newNodes []NormalizedFinding
			seenNodeMap := make(map[string]struct{})
			for _, n := range pCopy.Nodes {
				nCopy := n
				if canon, ok := dupMap[nCopy.ID]; ok {
					nCopy.ID = canon
				}
				if _, exists := seenNodeMap[nCopy.ID]; !exists {
					seenNodeMap[nCopy.ID] = struct{}{}
					newNodes = append(newNodes, nCopy)
				}
			}
			pCopy.Nodes = newNodes
		}

		// Remap Edges
		var newEdges []Relationship
		for _, e := range pCopy.Edges {
			eCopy := e
			if canonSrc, ok := dupMap[eCopy.SourceFindingID]; ok {
				eCopy.SourceFindingID = canonSrc
			}
			if canonTgt, ok := dupMap[eCopy.TargetFindingID]; ok {
				eCopy.TargetFindingID = canonTgt
			}
			if eCopy.SourceFindingID != eCopy.TargetFindingID {
				newEdges = append(newEdges, eCopy)
			}
		}
		pCopy.Edges = newEdges

		remapped[i] = pCopy
	}

	return remapped
}
