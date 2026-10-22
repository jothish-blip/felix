package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ComputeFingerprint generates a stable SHA-256 identity fingerprint for deduplication.
// It incorporates security identity without relying on variable evidence phrasing.
func ComputeFingerprint(target, category, endpoint, method, identityKey string) string {
	h := sha256.New()
	cleanTarget := strings.ToLower(strings.TrimSpace(target))
	cleanCategory := strings.ToLower(strings.TrimSpace(category))
	cleanEndpoint := strings.ToLower(strings.TrimSpace(endpoint))
	cleanMethod := strings.ToUpper(strings.TrimSpace(method))
	cleanKey := strings.TrimSpace(identityKey)

	payload := fmt.Sprintf("%s|%s|%s|%s|%s", cleanTarget, cleanCategory, cleanEndpoint, cleanMethod, cleanKey)
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

// ComputeFindingFingerprint computes a canonical SHA-256 fingerprint for finding deduplication.
func ComputeFindingFingerprint(target, category, endpoint, method, identityKey string) string {
	return ComputeFingerprint(target, category, endpoint, method, identityKey)
}

// ComputeStableFindingID generates a deterministic, stable finding identifier (fnd_<hex>).
func ComputeStableFindingID(target, ruleID, category, endpoint, method, identityKey string) string {
	h := sha256.New()
	cleanTarget := NormalizeURL(target)
	cleanRule := strings.ToUpper(strings.TrimSpace(ruleID))
	cleanCategory := NormalizeCategory(category)
	cleanEndpoint := NormalizeURL(endpoint)
	cleanMethod := NormalizeMethod(method)
	cleanKey := strings.TrimSpace(identityKey)

	payload := fmt.Sprintf("%s|%s|%s|%s|%s|%s", cleanTarget, cleanRule, cleanCategory, cleanEndpoint, cleanMethod, cleanKey)
	h.Write([]byte(payload))
	sum := h.Sum(nil)
	return fmt.Sprintf("fnd_%s", hex.EncodeToString(sum[:12])) // 24 hex characters
}

// DeduplicatorFunc defines a function signature for finding deduplication engines.
type DeduplicatorFunc func(findings []Finding) []Finding

var globalDeduplicator DeduplicatorFunc

// RegisterDeduplicator registers the canonical finding deduplicator (e.g. from pkg/correlation).
func RegisterDeduplicator(fn DeduplicatorFunc) {
	globalDeduplicator = fn
}

// DeduplicateFindings merges equivalent findings into a single canonical entry with aggregated evidence.
// Uses the registered canonical deduplicator if available, or falls back to legacy deduplication.
func DeduplicateFindings(findings []Finding) []Finding {
	if globalDeduplicator != nil {
		return globalDeduplicator(findings)
	}
	return legacyDeduplicateFindings(findings)
}

func extractBoundaries(f Finding) (string, string) {
	if f.EvidenceDetails.Details == nil {
		return "", ""
	}
	return strings.TrimSpace(f.EvidenceDetails.Details["tenant_id"]),
		strings.TrimSpace(f.EvidenceDetails.Details["account_id"])
}

func legacyDeduplicateFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}

	type groupEntry struct {
		key   string
		items []Finding
	}
	groupMap := make(map[string]*groupEntry)
	var groupKeys []string

	for _, rawF := range findings {
		norm := NormalizeFinding(rawF)
		fp := norm.Fingerprint

		if fp == "" || strings.HasPrefix(fp, "ambiguous:") {
			tok := norm.ID
			if tok == "" {
				tok = norm.Title
			}
			uniqueKey := fmt.Sprintf("ambiguous:%s:%s", tok, fp)
			entry := &groupEntry{key: uniqueKey, items: []Finding{norm}}
			groupMap[uniqueKey] = entry
			groupKeys = append(groupKeys, uniqueKey)
			continue
		}

		tenantID, accountID := extractBoundaries(norm)
		groupKey := fmt.Sprintf("%s|t:%s|a:%s", fp, tenantID, accountID)

		if entry, exists := groupMap[groupKey]; exists {
			entry.items = append(entry.items, norm)
		} else {
			entry := &groupEntry{key: groupKey, items: []Finding{norm}}
			groupMap[groupKey] = entry
			groupKeys = append(groupKeys, groupKey)
		}
	}

	result := make([]Finding, 0, len(groupKeys))
	for _, gk := range groupKeys {
		entry := groupMap[gk]
		items := entry.items

		if len(items) == 1 {
			single := items[0]
			if single.ScoreExplanation == nil || single.Score <= 0 {
				expl := ExplainFindingScore(single)
				single.Score = expl.Score
				single.ScoreExplanation = &expl
				if single.EvidenceDetails.Details == nil {
					single.EvidenceDetails.Details = make(map[string]string)
				}
				single.EvidenceDetails.Details["score_formula"] = expl.Formula
				single.EvidenceDetails.Details["score_rationale"] = expl.Rationale
			}
			result = append(result, single)
			continue
		}

		// Multi-item group: rank by authority to pick canonical representative
		sort.Slice(items, func(i, j int) bool {
			a, b := items[i], items[j]
			rankVA := VerificationRank(a.Verification.Status)
			rankVB := VerificationRank(b.Verification.Status)
			if rankVA != rankVB {
				return rankVA > rankVB
			}
			rankSA := FindingStatusRank(a.Status)
			rankSB := FindingStatusRank(b.Status)
			if rankSA != rankSB {
				return rankSA > rankSB
			}
			methodA := 0
			if a.AnalysisMethod == AnalysisMethodActive && a.Verification.Status == VerificationVerified {
				methodA = 2
			} else if a.AnalysisMethod == AnalysisMethodActive {
				methodA = 1
			}
			methodB := 0
			if b.AnalysisMethod == AnalysisMethodActive && b.Verification.Status == VerificationVerified {
				methodB = 2
			} else if b.AnalysisMethod == AnalysisMethodActive {
				methodB = 1
			}
			if methodA != methodB {
				return methodA > methodB
			}
			rankSevA := SeverityRank(a.Severity)
			rankSevB := SeverityRank(b.Severity)
			if rankSevA != rankSevB {
				return rankSevA > rankSevB
			}
			rankCA := ConfidenceRank(a.Confidence)
			rankCB := ConfidenceRank(b.Confidence)
			if rankCA != rankCB {
				return rankCA > rankCB
			}
			if !a.Timestamp.IsZero() && !b.Timestamp.IsZero() && !a.Timestamp.Equal(b.Timestamp) {
				return a.Timestamp.Before(b.Timestamp)
			}
			return a.ID < b.ID
		})

		canonical := items[0]
		var mergedIDs []string
		for _, dup := range items[1:] {
			mergedIDs = append(mergedIDs, dup.ID)
			mergeDuplicateLegacy(&canonical, dup)
		}
		sort.Strings(mergedIDs)

		if canonical.EvidenceDetails.Details == nil {
			canonical.EvidenceDetails.Details = make(map[string]string)
		}
		canonical.EvidenceDetails.Details["duplicate_count"] = strconv.Itoa(len(mergedIDs))
		canonical.EvidenceDetails.Details["duplicate_finding_ids"] = strings.Join(mergedIDs, ",")
		canonical.EvidenceDetails.Details["canonical_finding_id"] = canonical.ID

		expl := ExplainFindingScore(canonical)
		canonical.Score = expl.Score
		canonical.ScoreExplanation = &expl
		canonical.EvidenceDetails.Details["score_formula"] = expl.Formula
		canonical.EvidenceDetails.Details["score_rationale"] = expl.Rationale

		result = append(result, canonical)
	}

	return result
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

// isBypassDemonstrated verifies whether a finding affirmatively proves an authentication bypass.
// HTTP 200 alone cannot establish an authentication bypass without affirmative evidence,
// bypass context, and absence of refutation.
func isBypassDemonstrated(f Finding) bool {
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
		f.Verification.Status == VerificationVerified
	if !hasEvidence {
		return false
	}
	if f.Verification.Status == VerificationNotExposed {
		return false
	}
	return true
}

func mergeDuplicateLegacy(existing *Finding, norm Finding) {
	// 1. Merge Evidence Observation text without duplicating substrings
	if norm.Evidence != "" && !strings.Contains(existing.Evidence, norm.Evidence) {
		if existing.Evidence == "" {
			existing.Evidence = norm.Evidence
		} else {
			existing.Evidence = existing.Evidence + "; Also: " + norm.Evidence
		}
	}

	if existing.EvidenceDetails.Observation == "" {
		existing.EvidenceDetails.Observation = norm.EvidenceDetails.Observation
	} else if norm.EvidenceDetails.Observation != "" && !strings.Contains(existing.EvidenceDetails.Observation, norm.EvidenceDetails.Observation) {
		existing.EvidenceDetails.Observation = existing.EvidenceDetails.Observation + "; Also: " + norm.EvidenceDetails.Observation
	}

	// 2. Merge Location
	if norm.EvidenceDetails.Location != "" && !strings.Contains(existing.EvidenceDetails.Location, norm.EvidenceDetails.Location) {
		if existing.EvidenceDetails.Location == "" {
			existing.EvidenceDetails.Location = norm.EvidenceDetails.Location
		} else {
			existing.EvidenceDetails.Location = existing.EvidenceDetails.Location + ", " + norm.EvidenceDetails.Location
		}
	}

	// 3. Merge Negative Evidence
	if existing.EvidenceDetails.NegativeEvidence == "" {
		existing.EvidenceDetails.NegativeEvidence = norm.EvidenceDetails.NegativeEvidence
	} else if norm.EvidenceDetails.NegativeEvidence != "" && !strings.Contains(existing.EvidenceDetails.NegativeEvidence, norm.EvidenceDetails.NegativeEvidence) {
		existing.EvidenceDetails.NegativeEvidence = existing.EvidenceDetails.NegativeEvidence + " " + norm.EvidenceDetails.NegativeEvidence
	}

	// 4. Merge Expected & Observed Behaviors
	if existing.EvidenceDetails.ExpectedBehavior == "" && norm.EvidenceDetails.ExpectedBehavior != "" {
		existing.EvidenceDetails.ExpectedBehavior = norm.EvidenceDetails.ExpectedBehavior
	} else if norm.EvidenceDetails.ExpectedBehavior != "" && !strings.Contains(existing.EvidenceDetails.ExpectedBehavior, norm.EvidenceDetails.ExpectedBehavior) {
		existing.EvidenceDetails.ExpectedBehavior = existing.EvidenceDetails.ExpectedBehavior + "; " + norm.EvidenceDetails.ExpectedBehavior
	}
	if existing.EvidenceDetails.ObservedBehavior == "" && norm.EvidenceDetails.ObservedBehavior != "" {
		existing.EvidenceDetails.ObservedBehavior = norm.EvidenceDetails.ObservedBehavior
	} else if norm.EvidenceDetails.ObservedBehavior != "" && !strings.Contains(existing.EvidenceDetails.ObservedBehavior, norm.EvidenceDetails.ObservedBehavior) {
		existing.EvidenceDetails.ObservedBehavior = existing.EvidenceDetails.ObservedBehavior + "; " + norm.EvidenceDetails.ObservedBehavior
	}

	// 5. Merge HTTP & Detection metadata
	if existing.EvidenceDetails.HTTPStatus == 0 && norm.EvidenceDetails.HTTPStatus != 0 {
		existing.EvidenceDetails.HTTPStatus = norm.EvidenceDetails.HTTPStatus
	} else if existing.EvidenceDetails.HTTPStatus != 0 && norm.EvidenceDetails.HTTPStatus != 0 && existing.EvidenceDetails.HTTPStatus != norm.EvidenceDetails.HTTPStatus {
		if existing.EvidenceDetails.Details == nil {
			existing.EvidenceDetails.Details = make(map[string]string)
		}
		addAlternativeStatus(existing.EvidenceDetails.Details, norm.EvidenceDetails.HTTPStatus)
	}

	if existing.EvidenceDetails.HTTPMethod == "" && norm.EvidenceDetails.HTTPMethod != "" {
		existing.EvidenceDetails.HTTPMethod = norm.EvidenceDetails.HTTPMethod
	} else if existing.EvidenceDetails.HTTPMethod != "" && norm.EvidenceDetails.HTTPMethod != "" && !strings.EqualFold(existing.EvidenceDetails.HTTPMethod, norm.EvidenceDetails.HTTPMethod) {
		if existing.EvidenceDetails.Details == nil {
			existing.EvidenceDetails.Details = make(map[string]string)
		}
		addAlternativeString(existing.EvidenceDetails.Details, "alternative_http_methods", norm.EvidenceDetails.HTTPMethod)
	}

	if existing.EvidenceDetails.ContentType == "" && norm.EvidenceDetails.ContentType != "" {
		existing.EvidenceDetails.ContentType = norm.EvidenceDetails.ContentType
	} else if existing.EvidenceDetails.ContentType != "" && norm.EvidenceDetails.ContentType != "" && !strings.EqualFold(existing.EvidenceDetails.ContentType, norm.EvidenceDetails.ContentType) {
		if existing.EvidenceDetails.Details == nil {
			existing.EvidenceDetails.Details = make(map[string]string)
		}
		addAlternativeString(existing.EvidenceDetails.Details, "alternative_content_types", norm.EvidenceDetails.ContentType)
	}

	if existing.EvidenceDetails.DetectionMethod == "" && norm.EvidenceDetails.DetectionMethod != "" {
		existing.EvidenceDetails.DetectionMethod = norm.EvidenceDetails.DetectionMethod
	}
	if existing.EvidenceDetails.DetectionStatus == "" && norm.EvidenceDetails.DetectionStatus != "" {
		existing.EvidenceDetails.DetectionStatus = norm.EvidenceDetails.DetectionStatus
	}

	// Multi-target URL footprint preservation
	if norm.Target != "" && existing.Target != "" && !strings.EqualFold(existing.Target, norm.Target) {
		if existing.EvidenceDetails.Details == nil {
			existing.EvidenceDetails.Details = make(map[string]string)
		}
		addTargetURL(existing.EvidenceDetails.Details, existing.Target)
		addTargetURL(existing.EvidenceDetails.Details, norm.Target)
	}

	// 6. Merge Evidence Provenance
	if existing.Provenance == nil && norm.Provenance != nil {
		existing.Provenance = norm.Provenance
		existing.EvidenceDetails.Provenance = norm.Provenance
	} else if existing.Provenance != nil && norm.Provenance != nil {
		if existing.Provenance.AssetID == "" && norm.Provenance.AssetID != "" {
			existing.Provenance.AssetID = norm.Provenance.AssetID
		}
		if existing.Provenance.VerificationContext == "" && norm.Provenance.VerificationContext != "" {
			existing.Provenance.VerificationContext = norm.Provenance.VerificationContext
		}
		existing.EvidenceDetails.Provenance = existing.Provenance
	}
	if norm.Provenance != nil && norm.Provenance.EvidenceID != "" {
		if existing.EvidenceDetails.Details == nil {
			existing.EvidenceDetails.Details = make(map[string]string)
		}
		evSet := make(map[string]struct{})
		if existingIDs := existing.EvidenceDetails.Details["merged_evidence_ids"]; existingIDs != "" {
			for _, id := range strings.Split(existingIDs, ",") {
				if id = strings.TrimSpace(id); id != "" {
					evSet[id] = struct{}{}
				}
			}
		} else if existing.Provenance != nil && existing.Provenance.EvidenceID != "" {
			evSet[existing.Provenance.EvidenceID] = struct{}{}
		}
		evSet[norm.Provenance.EvidenceID] = struct{}{}
		var evIDs []string
		for id := range evSet {
			evIDs = append(evIDs, id)
		}
		sort.Strings(evIDs)
		existing.EvidenceDetails.Details["merged_evidence_ids"] = strings.Join(evIDs, ",")
	}

	// 7. Merge Details map with field-specific semantics
	if len(norm.EvidenceDetails.Details) > 0 {
		if existing.EvidenceDetails.Details == nil {
			existing.EvidenceDetails.Details = make(map[string]string)
		}
		for k, v := range norm.EvidenceDetails.Details {
			if k == "score_formula" || k == "score_rationale" || k == "duplicate_finding_ids" || k == "duplicate_count" || k == "canonical_finding_id" {
				continue
			}
			oldV, has := existing.EvidenceDetails.Details[k]

			switch k {
			// A. Test execution / coverage flags: if either detector tested it, the test was attempted
			case "unauth_bypass_tested":
				if oldV == "true" || v == "true" {
					existing.EvidenceDetails.Details[k] = "true"
				} else {
					existing.EvidenceDetails.Details[k] = "false"
				}
				continue

			// B. Positive Vulnerability Evidence Flags: affirmative leak proof is preserved
			case "cross_tenant", "cross_tenant_data_confirmed":
				if oldV == "true" || v == "true" {
					existing.EvidenceDetails.Details[k] = "true"
				} else {
					existing.EvidenceDetails.Details[k] = "false"
				}
				// Contradiction detection: check if tenant isolation was also claimed
				if (oldV == "true" || v == "true") && (existing.EvidenceDetails.Details["isolation_verified"] == "true" || norm.EvidenceDetails.Details["isolation_verified"] == "true") {
					existing.EvidenceDetails.Details["observation_conflict"] = "cross-tenant disclosure observed alongside tenant isolation claim"
					existing.EvidenceDetails.Details["disputed_tenant_isolation"] = "true"
					existing.EvidenceDetails.Details["isolation_verified"] = "false"
				}
				continue

			case "unescaped_reflection":
				if oldV == "true" || v == "true" {
					existing.EvidenceDetails.Details[k] = "true"
				} else {
					existing.EvidenceDetails.Details[k] = "false"
				}
				if (oldV == "true" && v == "false") || (oldV == "false" && v == "true") {
					if existing.Verification.Status != VerificationVerified {
						existing.EvidenceDetails.Details["disputed_unescaped_reflection"] = "true"
						existing.EvidenceDetails.Details["reflection_context_conflict"] = "divergent output encoding observed across detectors"
					}
				}
				continue

			case "isolation_verified":
				hasCrossTenant := existing.EvidenceDetails.Details["cross_tenant"] == "true" || norm.EvidenceDetails.Details["cross_tenant"] == "true" ||
					existing.EvidenceDetails.Details["cross_tenant_data_confirmed"] == "true" || norm.EvidenceDetails.Details["cross_tenant_data_confirmed"] == "true"
				if hasCrossTenant {
					existing.EvidenceDetails.Details["observation_conflict"] = "cross-tenant disclosure observed alongside tenant isolation claim"
					existing.EvidenceDetails.Details["disputed_tenant_isolation"] = "true"
					existing.EvidenceDetails.Details[k] = "false"
				} else if oldV == "true" || v == "true" {
					existing.EvidenceDetails.Details[k] = "true"
				} else {
					existing.EvidenceDetails.Details[k] = "false"
				}
				continue

			case "auth_required", "auth_enforced":
				bypassDemonstrated := isBypassDemonstrated(*existing) || isBypassDemonstrated(norm)
				if bypassDemonstrated {
					existing.EvidenceDetails.Details[k] = "false"
					existing.EvidenceDetails.Details["disputed_"+k] = "true"
					existing.EvidenceDetails.Details[k+"_contradiction"] = "conflicting observations: one detector observed authentication required while unauthenticated access succeeded on tested route"
				} else if (oldV == "true" && v == "false") || (oldV == "false" && v == "true") {
					existing.EvidenceDetails.Details[k] = oldV
					existing.EvidenceDetails.Details["disputed_"+k] = "true"
					existing.EvidenceDetails.Details[k+"_contradiction"] = "conflicting observations between detectors regarding authentication requirement"
				} else if oldV == "true" || v == "true" {
					existing.EvidenceDetails.Details[k] = "true"
				} else {
					existing.EvidenceDetails.Details[k] = "false"
				}
				continue

			case "has_csp":
				if (oldV == "true" && v == "false") || (oldV == "false" && v == "true") {
					existing.EvidenceDetails.Details[k] = oldV
					existing.EvidenceDetails.Details["disputed_has_csp"] = "true"
					existing.EvidenceDetails.Details["csp_divergence"] = "Content-Security-Policy header observed on some responses but absent on others"
				} else if oldV == "true" || v == "true" {
					existing.EvidenceDetails.Details[k] = "true"
				} else {
					existing.EvidenceDetails.Details[k] = "false"
				}
				continue

			case "is_defended":
				if (oldV == "true" && v == "false") || (oldV == "false" && v == "true") {
					existing.EvidenceDetails.Details[k] = oldV
					existing.EvidenceDetails.Details["disputed_is_defended"] = "true"
					existing.EvidenceDetails.Details["defense_divergence"] = "conflicting defense status between detectors"
				} else if oldV == "true" || v == "true" {
					existing.EvidenceDetails.Details[k] = "true"
				} else {
					existing.EvidenceDetails.Details[k] = "false"
				}
				continue

			case "marker_found", "has_credentials", "negative_proof", "access_denied_confirmed", "baseline_accessible", "exploitable", "in_scope":
				if oldV == "true" || v == "true" {
					existing.EvidenceDetails.Details[k] = "true"
				} else {
					existing.EvidenceDetails.Details[k] = "false"
				}
				continue

			case "payload":
				var altPayloads []string
				if exist := existing.EvidenceDetails.Details["additional_payloads"]; exist != "" {
					altPayloads = strings.Split(exist, " || ")
				}
				hasPayload := false
				for _, p := range altPayloads {
					if p == v {
						hasPayload = true
						break
					}
				}
				if !hasPayload && v != existing.EvidenceDetails.Details["payload"] {
					altPayloads = append(altPayloads, v)
					sort.Strings(altPayloads)
					existing.EvidenceDetails.Details["additional_payloads"] = strings.Join(altPayloads, " || ")
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
				existing.EvidenceDetails.Details["associated_targets"] = strings.Join(urls, ", ")
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
				existing.EvidenceDetails.Details["associated_target_ids"] = strings.Join(tids, ",")
				existing.EvidenceDetails.Details["target_id_count"] = strconv.Itoa(len(tids))
				continue

			case "owner_identity", "unauthorized_identity", "cookie_name", "parameter":
				if !has {
					existing.EvidenceDetails.Details[k] = v
				} else if oldV != v {
					addAlternativeString(existing.EvidenceDetails.Details, "alternative_"+k+"s", v)
				}
				continue

			default:
				if !has {
					existing.EvidenceDetails.Details[k] = v
				} else if oldV != v && !strings.Contains(oldV, v) {
					existing.EvidenceDetails.Details[k] = oldV + "; " + v
				}
			}
		}

		// Post-merge contradiction reconciliation
		if existing.EvidenceDetails.Details["cross_tenant"] == "true" || existing.EvidenceDetails.Details["cross_tenant_data_confirmed"] == "true" {
			if existing.EvidenceDetails.Details["isolation_verified"] == "true" {
				existing.EvidenceDetails.Details["observation_conflict"] = "cross-tenant disclosure observed alongside tenant isolation claim"
				existing.EvidenceDetails.Details["disputed_tenant_isolation"] = "true"
				existing.EvidenceDetails.Details["isolation_verified"] = "false"
			}
		}
		if isBypassDemonstrated(*existing) || isBypassDemonstrated(norm) {
			if existing.EvidenceDetails.Details["auth_required"] == "true" {
				existing.EvidenceDetails.Details["auth_required"] = "false"
				existing.EvidenceDetails.Details["disputed_auth_required"] = "true"
				existing.EvidenceDetails.Details["auth_required_contradiction"] = "conflicting observations: one detector observed authentication required while unauthenticated access succeeded on tested route"
			}
		}
	}

	// Merge PrimaryAssetID
	if existing.PrimaryAssetID == "" && norm.PrimaryAssetID != "" {
		existing.PrimaryAssetID = norm.PrimaryAssetID
	}

	// Merge AffectedAssetIDs
	if len(norm.AffectedAssetIDs) > 0 {
		assetMap := make(map[string]struct{}, len(existing.AffectedAssetIDs)+len(norm.AffectedAssetIDs))
		for _, a := range existing.AffectedAssetIDs {
			assetMap[a] = struct{}{}
		}
		for _, a := range norm.AffectedAssetIDs {
			if _, has := assetMap[a]; !has {
				assetMap[a] = struct{}{}
				existing.AffectedAssetIDs = append(existing.AffectedAssetIDs, a)
			}
		}
		sort.Strings(existing.AffectedAssetIDs)
	}

	// Merge RemediationAdvice
	if existing.RemediationAdvice == nil && norm.RemediationAdvice != nil {
		existing.RemediationAdvice = norm.RemediationAdvice
	} else if existing.RemediationAdvice != nil && norm.RemediationAdvice != nil {
		for _, s := range norm.RemediationAdvice.Steps {
			has := false
			for _, es := range existing.RemediationAdvice.Steps {
				if es == s {
					has = true
					break
				}
			}
			if !has {
				existing.RemediationAdvice.Steps = append(existing.RemediationAdvice.Steps, s)
			}
		}
		for _, r := range norm.RemediationAdvice.References {
			has := false
			for _, er := range existing.RemediationAdvice.References {
				if er == r {
					has = true
					break
				}
			}
			if !has {
				existing.RemediationAdvice.References = append(existing.RemediationAdvice.References, r)
			}
		}
	}

	// Merge Verification Limitations and Rationale
	if len(norm.Verification.Limitations) > 0 {
		limMap := make(map[string]struct{}, len(existing.Verification.Limitations)+len(norm.Verification.Limitations))
		for _, lim := range existing.Verification.Limitations {
			limMap[lim] = struct{}{}
		}
		for _, lim := range norm.Verification.Limitations {
			if _, has := limMap[lim]; !has {
				limMap[lim] = struct{}{}
				existing.Verification.Limitations = append(existing.Verification.Limitations, lim)
			}
		}
	}
	if existing.Verification.Rationale == "" && norm.Verification.Rationale != "" {
		existing.Verification.Rationale = norm.Verification.Rationale
	} else if norm.Verification.Rationale != "" && !strings.Contains(existing.Verification.Rationale, norm.Verification.Rationale) {
		existing.Verification.Rationale = existing.Verification.Rationale + "; " + norm.Verification.Rationale
	}

	if VerificationRank(norm.Verification.Status) > VerificationRank(existing.Verification.Status) {
		existing.Verification = norm.Verification
	} else if norm.Verification.Result != "" && !strings.Contains(existing.Verification.Result, norm.Verification.Result) {
		existing.Verification.Result = existing.Verification.Result + "; Note: " + norm.Verification.Result
	}

	if existing.Verification.SafeCurlCommand == "" && norm.Verification.SafeCurlCommand != "" {
		existing.Verification.SafeCurlCommand = norm.Verification.SafeCurlCommand
	} else if existing.Verification.SafeCurlCommand != "" && norm.Verification.SafeCurlCommand != "" && existing.Verification.SafeCurlCommand != norm.Verification.SafeCurlCommand {
		if existing.EvidenceDetails.Details == nil {
			existing.EvidenceDetails.Details = make(map[string]string)
		}
		addAlternativeString(existing.EvidenceDetails.Details, "alternative_curl_commands", norm.Verification.SafeCurlCommand)
	}
	if len(existing.Verification.ReproductionSteps) == 0 && len(norm.Verification.ReproductionSteps) > 0 {
		existing.Verification.ReproductionSteps = norm.Verification.ReproductionSteps
	}

	// Merge Framework classification fields
	if (existing.Framework == "" || existing.Framework == "generic") && norm.Framework != "" && norm.Framework != "generic" {
		existing.Framework = norm.Framework
	}
	if (existing.FrameworkVersion == "" || existing.FrameworkVersion == "generic") && norm.FrameworkVersion != "" && norm.FrameworkVersion != "generic" {
		existing.FrameworkVersion = norm.FrameworkVersion
	}
	if existing.ClassificationOutcome == "" || (norm.ClassificationOutcome == OutcomeConfirmed && existing.ClassificationOutcome != OutcomeConfirmed) {
		existing.ClassificationOutcome = norm.ClassificationOutcome
	}
	if existing.Reachability == "" || (norm.Reachability == ReachabilityConfirmedReachable && existing.Reachability != ReachabilityConfirmedReachable) {
		existing.Reachability = norm.Reachability
	}
	if existing.AuthContext == "" || existing.AuthContext == AuthContextUnknown {
		existing.AuthContext = norm.AuthContext
	}

	// Timestamp span (earliest timestamp)
	if !norm.Timestamp.IsZero() {
		if existing.Timestamp.IsZero() || norm.Timestamp.Before(existing.Timestamp) {
			existing.Timestamp = norm.Timestamp
		}
	}
}
