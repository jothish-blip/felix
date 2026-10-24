package monitor

import (
	"sort"
	"strings"
	"time"

	"felix/pkg/api"
	"felix/pkg/crawler"
)

// SnapshotBuildOptions controls snapshot assembly and normalization boundaries.
type SnapshotBuildOptions struct {
	TargetID    string
	TargetName  string
	BaseURLs    []string
	IsComplete  bool
	Truncated   bool
	Limitations []string
	Metadata    map[string]string
}

// BuildSnapshot synthesizes a canonical Snapshot from Phase 14 discovery, reconciliation, and live probing data.
func BuildSnapshot(
	candidates []crawler.RouteCandidate,
	recon *api.ReconciliationReport,
	prober *api.ProberReport,
	opts SnapshotBuildOptions,
) *Snapshot {
	now := time.Now().UTC()
	targetID := strings.TrimSpace(opts.TargetID)
	if targetID == "" {
		if len(opts.BaseURLs) > 0 {
			targetID = opts.BaseURLs[0]
		} else {
			targetID = "default_target"
		}
	}

	snapID := GenerateSnapshotID(targetID, now)
	snap := &Snapshot{
		ID:            snapID,
		SchemaVersion: CurrentSnapshotSchemaVersion,
		TargetID:      targetID,
		TargetName:    opts.TargetName,
		BaseURLs:      opts.BaseURLs,
		CollectedAt:   now,
		IsComplete:    opts.IsComplete,
		Truncated:     opts.Truncated,
		Limitations:   opts.Limitations,
		Metadata:      opts.Metadata,
	}

	// Index reconciliation items by canonical path
	reconMap := make(map[string]api.ReconciliationItem)
	if recon != nil {
		for _, item := range recon.Items {
			canon := strings.ToLower(strings.TrimSpace(item.CanonicalPath))
			reconMap[canon] = item
		}
		for _, item := range recon.ShadowSurface {
			canon := strings.ToLower(strings.TrimSpace(item.CanonicalPath))
			reconMap[canon] = item
		}
	}

	// Index prober results by canonical path
	proberMap := make(map[string]api.ProbeResult)
	if prober != nil {
		for _, res := range prober.Results {
			canon := strings.ToLower(strings.TrimSpace(res.CanonicalPath))
			proberMap[canon] = res
		}
	}

	// Group route candidates by canonical path
	routeGroup := make(map[string]*SurfaceRoute)

	for _, cand := range candidates {
		canon := api.CanonicalizeRoutePath(cand.Path)
		normKey := strings.ToLower(strings.TrimSpace(canon))

		existing, exists := routeGroup[normKey]
		if !exists {
			method := strings.ToUpper(strings.TrimSpace(cand.HTTPMethod))
			if method == "" || method == "UNKNOWN" {
				method = "GET" // Default safe inspection assumption
			}

			sr := &SurfaceRoute{
				CanonicalPath:        canon,
				RawPath:              cand.Path,
				Methods:              []string{method},
				DocumentationStatus:  DocStatusUndocumented,
				DiscoverySource:      string(cand.SourceType),
				DiscoveryConfidence:  string(cand.Confidence),
				OriginatingAsset:     cand.OriginatingAsset,
				Evidence:             cand.Evidence,
			}

			// Extract parameter shapes
			sr.ParameterShapes = extractParameterShapes(cand.Path)

			routeGroup[normKey] = sr
			existing = sr
		} else {
			// Merge additional methods
			candMethod := strings.ToUpper(strings.TrimSpace(cand.HTTPMethod))
			if candMethod != "" && candMethod != "UNKNOWN" {
				hasMethod := false
				for _, m := range existing.Methods {
					if m == candMethod {
						hasMethod = true
						break
					}
				}
				if !hasMethod {
					existing.Methods = append(existing.Methods, candMethod)
				}
			}
			// Merge parameter shapes
			candParams := extractParameterShapes(cand.Path)
			for _, cp := range candParams {
				hasParam := false
				for _, ep := range existing.ParameterShapes {
					if ep == cp {
						hasParam = true
						break
					}
				}
				if !hasParam {
					existing.ParameterShapes = append(existing.ParameterShapes, cp)
				}
			}
		}

		// Enrich with reconciliation metadata
		if ri, ok := reconMap[normKey]; ok {
			switch ri.Classification {
			case api.ClassificationDocumentedMatch:
				existing.DocumentationStatus = DocStatusDocumented
			case api.ClassificationUndocumentedCandidate:
				existing.DocumentationStatus = DocStatusUndocumented
			case api.ClassificationAmbiguousMatch:
				existing.DocumentationStatus = DocStatusAmbiguous
			}
			existing.MatchedSpec = ri.MatchedSpec
			existing.OperationID = ri.MatchedOperationID

			for _, hit := range ri.SensitiveHits {
				typeStr := string(hit.Type)
				hasHit := false
				for _, sh := range existing.SensitiveIdentifiers {
					if sh == typeStr {
						hasHit = true
						break
					}
				}
				if !hasHit {
					existing.SensitiveIdentifiers = append(existing.SensitiveIdentifiers, typeStr)
				}
			}
		}

		// Enrich with probe observations
		if pr, ok := proberMap[normKey]; ok {
			existing.ProbeStatus = string(pr.Classification)
			existing.Reachability = string(pr.Reachability)
		}
	}

	// Also include any documented operations from reconciliation report not found in client bundles
	if recon != nil {
		for _, item := range recon.Items {
			if item.Classification != api.ClassificationDocumentedMatch {
				continue
			}
			normKey := strings.ToLower(strings.TrimSpace(item.CanonicalPath))
			if _, exists := routeGroup[normKey]; !exists {
				method := strings.ToUpper(strings.TrimSpace(item.Method))
				if method == "" {
					method = "GET"
				}
				sr := &SurfaceRoute{
					CanonicalPath:       item.CanonicalPath,
					RawPath:             item.Path,
					Methods:             []string{method},
					DocumentationStatus: DocStatusDocumented,
					DiscoverySource:     "SPECIFICATION",
					DiscoveryConfidence: "CONFIRMED",
					MatchedSpec:         item.MatchedSpec,
					OperationID:         item.MatchedOperationID,
				}
				for _, hit := range item.SensitiveHits {
					sr.SensitiveIdentifiers = append(sr.SensitiveIdentifiers, string(hit.Type))
				}
				routeGroup[normKey] = sr
			}
		}
	}

	// Assemble final routes slice stably
	for _, sr := range routeGroup {
		sort.Strings(sr.Methods)
		sort.Strings(sr.ParameterShapes)
		sort.Strings(sr.SensitiveIdentifiers)
		snap.Routes = append(snap.Routes, *sr)
	}

	sort.Slice(snap.Routes, func(i, j int) bool {
		return snap.Routes[i].CanonicalPath < snap.Routes[j].CanonicalPath
	})

	return snap
}

// extractParameterShapes extracts normalized parameter names from URL path segments and query strings.
func extractParameterShapes(path string) []string {
	var shapes []string
	seen := make(map[string]bool)

	// Check path parameters like {id}, :id, {user_id}
	parts := strings.Split(path, "/")
	for _, seg := range parts {
		seg = strings.TrimSpace(seg)
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			paramName := strings.Trim(seg, "{}")
			if paramName != "" && !seen[paramName] {
				shapes = append(shapes, paramName)
				seen[paramName] = true
			}
		} else if strings.HasPrefix(seg, ":") {
			paramName := strings.TrimPrefix(seg, ":")
			if paramName != "" && !seen[paramName] {
				shapes = append(shapes, paramName)
				seen[paramName] = true
			}
		}
	}

	// Check query parameters like ?user_id=123&page=1
	if qIdx := strings.Index(path, "?"); qIdx != -1 {
		query := path[qIdx+1:]
		pairs := strings.Split(query, "&")
		for _, pair := range pairs {
			kv := strings.SplitN(pair, "=", 2)
			qParam := strings.TrimSpace(kv[0])
			if qParam != "" && !seen[qParam] {
				shapes = append(shapes, qParam)
				seen[qParam] = true
			}
		}
	}

	sort.Strings(shapes)
	return shapes
}
