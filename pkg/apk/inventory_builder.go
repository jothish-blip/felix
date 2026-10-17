package apk

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"felix/pkg/report"
	"felix/pkg/secrets"
)

// BuildBackendInventory synthesizes an evidence-backed backend inventory from manifest and artifact analysis.
func BuildBackendInventory(
	ctx context.Context,
	ws *Workspace,
	manifestRes *ManifestAnalysisResult,
	artifactRes *ArtifactAnalysisResult,
	limits Limits,
) (*BackendInventory, error) {
	if ws == nil || ws.Dir == "" {
		return nil, WrapError("inventory", "workspace is nil or uninitialized", ErrInvalidInput)
	}
	if err := ctx.Err(); err != nil {
		return nil, WrapError("inventory", "context cancelled before inventory generation", err)
	}

	maxEndpoints := limits.EffectiveMaxInventoryEndpoints()
	maxHosts := limits.EffectiveMaxInventoryHosts()
	maxProv := limits.EffectiveMaxProvenancePerEndpoint()

	inventory := &BackendInventory{
		APKSHA256:   ws.SHA256,
		APKFileName: filepath.Base(ws.APKPath),
		Categories:  make(map[string]int),
		Hosts:       []HostGroup{},
		Endpoints:   []EndpointEntry{},
		Limitations: []string{},
	}

	// Step 1: Ensure manifest and artifact analysis results are populated
	var err error
	if manifestRes == nil && ws.ManifestPath != "" {
		manifestRes, err = AnalyzeManifest(ctx, ws, limits)
		if err != nil {
			inventory.Limitations = append(inventory.Limitations, fmt.Sprintf("Manifest analysis error: %v", err))
		}
	}

	if artifactRes == nil {
		artifactRes, err = AnalyzeArtifacts(ctx, ws, limits)
		if err != nil {
			inventory.Limitations = append(inventory.Limitations, fmt.Sprintf("Artifact analysis error: %v", err))
		}
	}

	// Deduplication map: NormalizedURL -> *EndpointEntry
	endpointMap := make(map[string]*EndpointEntry)

	// Step 2: Harvest Endpoints from Manifest
	if manifestRes != nil && manifestRes.Document != nil {
		harvestManifestEndpoints(ws, manifestRes, endpointMap, limits, inventory)
	}

	// Step 3: Harvest Endpoints from Artifact Analysis Findings and Intelligence
	if artifactRes != nil {
		harvestArtifactEndpoints(ws, artifactRes, endpointMap, limits, inventory)
	}

	// Step 4: Classify and Infer Routes (unambiguous vs ambiguous base URL resolution)
	resolveInferredRoutes(endpointMap, limits, inventory)

	// Step 5: Enforce Endpoint Limits and Collect Slice
	limitReached := false
	endpoints := make([]EndpointEntry, 0, len(endpointMap))
	for _, ep := range endpointMap {
		if len(endpoints) >= maxEndpoints {
			limitReached = true
			break
		}

		// Sort provenance deterministically
		sort.Slice(ep.Provenance, func(i, j int) bool {
			pi, pj := ep.Provenance[i], ep.Provenance[j]
			if pi.ArtifactPath != pj.ArtifactPath {
				return pi.ArtifactPath < pj.ArtifactPath
			}
			if pi.DEXFile != pj.DEXFile {
				return pi.DEXFile < pj.DEXFile
			}
			return pi.ComponentContext < pj.ComponentContext
		})

		// Sort evidence, rules, finding IDs
		sort.Strings(ep.Evidence)
		sort.Strings(ep.AssociatedRules)
		sort.Strings(ep.FindingIDs)

		endpoints = append(endpoints, *ep)
	}

	if limitReached {
		inventory.Limitations = append(inventory.Limitations,
			fmt.Sprintf("Inventory endpoint limit reached: truncated at %d unique endpoints", maxEndpoints))
	}

	// Sort endpoints by NormalizedURL ascending
	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].NormalizedURL < endpoints[j].NormalizedURL
	})

	// Step 6: Group Endpoints by Backend Host
	hostMap := make(map[string]*HostGroup)
	for _, ep := range endpoints {
		hostId := ep.HostIdentity
		if hostId == "" {
			hostId = "(unresolved)"
		}

		hg, exists := hostMap[hostId]
		if !exists {
			if len(hostMap) >= maxHosts {
				// Bound host groups
				continue
			}
			hg = &HostGroup{
				HostIdentity:      hostId,
				Hostname:          ep.Host,
				Port:              ep.Port,
				ServiceIndicators: []string{},
				ArtifactOrigins:   []string{},
				Endpoints:         []EndpointEntry{},
			}
			hostMap[hostId] = hg
		}

		hg.Endpoints = append(hg.Endpoints, ep)
		hg.EndpointCount++

		if ep.Classification == ClassificationConfirmedReference {
			hg.ConfirmedCount++
		} else {
			hg.InferredCount++
		}

		// Collect service indicators
		if ind := serviceIndicatorForCategory(ep.Category); ind != "" {
			hg.ServiceIndicators = addUniqueString(hg.ServiceIndicators, ind)
		}

		// Collect artifact origins
		for _, p := range ep.Provenance {
			if p.ArtifactPath != "" {
				hg.ArtifactOrigins = addUniqueString(hg.ArtifactOrigins, p.ArtifactPath)
			}
		}
	}

	if len(hostMap) >= maxHosts {
		inventory.Limitations = append(inventory.Limitations,
			fmt.Sprintf("Inventory host group limit reached: truncated at %d host groups", maxHosts))
	}

	// Sort HostGroups by HostIdentity ascending
	hostList := make([]HostGroup, 0, len(hostMap))
	for _, hg := range hostMap {
		sort.Strings(hg.ServiceIndicators)
		sort.Strings(hg.ArtifactOrigins)
		sort.Slice(hg.Endpoints, func(i, j int) bool {
			return hg.Endpoints[i].NormalizedURL < hg.Endpoints[j].NormalizedURL
		})
		hostList = append(hostList, *hg)
	}
	sort.Slice(hostList, func(i, j int) bool {
		return hostList[i].HostIdentity < hostList[j].HostIdentity
	})

	// Step 7: Calculate Inventory Summary
	confirmedTotal := 0
	inferredTotal := 0
	categoryCounts := make(map[string]int)

	for _, ep := range endpoints {
		if ep.Classification == ClassificationConfirmedReference {
			confirmedTotal++
		} else {
			inferredTotal++
		}
		categoryCounts[string(ep.Category)]++
	}

	inventory.TotalEndpoints = len(endpoints)
	inventory.TotalHosts = len(hostList)
	inventory.ConfirmedCount = confirmedTotal
	inventory.InferredCount = inferredTotal
	inventory.Categories = categoryCounts
	inventory.Endpoints = endpoints
	inventory.Hosts = hostList

	_ = maxProv // used in helper

	return inventory, nil
}

// harvestManifestEndpoints extracts deep links and network security config domains from the manifest.
func harvestManifestEndpoints(
	ws *Workspace,
	res *ManifestAnalysisResult,
	out map[string]*EndpointEntry,
	limits Limits,
	inv *BackendInventory,
) {
	manifestPath := ws.ManifestPath
	if manifestPath == "" {
		manifestPath = "AndroidManifest.xml"
	}

	// 1. Component Intent Filters (Deep Links / App Links)
	doc := res.Document
	components := getAllComponents(doc)
	for _, comp := range components {
		for _, filter := range comp.IntentFilters {
			for _, data := range filter.Data {
				if data.Scheme == "" && data.Host == "" {
					continue
				}

				// Build raw URL candidate from intent filter
				rawCandidate := ""
				if data.Scheme != "" && data.Host != "" {
					rawCandidate = data.Scheme + "://" + data.Host
					if data.Port != "" {
						rawCandidate += ":" + data.Port
					}
					targetPath := data.Path
					if targetPath == "" {
						targetPath = data.PathPrefix
					}
					if targetPath == "" {
						targetPath = data.PathPattern
					}
					if targetPath == "" {
						targetPath = "/"
					} else if !strings.HasPrefix(targetPath, "/") {
						targetPath = "/" + targetPath
					}
					rawCandidate += targetPath
				} else if data.Scheme != "" && (data.Scheme == "http" || data.Scheme == "https") {
					continue // scheme without host is incomplete
				} else if data.Host != "" {
					rawCandidate = "https://" + data.Host + "/"
				}

				if rawCandidate == "" {
					continue
				}

				norm, err := NormalizeEndpoint(rawCandidate)
				if err != nil || norm == nil {
					continue
				}

				prov := ProvenanceRecord{
					APKSHA256:        ws.SHA256,
					APKFileName:      filepath.Base(ws.APKPath),
					ArtifactType:     "manifest",
					ArtifactPath:     manifestPath,
					ComponentContext: fmt.Sprintf("%s:%s", comp.Type, comp.Name),
					Location:         "intent-filter:data",
					AnalysisStage:    "manifest_analysis",
					Classification:   string(ClassificationConfirmedReference),
				}

				evidence := fmt.Sprintf("Manifest deep link in %s: %s", comp.Name, norm.NormalizedURL)

				category := CategoryDeepLink
				if isAuthPath(norm.Path) {
					category = CategoryAuthentication
				}

				upsertEndpoint(out, norm, category, ClassificationConfirmedReference,
					report.ConfidenceHigh,
					"Manifest declared deep link / app link intent filter",
					prov, evidence, "APK-MANIFEST-DEEP-LINK", "", limits)
			}
		}
	}

	// 2. Network Security Config Domains
	if res.NetworkSecurityConfig != nil {
		nscPath := res.NetworkSecurityConfig.ResolvedPath
		if nscPath == "" {
			nscPath = "res/xml/network_security_config.xml"
		}

		for _, d := range res.NetworkSecurityConfig.Domains {
			if d.Domain == "" {
				continue
			}
			rawDomainURL := "https://" + d.Domain + "/"
			norm, err := NormalizeEndpoint(rawDomainURL)
			if err != nil || norm == nil {
				continue
			}

			prov := ProvenanceRecord{
				APKSHA256:        ws.SHA256,
				APKFileName:      filepath.Base(ws.APKPath),
				ArtifactType:     "config",
				ArtifactPath:     nscPath,
				ComponentContext: "network_security_config",
				Location:         "domain",
				AnalysisStage:    "manifest_analysis",
				Classification:   string(ClassificationConfirmedReference),
			}

			evidence := fmt.Sprintf("Network security config domain: %s (includeSubdomains=%v)", d.Domain, d.IncludeSubdomains)

			category := CategoryAPI
			if strings.Contains(d.Domain, "firebaseio.com") {
				category = CategoryFirebase
			} else if strings.Contains(d.Domain, ".s3.") || strings.Contains(d.Domain, ".amazonaws.com") {
				category = CategoryStorage
			}

			upsertEndpoint(out, norm, category, ClassificationConfirmedReference,
				report.ConfidenceHigh,
				"Domain declared in network security configuration",
				prov, evidence, "APK-MANIFEST-NETWORK-CONFIG", "", limits)
		}
	}
}

// harvestArtifactEndpoints processes artifact findings, base URLs, services, and route paths.
func harvestArtifactEndpoints(
	ws *Workspace,
	res *ArtifactAnalysisResult,
	out map[string]*EndpointEntry,
	limits Limits,
	inv *BackendInventory,
) {
	for _, f := range res.Findings {
		rawCandidate := ""
		category := CategoryAPI
		classification := ClassificationConfirmedReference
		confidence := f.Confidence
		if confidence == "" {
			confidence = report.ConfidenceHigh
		}
		rationale := f.Title

		switch f.RuleID {
		case "APK-ART-API-BASE-URL":
			if baseURL, ok := f.EvidenceDetails.Details["base_url"]; ok && baseURL != "" {
				rawCandidate = baseURL
			} else {
				rawCandidate = f.Endpoint
			}
			category = CategoryAPI
			classification = ClassificationConfirmedReference
			rationale = "Discovered API base URL in application artifacts"

		case "APK-ART-API-ENDPOINT":
			if route, ok := f.EvidenceDetails.Details["route"]; ok && route != "" {
				rawCandidate = route
			} else {
				rawCandidate = f.Endpoint
			}
			if isAuthPath(rawCandidate) {
				category = CategoryAuthentication
			} else {
				category = CategoryAPI
			}
			classification = ClassificationInferredRoute
			rationale = "Discovered versioned API endpoint route fragment"

		case "APK-ART-GRAPHQL":
			if epURL, ok := f.EvidenceDetails.Details["endpoint_url"]; ok && epURL != "" {
				rawCandidate = epURL
				classification = ClassificationConfirmedReference
			} else if ref, ok := f.EvidenceDetails.Details["reference"]; ok && ref != "" {
				rawCandidate = ref
				if strings.HasPrefix(ref, "/") {
					classification = ClassificationInferredRoute
				}
			} else {
				rawCandidate = f.Endpoint
			}
			category = CategoryGraphQL
			rationale = "Discovered GraphQL API reference or query operation"

		case "APK-ART-SERVICE-FIREBASE":
			if fbURL, ok := f.EvidenceDetails.Details["firebase_url"]; ok && fbURL != "" {
				rawCandidate = fbURL
			} else if fbHost, ok := f.EvidenceDetails.Details["firebase_host"]; ok && fbHost != "" {
				rawCandidate = "https://" + fbHost + "/"
			} else {
				rawCandidate = f.Endpoint
			}
			category = CategoryFirebase
			classification = ClassificationConfirmedReference
			rationale = "Discovered Firebase backend database or project configuration"

		case "APK-ART-SERVICE-AWS":
			if s3Host, ok := f.EvidenceDetails.Details["bucket_host"]; ok && s3Host != "" {
				rawCandidate = "https://" + s3Host + "/"
				category = CategoryStorage
			} else if cogHost, ok := f.EvidenceDetails.Details["cognito_host"]; ok && cogHost != "" {
				rawCandidate = "https://" + cogHost + "/"
				category = CategoryCloudService
			} else if gwHost, ok := f.EvidenceDetails.Details["apigateway_host"]; ok && gwHost != "" {
				rawCandidate = "https://" + gwHost + "/"
				category = CategoryAPI
			} else {
				rawCandidate = f.Endpoint
				category = CategoryCloudService
			}
			classification = ClassificationConfirmedReference
			rationale = "Discovered Amazon Web Services cloud infrastructure indicator"

		case "APK-ART-SECRET-DATABASE":
			rawCandidate = f.Endpoint
			category = CategoryDatabase
			classification = ClassificationConfirmedReference
			rationale = "Discovered database connection endpoint URI"

		default:
			// If finding endpoint looks like an HTTP URL or path, inspect it
			if strings.HasPrefix(f.Endpoint, "http://") || strings.HasPrefix(f.Endpoint, "https://") || strings.HasPrefix(f.Endpoint, "/") {
				rawCandidate = f.Endpoint
				category = CategoryOther
				rationale = f.Title
			}
		}

		if rawCandidate == "" {
			continue
		}

		norm, err := NormalizeEndpoint(rawCandidate)
		if err != nil || norm == nil {
			continue
		}

		// Reclassify if telemetry or auth host
		if isTelemetryHost(norm.Host) {
			category = CategoryCloudService
			rationale = "Discovered third-party telemetry or analytics host indicator"
		} else if isAuthHost(norm.Host) {
			category = CategoryAuthentication
			rationale = "Discovered authentication / identity provider backend endpoint"
		}

		// Provenance tracking
		fileOrigin := f.EvidenceDetails.Details["file_origin"]
		if fileOrigin == "" {
			fileOrigin = f.Target
		}
		if fileOrigin == "" {
			fileOrigin = "classes.dex"
		}

		dexFile := ""
		if strings.HasSuffix(fileOrigin, ".dex") {
			dexFile = fileOrigin
		} else if strings.Contains(f.EvidenceDetails.Details["sources"], ".dex") {
			dexFile = f.EvidenceDetails.Details["sources"]
		}

		artType := "config"
		if strings.HasSuffix(fileOrigin, ".dex") {
			artType = "dex"
		} else if strings.HasSuffix(fileOrigin, ".js") {
			artType = "javascript"
		} else if strings.HasPrefix(fileOrigin, "res/") {
			artType = "resource"
		}

		prov := ProvenanceRecord{
			APKSHA256:      ws.SHA256,
			APKFileName:    filepath.Base(ws.APKPath),
			ArtifactType:   artType,
			ArtifactPath:   fileOrigin,
			DEXFile:        dexFile,
			Location:       f.EvidenceDetails.Location,
			AnalysisStage:  "artifact_intelligence",
			Classification: string(classification),
		}

		safeObs := secrets.RedactText(f.Evidence)

		upsertEndpoint(out, norm, category, classification, confidence, rationale, prov, safeObs, f.RuleID, f.ID, limits)
	}
}

// resolveInferredRoutes pairs relative route fragments with base URLs if an unambiguous candidate exists.
func resolveInferredRoutes(endpointMap map[string]*EndpointEntry, limits Limits, inv *BackendInventory) {
	// 1. Identify confirmed, non-service API base URLs and dedicated authentication base URLs
	apiBaseURLSet := make(map[string]bool)
	authBaseURLSet := make(map[string]bool)

	for _, ep := range endpointMap {
		if ep.Classification == ClassificationConfirmedReference && ep.Scheme != "" && ep.Host != "" {
			// Only consider HTTP/HTTPS schemes
			if ep.Scheme != "http" && ep.Scheme != "https" {
				continue
			}
			// Exclude storage, firebase, database, deep links, cloud services, and telemetry
			if ep.Category == CategoryStorage ||
				ep.Category == CategoryFirebase ||
				ep.Category == CategoryDatabase ||
				ep.Category == CategoryDeepLink ||
				ep.Category == CategoryCloudService ||
				isTelemetryHost(ep.Host) {
				continue
			}

			base := fmt.Sprintf("%s://%s", ep.Scheme, ep.Host)
			if ep.Port > 0 && ep.Port != DefaultPortForScheme(ep.Scheme) {
				base = fmt.Sprintf("%s://%s:%d", ep.Scheme, ep.Host, ep.Port)
			}

			if ep.Category == CategoryAuthentication || isAuthHost(ep.Host) {
				authBaseURLSet[base] = true
			} else if ep.Category == CategoryAPI {
				apiBaseURLSet[base] = true
			}
		}
	}

	apiBaseURLs := make([]string, 0, len(apiBaseURLSet))
	for b := range apiBaseURLSet {
		apiBaseURLs = append(apiBaseURLs, b)
	}
	sort.Strings(apiBaseURLs)

	authBaseURLs := make([]string, 0, len(authBaseURLSet))
	for b := range authBaseURLSet {
		authBaseURLs = append(authBaseURLs, b)
	}
	sort.Strings(authBaseURLs)

	// 2. Process relative routes
	var relativeRoutes []*EndpointEntry
	for _, ep := range endpointMap {
		if ep.Classification == ClassificationInferredRoute && strings.HasPrefix(ep.NormalizedURL, "/") {
			relativeRoutes = append(relativeRoutes, ep)
		}
	}

	for _, rel := range relativeRoutes {
		routePath := rel.Path
		isAuth := isAuthPath(routePath)

		// Determine target candidate base URLs
		var candidateBases []string
		if isAuth && len(authBaseURLs) > 0 {
			candidateBases = authBaseURLs
		} else {
			candidateBases = apiBaseURLs
		}

		if len(candidateBases) == 1 {
			singleBaseURL := candidateBases[0]
			candidateURL := singleBaseURL + routePath
			norm, err := NormalizeEndpoint(candidateURL)
			if err == nil && norm != nil {
				delete(endpointMap, rel.NormalizedURL)

				reason := "Combined relative route with unique discovered API base URL"
				if isAuth && len(authBaseURLs) == 1 {
					reason = "Combined relative authentication route with unique discovered authentication base URL"
				}

				details := &InferredRouteDetails{
					BaseURL:   singleBaseURL,
					RoutePath: routePath,
					Reason:    reason,
				}

				rel.NormalizedURL = norm.NormalizedURL
				rel.Scheme = norm.Scheme
				rel.Host = norm.Host
				rel.Port = norm.Port
				rel.Path = norm.Path
				rel.RawQuery = norm.RawQuery
				rel.HostIdentity = norm.HostIdentity
				rel.Confidence = report.ConfidenceMedium
				rel.Rationale = "Inferred route: " + reason
				rel.InferredDetails = details

				if existing, exists := endpointMap[norm.NormalizedURL]; exists {
					mergeEndpointEntries(existing, rel, limits)
				} else {
					endpointMap[norm.NormalizedURL] = rel
				}
			}
		} else {
			reason := "No API base URL identified; retained as unresolved relative route"
			if len(candidateBases) > 1 {
				reason = fmt.Sprintf("Base URL is ambiguous (%d candidates: %s); retained as unresolved relative route",
					len(candidateBases), strings.Join(candidateBases, ", "))
			}

			rel.HostIdentity = "(unresolved)"
			rel.Confidence = report.ConfidenceLow
			rel.InferredDetails = &InferredRouteDetails{
				RoutePath: routePath,
				Reason:    reason,
			}
		}
	}
}

// upsertEndpoint adds a new endpoint entry or merges evidence and provenance into an existing canonical entry.
func upsertEndpoint(
	out map[string]*EndpointEntry,
	norm *NormalizedEndpoint,
	category EndpointCategory,
	class ReferenceClassification,
	confidence string,
	rationale string,
	prov ProvenanceRecord,
	evidence string,
	ruleID string,
	findingID string,
	limits Limits,
) {
	canonicalURL := norm.NormalizedURL
	existing, exists := out[canonicalURL]
	if !exists {
		out[canonicalURL] = &EndpointEntry{
			NormalizedURL:   canonicalURL,
			RawURL:          norm.RawURL,
			Scheme:          norm.Scheme,
			Host:            norm.Host,
			Port:            norm.Port,
			Path:            norm.Path,
			RawQuery:        norm.RawQuery,
			HostIdentity:    norm.HostIdentity,
			Category:        category,
			Classification:  class,
			Confidence:      confidence,
			Rationale:       rationale,
			Provenance:      []ProvenanceRecord{prov},
			Evidence:        []string{evidence},
			AssociatedRules: []string{ruleID},
			FindingIDs:      []string{findingID},
		}
		return
	}

	// Merge into existing entry
	mergeProvenance(existing, prov, limits.EffectiveMaxProvenancePerEndpoint())

	if evidence != "" {
		existing.Evidence = addUniqueString(existing.Evidence, evidence)
	}
	if ruleID != "" {
		existing.AssociatedRules = addUniqueString(existing.AssociatedRules, ruleID)
	}
	if findingID != "" {
		existing.FindingIDs = addUniqueString(existing.FindingIDs, findingID)
	}

	// Direct confirmed reference always supersedes inferred classification
	if existing.Classification == ClassificationInferredRoute && class == ClassificationConfirmedReference {
		existing.Classification = ClassificationConfirmedReference
		existing.Confidence = confidence
		existing.Rationale = rationale
	}
}

func mergeEndpointEntries(dst, src *EndpointEntry, limits Limits) {
	maxProv := limits.EffectiveMaxProvenancePerEndpoint()
	for _, p := range src.Provenance {
		mergeProvenance(dst, p, maxProv)
	}
	for _, e := range src.Evidence {
		dst.Evidence = addUniqueString(dst.Evidence, e)
	}
	for _, r := range src.AssociatedRules {
		dst.AssociatedRules = addUniqueString(dst.AssociatedRules, r)
	}
	for _, fid := range src.FindingIDs {
		dst.FindingIDs = addUniqueString(dst.FindingIDs, fid)
	}
	if dst.Classification == ClassificationInferredRoute && src.Classification == ClassificationConfirmedReference {
		dst.Classification = ClassificationConfirmedReference
		dst.Confidence = src.Confidence
		dst.Rationale = src.Rationale
	}
}

func mergeProvenance(entry *EndpointEntry, prov ProvenanceRecord, maxProv int) {
	if prov.ArtifactPath == "" && prov.DEXFile == "" {
		return
	}
	for _, p := range entry.Provenance {
		if p.ArtifactPath == prov.ArtifactPath &&
			p.DEXFile == prov.DEXFile &&
			p.ComponentContext == prov.ComponentContext &&
			p.Location == prov.Location {
			return // already present
		}
	}
	if len(entry.Provenance) < maxProv {
		entry.Provenance = append(entry.Provenance, prov)
	}
}

func addUniqueString(slice []string, s string) []string {
	clean := strings.TrimSpace(s)
	if clean == "" {
		return slice
	}
	for _, item := range slice {
		if item == clean {
			return slice
		}
	}
	return append(slice, clean)
}

func isAuthPath(p string) bool {
	pLower := strings.ToLower(p)
	return strings.Contains(pLower, "/oauth") ||
		strings.Contains(pLower, "/auth") ||
		strings.Contains(pLower, "/login") ||
		strings.Contains(pLower, "/token") ||
		strings.Contains(pLower, "/sso") ||
		strings.Contains(pLower, "/saml")
}

func serviceIndicatorForCategory(c EndpointCategory) string {
	switch c {
	case CategoryFirebase:
		return "Firebase"
	case CategoryStorage:
		return "Storage / S3"
	case CategoryGraphQL:
		return "GraphQL"
	case CategoryCloudService:
		return "Cloud Infrastructure"
	case CategoryDatabase:
		return "Database"
	case CategoryAuthentication:
		return "Authentication / OAuth"
	case CategoryDeepLink:
		return "Deep Link / App Link"
	default:
		return ""
	}
}

func getAllComponents(doc *ManifestDocument) []ComponentInfo {
	if doc == nil {
		return nil
	}
	app := doc.Application
	var list []ComponentInfo
	list = append(list, app.Activities...)
	for _, a := range app.ActivityAliases {
		list = append(list, a.ComponentInfo)
	}
	list = append(list, app.Services...)
	list = append(list, app.Receivers...)
	for _, p := range app.Providers {
		list = append(list, p.ComponentInfo)
	}
	return list
}

func isAuthHost(host string) bool {
	h := strings.ToLower(host)
	return strings.HasPrefix(h, "auth.") ||
		strings.HasPrefix(h, "login.") ||
		strings.HasPrefix(h, "identity.") ||
		strings.HasPrefix(h, "oauth.") ||
		strings.HasPrefix(h, "sso.")
}

func isTelemetryHost(host string) bool {
	h := strings.ToLower(host)
	telemetryVendors := []string{
		"crashlytics.com", "firebaseinstallations.googleapis.com",
		"app-measurement.com", "google-analytics.com", "analytics.google.com",
		"sentry.io", "bugsnag.com", "mixpanel.com", "segment.io", "segment.com",
		"adjust.com", "appsflyer.com", "branch.io", "flurry.com",
		"amplitude.com", "count.ly", "datadoghq.com", "onesignal.com",
		"instabug.com", "kochava.com",
	}
	for _, v := range telemetryVendors {
		if h == v || strings.HasSuffix(h, "."+v) {
			return true
		}
	}
	if strings.Contains(h, "telemetry") || strings.Contains(h, "analytics") || strings.Contains(h, "tracking") {
		return true
	}
	return false
}
