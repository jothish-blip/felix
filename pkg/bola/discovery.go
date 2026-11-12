package bola

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// DiscoveryObservation represents a response/resource observation captured during Phase 3 crawling.
type DiscoveryObservation struct {
	Identity        string   `json:"identity"`
	URL             string   `json:"url"`
	Path            string   `json:"path"`
	Method          string   `json:"method"`
	StatusCode      int      `json:"status_code"`
	ContentType     string   `json:"content_type"`
	Body            []byte   `json:"-"`
	DiscoveryMethod string   `json:"discovery_method"` // HTML_CRAWL, HTML_FORM, JS_ROUTE_CANDIDATE, OPENAPI_SPEC, SEED
	Classification  string   `json:"classification"`   // CONFIRMED_ENDPOINT, ENDPOINT_CANDIDATE, OBSERVED_FORM, STATIC_ASSET, INACCESSIBLE_RESOURCE
	QueryParams     []string `json:"query_params,omitempty"`
	FormFieldNames  []string `json:"form_field_names,omitempty"`
}

// DiscoveredObjectCandidate captures a discovered object reference and its provenance before/during testing.
type DiscoveredObjectCandidate struct {
	TemplatePath         string `json:"template_path"`
	Method               string `json:"method"`
	ObjectID             string `json:"object_id"`
	ParamName            string `json:"param_name"`
	Location             string `json:"location"`
	OwnerIdentity        string `json:"owner_identity,omitempty"`
	OwnershipEstablished bool   `json:"ownership_established"`
	OwnershipEvidence    string `json:"ownership_evidence,omitempty"`
	ProtectedData        string `json:"protected_data,omitempty"`
	DiscoverySource      string `json:"discovery_source"`
	Confidence           string `json:"confidence"`
	IsPublic             bool   `json:"is_public,omitempty"`
	InconclusiveReason   string `json:"inconclusive_reason,omitempty"`
}

// DiscoverySurfaceResult aggregates dynamically extracted BOLA templates, concrete objects, and unowned candidates.
type DiscoverySurfaceResult struct {
	Endpoints          []EndpointTemplate          `json:"endpoints"`
	Objects            []ObjectIdentifier          `json:"objects"`
	Candidates         []DiscoveredObjectCandidate `json:"candidates"`
	UnknownCandidates  []DiscoveredObjectCandidate `json:"unknown_candidates,omitempty"`
	TotalDiscovered    int                         `json:"total_discovered"`
	TotalWithOwnership int                         `json:"total_with_ownership"`
}

var (
	rxVersionSeg      = regexp.MustCompile(`^v\d+(?:\.\d+)?$`)
	rxUUIDSeg         = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	rxPrefixedIDSeg   = regexp.MustCompile(`^[a-zA-Z]{2,12}[-_][a-zA-Z0-9_-]{2,}$`)
	rxPositiveIntSeg  = regexp.MustCompile(`^\d{1,12}$`)
	rxTemplateSeg     = regexp.MustCompile(`^(\{[^}]+\}|:[a-zA-Z0-9_]+|\[[a-zA-Z0-9_]+\])$`)
	rxStaticExtension = regexp.MustCompile(`(?i)\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|pdf|zip|txt|xml|webp)$`)
)

var nonObjectSegments = map[string]bool{
	"api": true, "auth": true, "login": true, "logout": true, "register": true, "signup": true,
	"health": true, "healthz": true, "ready": true, "metrics": true, "status": true, "ping": true,
	"version": true, "docs": true, "swagger": true, "openapi": true, "static": true, "assets": true,
	"public": true, "js": true, "css": true, "img": true, "images": true, "fonts": true,
	"favicon.ico": true, "robots.txt": true, "me": true, "self": true, "current": true, "config": true,
}

var resourceParentNouns = map[string]bool{
	"user": true, "users": true, "profile": true, "profiles": true, "account": true, "accounts": true,
	"doc": true, "docs": true, "document": true, "documents": true, "file": true, "files": true,
	"order": true, "orders": true, "invoice": true, "invoices": true, "record": true, "records": true,
	"item": true, "items": true, "project": true, "projects": true, "note": true, "notes": true,
	"ticket": true, "tickets": true, "message": true, "messages": true, "tenant": true, "tenants": true,
	"member": true, "members": true, "wallet": true, "wallets": true, "report": true, "reports": true,
	"resource": true, "resources": true, "product": true, "products": true, "customer": true, "customers": true,
	"post": true, "posts": true, "comment": true, "comments": true, "object": true, "objects": true,
}

var objectIDParamNames = map[string]bool{
	"id": true, "user_id": true, "userid": true, "username": true, "owner_id": true, "ownerid": true,
	"doc_id": true, "docid": true, "document_id": true, "documentid": true, "file_id": true, "fileid": true,
	"order_id": true, "orderid": true, "account_id": true, "accountid": true, "record_id": true, "recordid": true,
	"profile_id": true, "profileid": true, "item_id": true, "itemid": true, "project_id": true, "projectid": true,
	"tenant_id": true, "tenantid": true, "uuid": true, "object_id": true, "objectid": true,
}

var privateDataKeys = []string{
	"secret", "private", "private_note", "privatenote", "confidential", "internal_note", "internalnote",
	"ssn", "tax_id", "taxid", "email", "phone", "address", "token", "api_key", "apikey",
	"owner_secret", "salary", "balance", "iban", "content", "note", "body", "details", "title", "name",
}

var ownerFieldKeys = []string{
	"owner", "owner_id", "ownerid", "user_id", "userid", "user", "user_name", "tenant_id", "tenantid", "author", "author_id", "username", "created_by", "createdby", "email",
}

var destructiveURLKeywords = []string{
	"delete", "remove", "destroy", "drop", "purge", "suspend", "ban", "deactivate",
	"terminate", "wipe", "truncate", "restart", "reboot", "shutdown", "logout", "signout",
	"checkout", "payment", "refund", "transfer", "password",
}

type identityAnchor struct {
	alias   string
	role    string
	markers map[string]bool // lowercased known IDs, usernames, emails belonging exclusively to this identity
}

// DiscoverObjectSurface dynamically builds BOLA endpoint templates and owned object inventories
// from multi-identity crawl observations, JSON responses, forms, query params, JS candidates, and OpenAPI docs.
func DiscoverObjectSurface(baseURL string, identities []TestIdentity, observations []DiscoveryObservation, maxObjects int) DiscoverySurfaceResult {
	if maxObjects <= 0 {
		maxObjects = 25
	}

	res := DiscoverySurfaceResult{}
	anchors := buildIdentityAnchors(identities, observations)
	anonBodies := collectIdentityBodies(observations, "ANONYMOUS")
	obsByRoute := groupObservationsByNormalizedRoute(observations)

	templateMap := make(map[string]EndpointTemplate)
	objectMap := make(map[string]ObjectIdentifier)
	candidateMap := make(map[string]DiscoveredObjectCandidate)

	// 1. Parse any accessible OpenAPI / Swagger JSON documents for endpoint templates.
	for _, ob := range observations {
		if len(ob.Body) == 0 || !strings.Contains(strings.ToLower(ob.ContentType), "json") {
			continue
		}
		extractOpenAPIBOLATemplates(ob.Body, templateMap, candidateMap)
	}

	// 2. Analyze crawled resources (path segments, query parameters, forms, JSON payloads).
	for _, ob := range observations {
		if ob.Classification == "STATIC_ASSET" || isDestructivePath(ob.Path) {
			continue
		}
		method := strings.ToUpper(strings.TrimSpace(ob.Method))
		if method == "" {
			method = "GET"
		}
		// Safe non-mutating discovery focus unless concrete safe template exists
		if method != "GET" && method != "HEAD" && method != "OPTIONS" {
			continue
		}

		cleanPath := normalizeURLPath(ob.Path)
		if cleanPath == "" || rxStaticExtension.MatchString(cleanPath) {
			continue
		}

		// 2a. Path-based object extraction
		if tplPath, paramName, concreteID, isTemplate, ok := classifyPathObjectSegment(cleanPath, ob.ContentType, ob.Body); ok {
			tplKey := method + " " + tplPath
			if _, exists := templateMap[tplKey]; !exists {
				templateMap[tplKey] = EndpointTemplate{
					PathPattern: tplPath,
					Method:      method,
					Params:      []string{paramName},
				}
			}
			if !isTemplate && concreteID != "" {
				cand := buildCandidateFromObservation(tplPath, method, concreteID, paramName, "path", ob, anchors, anonBodies, obsByRoute)
				ckey := fmt.Sprintf("%s|%s|%s|%s", cand.Method, cand.TemplatePath, cand.ParamName, cand.ObjectID)
				candidateMap[ckey] = mergeCandidate(candidateMap[ckey], cand)
			} else if isTemplate {
				ckey := fmt.Sprintf("%s|%s|%s|", method, tplPath, paramName)
				if _, exists := candidateMap[ckey]; !exists {
					candidateMap[ckey] = DiscoveredObjectCandidate{
						TemplatePath:         tplPath,
						Method:               method,
						ParamName:            paramName,
						Location:             "path",
						DiscoverySource:      normalizeDiscoverySource(ob.DiscoveryMethod),
						Confidence:           confidenceFromDiscoveryMethod(ob.DiscoveryMethod),
						OwnershipEstablished: false,
						InconclusiveReason:   "Parameterized route discovered without concrete owned object identifier",
					}
				}
			}
		}

		// 2b. Query parameter object extraction
		parsedURL, err := url.Parse(ob.URL)
		if err == nil && len(parsedURL.Query()) > 0 {
			for qk, qvals := range parsedURL.Query() {
				if !isObjectParamName(qk) {
					continue
				}
				val := ""
				if len(qvals) > 0 {
					val = strings.TrimSpace(qvals[0])
				}
				tplKey := method + " " + cleanPath + "?" + qk
				if _, exists := templateMap[tplKey]; !exists {
					templateMap[tplKey] = EndpointTemplate{
						PathPattern: cleanPath,
						Method:      method,
						Params:      []string{qk},
					}
				}
				if val != "" {
					cand := buildCandidateFromObservation(cleanPath, method, val, qk, "query", ob, anchors, anonBodies, obsByRoute)
					ckey := fmt.Sprintf("%s|%s|%s|%s", cand.Method, cand.TemplatePath, cand.ParamName, cand.ObjectID)
					candidateMap[ckey] = mergeCandidate(candidateMap[ckey], cand)
				}
			}
		}
	}

	// 3. Inspect JSON collection responses for dynamic objects (e.g. GET /api/documents returning {"items":[...]}).
	for _, ob := range observations {
		if ob.StatusCode < 200 || ob.StatusCode >= 300 || len(ob.Body) == 0 {
			continue
		}
		if !strings.Contains(strings.ToLower(ob.ContentType), "json") {
			continue
		}
		if isDestructivePath(ob.Path) {
			continue
		}
		extractObjectsFromJSONPayload(ob, templateMap, candidateMap, anchors, anonBodies)
	}

	// Sort deterministically
	var candKeys []string
	for k := range candidateMap {
		candKeys = append(candKeys, k)
	}
	sort.Strings(candKeys)

	for _, k := range candKeys {
		cand := candidateMap[k]
		res.Candidates = append(res.Candidates, cand)

		if cand.ObjectID == "" {
			res.UnknownCandidates = append(res.UnknownCandidates, cand)
			continue
		}

		if len(objectMap) >= maxObjects {
			continue
		}

		objKey := fmt.Sprintf("%s|%s|%s|%s", cand.Location, cand.ParamName, cand.ObjectID, cand.TemplatePath)
		obj := ObjectIdentifier{
			ID:                   cand.ObjectID,
			Type:                 inferObjectType(cand.TemplatePath, cand.ParamName),
			Location:             cand.Location,
			ParamName:            cand.ParamName,
			TemplatePath:         cand.TemplatePath,
			OwnerIdentity:        cand.OwnerIdentity,
			ProtectedData:        cand.ProtectedData,
			DiscoverySource:      cand.DiscoverySource,
			DiscoveryConfidence:  cand.Confidence,
			OwnershipEstablished: cand.OwnershipEstablished,
			OwnershipUnconfirmed: !cand.OwnershipEstablished && !cand.IsPublic,
			IsPublic:             cand.IsPublic,
		}
		if !cand.OwnershipEstablished || cand.OwnerIdentity == "" {
			res.UnknownCandidates = append(res.UnknownCandidates, cand)
		} else {
			res.TotalWithOwnership++
		}
		objectMap[objKey] = obj
	}

	var tplKeys []string
	for k := range templateMap {
		tplKeys = append(tplKeys, k)
	}
	sort.Strings(tplKeys)
	for _, k := range tplKeys {
		res.Endpoints = append(res.Endpoints, templateMap[k])
	}

	var objKeys []string
	for k := range objectMap {
		objKeys = append(objKeys, k)
	}
	sort.Strings(objKeys)
	for _, k := range objKeys {
		res.Objects = append(res.Objects, objectMap[k])
	}

	res.TotalDiscovered = len(res.Objects)
	return res
}

func buildIdentityAnchors(identities []TestIdentity, obs []DiscoveryObservation) map[string]*identityAnchor {
	anchors := make(map[string]*identityAnchor)
	for _, id := range identities {
		alias := strings.TrimSpace(id.Alias)
		if alias == "" {
			continue
		}
		a := &identityAnchor{
			alias:   alias,
			role:    strings.ToLower(strings.TrimSpace(id.Role)),
			markers: make(map[string]bool),
		}
		a.markers[strings.ToLower(alias)] = true
		if id.Username != "" {
			a.markers[strings.ToLower(strings.TrimSpace(id.Username))] = true
		}
		anchors[strings.ToUpper(alias)] = a
	}

	// Enrich anchors ONLY from self-scoped identity endpoints (/me, /profile, /account, /whoami)
	for _, ob := range obs {
		idKey := strings.ToUpper(strings.TrimSpace(ob.Identity))
		if idKey == "" || idKey == "ANONYMOUS" || ob.StatusCode < 200 || ob.StatusCode >= 300 || len(ob.Body) == 0 {
			continue
		}
		a, exists := anchors[idKey]
		if !exists {
			continue
		}
		lowPath := strings.ToLower(ob.Path)
		if !strings.Contains(lowPath, "/me") && !strings.Contains(lowPath, "/profile") &&
			!strings.Contains(lowPath, "/account") && !strings.Contains(lowPath, "/whoami") {
			continue
		}
		var parsed map[string]any
		if json.Unmarshal(ob.Body, &parsed) != nil {
			continue
		}
		var inspectObj func(m map[string]any, depth int)
		inspectObj = func(m map[string]any, depth int) {
			if m == nil || depth > 2 {
				return
			}
			for _, k := range []string{"id", "user_id", "userId", "username", "email", "owner", "owner_id", "ownerId", "tenant_id", "tenantId"} {
				if val, ok := lookupCaseInsensitive(m, k); ok && val != nil {
					s := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", val)))
					if s != "" && s != "null" && s != "<nil>" && len(s) >= 2 {
						a.markers[s] = true
					}
				}
			}
			for _, wrapKey := range []string{"data", "user", "account", "profile", "result", "me"} {
				if sub, ok := lookupCaseInsensitive(m, wrapKey); ok {
					if subMap, ok := sub.(map[string]any); ok {
						inspectObj(subMap, depth+1)
					}
				}
			}
		}
		inspectObj(parsed, 0)
	}
	return anchors
}

func collectIdentityBodies(obs []DiscoveryObservation, targetID string) map[string]string {
	out := make(map[string]string)
	for _, ob := range obs {
		if strings.EqualFold(ob.Identity, targetID) && ob.StatusCode >= 200 && ob.StatusCode < 300 && len(ob.Body) > 0 {
			key := strings.ToUpper(ob.Method) + " " + normalizeURLPath(ob.Path)
			out[key] = string(ob.Body)
		}
	}
	return out
}

func groupObservationsByNormalizedRoute(obs []DiscoveryObservation) map[string][]DiscoveryObservation {
	grouped := make(map[string][]DiscoveryObservation)
	for _, ob := range obs {
		key := strings.ToUpper(ob.Method) + " " + normalizeURLPath(ob.Path)
		grouped[key] = append(grouped[key], ob)
	}
	return grouped
}

func extractOpenAPIBOLATemplates(body []byte, templates map[string]EndpointTemplate, candidates map[string]DiscoveredObjectCandidate) {
	var doc struct {
		OpenAPI string                    `json:"openapi"`
		Swagger string                    `json:"swagger"`
		Paths   map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || (doc.OpenAPI == "" && doc.Swagger == "") || len(doc.Paths) == 0 {
		return
	}
	for rawPath, methods := range doc.Paths {
		if isDestructivePath(rawPath) {
			continue
		}
		for mName, opRaw := range methods {
			m := strings.ToUpper(mName)
			if m != "GET" && m != "HEAD" {
				continue
			}
			var params []string
			var queryParams []string
			// Extract {pathParam}
			segs := strings.Split(strings.Trim(rawPath, "/"), "/")
			for _, seg := range segs {
				if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
					params = append(params, strings.Trim(seg, "{}"))
				}
			}
			if opMap, ok := opRaw.(map[string]any); ok {
				if pList, ok := opMap["parameters"].([]any); ok {
					for _, pRaw := range pList {
						pm, ok := pRaw.(map[string]any)
						if !ok {
							continue
						}
						inVal, _ := pm["in"].(string)
						nameVal, _ := pm["name"].(string)
						if nameVal == "" {
							continue
						}
						if strings.EqualFold(inVal, "query") && isObjectParamName(nameVal) {
							queryParams = append(queryParams, nameVal)
						}
					}
				}
			}
			if len(params) > 0 {
				key := m + " " + normalizeURLPath(rawPath)
				if _, exists := templates[key]; !exists {
					templates[key] = EndpointTemplate{
						PathPattern: normalizeURLPath(rawPath),
						Method:      m,
						Params:      params,
					}
				}
				ckey := fmt.Sprintf("%s|%s|%s|", m, normalizeURLPath(rawPath), params[0])
				if _, exists := candidates[ckey]; !exists {
					candidates[ckey] = DiscoveredObjectCandidate{
						TemplatePath:    normalizeURLPath(rawPath),
						Method:          m,
						ParamName:       params[0],
						Location:        "path",
						DiscoverySource: "OPENAPI_SPEC",
						Confidence:      "MEDIUM",
						InconclusiveReason: "OpenAPI parameterized template requires concrete owned object ID",
					}
				}
			}
			for _, qp := range queryParams {
				key := m + " " + normalizeURLPath(rawPath) + "?" + qp
				if _, exists := templates[key]; !exists {
					templates[key] = EndpointTemplate{
						PathPattern: normalizeURLPath(rawPath),
						Method:      m,
						Params:      []string{qp},
					}
				}
			}
		}
	}
}

func classifyPathObjectSegment(path, contentType string, body []byte) (templatePath, paramName, concreteID string, isTemplate, ok bool) {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return "", "", "", false, false
	}
	segs := strings.Split(trimmed, "/")
	if len(segs) < 2 {
		return "", "", "", false, false
	}

	targetIdx := -1
	for i := len(segs) - 1; i >= 1; i-- {
		seg := segs[i]
		lowSeg := strings.ToLower(seg)
		parent := strings.ToLower(segs[i-1])

		// Explicit parameterized placeholder ({id}, :id, [id])
		if rxTemplateSeg.MatchString(seg) {
			pName := strings.Trim(seg, "{}:[]")
			if pName == "" {
				pName = "id"
			}
			tSegs := append([]string{}, segs...)
			tSegs[i] = "{" + pName + "}"
			return "/" + strings.Join(tSegs, "/"), pName, "", true, true
		}

		// Filter out version numbers and non-object route nouns
		if rxVersionSeg.MatchString(lowSeg) || nonObjectSegments[lowSeg] || rxStaticExtension.MatchString(lowSeg) {
			continue
		}
		if parent == "static" || parent == "assets" || parent == "images" || parent == "js" || parent == "css" || parent == "fonts" {
			continue
		}

		isUUID := rxUUIDSeg.MatchString(seg)
		isPrefixed := rxPrefixedIDSeg.MatchString(seg)
		isNum := rxPositiveIntSeg.MatchString(seg)
		hasResourceParent := resourceParentNouns[parent]

		if isUUID || isPrefixed {
			targetIdx = i
			concreteID = seg
			paramName = singularParamName(parent)
			break
		}
		if isNum {
			// Avoid treating standalone version/year numbers outside resource routes unless backed by resource parent or JSON payload
			if hasResourceParent || looksLikeObjectJSON(body, seg) {
				targetIdx = i
				concreteID = seg
				paramName = singularParamName(parent)
				break
			}
			continue
		}
		// String slug identifier after explicit resource collection noun (e.g. /users/alice, /profiles/bob)
		if hasResourceParent && len(seg) >= 2 && len(seg) <= 64 && !strings.Contains(seg, ".") {
			// Ignore obvious collection sub-actions like /users/list or /documents/create
			if lowSeg == "list" || lowSeg == "all" || lowSeg == "new" || lowSeg == "create" || lowSeg == "search" {
				continue
			}
			targetIdx = i
			concreteID = seg
			paramName = singularParamName(parent)
			break
		}
	}

	if targetIdx < 0 {
		return "", "", "", false, false
	}
	tSegs := append([]string{}, segs...)
	tSegs[targetIdx] = "{" + paramName + "}"
	return "/" + strings.Join(tSegs, "/"), paramName, concreteID, false, true
}

func buildCandidateFromObservation(
	tplPath, method, objectID, paramName, location string,
	ob DiscoveryObservation,
	anchors map[string]*identityAnchor,
	anonBodies map[string]string,
	obsByRoute map[string][]DiscoveryObservation,
) DiscoveredObjectCandidate {
	cand := DiscoveredObjectCandidate{
		TemplatePath:    tplPath,
		Method:          method,
		ObjectID:        objectID,
		ParamName:       paramName,
		Location:        location,
		DiscoverySource: normalizeDiscoverySource(ob.DiscoveryMethod),
		Confidence:      confidenceFromDiscoveryMethod(ob.DiscoveryMethod),
	}

	if len(ob.Body) > 0 && ob.StatusCode >= 200 && ob.StatusCode < 300 {
		var data map[string]any
		if json.Unmarshal(ob.Body, &data) == nil && data != nil {
			// 1. Check explicit public flag or non-private catalog semantics
			if isExplicitlyPublicObject(ob, obsByRoute, anonBodies, anchors) {
				cand.IsPublic = true
				cand.OwnershipEstablished = false
				cand.OwnershipEvidence = "Resource accessible identically to anonymous and authenticated identities without owner-specific private fields"
				return cand
			}

			// 2. Establish ownership from JSON owner fields matching known identity anchors
			for _, okKey := range ownerFieldKeys {
				if val, exists := lookupCaseInsensitive(data, okKey); exists && val != nil {
					strVal := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", val)))
					if matchedAlias := matchAnchor(strVal, anchors); matchedAlias != "" {
						cand.OwnerIdentity = matchedAlias
						cand.OwnershipEstablished = true
						cand.OwnershipEvidence = fmt.Sprintf("JSON owner field %q matches identity %s", okKey, matchedAlias)
						break
					}
				}
			}

			// 3. Fallback: if discovered under a single authenticated non-anonymous identity (e.g. USER_A link exclusivity)
			if !cand.OwnershipEstablished && !strings.EqualFold(ob.Identity, "ANONYMOUS") && !strings.EqualFold(ob.Identity, "ADMIN") {
				routeKey := strings.ToUpper(ob.Method) + " " + normalizeURLPath(ob.Path)
				seenIdentities := make(map[string]bool)
				for _, peer := range obsByRoute[routeKey] {
					if peer.StatusCode >= 200 && peer.StatusCode < 300 && !strings.EqualFold(peer.Identity, "ADMIN") {
						seenIdentities[strings.ToUpper(peer.Identity)] = true
					}
				}
				// Check if objectID itself matches an anchor marker
				if matchedAlias := matchAnchor(strings.ToLower(objectID), anchors); matchedAlias != "" {
					cand.OwnerIdentity = matchedAlias
					cand.OwnershipEstablished = true
					cand.OwnershipEvidence = fmt.Sprintf("Object identifier %q matches identity %s", objectID, matchedAlias)
				} else if len(seenIdentities) == 1 && seenIdentities[strings.ToUpper(ob.Identity)] {
					// Observed exclusively inside one non-admin authenticated identity's crawl
					cand.OwnerIdentity = strings.ToLower(ob.Identity)
					cand.OwnershipEstablished = true
					cand.OwnershipEvidence = fmt.Sprintf("Discovered and accessible exclusively within %s session context during crawl", ob.Identity)
				}
			}

			// Extract real sensitive/identifying protected data marker from JSON response
			if anonRaw, hasAnon := anonBodies[strings.ToUpper(ob.Method)+" "+normalizeURLPath(ob.Path)]; hasAnon {
				cand.ProtectedData = extractProtectedMarker(data, anonRaw, cand.IsPublic)
			} else {
				cand.ProtectedData = extractProtectedMarker(data, "", cand.IsPublic)
			}
		}
	}

	if cand.OwnerIdentity == "" {
		// Check if ID itself identifies an identity (e.g. /users/user_a or /users/alice)
		if matchedAlias := matchAnchor(strings.ToLower(objectID), anchors); matchedAlias != "" {
			cand.OwnerIdentity = matchedAlias
			cand.OwnershipEstablished = true
			cand.OwnershipEvidence = fmt.Sprintf("Identifier %q maps to identity %s", objectID, matchedAlias)
		}
	}

	if !cand.OwnershipEstablished || cand.OwnerIdentity == "" {
		cand.InconclusiveReason = "Object ownership could not be established from response or identity inventory"
	}
	return cand
}

func extractObjectsFromJSONPayload(
	ob DiscoveryObservation,
	templates map[string]EndpointTemplate,
	candidates map[string]DiscoveredObjectCandidate,
	anchors map[string]*identityAnchor,
	anonBodies map[string]string,
) {
	var root any
	if json.Unmarshal(ob.Body, &root) != nil || root == nil {
		return
	}

	var items []map[string]any
	switch v := root.(type) {
	case []any:
		for _, el := range v {
			if m, ok := el.(map[string]any); ok {
				items = append(items, m)
			}
		}
	case map[string]any:
		for _, listKey := range []string{"items", "data", "documents", "users", "books", "orders", "vehicles", "records", "results", "objects"} {
			if sub, ok := lookupCaseInsensitive(v, listKey); ok {
				if arr, ok := sub.([]any); ok {
					for _, el := range arr {
						if m, ok := el.(map[string]any); ok {
							items = append(items, m)
						}
					}
				}
			}
		}
		// Fallback: inspect any top-level slice of JSON objects (e.g., {"Accounts": [...]})
		if len(items) == 0 {
			for _, sub := range v {
				if arr, ok := sub.([]any); ok {
					for _, el := range arr {
						if m, ok := el.(map[string]any); ok {
							items = append(items, m)
						}
					}
				}
			}
		}
	}

	basePath := strings.TrimRight(normalizeURLPath(ob.Path), "/")
	if basePath == "" || len(items) == 0 {
		return
	}

	// Prefer existing parameterized child templates (e.g., from OpenAPI /users/v1/{username}).
	// If basePath is a view/debug sub-endpoint like /users/v1/_debug without a child template, check its parent collection /users/v1/{...}.
	findChildTemplate := func(collectionPath string) *EndpointTemplate {
		pfx := collectionPath + "/{"
		var matches []EndpointTemplate
		for _, tpl := range templates {
			if strings.EqualFold(tpl.Method, "GET") && strings.HasPrefix(tpl.PathPattern, pfx) {
				suffix := tpl.PathPattern[len(collectionPath)+1:]
				if !strings.Contains(suffix, "/") && strings.HasPrefix(suffix, "{") && strings.HasSuffix(suffix, "}") {
					matches = append(matches, tpl)
				}
			}
		}
		if len(matches) == 0 {
			return nil
		}
		sort.Slice(matches, func(i, j int) bool {
			return matches[i].PathPattern < matches[j].PathPattern
		})
		cp := matches[0]
		return &cp
	}

	lastSegLow := strings.ToLower(lastSegment(basePath))
	isCollectionViewSuffix := lastSegLow == "_debug" || lastSegLow == "debug" || lastSegLow == "all" ||
		lastSegLow == "list" || lastSegLow == "summary" || lastSegLow == "export" || lastSegLow == "search"

	matchedChildTemplate := findChildTemplate(basePath)
	if matchedChildTemplate == nil && isCollectionViewSuffix {
		if idx := strings.LastIndex(basePath, "/"); idx > 0 {
			matchedChildTemplate = findChildTemplate(basePath[:idx])
		}
	}
	// Do not synthesize a nonexistent synthetic child URL on debug/search/all view routes when no real template exists.
	if matchedChildTemplate == nil && isCollectionViewSuffix {
		return
	}

	for _, item := range items {
		idVal := ""
		paramName := ""
		if matchedChildTemplate != nil && len(matchedChildTemplate.Params) > 0 {
			tpName := matchedChildTemplate.Params[0]
			if raw, ok := lookupCaseInsensitive(item, tpName); ok && raw != nil {
				s := strings.TrimSpace(fmt.Sprintf("%v", raw))
				if s != "" && s != "null" && s != "<nil>" {
					idVal = s
					paramName = tpName
				}
			}
		}
		if idVal == "" {
			for _, idKey := range []string{"id", "doc_id", "docId", "document_id", "user_id", "userId", "username", "book_title", "vehicle_id", "vehicleId", "order_id", "orderId", "report_id", "uuid"} {
				if raw, ok := lookupCaseInsensitive(item, idKey); ok && raw != nil {
					s := strings.TrimSpace(fmt.Sprintf("%v", raw))
					if s != "" && s != "null" && s != "<nil>" {
						idVal = s
						if paramName == "" {
							paramName = idKey
						}
						break
					}
				}
			}
		}
		if idVal == "" {
			continue
		}

		tplPath := ""
		if matchedChildTemplate != nil {
			tplPath = matchedChildTemplate.PathPattern
			if len(matchedChildTemplate.Params) > 0 {
				paramName = matchedChildTemplate.Params[0]
			}
		} else {
			if paramName == "" || paramName == "id" {
				segForNoun := lastSegment(basePath)
				if rxVersionSeg.MatchString(strings.ToLower(segForNoun)) {
					trimmedSegs := strings.Split(strings.Trim(basePath, "/"), "/")
					if len(trimmedSegs) >= 2 {
						segForNoun = trimmedSegs[len(trimmedSegs)-2]
					}
				}
				paramName = singularParamName(segForNoun)
			}
			tplPath = basePath + "/{" + paramName + "}"
		}
		tplKey := "GET " + tplPath
		if _, exists := templates[tplKey]; !exists {
			templates[tplKey] = EndpointTemplate{
				PathPattern: tplPath,
				Method:      "GET",
				Params:      []string{paramName},
			}
		}

		cand := DiscoveredObjectCandidate{
			TemplatePath:    tplPath,
			Method:          "GET",
			ObjectID:        idVal,
			ParamName:       paramName,
			Location:        "path",
			DiscoverySource: "RESPONSE_JSON",
			Confidence:      "HIGH",
		}
		for _, okKey := range ownerFieldKeys {
			if val, exists := lookupCaseInsensitive(item, okKey); exists && val != nil {
				strVal := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", val)))
				if matchedAlias := matchAnchor(strVal, anchors); matchedAlias != "" {
					cand.OwnerIdentity = matchedAlias
					cand.OwnershipEstablished = true
					cand.OwnershipEvidence = fmt.Sprintf("Collection JSON owner field %q matches identity %s", okKey, matchedAlias)
					break
				}
			}
		}
		cand.ProtectedData = extractProtectedMarker(item, "", false)
		ckey := fmt.Sprintf("%s|%s|%s|%s", cand.Method, cand.TemplatePath, cand.ParamName, cand.ObjectID)
		candidateMapMerge(candidates, ckey, cand)
	}
}

func candidateMapMerge(m map[string]DiscoveredObjectCandidate, key string, cand DiscoveredObjectCandidate) {
	m[key] = mergeCandidate(m[key], cand)
}

func mergeCandidate(existing, incoming DiscoveredObjectCandidate) DiscoveredObjectCandidate {
	if existing.TemplatePath == "" {
		return incoming
	}
	if !existing.OwnershipEstablished && incoming.OwnershipEstablished {
		existing.OwnerIdentity = incoming.OwnerIdentity
		existing.OwnershipEstablished = true
		existing.OwnershipEvidence = incoming.OwnershipEvidence
	}
	if existing.ProtectedData == "" && incoming.ProtectedData != "" {
		existing.ProtectedData = incoming.ProtectedData
	}
	if existing.IsPublic && !existing.OwnershipEstablished {
		return existing
	}
	if existing.Confidence == "LOW" && incoming.Confidence != "LOW" {
		existing.Confidence = incoming.Confidence
		existing.DiscoverySource = incoming.DiscoverySource
	}
	return existing
}

func isExplicitlyPublicObject(ob DiscoveryObservation, obsByRoute map[string][]DiscoveryObservation, anonBodies map[string]string, anchors map[string]*identityAnchor) bool {
	var data map[string]any
	if json.Unmarshal(ob.Body, &data) != nil {
		return false
	}
	if v, ok := lookupCaseInsensitive(data, "public"); ok {
		if b, isBool := v.(bool); isBool && b {
			return true
		}
	}
	if v, ok := lookupCaseInsensitive(data, "visibility"); ok {
		if strings.EqualFold(fmt.Sprintf("%v", v), "public") {
			return true
		}
	}
	// Must have zero owner fields matching a user anchor
	for _, okKey := range ownerFieldKeys {
		if val, exists := lookupCaseInsensitive(data, okKey); exists && val != nil {
			if matchAnchor(strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", val))), anchors) != "" {
				return false
			}
		}
	}
	routeKey := strings.ToUpper(ob.Method) + " " + normalizeURLPath(ob.Path)
	anonBody, ok := anonBodies[routeKey]
	if !ok {
		return false
	}
	// If anonymous body equals authenticated body AND contains /public or lacks private markers
	if strings.TrimSpace(anonBody) == strings.TrimSpace(string(ob.Body)) && strings.Contains(strings.ToLower(ob.Path), "public") {
		return true
	}
	return false
}

func extractProtectedMarker(data map[string]any, anonBody string, isPublic bool) string {
	if isPublic || data == nil {
		return ""
	}
	for _, k := range privateDataKeys {
		if raw, ok := lookupCaseInsensitive(data, k); ok && raw != nil {
			val := strings.TrimSpace(fmt.Sprintf("%v", raw))
			if len(val) < 4 {
				continue
			}
			lowVal := strings.ToLower(val)
			if lowVal == "null" || lowVal == "true" || lowVal == "false" || lowVal == "user" || lowVal == "admin" {
				continue
			}
			if anonBody != "" && strings.Contains(anonBody, val) {
				// Avoid marker if anonymous already received it when not explicitly private (unless email/secret)
				if !strings.Contains(strings.ToLower(k), "secret") && !strings.Contains(strings.ToLower(k), "ssn") && !strings.Contains(strings.ToLower(k), "email") {
					continue
				}
			}
			return val
		}
	}
	return ""
}

func matchAnchor(val string, anchors map[string]*identityAnchor) string {
	val = strings.TrimSpace(strings.ToLower(val))
	if val == "" {
		return ""
	}
	for _, a := range anchors {
		if a.role == "anonymous" || strings.EqualFold(a.alias, "anonymous") {
			continue
		}
		if a.markers[val] {
			return strings.ToLower(a.alias)
		}
	}
	return ""
}

func lookupCaseInsensitive(m map[string]any, key string) (any, bool) {
	if m == nil {
		return nil, false
	}
	if v, ok := m[key]; ok {
		return v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

func looksLikeObjectJSON(body []byte, seg string) bool {
	if len(body) == 0 {
		return false
	}
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return false
	}
	for _, k := range []string{"id", "user_id", "userId", "owner", "ownerId", "email", "username"} {
		if v, ok := lookupCaseInsensitive(m, k); ok && v != nil {
			if strings.EqualFold(strings.TrimSpace(fmt.Sprintf("%v", v)), seg) {
				return true
			}
			return true
		}
	}
	return false
}

func isObjectParamName(name string) bool {
	low := strings.ToLower(strings.TrimSpace(name))
	if objectIDParamNames[low] {
		return true
	}
	return strings.HasSuffix(low, "_id") || strings.HasSuffix(low, "id") && len(low) <= 18
}

func singularParamName(parent string) string {
	p := strings.ToLower(strings.TrimSpace(parent))
	switch {
	case strings.HasPrefix(p, "user"):
		return "userId"
	case strings.HasPrefix(p, "doc"):
		return "docId"
	case strings.HasPrefix(p, "order"):
		return "orderId"
	case strings.HasPrefix(p, "account"):
		return "accountId"
	case strings.HasPrefix(p, "file"):
		return "fileId"
	case strings.HasPrefix(p, "profile"):
		return "profileId"
	default:
		return "id"
	}
}

func inferObjectType(path, param string) string {
	low := strings.ToLower(path + " " + param)
	switch {
	case strings.Contains(low, "doc") || strings.Contains(low, "file"):
		return "document"
	case strings.Contains(low, "profile") || strings.Contains(low, "user") || strings.Contains(low, "account"):
		return "user_profile"
	case strings.Contains(low, "order") || strings.Contains(low, "invoice"):
		return "order"
	default:
		return "resource"
	}
}

func normalizeURLPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		if u, err := url.Parse(p); err == nil && u.Path != "" {
			p = u.Path
		}
	}
	if idx := strings.Index(p, "?"); idx >= 0 {
		p = p[:idx]
	}
	if p == "" {
		return "/"
	}
	return p
}

func lastSegment(p string) string {
	trimmed := strings.Trim(p, "/")
	if trimmed == "" {
		return ""
	}
	parts := strings.Split(trimmed, "/")
	return parts[len(parts)-1]
}

func normalizeDiscoverySource(m string) string {
	if strings.TrimSpace(m) == "" {
		return "CRAWLER"
	}
	return strings.ToUpper(strings.TrimSpace(m))
}

func confidenceFromDiscoveryMethod(m string) string {
	switch strings.ToUpper(strings.TrimSpace(m)) {
	case "HTML_CRAWL", "HTML_FORM", "RESPONSE_JSON":
		return "HIGH"
	case "OPENAPI_SPEC":
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func isDestructivePath(path string) bool {
	low := strings.ToLower(path)
	for _, kw := range destructiveURLKeywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	// Check non-trivial integer parse guard unused helper if needed
	_ = strconv.ErrSyntax
	return false
}
