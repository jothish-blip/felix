package bopla

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
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
	Classification  string   `json:"classification"`
	FormFieldNames  []string `json:"form_field_names,omitempty"`
}

// DiscoverySurfaceResult aggregates dynamically discovered BOPLA property policies and inventory coverage.
type DiscoverySurfaceResult struct {
	Policies             []PropertyPolicy           `json:"policies"`
	Inventory            []DiscoveredPropertyRecord `json:"inventory"`
	TotalDiscovered      int                        `json:"total_discovered"`
	PropertiesWithPolicy int                        `json:"properties_with_policy"`
}

var (
	rxStaticBOPLAAsset = regexp.MustCompile(`(?i)\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|pdf|zip|txt|xml|webp)$`)
	rxSSNPattern       = regexp.MustCompile(`^\d{3}-\d{2}-\d{4}$`)
	rxBcryptOrHash     = regexp.MustCompile(`^(\$2[aby]\$|\$argon2|[0-9a-fA-F]{40,128})$`)
	rxAPIKeyPattern    = regexp.MustCompile(`^(sk_|pk_|ak_|tok_|sec_|key_)[A-Za-z0-9_-]{8,}$`)
)

type openAPIPropMeta struct {
	readOnly       bool
	writeOnly      bool
	adminOnly      bool
	internalOnly   bool
	expectedAccess ExpectedAccessRule
	description    string
	propType       string
}

type openAPIWriteEndpoint struct {
	method      string
	path        string
	readBack    string
	properties  map[string]openAPIPropMeta
	fromSchema  bool
}

type endpointObsGroup struct {
	path           string
	jsonByIdent    map[string]any
	flatByIdent    map[string]map[string]any
	observedBy     map[string]bool
	sources        map[string]bool
	formFields     map[string]bool
	hasWriteMethod map[string]bool
}

func isAdminRole(ident string, identities []TestIdentity) bool {
	low := strings.ToLower(strings.TrimSpace(ident))
	if low == "admin" || low == "superadmin" || low == "administrator" || low == "staff" {
		return true
	}
	for _, id := range identities {
		if strings.EqualFold(id.Alias, ident) || strings.EqualFold(id.Role, ident) {
			r := strings.ToLower(strings.TrimSpace(id.Role))
			return r == "admin" || r == "superadmin" || r == "administrator" || id.PrivilegeLevel >= 5
		}
	}
	return false
}

func normalizeBOPLAPath(rawPath, baseOrigin string) string {
	p := strings.TrimSpace(rawPath)
	if p == "" {
		return ""
	}
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		u, err := url.Parse(p)
		if err != nil {
			return ""
		}
		if baseOrigin != "" {
			if bu, err := url.Parse(baseOrigin); err == nil && !strings.EqualFold(u.Host, bu.Host) {
				return ""
			}
		}
		p = u.Path
	} else if idx := strings.IndexAny(p, "?#"); idx >= 0 {
		p = p[:idx]
	}
	if p == "" || !strings.HasPrefix(p, "/") {
		return ""
	}
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	return p
}

func isBOPLABoilerplatePath(p string) bool {
	low := strings.ToLower(strings.TrimSpace(p))
	switch low {
	case "", "/", "/health", "/healthz", "/ready", "/live", "/ping", "/status",
		"/version", "/favicon.ico", "/robots.txt",
		"/openapi.json", "/swagger.json", "/api/openapi.json", "/api/swagger.json":
		return true
	}
	return rxStaticBOPLAAsset.MatchString(low)
}

func flattenJSONProperties(val any, prefix string, depth int, out map[string]any) {
	if depth > 4 || len(out) >= 120 {
		return
	}
	switch v := val.(type) {
	case map[string]interface{}:
		for k, item := range v {
			fullKey := k
			if prefix != "" {
				fullKey = prefix + "." + k
			}
			switch child := item.(type) {
			case map[string]interface{}:
				flattenJSONProperties(child, fullKey, depth+1, out)
			case []interface{}:
				if len(child) > 0 {
					if _, isObj := child[0].(map[string]interface{}); isObj {
						flattenJSONProperties(child[0], fullKey+"[0]", depth+1, out)
					} else {
						out[fullKey] = child
					}
				}
			default:
				out[fullKey] = item
			}
		}
	case []interface{}:
		if len(v) > 0 {
			if obj, isObj := v[0].(map[string]interface{}); isObj {
				nextPrefix := "[0]"
				if prefix != "" {
					nextPrefix = prefix + "[0]"
				}
				flattenJSONProperties(obj, nextPrefix, depth+1, out)
			}
		}
	}
}

func isHighlySensitiveExposureField(leafName string, val any) (sensitive bool, category string, secretPattern bool) {
	low := strings.ToLower(strings.TrimSpace(leafName))

	// Clear credential/secret/hidden-internal exposure fields
	secretKeys := map[string]string{
		"password":        "CREDENTIALS",
		"passwd":          "CREDENTIALS",
		"passcode":        "CREDENTIALS",
		"user_password":   "CREDENTIALS",
		"password_hash":   "CREDENTIALS",
		"hashed_password": "CREDENTIALS",
		"password_salt":   "CREDENTIALS",
		"api_secret":      "CREDENTIALS",
		"secret_key":      "CREDENTIALS",
		"secret":          "CREDENTIALS",
		"secret_content":  "CREDENTIALS",
		"private_key":     "CREDENTIALS",
		"client_secret":   "CREDENTIALS",
		"signing_secret":  "CREDENTIALS",
		"billing_secret":  "CREDENTIALS",
		"access_token":    "CREDENTIALS",
		"refresh_token":   "CREDENTIALS",
		"auth_token":      "CREDENTIALS",
		"internal_notes":  "INTERNAL_DATA",
		"admin_notes":     "INTERNAL_DATA",
		"admin_comment":   "INTERNAL_DATA",
		"staff_notes":     "INTERNAL_DATA",
		"ssn":             "PII",
		"tax_id":          "PII",
		"salary":          "FINANCIAL",
		"audit_flags":     "INTERNAL_DATA",
		"secret_flag":     "INTERNAL_DATA",
	}
	if cat, ok := secretKeys[low]; ok {
		secretVal := false
		if s, ok := val.(string); ok {
			sTrim := strings.TrimSpace(s)
			nonEmptyUnmasked := len(sTrim) >= 3 && sTrim != "null" && sTrim != "<nil>" && !IsMasked(sTrim, "****")
			if rxSSNPattern.MatchString(sTrim) || rxBcryptOrHash.MatchString(sTrim) || rxAPIKeyPattern.MatchString(sTrim) ||
				strings.HasPrefix(low, "internal_") || strings.HasPrefix(low, "admin_") || low == "ssn" ||
				low == "password_hash" || strings.Contains(low, "secret") ||
				(nonEmptyUnmasked && (low == "password" || low == "passwd" || low == "passcode" || low == "user_password" || low == "access_token" || low == "refresh_token" || low == "auth_token" || low == "private_key")) {
				secretVal = true
			}
		} else if val != nil && (strings.HasPrefix(low, "internal_") || strings.HasPrefix(low, "admin_") || low == "audit_flags") {
			secretVal = true
		}
		return true, cat, secretVal
	}

	// Unmasked value inspection regardless of exact key name match
	if s, ok := val.(string); ok {
		sTrim := strings.TrimSpace(s)
		if rxSSNPattern.MatchString(sTrim) {
			return true, "PII", true
		}
		if rxBcryptOrHash.MatchString(sTrim) && (strings.Contains(low, "pass") || strings.Contains(low, "hash") || strings.Contains(low, "secret")) {
			return true, "CREDENTIALS", true
		}
		if rxAPIKeyPattern.MatchString(sTrim) && (strings.Contains(low, "key") || strings.Contains(low, "secret") || strings.Contains(low, "token")) {
			return true, "CREDENTIALS", true
		}
	}

	// Ambiguous name-only hints (requires corroboration; cannot be auto-confirmed)
	ambiguousKeys := []string{"internal", "secret", "ssn", "salary", "notes", "debug", "commission", "cost_price"}
	for _, k := range ambiguousKeys {
		if strings.Contains(low, k) {
			return true, "SENSITIVE_CANDIDATE", false
		}
	}
	return false, "", false
}

func isSystemManagedWriteProperty(leafName string) (isSys bool, classification string, testVal any) {
	low := strings.ToLower(strings.TrimSpace(leafName))
	switch low {
	case "role", "user_role", "account_role":
		return true, "ROLE_RESTRICTED", "admin"
	case "is_admin", "admin", "is_staff", "is_superuser", "superuser":
		return true, "ROLE_RESTRICTED", true
	case "permissions", "scopes", "privileges":
		return true, "ROLE_RESTRICTED", []string{"admin:all"}
	case "verified", "approved", "is_verified", "email_verified", "account_verified":
		return true, "SYSTEM_MANAGED", true
	case "tier", "plan", "plan_tier", "subscription_tier":
		return true, "SYSTEM_MANAGED", "enterprise"
	case "balance", "credits", "wallet_balance", "discount", "quota":
		return true, "SYSTEM_MANAGED", 9999
	case "tenant_id", "org_id", "organization_id":
		return true, "TENANT_ISOLATION", "tenant_foreign_probe"
	case "account_status", "membership_level":
		return true, "SYSTEM_MANAGED", "vip"
	}
	return false, "", nil
}

func isPublicBenignProperty(leafName string) bool {
	low := strings.ToLower(strings.TrimSpace(leafName))
	switch low {
	case "id", "uuid", "name", "display_name", "username", "title", "description", "summary",
		"bio", "avatar", "locale", "language", "theme", "version", "status", "ok", "healthy",
		"message", "msg", "count", "total", "page", "limit", "offset", "created_at", "updated_at":
		return true
	}
	return false
}

func extractBOPLALeafName(propPath string) string {
	clean := strings.TrimSpace(propPath)
	if idx := strings.LastIndex(clean, "."); idx >= 0 {
		clean = clean[idx+1:]
	}
	if idx := strings.Index(clean, "["); idx >= 0 {
		clean = clean[:idx]
	}
	return strings.TrimSpace(clean)
}

func sanitizePropertyID(prefix, ep, prop string) string {
	raw := strings.ToLower(prefix + "-" + strings.Trim(ep, "/") + "-" + prop)
	var b strings.Builder
	prevDash := false
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
		} else if !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func resolveOpenAPISchema(doc, schema map[string]interface{}, depth int) map[string]openAPIPropMeta {
	out := make(map[string]openAPIPropMeta)
	if schema == nil || depth > 4 {
		return out
	}
	if ref, ok := schema["$ref"].(string); ok {
		parts := strings.Split(strings.TrimPrefix(ref, "#/"), "/")
		curr := any(doc)
		for _, p := range parts {
			m, ok := curr.(map[string]interface{})
			if !ok {
				curr = nil
				break
			}
			curr = m[p]
		}
		if target, ok := curr.(map[string]interface{}); ok {
			return resolveOpenAPISchema(doc, target, depth+1)
		}
	}

	if items, ok := schema["items"].(map[string]interface{}); ok {
		for k, v := range resolveOpenAPISchema(doc, items, depth+1) {
			out[k] = v
		}
	}

	props, _ := schema["properties"].(map[string]interface{})
	for propName, raw := range props {
		pm, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		meta := openAPIPropMeta{}
		if ro, ok := pm["readOnly"].(bool); ok {
			meta.readOnly = ro
		}
		if wo, ok := pm["writeOnly"].(bool); ok {
			meta.writeOnly = wo
		}
		if d, ok := pm["description"].(string); ok {
			meta.description = d
		}
		if t, ok := pm["type"].(string); ok {
			meta.propType = t
		}
		for _, ext := range []string{"x-admin-only", "x-internal", "x-restricted", "x-system-managed"} {
			if b, ok := pm[ext].(bool); ok && b {
				if ext == "x-admin-only" || ext == "x-restricted" {
					meta.adminOnly = true
				} else {
					meta.internalOnly = true
				}
			}
		}
		if ea, ok := pm["x-expected-access"].(string); ok {
			switch strings.ToUpper(strings.TrimSpace(ea)) {
			case "OMITTED":
				meta.expectedAccess = ExpectedOmitted
			case "MASKED":
				meta.expectedAccess = ExpectedMasked
			case "READ_ONLY":
				meta.expectedAccess = ExpectedReadOnly
			case "IMMUTABLE":
				meta.expectedAccess = ExpectedImmutable
			case "AUTHORIZED_ONLY":
				meta.expectedAccess = ExpectedAuthorizedOnly
			}
		}
		lowDesc := strings.ToLower(meta.description)
		if strings.Contains(lowDesc, "admin only") || strings.Contains(lowDesc, "privileged") || strings.Contains(lowDesc, "internal only") {
			meta.adminOnly = true
		}
		out[propName] = meta
		if nestedProps, ok := pm["properties"].(map[string]interface{}); ok && len(nestedProps) > 0 {
			for nk, nv := range resolveOpenAPISchema(doc, pm, depth+1) {
				if _, exists := out[nk]; !exists {
					out[nk] = nv
				}
			}
		}
		if nestedItems, ok := pm["items"].(map[string]interface{}); ok {
			for nk, nv := range resolveOpenAPISchema(doc, nestedItems, depth+1) {
				if _, exists := out[nk]; !exists {
					out[nk] = nv
				}
			}
		}
	}
	return out
}

func extractOpenAPIBOPLASurface(body []byte, baseURL string) (readProps map[string]map[string]openAPIPropMeta, writeEndpoints []openAPIWriteEndpoint) {
	readProps = make(map[string]map[string]openAPIPropMeta)
	var doc map[string]interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		return readProps, writeEndpoints
	}
	if _, hasOA := doc["openapi"]; !hasOA {
		if _, hasSw := doc["swagger"]; !hasSw {
			return readProps, writeEndpoints
		}
	}
	paths, ok := doc["paths"].(map[string]interface{})
	if !ok {
		return readProps, writeEndpoints
	}

	getPaths := make(map[string]bool)
	for rawP, item := range paths {
		p := normalizeBOPLAPath(rawP, baseURL)
		if p == "" {
			continue
		}
		if m, ok := item.(map[string]interface{}); ok {
			if _, hasGet := m["get"]; hasGet {
				getPaths[p] = true
			}
		}
	}

	for rawP, item := range paths {
		p := normalizeBOPLAPath(rawP, baseURL)
		if p == "" || isBOPLABoilerplatePath(p) {
			continue
		}
		pathMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract GET response schema properties
		if getOp, ok := pathMap["get"].(map[string]interface{}); ok {
			if resps, ok := getOp["responses"].(map[string]interface{}); ok {
				for code, rRaw := range resps {
					if !strings.HasPrefix(code, "2") {
						continue
					}
					rMap, ok := rRaw.(map[string]interface{})
					if !ok {
						continue
					}
					if content, ok := rMap["content"].(map[string]interface{}); ok {
						if jMedia, ok := content["application/json"].(map[string]interface{}); ok {
							if sch, ok := jMedia["schema"].(map[string]interface{}); ok {
								props := resolveOpenAPISchema(doc, sch, 0)
								if len(props) > 0 {
									readProps[p] = props
								}
							}
						}
					}
				}
			}
		}

		// Extract PUT/PATCH/POST request schemas for mass assignment candidates
		for _, mName := range []string{"put", "patch", "post"} {
			op, ok := pathMap[mName].(map[string]interface{})
			if !ok {
				continue
			}
			we := openAPIWriteEndpoint{
				method:     strings.ToUpper(mName),
				path:       p,
				properties: make(map[string]openAPIPropMeta),
			}
			if rb, ok := op["x-readback-endpoint"].(string); ok {
				we.readBack = rb
			} else if getPaths[p] {
				we.readBack = p
			} else if idx := strings.LastIndex(p, "/"); idx > 0 && getPaths[p[:idx]] {
				we.readBack = p[:idx]
			}

			if reqBody, ok := op["requestBody"].(map[string]interface{}); ok {
				if content, ok := reqBody["content"].(map[string]interface{}); ok {
					if jMedia, ok := content["application/json"].(map[string]interface{}); ok {
						if sch, ok := jMedia["schema"].(map[string]interface{}); ok {
							we.properties = resolveOpenAPISchema(doc, sch, 0)
							we.fromSchema = true
						}
					}
				}
			}
			writeEndpoints = append(writeEndpoints, we)
		}
	}
	return readProps, writeEndpoints
}

// DiscoverPropertySurface dynamically extracts and classifies object properties across crawled
// JSON responses, OpenAPI schemas, and HTML form fields for BOPLA assessment.
func DiscoverPropertySurface(baseURL string, identities []TestIdentity, observations []DiscoveryObservation, maxProperties int) DiscoverySurfaceResult {
	res := DiscoverySurfaceResult{}
	groups := make(map[string]*endpointObsGroup)
	oaReadProps := make(map[string]map[string]openAPIPropMeta)
	var oaWriteOps []openAPIWriteEndpoint

	for _, obs := range observations {
		if len(obs.Body) > 0 && strings.Contains(strings.ToLower(obs.ContentType+string(obs.Body[:minInt(len(obs.Body), 256)])), "json") {
			rp, wOps := extractOpenAPIBOPLASurface(obs.Body, baseURL)
			for p, m := range rp {
				oaReadProps[p] = m
			}
			oaWriteOps = append(oaWriteOps, wOps...)
		}

		p := normalizeBOPLAPath(obs.Path, baseURL)
		if p == "" {
			p = normalizeBOPLAPath(obs.URL, baseURL)
		}
		if p == "" || isBOPLABoilerplatePath(p) {
			continue
		}
		if strings.EqualFold(obs.Classification, "STATIC_ASSET") {
			continue
		}

		g, ok := groups[p]
		if !ok {
			g = &endpointObsGroup{
				path:           p,
				jsonByIdent:    make(map[string]any),
				flatByIdent:    make(map[string]map[string]any),
				observedBy:     make(map[string]bool),
				sources:        make(map[string]bool),
				formFields:     make(map[string]bool),
				hasWriteMethod: make(map[string]bool),
			}
			groups[p] = g
		}
		if obs.DiscoveryMethod != "" {
			g.sources[obs.DiscoveryMethod] = true
		}
		identKey := strings.ToUpper(strings.TrimSpace(obs.Identity))
		if identKey != "" {
			g.observedBy[identKey] = true
		}
		method := strings.ToUpper(strings.TrimSpace(obs.Method))
		if method == "" {
			method = "GET"
		}
		if method == "PUT" || method == "PATCH" || method == "POST" {
			g.hasWriteMethod[method] = true
		}
		for _, fn := range obs.FormFieldNames {
			g.formFields[strings.ToLower(strings.TrimSpace(fn))] = true
		}

		if obs.StatusCode >= 200 && obs.StatusCode < 300 && len(obs.Body) > 0 {
			var parsed any
			if json.Unmarshal(obs.Body, &parsed) == nil {
				if _, isMap := parsed.(map[string]interface{}); isMap {
					if identKey != "" {
						g.jsonByIdent[identKey] = parsed
						flat := make(map[string]any)
						flattenJSONProperties(parsed, "", 0, flat)
						g.flatByIdent[identKey] = flat
					}
				} else if _, isArr := parsed.([]interface{}); isArr {
					if identKey != "" {
						g.jsonByIdent[identKey] = parsed
						flat := make(map[string]any)
						flattenJSONProperties(parsed, "", 0, flat)
						g.flatByIdent[identKey] = flat
					}
				}
			}
		}
	}

	for _, wo := range oaWriteOps {
		g, ok := groups[wo.path]
		if !ok {
			g = &endpointObsGroup{
				path:           wo.path,
				jsonByIdent:    make(map[string]any),
				flatByIdent:    make(map[string]map[string]any),
				observedBy:     make(map[string]bool),
				sources:        map[string]bool{"OPENAPI_SPEC": true},
				formFields:     make(map[string]bool),
				hasWriteMethod: make(map[string]bool),
			}
			groups[wo.path] = g
		}
		g.sources["OPENAPI_SPEC"] = true
		g.hasWriteMethod[wo.method] = true
	}

	var paths []string
	for p := range groups {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var allPolicies []PropertyPolicy
	seenPolicyKey := make(map[string]bool)

	for _, p := range paths {
		g := groups[p]

		// Partition identity keys into admin vs restricted/standard
		var adminProps, restrictedProps []map[string]any
		allPropKeys := make(map[string]bool)
		var sampleAdminVal = make(map[string]any)
		var sampleRestrictedVal = make(map[string]any)

		for identKey, flat := range g.flatByIdent {
			if isAdminRole(identKey, identities) {
				adminProps = append(adminProps, flat)
				for pk, pv := range flat {
					allPropKeys[pk] = true
					if _, exists := sampleAdminVal[pk]; !exists {
						sampleAdminVal[pk] = pv
					}
				}
			} else {
				restrictedProps = append(restrictedProps, flat)
				for pk, pv := range flat {
					allPropKeys[pk] = true
					if _, exists := sampleRestrictedVal[pk]; !exists {
						sampleRestrictedVal[pk] = pv
					}
				}
			}
		}

		// Merge OpenAPI schema properties for this endpoint
		schemaProps := oaReadProps[p]
		for sp := range schemaProps {
			allPropKeys[sp] = true
		}
		for _, wo := range oaWriteOps {
			if wo.path == p {
				for sp := range wo.properties {
					allPropKeys[sp] = true
				}
			}
		}

		var srcList []string
		for s := range g.sources {
			srcList = append(srcList, s)
		}
		sort.Strings(srcList)
		srcStr := strings.Join(srcList, ",")
		if srcStr == "" {
			srcStr = "CRAWL_OBSERVATION"
		}

		var obsList []string
		for o := range g.observedBy {
			obsList = append(obsList, o)
		}
		sort.Strings(obsList)

		var propNames []string
		for k := range allPropKeys {
			propNames = append(propNames, k)
		}
		sort.Strings(propNames)

		for _, propPath := range propNames {
			leaf := extractBOPLALeafName(propPath)
			if leaf == "" || isPublicBenignProperty(leaf) {
				continue
			}

			val, hasAdmin := sampleAdminVal[propPath]
			if !hasAdmin {
				val = sampleRestrictedVal[propPath]
			}
			oaMeta, hasOAMeta := schemaProps[leaf]
			if !hasOAMeta {
				oaMeta, hasOAMeta = schemaProps[propPath]
			}

			// 1. Check cross-identity omission / masking differential on READ
			adminPresent := false
			for _, ap := range adminProps {
				if v, ok := ap[propPath]; ok && v != nil && !IsMasked(v, "****") {
					adminPresent = true
					break
				}
			}
			restrictedOmittedOrMasked := false
			restrictedMaskedOnly := false
			for _, rp := range restrictedProps {
				v, ok := rp[propPath]
				if !ok || v == nil {
					restrictedOmittedOrMasked = true
					break
				}
				if IsMasked(v, "****") {
					restrictedOmittedOrMasked = true
					restrictedMaskedOnly = true
					break
				}
			}

			isSens, sensCat, hasSecretVal := isHighlySensitiveExposureField(leaf, val)
			isSysManaged, sysClass, mutVal := isSystemManagedWriteProperty(leaf)

			// A. Read / Excessive Exposure Policy generation
			shouldTestRead := false
			expectedAccess := ExpectedAuthorizedOnly
			policyEstablished := false
			policyEvidence := ""
			classification := "UNKNOWN"
			confidence := "LOW"

			if hasOAMeta && (oaMeta.adminOnly || oaMeta.internalOnly || oaMeta.expectedAccess == ExpectedOmitted || oaMeta.expectedAccess == ExpectedMasked || oaMeta.expectedAccess == ExpectedAuthorizedOnly) {
				shouldTestRead = true
				policyEstablished = true
				confidence = "HIGH"
				classification = "ROLE_RESTRICTED"
				if oaMeta.expectedAccess != "" {
					expectedAccess = oaMeta.expectedAccess
				} else if oaMeta.adminOnly {
					expectedAccess = ExpectedOmitted
				}
				policyEvidence = "OpenAPI schema metadata declares property restricted/internal"
			} else if adminPresent && restrictedOmittedOrMasked && len(restrictedProps) > 0 {
				shouldTestRead = true
				policyEstablished = true
				confidence = "HIGH"
				classification = "ROLE_RESTRICTED"
				if restrictedMaskedOnly {
					expectedAccess = ExpectedMasked
				} else {
					expectedAccess = ExpectedOmitted
				}
				policyEvidence = "Cross-identity response differential: admin observes property while restricted identity omits or masks it"
			} else if isSens && hasSecretVal {
				shouldTestRead = true
				policyEstablished = true
				confidence = "HIGH"
				classification = "SENSITIVE"
				expectedAccess = ExpectedOmitted
				policyEvidence = "Observed non-public credential/secret/internal value pattern in API response"
			} else if isSens && sensCat != "SENSITIVE_CANDIDATE" && len(adminProps) > 0 {
				shouldTestRead = true
				policyEstablished = false
				confidence = "LOW"
				classification = "SENSITIVE"
				expectedAccess = ExpectedAuthorizedOnly
				policyEvidence = "Sensitive property naming detected; policy unestablished pending schema or role differential corroboration"
			}

			if shouldTestRead {
				cat := CategoryBOPLAPropertyRead
				if classification == "SENSITIVE" {
					cat = CategoryBOPLAExcessiveExposure
				}
				pid := sanitizePropertyID("read", p, propPath)
				dedup := "GET " + p + "::" + propPath
				if !seenPolicyKey[dedup] {
					seenPolicyKey[dedup] = true
					pol := PropertyPolicy{
						PropertyID:              pid,
						Name:                    "Property Read Exposure: " + propPath,
						Endpoint:                p,
						Method:                  "GET",
						Category:                cat,
						PropertyPath:            propPath,
						SensitivityCategory:     sensCat,
						PropertyClassification:  classification,
						ExpectedAccess:          expectedAccess,
						AllowedRoles:            []string{"admin", "superadmin"},
						RestrictedRoles:         []string{"user", "viewer", "guest", "anonymous"},
						IsStateChanging:         false,
						MaskPattern:             "****",
						PositiveControlRequired: true,
						DiscoverySource:         srcStr,
						DiscoveryConfidence:     confidence,
						PolicyEvidence:          policyEvidence,
						PolicyUnestablished:     !policyEstablished,
						SafetyClass:             "SAFE_READ",
					}
					allPolicies = append(allPolicies, pol)
					res.Inventory = append(res.Inventory, DiscoveredPropertyRecord{
						PropertyID:             pid,
						Endpoint:               p,
						Method:                 "GET",
						PropertyPath:           propPath,
						PropertyClassification: classification,
						ExpectedAccess:         string(expectedAccess),
						DiscoverySource:        srcStr,
						DiscoveryConfidence:    confidence,
						PolicyEstablished:      policyEstablished,
						PolicyEvidence:         policyEvidence,
						ObservedBy:             obsList,
						SafetyClass:            "SAFE_READ",
						Testability:            "TESTABLE",
					})
					if policyEstablished {
						res.PropertiesWithPolicy++
					}
				}
			}

			// B. Mass Assignment / ReadOnly Write Policy generation
			// Corroborate via OpenAPI readOnly OR UI form omission (field exists in GET JSON or OpenAPI but omitted in HTML form) OR known system-managed attribute on mutating endpoint.
			writeMethod := ""
			readBackPath := p
			for _, wo := range oaWriteOps {
				if wo.path == p || wo.readBack == p {
					writeMethod = wo.method
					if wo.readBack != "" {
						readBackPath = wo.readBack
					}
					if m, ok := wo.properties[leaf]; ok {
						oaMeta = m
						hasOAMeta = true
					}
					break
				}
			}
			if writeMethod == "" {
				for _, m := range []string{"PUT", "PATCH", "POST"} {
					if g.hasWriteMethod[m] {
						writeMethod = m
						break
					}
				}
			}

			if writeMethod != "" && (isSysManaged || (hasOAMeta && oaMeta.readOnly)) {
				formHidden := len(g.formFields) > 0 && !g.formFields[strings.ToLower(leaf)]
				if hasOAMeta && oaMeta.readOnly {
					if sysClass == "" {
						sysClass = "SYSTEM_MANAGED"
					}
					if mutVal == nil {
						mutVal = "felix_bopla_override"
					}
				}
				if mutVal == nil {
					continue
				}

				writeEstablished := (hasOAMeta && (oaMeta.readOnly || oaMeta.adminOnly)) || formHidden
				writeConfidence := "LOW"
				writeEvidence := "System-managed property candidate inferred on mutating endpoint without explicit readOnly schema"
				if hasOAMeta && oaMeta.readOnly {
					writeConfidence = "HIGH"
					writeEvidence = "OpenAPI schema declares property readOnly on mutating endpoint"
				} else if formHidden {
					writeConfidence = "HIGH"
					writeEvidence = "Property present in API object representation but hidden from user HTML form"
				} else if sysClass != "" {
					writeConfidence = "MEDIUM"
					writeEvidence = "Privileged role/account attribute observed alongside mutating endpoint"
				}

				destructiveWrite := IsDestructivePropertyAction(p, propPath)
				restorePayload := ""
				reversible := false
				safety := "STATE_CHANGING"
				testability := "GATED_STATE_CHANGING"
				skipReason := ""

				if destructiveWrite {
					safety = "DESTRUCTIVE"
					testability = "EXCLUDED_DESTRUCTIVE"
					skipReason = "Excluded by safety policy due to credential/account-destructive property semantics"
				} else if origVal, ok := sampleRestrictedVal[propPath]; ok && origVal != nil && readBackPath != "" && (writeMethod == "PUT" || writeMethod == "PATCH") {
					restorePayload = buildMutationPayload(propPath, origVal)
					reversible = true
					safety = "REVERSIBLE_MUTATION"
				}

				pid := sanitizePropertyID("write", p, propPath)
				dedup := writeMethod + " " + p + "::" + propPath
				if !seenPolicyKey[dedup] {
					seenPolicyKey[dedup] = true
					pol := PropertyPolicy{
						PropertyID:              pid,
						Name:                    "Mass Assignment Check: " + propPath,
						Endpoint:                p,
						Method:                  writeMethod,
						Category:                CategoryBOPLAMassAssignment,
						PropertyPath:            propPath,
						PropertyClassification:  sysClass,
						ExpectedAccess:          ExpectedReadOnly,
						AllowedRoles:            []string{"admin", "superadmin"},
						RestrictedRoles:         []string{"user", "viewer", "guest"},
						IsStateChanging:         true,
						MutationValue:           mutVal,
						ReadBackEndpoint:        readBackPath,
						ReadBackMethod:          "GET",
						PositiveControlRequired: true,
						DiscoverySource:         srcStr,
						DiscoveryConfidence:     writeConfidence,
						PolicyEvidence:          writeEvidence,
						PolicyUnestablished:     !writeEstablished,
						IsReversibleTest:        reversible,
						RestorePayload:          restorePayload,
						SafetyClass:             safety,
					}
					allPolicies = append(allPolicies, pol)
					res.Inventory = append(res.Inventory, DiscoveredPropertyRecord{
						PropertyID:             pid,
						Endpoint:               p,
						Method:                 writeMethod,
						PropertyPath:           propPath,
						PropertyClassification: sysClass,
						ExpectedAccess:         string(ExpectedReadOnly),
						DiscoverySource:        srcStr,
						DiscoveryConfidence:    writeConfidence,
						PolicyEstablished:      writeEstablished,
						PolicyEvidence:         writeEvidence,
						ObservedBy:             obsList,
						SafetyClass:            safety,
						Testability:            testability,
						SkipReason:             skipReason,
					})
					if writeEstablished {
						res.PropertiesWithPolicy++
					}
				}
			}
		}
	}

	sort.SliceStable(allPolicies, func(i, j int) bool {
		score := func(pol PropertyPolicy) int {
			if pol.SafetyClass == "DESTRUCTIVE" {
				return 3
			}
			if pol.IsStateChanging {
				return 2
			}
			if pol.PolicyUnestablished {
				return 1
			}
			return 0
		}
		si, sj := score(allPolicies[i]), score(allPolicies[j])
		if si != sj {
			return si < sj
		}
		return allPolicies[i].PropertyID < allPolicies[j].PropertyID
	})

	if maxProperties > 0 && len(allPolicies) > maxProperties {
		res.Policies = allPolicies[:maxProperties]
	} else {
		res.Policies = allPolicies
	}
	res.TotalDiscovered = len(res.Inventory)
	return res
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
