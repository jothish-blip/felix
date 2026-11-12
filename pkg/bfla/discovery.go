package bfla

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// DiscoveryObservation represents a response/resource observation captured during Phase 3 crawling.
type DiscoveryObservation struct {
	Identity           string   `json:"identity"`
	URL                string   `json:"url"`
	Path               string   `json:"path"`
	Method             string   `json:"method"`
	StatusCode         int      `json:"status_code"`
	ContentType        string   `json:"content_type"`
	Body               []byte   `json:"-"`
	DiscoveryMethod    string   `json:"discovery_method"` // HTML_CRAWL, HTML_FORM, JS_ROUTE_CANDIDATE, OPENAPI_SPEC, SEED
	Classification     string   `json:"classification"`
	AuthRequirement    string   `json:"auth_requirement,omitempty"` // ANONYMOUS_PUBLIC, AUTHENTICATED_USER, ADMIN_ONLY, DIFFERENTIAL, UNKNOWN
	AccessDifferential string   `json:"access_differential,omitempty"`
	FormFieldNames     []string `json:"form_field_names,omitempty"`
}

// DiscoverySurfaceResult aggregates discovered BFLA function policies and inventory coverage.
type DiscoverySurfaceResult struct {
	Policies                     []FunctionPolicy           `json:"policies"`
	Inventory                    []DiscoveredFunctionRecord `json:"inventory"`
	TotalDiscovered              int                        `json:"total_discovered"`
	FunctionsWithEstablishedRole int                        `json:"functions_with_established_role"`
	ExcludedDestructive          int                        `json:"excluded_destructive"`
}

var (
	rxStaticBFLAAsset = regexp.MustCompile(`(?i)\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|pdf|zip|txt|xml|webp)$`)
	rxSafeIDSegment   = regexp.MustCompile(`^(\{[^}]+\}|:[a-zA-Z0-9_]+)$`)
)

type aggFuncState struct {
	path                string
	method              string
	name                string
	category            Category
	sources             map[string]bool
	observedBy          map[string]bool
	adminStatuses       []int
	adminBodies         [][]byte
	lowerStatuses       []int
	lowerObservedIn     bool
	adminOnlyHint       bool
	openAPIAdminRole    bool
	openAPIAuthRequired bool
	roleEvidence        []string
	formFields          []string
	explicitMarker      string
}

func isAdminRoleName(ident string, identities []TestIdentity) bool {
	low := strings.ToLower(strings.TrimSpace(ident))
	if low == "admin" || low == "superadmin" || low == "administrator" || low == "root" || low == "staff" {
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

func isLowerIdentityName(ident string, identities []TestIdentity) bool {
	if isAdminRoleName(ident, identities) {
		return false
	}
	return strings.TrimSpace(ident) != ""
}

func isPublicOrAuthBoilerplate(p string) bool {
	low := strings.ToLower(strings.TrimSpace(p))
	switch low {
	case "", "/", "/health", "/healthz", "/ready", "/readyz", "/live", "/livez",
		"/ping", "/status", "/version", "/favicon.ico", "/robots.txt",
		"/openapi.json", "/swagger.json", "/api/openapi.json", "/api/swagger.json",
		"/login", "/signin", "/auth/login", "/api/login", "/api/auth/login",
		"/register", "/signup":
		return true
	}
	return rxStaticBFLAAsset.MatchString(low)
}

func looksLikePrivilegedPath(p string) bool {
	low := strings.ToLower(p)
	privilegedHints := []string{
		"/admin", "/_admin", "/administrator", "/superadmin", "/internal", "/_internal", "/debug", "/_debug",
		"/metrics", "/_metrics", "/audit", "/system", "/config", "/_config", "/settings", "/staff",
		"/manage", "/management", "/roles", "/permissions", "/export",
		"/impersonate", "/purge", "/logs", "/diagnostics", "/tenants",
	}
	for _, h := range privilegedHints {
		if strings.Contains(low, h) {
			return true
		}
	}
	return false
}

func sanitizeFunctionID(method, p string) string {
	raw := strings.ToLower(method + "-" + strings.Trim(p, "/"))
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
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "root"
	}
	return out
}

func extractPrivilegedMarker(body []byte) string {
	var m map[string]interface{}
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	priorityKeys := []string{
		"audit_logs", "audit", "system_config", "config", "admin_metrics",
		"metrics", "users", "roles", "permissions", "settings", "internal",
		"diagnostics", "tenants", "secret_flag",
	}
	for _, pk := range priorityKeys {
		for k := range m {
			if strings.EqualFold(k, pk) {
				return k
			}
		}
	}
	return ""
}

func extractOpenAPIFunctionStates(body []byte, baseOrigin string, agg map[string]*aggFuncState) {
	var doc map[string]interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		return
	}
	if _, hasOpenAPI := doc["openapi"]; !hasOpenAPI {
		if _, hasSwagger := doc["swagger"]; !hasSwagger {
			return
		}
	}
	pathsRaw, ok := doc["paths"].(map[string]interface{})
	if !ok {
		return
	}

	httpMethods := map[string]bool{
		"get": true, "post": true, "put": true, "patch": true, "delete": true,
	}

	for rawPath, pathItem := range pathsRaw {
		pathMap, ok := pathItem.(map[string]interface{})
		if !ok {
			continue
		}
		cleanPath := normalizeBFLAPath(rawPath, baseOrigin)
		if cleanPath == "" || isPublicOrAuthBoilerplate(cleanPath) {
			continue
		}
		// Skip object-templated GET item endpoints unless admin-oriented; BOLA covers object-id reads
		hasTemplateParam := false
		for _, seg := range strings.Split(strings.Trim(cleanPath, "/"), "/") {
			if rxSafeIDSegment.MatchString(seg) {
				hasTemplateParam = true
				break
			}
		}

		for mKey, opRaw := range pathMap {
			lm := strings.ToLower(mKey)
			if !httpMethods[lm] {
				continue
			}
			op, ok := opRaw.(map[string]interface{})
			if !ok {
				continue
			}
			method := strings.ToUpper(lm)

			isAdminSpec, hasSecurity, summaryText := parseOpenAPIOperationPrivilege(op)
			// Skip parameterized item-GET paths in BFLA unless explicitly tagged admin/privileged
			if hasTemplateParam && !isAdminSpec && !looksLikePrivilegedPath(cleanPath) {
				continue
			}

			key := method + " " + cleanPath
			st := ensureAggState(agg, key, cleanPath, method)
			st.sources["OPENAPI_SPEC"] = true
			if summaryText != "" && st.name == "" {
				st.name = summaryText
			}
			if isAdminSpec {
				st.openAPIAdminRole = true
				st.roleEvidence = appendUniqueStr(st.roleEvidence, "OpenAPI specification metadata/security declares privileged admin role")
			}
			if hasSecurity {
				st.openAPIAuthRequired = true
			}
		}
	}
}

func parseOpenAPIOperationPrivilege(op map[string]interface{}) (isAdmin bool, hasSecurity bool, summary string) {
	if s, ok := op["summary"].(string); ok {
		summary = strings.TrimSpace(s)
	}
	desc, _ := op["description"].(string)

	checkAdminText := func(txt string) bool {
		lt := strings.ToLower(txt)
		return strings.Contains(lt, "admin") ||
			strings.Contains(lt, "superadmin") ||
			strings.Contains(lt, "privileged") ||
			strings.Contains(lt, "staff") ||
			strings.Contains(lt, "operator") ||
			strings.Contains(lt, "internal only")
	}

	if checkAdminText(summary) || checkAdminText(desc) {
		isAdmin = true
	}

	if tags, ok := op["tags"].([]interface{}); ok {
		for _, t := range tags {
			if ts, ok := t.(string); ok && checkAdminText(ts) {
				isAdmin = true
			}
		}
	}

	for _, extKey := range []string{"x-required-role", "x-role", "x-roles", "x-permissions"} {
		if raw, exists := op[extKey]; exists {
			switch v := raw.(type) {
			case string:
				if checkAdminText(v) {
					isAdmin = true
				}
			case []interface{}:
				for _, item := range v {
					if s, ok := item.(string); ok && checkAdminText(s) {
						isAdmin = true
					}
				}
			}
		}
	}

	if sec, ok := op["security"].([]interface{}); ok && len(sec) > 0 {
		hasSecurity = true
		for _, item := range sec {
			if secObj, ok := item.(map[string]interface{}); ok {
				for scheme, scopesRaw := range secObj {
					if checkAdminText(scheme) {
						isAdmin = true
					}
					if scopes, ok := scopesRaw.([]interface{}); ok {
						for _, sc := range scopes {
							if s, ok := sc.(string); ok && checkAdminText(s) {
								isAdmin = true
							}
						}
					}
				}
			}
		}
	}

	return isAdmin, hasSecurity, summary
}

func ensureAggState(agg map[string]*aggFuncState, key, path, method string) *aggFuncState {
	if existing, ok := agg[key]; ok {
		return existing
	}
	st := &aggFuncState{
		path:       path,
		method:     method,
		sources:    make(map[string]bool),
		observedBy: make(map[string]bool),
	}
	agg[key] = st
	return st
}

func appendUniqueStr(slice []string, val string) []string {
	for _, existing := range slice {
		if existing == val {
			return slice
		}
	}
	return append(slice, val)
}

func normalizeBFLAPath(rawPath, baseOrigin string) string {
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
			bu, err := url.Parse(baseOrigin)
			if err == nil && !strings.EqualFold(u.Host, bu.Host) {
				return ""
			}
		}
		p = u.Path
	} else {
		if idx := strings.IndexAny(p, "?#"); idx >= 0 {
			p = p[:idx]
		}
	}
	if p == "" || !strings.HasPrefix(p, "/") {
		return ""
	}
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	return p
}

// DiscoverFunctionSurface builds a structured, safety-classified BFLA function policy inventory
// from crawled routes, HTML forms, JS route candidates, OpenAPI specs, and visibility matrix signals.
func DiscoverFunctionSurface(baseURL string, identities []TestIdentity, observations []DiscoveryObservation, maxFunctions int) DiscoverySurfaceResult {
	res := DiscoverySurfaceResult{}
	agg := make(map[string]*aggFuncState)

	for _, obs := range observations {
		// Parse embedded OpenAPI / Swagger specifications whenever observed
		if len(obs.Body) > 0 && strings.Contains(strings.ToLower(obs.ContentType+string(obs.Body[:minInt(len(obs.Body), 256)])), "json") {
			extractOpenAPIFunctionStates(obs.Body, baseURL, agg)
		}

		p := normalizeBFLAPath(obs.Path, baseURL)
		if p == "" {
			p = normalizeBFLAPath(obs.URL, baseURL)
		}
		if p == "" || isPublicOrAuthBoilerplate(p) {
			continue
		}
		if strings.EqualFold(obs.Classification, "STATIC_ASSET") {
			continue
		}

		method := strings.ToUpper(strings.TrimSpace(obs.Method))
		if method == "" {
			method = "GET"
		}

		key := method + " " + p
		st := ensureAggState(agg, key, p, method)
		if obs.DiscoveryMethod != "" {
			st.sources[obs.DiscoveryMethod] = true
		}
		if obs.Identity != "" {
			st.observedBy[strings.ToUpper(strings.TrimSpace(obs.Identity))] = true
		}
		if len(obs.FormFieldNames) > 0 {
			for _, f := range obs.FormFieldNames {
				st.formFields = appendUniqueStr(st.formFields, f)
			}
		}

		if strings.EqualFold(obs.AuthRequirement, "ADMIN_ONLY") {
			st.adminOnlyHint = true
			st.roleEvidence = appendUniqueStr(st.roleEvidence, "Visibility matrix indicates ADMIN_ONLY access restriction")
		}

		isAdminObs := isAdminRoleName(obs.Identity, identities)
		isLowerObs := isLowerIdentityName(obs.Identity, identities)

		if isAdminObs {
			st.adminStatuses = append(st.adminStatuses, obs.StatusCode)
			if obs.StatusCode >= 200 && obs.StatusCode < 300 && len(obs.Body) > 0 {
				st.adminBodies = append(st.adminBodies, obs.Body)
				if st.explicitMarker == "" {
					st.explicitMarker = extractPrivilegedMarker(obs.Body)
				}
			}
		} else if isLowerObs {
			st.lowerStatuses = append(st.lowerStatuses, obs.StatusCode)
			if obs.Classification == "CONFIRMED_ENDPOINT" || obs.Classification == "OBSERVED_FORM" {
				st.lowerObservedIn = true
			}
		}
	}

	var keys []string
	for k := range agg {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var candidatePolicies []FunctionPolicy
	for _, k := range keys {
		st := agg[k]

		adminSaw2xx := false
		adminHasPrivilegedPayload := false
		for idx, code := range st.adminStatuses {
			if code >= 200 && code < 300 {
				adminSaw2xx = true
				if idx < len(st.adminBodies) {
					resp := ResponseData{StatusCode: code, Body: st.adminBodies[idx]}
					if !IsHTMLOrLoginPage(resp) && !IsGenericErrorJSON(resp.Body) && HasPrivilegedIndicators(resp.Body) {
						adminHasPrivilegedPayload = true
					}
				}
			}
		}

		lowerSawDenied := false
		lowerSaw2xx := false
		for _, code := range st.lowerStatuses {
			if code == 401 || code == 403 || code == 404 {
				lowerSawDenied = true
			} else if code >= 200 && code < 300 {
				lowerSaw2xx = true
			}
		}

		observedOnlyByAdmin := len(st.adminStatuses) > 0 && !st.lowerObservedIn && !lowerSaw2xx
		pathPrivileged := looksLikePrivilegedPath(st.path)
		stateChanging := isWriteMethod(st.method)
		destructive := IsDestructiveFunction(st.method, st.path)

		// Decide if this discovered endpoint belongs in BFLA assessment scope:
		// Must have at least one signal suggesting privileged/function-restricted behavior OR be a state-changing function.
		// Never blindly treat arbitrary user-level GET endpoints without privilege/function cues as admin functions.
		if !st.openAPIAdminRole && !st.adminOnlyHint && !pathPrivileged && !observedOnlyByAdmin && !stateChanging {
			continue
		}
		// Skip non-privileged write paths that belong purely to user auth/self-profile unless OpenAPI admin or admin path
		lowPath := strings.ToLower(st.path)
		if !st.openAPIAdminRole && !st.adminOnlyHint && !pathPrivileged && (strings.Contains(lowPath, "/profile") || strings.Contains(lowPath, "/me") || strings.Contains(lowPath, "/account")) {
			continue
		}

		// Determine if required role is authoritatively established (cannot be solely path convention).
		roleEstablished := false
		var reasons []string
		for _, r := range st.roleEvidence {
			reasons = appendUniqueStr(reasons, r)
		}
		if st.openAPIAdminRole {
			roleEstablished = true
		}
		if st.adminOnlyHint || (adminSaw2xx && lowerSawDenied) {
			roleEstablished = true
			reasons = appendUniqueStr(reasons, "Crawl differential showed admin 2xx while lower-privilege received 401/403/404")
		}
		if observedOnlyByAdmin && pathPrivileged {
			roleEstablished = true
			reasons = appendUniqueStr(reasons, "Discovered exclusively in admin crawl surface and matches administrative function naming")
		}
		if adminHasPrivilegedPayload && pathPrivileged {
			roleEstablished = true
			reasons = appendUniqueStr(reasons, "Admin positive control returned privileged data indicators")
		}
		if len(reasons) == 0 && pathPrivileged {
			reasons = append(reasons, "Path naming convention suggests privileged function without independent role corroboration")
		} else if len(reasons) == 0 && stateChanging {
			reasons = append(reasons, "State-changing function candidate discovered without explicit role policy")
		}

		confidence := "LOW"
		if st.openAPIAdminRole || (adminSaw2xx && lowerSawDenied) {
			confidence = "HIGH"
		} else if roleEstablished {
			confidence = "MEDIUM"
		}

		var srcList []string
		for s := range st.sources {
			srcList = append(srcList, s)
		}
		sort.Strings(srcList)

		var obsList []string
		for o := range st.observedBy {
			obsList = append(obsList, o)
		}
		sort.Strings(obsList)

		cat := CategoryBFLAAdminEndpoint
		safetyClass := "SAFE_READ"
		testability := "TESTABLE"
		skipReason := ""

		if destructive {
			safetyClass = "DESTRUCTIVE"
			testability = "EXCLUDED_DESTRUCTIVE"
			skipReason = "Excluded by default safety policy due to destructive path/method semantics"
			res.ExcludedDestructive++
		} else if stateChanging {
			cat = CategoryBFLAWriteMutation
			safetyClass = "STATE_CHANGING"
			testability = "GATED_STATE_CHANGING"
		}

		payload := ""
		if stateChanging && !destructive && len(st.formFields) > 0 {
			m := make(map[string]string, len(st.formFields))
			for _, f := range st.formFields {
				m[f] = "felix_safe_probe"
			}
			if b, err := json.Marshal(m); err == nil {
				payload = string(b)
			}
		}

		funcName := st.name
		if funcName == "" {
			funcName = st.method + " " + st.path
		}

		restricted := []string{"user", "viewer", "guest", "anonymous"}
		roleEvidenceStr := strings.Join(reasons, "; ")
		funcID := sanitizeFunctionID(st.method, st.path)

		pol := FunctionPolicy{
			FunctionID:              funcID,
			Name:                    funcName,
			Path:                    st.path,
			Method:                  st.method,
			AlternateMethods:        defaultAlternateMethods(st.method),
			Category:                cat,
			AllowedRoles:            []string{"admin", "superadmin"},
			RestrictedRoles:         restricted,
			RequiredPrivilegeLevel:  5,
			ProtectedResponseMarker: st.explicitMarker,
			PositiveControlRequired: true,
			IsStateChanging:         stateChanging,
			Payload:                 payload,
			DiscoverySource:         strings.Join(srcList, ","),
			DiscoveryConfidence:     confidence,
			RoleEvidence:            roleEvidenceStr,
			RoleUnestablished:       !roleEstablished,
			Testability:             testability,
			SafetyClass:             safetyClass,
		}

		rec := DiscoveredFunctionRecord{
			FunctionID:          funcID,
			Path:                st.path,
			Method:              st.method,
			DiscoverySource:     strings.Join(srcList, ","),
			DiscoveryConfidence: confidence,
			RequiredRole:        "admin",
			RoleEvidence:        roleEvidenceStr,
			RoleEstablished:     roleEstablished,
			ObservedBy:          obsList,
			SafetyClass:         safetyClass,
			Testability:         testability,
			SkipReason:          skipReason,
		}

		candidatePolicies = append(candidatePolicies, pol)
		res.Inventory = append(res.Inventory, rec)
		if roleEstablished {
			res.FunctionsWithEstablishedRole++
		}
	}

	// Deterministic prioritization: established safe reads first, then unestablished safe reads, then gated/excluded.
	sort.SliceStable(candidatePolicies, func(i, j int) bool {
		score := func(p FunctionPolicy) int {
			if p.SafetyClass == "DESTRUCTIVE" {
				return 3
			}
			if p.IsStateChanging {
				return 2
			}
			if p.RoleUnestablished {
				return 1
			}
			return 0
		}
		si, sj := score(candidatePolicies[i]), score(candidatePolicies[j])
		if si != sj {
			return si < sj
		}
		return candidatePolicies[i].FunctionID < candidatePolicies[j].FunctionID
	})

	if maxFunctions > 0 && len(candidatePolicies) > maxFunctions {
		// Preserve destructive/skipped records plus up to maxFunctions runnable policies
		var bounded []FunctionPolicy
		active := 0
		for _, p := range candidatePolicies {
			if p.SafetyClass == "DESTRUCTIVE" {
				bounded = append(bounded, p)
				continue
			}
			if active < maxFunctions {
				bounded = append(bounded, p)
				active++
			}
		}
		res.Policies = bounded
	} else {
		res.Policies = candidatePolicies
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
