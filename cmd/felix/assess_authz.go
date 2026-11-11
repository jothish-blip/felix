package main

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"felix/pkg/auth"
	"felix/pkg/bfla"
	"felix/pkg/bola"
	"felix/pkg/bopla"
	"felix/pkg/crawler"
	"felix/pkg/intelligence"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

type authzObservation struct {
	Identity        string
	URL             string
	Path            string
	Method          string
	StatusCode      int
	ContentType     string
	Body            []byte
	DiscoveryMethod string
	Classification  string
	AuthRequirement string
	QueryParams     []string
	FormFieldNames  []string
}

type authzDiscoveryCache struct {
	Prepared             bool
	Observations         []authzObservation
	CrawlCountByIdentity map[string]int
}

type authzIdentityMeta struct {
	Ctx       auth.IdentityContext
	Alias     string
	Role      string
	PrivLevel int
	Username  string
	Scheme    string
	Client    *http.Client
}

func aliasForIdentityCtx(id auth.IdentityContext) string {
	switch id {
	case auth.IdentityUnauthenticated:
		return "ANONYMOUS"
	case auth.IdentityUserA:
		return "USER_A"
	case auth.IdentityUserB:
		return "USER_B"
	case auth.IdentityAdmin:
		return "ADMIN"
	default:
		return strings.ToUpper(string(id))
	}
}

func normalizeAuthzRole(id auth.IdentityContext, rawRole auth.PersonaRole) (role string, priv int) {
	low := strings.ToLower(strings.TrimSpace(string(rawRole)))
	switch {
	case id == auth.IdentityAdmin || low == "admin" || low == "superadmin" || low == "administrator":
		return "admin", 5
	case id == auth.IdentityUnauthenticated || low == "anonymous" || low == "guest":
		return "anonymous", 0
	case low == "" || low == "victim" || low == "attacker" || low == "user" || low == "custom":
		return "user", 1
	default:
		return low, 1
	}
}

func describeCredentialScheme(rt *AssessmentRuntimeContext, id auth.IdentityContext) string {
	if id == auth.IdentityUnauthenticated || rt.IdentityMgr == nil {
		return "none"
	}
	if sum, ok := rt.IdentityMgr.IdentityCredentialSummary(id); ok {
		var parts []string
		if sum.HasBearer {
			parts = append(parts, "bearer")
		}
		if sum.HasHeader {
			parts = append(parts, "header")
		}
		if sum.HasCookies {
			parts = append(parts, fmt.Sprintf("cookies(%d)", sum.CookieCount))
		}
		if len(parts) > 0 {
			return strings.Join(parts, "+")
		}
		if sum.AuthMethod != "" {
			return strings.ToLower(string(sum.AuthMethod))
		}
	}
	return "configured"
}

func verifySyntheticFixtureTarget(rt *AssessmentRuntimeContext) *report.FixtureVerificationSummary {
	if rt == nil {
		return &report.FixtureVerificationSummary{
			Verified: false,
			Method:   "NOT_REQUESTED",
			Reason:   "Missing assessment runtime context",
		}
	}
	if rt.FixtureVerification != nil {
		return rt.FixtureVerification
	}

	res := &report.FixtureVerificationSummary{
		RequestedStateChanging: rt.Opts.AllowStateChanging,
		SyntheticFixtureFlag:   rt.Opts.SyntheticFixture,
	}

	if !rt.Opts.AllowStateChanging {
		res.Method = "NOT_REQUESTED"
		res.Reason = "State-changing probes disabled by default (--allow-state-changing not set)"
		rt.FixtureVerification = res
		return res
	}
	if !rt.Opts.SyntheticFixture {
		res.Method = "FAILED_MISSING_FLAG"
		res.Reason = "State-changing probes blocked: --allow-state-changing requires --synthetic-fixture confirmation"
		rt.FixtureVerification = res
		return res
	}

	u, err := url.Parse(rt.TargetURL)
	if err != nil || strings.TrimSpace(u.Hostname()) == "" {
		res.Method = "FAILED_NOT_ISOLATED"
		res.Reason = "State-changing probes blocked: unable to parse target hostname for fixture verification"
		rt.FixtureVerification = res
		return res
	}
	hostname := strings.ToLower(strings.TrimSpace(u.Hostname()))
	hostPort := strings.ToLower(strings.TrimSpace(u.Host))

	isLoopback := auth.IsLoopbackHost(hostname)
	explicitMatch := false
	for _, fh := range rt.Opts.FixtureHosts {
		if auth.MatchAuthorizedFixtureHost(hostname, hostPort, fh) {
			explicitMatch = true
			break
		}
	}
	if !isLoopback && !explicitMatch {
		res.Method = "FAILED_NOT_ISOLATED"
		res.Reason = fmt.Sprintf("State-changing probes blocked: target host %q is neither loopback nor listed in --fixture-hosts", hostPort)
		rt.FixtureVerification = res
		return res
	}

	hasAttestation, prodMarker := inspectTargetFixtureSignals(rt)
	if prodMarker != "" {
		res.Method = "FAILED_PRODUCTION_MARKER"
		res.Reason = fmt.Sprintf("State-changing probes blocked unconditionally: target advertised non-fixture/production marker (%s)", prodMarker)
		rt.FixtureVerification = res
		return res
	}

	authorizedHosts := make([]string, 0, len(rt.Opts.FixtureHosts)+1)
	seenHost := make(map[string]bool)
	for _, fh := range rt.Opts.FixtureHosts {
		clean := strings.ToLower(strings.TrimSpace(fh))
		if clean != "" && !seenHost[clean] {
			seenHost[clean] = true
			authorizedHosts = append(authorizedHosts, clean)
		}
	}

	if hasAttestation {
		if hostPort != "" && !seenHost[hostPort] {
			authorizedHosts = append(authorizedHosts, hostPort)
		}
		res.Verified = true
		res.Method = "HEADER_ATTESTATION"
		res.AuthorizedHosts = authorizedHosts
		res.Reason = "Target verified as isolated synthetic fixture via response fixture attestation"
		rt.FixtureVerification = res
		return res
	}

	if explicitMatch {
		if hostPort != "" && !seenHost[hostPort] {
			authorizedHosts = append(authorizedHosts, hostPort)
		}
		res.Verified = true
		res.Method = "EXPLICIT_FIXTURE_HOST"
		res.AuthorizedHosts = authorizedHosts
		res.Reason = fmt.Sprintf("Target host %q explicitly pinned via --fixture-hosts without production conflict markers", hostPort)
		rt.FixtureVerification = res
		return res
	}

	res.Method = "FAILED_UNVERIFIED_TARGET"
	res.Reason = "State-changing probes blocked: loopback target lacks synthetic fixture attestation header (X-Felix-Synthetic-Fixture: true) and is not pinned via --fixture-hosts"
	rt.FixtureVerification = res
	return res
}

func inspectTargetFixtureSignals(rt *AssessmentRuntimeContext) (hasAttestation bool, prodMarker string) {
	checkHeaders := func(h http.Header, bodyHTML string) {
		if h != nil {
			for _, hdr := range []string{"X-Environment", "X-App-Env", "X-Felix-Environment"} {
				if val := strings.ToLower(strings.TrimSpace(h.Get(hdr))); val != "" {
					if val == "production" || val == "prod" || val == "staging" || strings.Contains(val, "production") {
						prodMarker = fmt.Sprintf("%s=%s", hdr, val)
						return
					}
				}
			}
			for _, hdr := range []string{"X-Felix-Synthetic-Fixture", "X-Synthetic-Fixture"} {
				if val := strings.ToLower(strings.TrimSpace(h.Get(hdr))); val != "" {
					if val == "false" || val == "0" || val == "no" {
						prodMarker = fmt.Sprintf("%s=%s", hdr, val)
						return
					}
					if val == "true" || val == "1" {
						hasAttestation = true
					}
				}
			}
		}
		lowBody := strings.ToLower(bodyHTML)
		if strings.Contains(lowBody, `<meta name="felix-synthetic-fixture" content="true"`) ||
			strings.Contains(lowBody, `<meta name="synthetic-fixture" content="true"`) {
			hasAttestation = true
		}
	}

	checkHeaders(rt.Header, rt.HTMLContent)
	if prodMarker != "" {
		return false, prodMarker
	}

	if rt.Client != nil && rt.TargetURL != "" {
		probePaths := []string{"/health"}
		if rt.Header == nil {
			probePaths = []string{"/", "/health"}
		}
		for _, p := range probePaths {
			target := strings.TrimRight(rt.TargetURL, "/") + p
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			if err == nil {
				resp, doErr := rt.Client.Do(req)
				if doErr == nil {
					snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
					_ = resp.Body.Close()
					checkHeaders(resp.Header, string(snippet))
				}
			}
			cancel()
			if prodMarker != "" {
				return false, prodMarker
			}
		}
	}
	return hasAttestation, ""
}

func buildCLIAuthRecord(rt *AssessmentRuntimeContext) *auth.AuthorizationRecord {
	validFrom := time.Now().UTC().Add(-1 * time.Hour)
	validUntil := time.Now().UTC().Add(24 * time.Hour)
	authorizer := rt.Opts.AuthorizingParty
	if authorizer == "" {
		authorizer = "CLI Operator"
	}
	return &auth.AuthorizationRecord{
		ID:                  "authz-cert",
		AuthorizingParty:    authorizer,
		AuthorizationMethod: "EXPLICIT_CLI_CERTIFICATION",
		Status:              "APPROVED",
		ValidFrom:           &validFrom,
		ValidUntil:          &validUntil,
	}
}

func collectIdentityProfiles(rt *AssessmentRuntimeContext) (
	identMap map[string]*http.Client,
	profiles []authzIdentityMeta,
	authIdents []auth.IdentityContext,
	hasDistinctUsers bool,
	hasAdmin bool,
) {
	identMap = make(map[string]*http.Client)
	if rt.IdentityMgr == nil {
		identMap["ANONYMOUS"] = rt.Client
		profiles = append(profiles, authzIdentityMeta{
			Ctx:       auth.IdentityUnauthenticated,
			Alias:     "ANONYMOUS",
			Role:      "anonymous",
			PrivLevel: 0,
			Scheme:    "none",
			Client:    rt.Client,
		})
		return
	}

	// Ensure identity verification ran once for configured identities beyond USER_A
	for _, idCtx := range rt.IdentityMgr.ConfiguredIdentities() {
		alias := aliasForIdentityCtx(idCtx)
		rawRole := rt.IdentityMgr.IdentityRole(idCtx)
		role, priv := normalizeAuthzRole(idCtx, rawRole)
		uname := rt.IdentityMgr.IdentityUsername(idCtx)
		scheme := describeCredentialScheme(rt, idCtx)
		client := rt.ClientFor(idCtx)

		// Skip USER_B if its credentials are byte-for-byte identical to USER_A
		if idCtx == auth.IdentityUserB && rt.IdentityMgr.HasIdentity(auth.IdentityUserA) &&
			!rt.IdentityMgr.AreCredentialsDistinct(auth.IdentityUserA, auth.IdentityUserB) {
			updateIdentityCoverageEntry(rt, alias, role, uname, scheme, true, false,
				"Credential matches USER_A; skipped as non-distinct peer identity", 0, 0)
			continue
		}

		identMap[alias] = client
		profiles = append(profiles, authzIdentityMeta{
			Ctx:       idCtx,
			Alias:     alias,
			Role:      role,
			PrivLevel: priv,
			Username:  uname,
			Scheme:    scheme,
			Client:    client,
		})

		if idCtx != auth.IdentityUnauthenticated {
			authIdents = append(authIdents, idCtx)
		}
		if role == "admin" || idCtx == auth.IdentityAdmin {
			hasAdmin = true
		}

		verified := idCtx == auth.IdentityUnauthenticated
		verNote := "Unauthenticated baseline context"
		if idCtx == auth.IdentityUserA && rt.AuthVerification != nil {
			verified = rt.AuthVerification.Verified
			if verified {
				verNote = fmt.Sprintf("Verified (%s, HTTP %d)", scheme, rt.AuthVerification.StatusCode)
			} else if rt.AuthVerification.FailureReason != "" {
				verNote = rt.AuthVerification.FailureReason
			}
		} else if idCtx != auth.IdentityUnauthenticated {
			ctx, cancel := context.WithTimeout(context.Background(), rt.Opts.Timeout)
			vr, err := rt.IdentityMgr.VerifyIdentity(ctx, idCtx, rt.TargetURL)
			cancel()
			if err == nil && vr != nil {
				verified = vr.Verified
				if verified {
					verNote = fmt.Sprintf("Verified (%s, HTTP %d)", scheme, vr.StatusCode)
				} else if vr.FailureReason != "" {
					verNote = vr.FailureReason
				}
			}
		}
		updateIdentityCoverageEntry(rt, alias, role, uname, scheme, true, verified, verNote, 0, 0)
	}

	// Mark absent standard identities honestly as NOT_CONFIGURED
	for _, stdID := range []auth.IdentityContext{auth.IdentityUserA, auth.IdentityUserB, auth.IdentityAdmin} {
		if !rt.IdentityMgr.HasIdentity(stdID) {
			role, _ := normalizeAuthzRole(stdID, rt.IdentityMgr.IdentityRole(stdID))
			updateIdentityCoverageEntry(rt, aliasForIdentityCtx(stdID), role, "", "none", false, false, "NOT_CONFIGURED", 0, 0)
		}
	}

	if len(authIdents) >= 2 {
		hasDistinctUsers = true
	} else if len(authIdents) == 1 && len(identMap) >= 2 {
		hasDistinctUsers = true
	}
	return
}

func ensureAuthzReportInitialized(rt *AssessmentRuntimeContext) *report.AuthorizationReportSummary {
	if rt.AuthzReport == nil {
		rt.AuthzReport = &report.AuthorizationReportSummary{
			Status:      "PARTIAL",
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		}
	}
	return rt.AuthzReport
}

func updateIdentityCoverageEntry(
	rt *AssessmentRuntimeContext,
	alias, role, username, scheme string,
	configured, verified bool,
	note string,
	crawledDelta, testsDelta int,
) {
	rep := ensureAuthzReportInitialized(rt)
	for i := range rep.IdentityCoverage {
		if rep.IdentityCoverage[i].Identity == alias {
			if role != "" {
				rep.IdentityCoverage[i].Role = role
			}
			if username != "" {
				rep.IdentityCoverage[i].Username = username
			}
			if scheme != "" {
				rep.IdentityCoverage[i].CredentialScheme = scheme
			}
			rep.IdentityCoverage[i].Configured = configured
			rep.IdentityCoverage[i].Verified = verified
			if note != "" {
				rep.IdentityCoverage[i].VerificationNote = note
			}
			if crawledDelta > 0 {
				rep.IdentityCoverage[i].CrawledEndpoints += crawledDelta
			}
			if testsDelta > 0 {
				rep.IdentityCoverage[i].TestsExecuted += testsDelta
			}
			return
		}
	}
	rep.IdentityCoverage = append(rep.IdentityCoverage, report.IdentityCoverageEntry{
		Identity:         alias,
		Role:             role,
		Username:         username,
		CredentialScheme: scheme,
		Configured:       configured,
		Verified:         verified,
		VerificationNote: note,
		CrawledEndpoints: crawledDelta,
		TestsExecuted:    testsDelta,
	})
}

func bumpIdentityTestCount(rt *AssessmentRuntimeContext, alias string, delta int) {
	if alias == "" || delta <= 0 {
		return
	}
	rep := ensureAuthzReportInitialized(rt)
	for i := range rep.IdentityCoverage {
		if strings.EqualFold(rep.IdentityCoverage[i].Identity, alias) {
			rep.IdentityCoverage[i].TestsExecuted += delta
			return
		}
	}
}

func visibilityAuthRequirement(vm *crawler.IdentityVisibilityMatrix, pathKey string) string {
	if vm == nil || len(vm.Endpoints) == 0 {
		return ""
	}
	obsMap, ok := vm.Endpoints[pathKey]
	if !ok {
		return ""
	}
	adminOK := false
	userOK := false
	anonOK := false
	userDenied := false
	for ident, obs := range obsMap {
		switch strings.ToUpper(ident) {
		case "ADMIN":
			if obs.StatusCode >= 200 && obs.StatusCode < 300 {
				adminOK = true
			}
		case "ANONYMOUS":
			if obs.StatusCode >= 200 && obs.StatusCode < 300 {
				anonOK = true
			}
		default:
			if obs.StatusCode >= 200 && obs.StatusCode < 300 {
				userOK = true
			} else if obs.StatusCode == 401 || obs.StatusCode == 403 || obs.StatusCode == 404 {
				userDenied = true
			}
		}
	}
	if adminOK && !userOK && !anonOK && userDenied {
		return "ADMIN_ONLY"
	}
	if anonOK {
		return "ANONYMOUS_PUBLIC"
	}
	if userOK {
		return "AUTHENTICATED_USER"
	}
	return ""
}

func ensureAuthzDiscovery(rt *AssessmentRuntimeContext) *authzDiscoveryCache {
	if rt.AuthzDiscoveryData != nil && rt.AuthzDiscoveryData.Prepared {
		return rt.AuthzDiscoveryData
	}

	cache := &authzDiscoveryCache{
		Prepared:             true,
		CrawlCountByIdentity: make(map[string]int),
	}
	seenObs := make(map[string]bool)
	fetchedAssetMap := make(map[string]crawler.Asset) // key: ident::normalizedPath

	if rt.MultiCrawlResult != nil {
		for ident, crawlRes := range rt.MultiCrawlResult.PerIdentity {
			if crawlRes == nil {
				continue
			}
			cache.CrawlCountByIdentity[ident] = len(crawlRes.Resources)
			updateIdentityCoverageEntry(rt, ident, "", "", "", true, false, "", len(crawlRes.Resources), 0)

			for _, a := range crawlRes.AssetsForInventory {
				p := normalizeAuthzURLPath(a.URL)
				if p != "" {
					fetchedAssetMap[ident+"::"+p] = a
				}
			}

			for _, dr := range crawlRes.Resources {
				if dr.Classification == crawler.ClassificationStaticAsset ||
					dr.Classification == crawler.ClassificationOutOfScope ||
					dr.Classification == crawler.ClassificationExcludedDestructive {
					continue
				}
				method := strings.ToUpper(strings.TrimSpace(dr.HTTPMethod))
				if method == "" {
					method = "GET"
				}
				p := dr.Path
				if p == "" {
					p = normalizeAuthzURLPath(dr.URL)
				}
				var fieldNames []string
				for _, ff := range dr.FormFields {
					if ff.Name != "" {
						fieldNames = append(fieldNames, ff.Name)
					}
				}
				var body []byte
				ct := dr.ContentType
				status := dr.StatusCode
				if asset, ok := fetchedAssetMap[ident+"::"+p]; ok {
					body = asset.Content
					if ct == "" {
						ct = asset.ContentType
					}
					if status == 0 {
						status = asset.StatusCode
					}
				}

				key := ident + "::" + method + "::" + p
				if seenObs[key] {
					continue
				}
				seenObs[key] = true
				cache.Observations = append(cache.Observations, authzObservation{
					Identity:        ident,
					URL:             dr.URL,
					Path:            p,
					Method:          method,
					StatusCode:      status,
					ContentType:     ct,
					Body:            body,
					DiscoveryMethod: dr.DiscoveryMethod,
					Classification:  string(dr.Classification),
					AuthRequirement: visibilityAuthRequirement(rt.VisibilityMatrix, p),
					QueryParams:     dr.QueryParams,
					FormFieldNames:  fieldNames,
				})
			}
		}
	}

	// Ensure root response observation is captured even when --modules omits "recon"
	if len(rt.BodyBytes) > 0 {
		defIdent := "ANONYMOUS"
		if rt.IdentityMgr != nil && rt.IdentityMgr.HasIdentity(auth.IdentityUserA) {
			defIdent = "USER_A"
		}
		rootPath := normalizeAuthzURLPath(rt.TargetURL)
		if rootPath == "" {
			rootPath = "/"
		}
		key := defIdent + "::GET::" + rootPath
		if !seenObs[key] {
			seenObs[key] = true
			ct := ""
			if rt.Header != nil {
				ct = rt.Header.Get("Content-Type")
			}
			cache.Observations = append(cache.Observations, authzObservation{
				Identity:        defIdent,
				URL:             rt.TargetURL,
				Path:            rootPath,
				Method:          "GET",
				StatusCode:      rt.StatusCode,
				ContentType:     ct,
				Body:            rt.BodyBytes,
				DiscoveryMethod: "SEED",
				Classification:  string(crawler.ClassificationConfirmedEndpoint),
			})
		}
	}

	// Bounded read-only discovery enrichment:
	// 1) Check common OpenAPI/Swagger endpoints once if not already observed.
	// 2) Fetch up to 12 un-fetched API GET candidates across configured identities so JSON payloads & ownership markers are observable.
	if !rt.Opts.SafeMode {
		identMap, _, _, _, _ := collectIdentityProfiles(rt)
		baseTrimmed := strings.TrimRight(rt.TargetURL, "/")

		// Prioritize ADMIN -> USER_A -> USER_B -> ANONYMOUS when probing OpenAPI schema once
		preferredSpecIdent := "ANONYMOUS"
		for _, pref := range []string{"ADMIN", "USER_A", "USER_B", "ANONYMOUS"} {
			if identMap[pref] != nil {
				preferredSpecIdent = pref
				break
			}
		}

		openAPICandidates := []string{"/openapi.json", "/swagger.json", "/api/openapi.json", "/api/swagger.json"}
		for _, sp := range openAPICandidates {
			if int(rt.AuthzDispatchedRequests) >= rt.Opts.AuthzMaxRequests && rt.Opts.AuthzMaxRequests > 0 {
				break
			}
			specURL := baseTrimmed + sp
			if rt.ScopeAllowed != nil && !rt.ScopeAllowed(specURL) {
				continue
			}
			alreadyFetched := false
			for ident := range identMap {
				if seenObs[ident+"::GET::"+sp] && len(fetchedAssetMap[ident+"::"+sp].Content) > 0 {
					alreadyFetched = true
					break
				}
			}
			if alreadyFetched {
				continue
			}
			code, ct, body, err := safeAuthzGET(identMap[preferredSpecIdent], specURL, rt.Opts.Timeout, &rt.AuthzDispatchedRequests)
			if err == nil && code >= 200 && code < 300 && strings.Contains(strings.ToLower(ct+string(body[:minIntLocal(len(body), 128)])), "openapi") ||
				(err == nil && code >= 200 && code < 300 && strings.Contains(string(body[:minIntLocal(len(body), 128)]), `"swagger"`)) {
				cache.Observations = append(cache.Observations, authzObservation{
					Identity:        preferredSpecIdent,
					URL:             specURL,
					Path:            sp,
					Method:          "GET",
					StatusCode:      code,
					ContentType:     ct,
					Body:            body,
					DiscoveryMethod: "OPENAPI_SPEC",
					Classification:  string(crawler.ClassificationConfirmedEndpoint),
				})
				seenObs[preferredSpecIdent+"::GET::"+sp] = true
				break
			}
		}

		// Collect candidate API GET paths that lacked fetched JSON bodies
		candSet := make(map[string]bool)
		for _, obs := range cache.Observations {
			if obs.Method == "GET" && len(obs.Body) == 0 && isSafeCandidateGETPath(obs.Path) {
				candSet[obs.Path] = true
			}
		}
		var candPaths []string
		for p := range candSet {
			candPaths = append(candPaths, p)
		}
		sort.Strings(candPaths)
		if len(candPaths) > 12 {
			candPaths = candPaths[:12]
		}

		var identOrder []string
		for k := range identMap {
			identOrder = append(identOrder, k)
		}
		sort.Strings(identOrder)

		for _, cp := range candPaths {
			targetEndpoint := baseTrimmed + cp
			if rt.ScopeAllowed != nil && !rt.ScopeAllowed(targetEndpoint) {
				continue
			}
			for _, ident := range identOrder {
				if rt.Opts.AuthzMaxRequests > 0 && int(rt.AuthzDispatchedRequests) >= rt.Opts.AuthzMaxRequests {
					break
				}
				client := identMap[ident]
				if client == nil {
					continue
				}
				code, ct, body, err := safeAuthzGET(client, targetEndpoint, rt.Opts.Timeout, &rt.AuthzDispatchedRequests)
				if err != nil {
					continue
				}
				cache.Observations = append(cache.Observations, authzObservation{
					Identity:        ident,
					URL:             targetEndpoint,
					Path:            cp,
					Method:          "GET",
					StatusCode:      code,
					ContentType:     ct,
					Body:            body,
					DiscoveryMethod: "JS_ROUTE_CANDIDATE",
					Classification:  string(crawler.ClassificationConfirmedEndpoint),
					AuthRequirement: visibilityAuthRequirement(rt.VisibilityMatrix, cp),
				})
			}
		}
	}

	rt.AuthzDiscoveryData = cache
	return cache
}

func safeAuthzGET(client *http.Client, targetURL string, timeout time.Duration, counter *int32) (int, string, []byte, error) {
	if client == nil {
		return 0, "", nil, fmt.Errorf("nil client")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return 0, "", nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Felix-Auditor/1.0)")
	if counter != nil {
		*counter++
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return resp.StatusCode, resp.Header.Get("Content-Type"), nil, err
	}
	return resp.StatusCode, resp.Header.Get("Content-Type"), body, nil
}

func normalizeAuthzURLPath(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	p := u.Path
	if p == "" {
		return "/"
	}
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	return p
}

func isSafeCandidateGETPath(p string) bool {
	if p == "" || p == "/" || strings.Contains(p, "{") || strings.Contains(p, ":") {
		return false
	}
	low := strings.ToLower(p)
	if bfla.IsDestructiveFunction("GET", low) {
		return false
	}
	if strings.HasSuffix(low, ".js") || strings.HasSuffix(low, ".css") || strings.HasSuffix(low, ".png") ||
		strings.HasSuffix(low, ".svg") || strings.HasSuffix(low, ".ico") || strings.HasSuffix(low, ".html") {
		return false
	}
	apiHints := []string{"/api", "/v1/", "/v2/", "/user", "/order", "/profile", "/account", "/admin", "/internal", "/invoice", "/document", "/project", "/tenant", "/settings"}
	for _, h := range apiHints {
		if strings.Contains(low, h) {
			return true
		}
	}
	return false
}

func executeAuthzModule(moduleName string, rt *AssessmentRuntimeContext) []report.Finding {
	ensureAuthzReportInitialized(rt)
	if rt.Opts.SafeMode {
		switch moduleName {
		case "bola":
			rt.AuthzReport.BOLA = &report.BOLACoverageSection{Status: "SKIPPED", Limitations: []string{"Skipped under --safe passive mode"}}
			rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BOLA-001", intelligence.StrategyDifferentialBehavior, intelligence.OutcomeInconclusive, "Skipped under --safe passive mode", 0)
		case "bfla":
			rt.AuthzReport.BFLA = &report.BFLACoverageSection{Status: "SKIPPED", Limitations: []string{"Skipped under --safe passive mode"}}
			rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BFLA-001", intelligence.StrategyDifferentialBehavior, intelligence.OutcomeInconclusive, "Skipped under --safe passive mode", 0)
		case "bopla":
			rt.AuthzReport.BOPLA = &report.BOPLACoverageSection{Status: "SKIPPED", Limitations: []string{"Skipped under --safe passive mode"}}
			rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BOPLA-001", intelligence.StrategyDynamicFuzzing, intelligence.OutcomeInconclusive, "Skipped under --safe passive mode", 0)
		case "authz":
			rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-AUTH-001", intelligence.StrategyDifferentialBehavior, intelligence.OutcomeInconclusive, "Skipped under --safe passive mode", 0)
		}
		return nil
	}

	switch moduleName {
	case "bola":
		return runUnifiedBOLA(rt)
	case "bfla":
		return runUnifiedBFLA(rt)
	case "bopla":
		return runUnifiedBOPLA(rt)
	case "authz":
		return runUnifiedAuthzCorrelation(rt)
	default:
		return nil
	}
}

func runUnifiedBOLA(rt *AssessmentRuntimeContext) []report.Finding {
	identClients, profiles, authIdents, _, _ := collectIdentityProfiles(rt)
	disc := ensureAuthzDiscovery(rt)

	bolaObs := make([]bola.DiscoveryObservation, 0, len(disc.Observations))
	for _, o := range disc.Observations {
		bolaObs = append(bolaObs, bola.DiscoveryObservation{
			Identity:        o.Identity,
			URL:             o.URL,
			Path:            o.Path,
			Method:          o.Method,
			StatusCode:      o.StatusCode,
			ContentType:     o.ContentType,
			Body:            o.Body,
			DiscoveryMethod: o.DiscoveryMethod,
			Classification:  o.Classification,
			QueryParams:     o.QueryParams,
			FormFieldNames:  o.FormFieldNames,
		})
	}

	var bolaIdents []bola.TestIdentity
	for _, p := range profiles {
		bolaIdents = append(bolaIdents, bola.TestIdentity{
			Alias:          p.Alias,
			Role:           p.Role,
			Username:       p.Username,
			PrivilegeLevel: p.PrivLevel,
		})
	}

	surface := bola.DiscoverObjectSurface(rt.TargetURL, bolaIdents, bolaObs, rt.Opts.AuthzMaxObjects)
	sec := &report.BOLACoverageSection{
		Status:               "TESTED",
		ObjectsDiscovered:    surface.TotalDiscovered,
		ObjectsWithOwnership: surface.TotalWithOwnership,
	}
	rt.AuthzReport.BOLA = sec

	if len(authIdents) < 2 || len(identClients) < 2 {
		sec.Status = "NOT_CONFIGURED"
		sec.Limitations = append(sec.Limitations, "Requires at least two distinct authenticated identities (e.g., --auth-user-a and --auth-user-b) to verify cross-user object authorization boundaries")
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BOLA-001", intelligence.StrategyDifferentialBehavior, intelligence.OutcomeSkippedMissingMultiRole, sec.Limitations[0], 0)
		return nil
	}

	if len(surface.Objects) == 0 {
		sec.Limitations = append(sec.Limitations, "No concrete parameterized object references discovered within crawl scope")
		if len(surface.UnknownCandidates) > 0 {
			for _, uc := range surface.UnknownCandidates {
				rt.AuthzReport.CoverageItems = append(rt.AuthzReport.CoverageItems, report.AuthzItemCoverageEntry{
					Engine:          "BOLA",
					Item:            uc.TemplatePath + " (" + uc.ObjectID + ")",
					Method:          uc.Method,
					DiscoverySource: uc.DiscoverySource,
					Outcome:         "INCONCLUSIVE",
					Reason:          uc.InconclusiveReason,
				})
				sec.InconclusiveCount++
			}
			rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BOLA-001", intelligence.StrategyDifferentialBehavior, intelligence.OutcomeInconclusive, "Discovered object references lacked verifiable ownership context", 10)
			return nil
		}
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BOLA-001", intelligence.StrategyDifferentialBehavior, intelligence.OutcomePassed, "No unauthorized cross-object references discovered in accessible surface", 15)
		return nil
	}

	fv := verifySyntheticFixtureTarget(rt)
	allowStateChanging := fv.Verified
	isFixtureFn := func(rawURL string) bool {
		return fv.Verified && auth.IsIsolatedFixtureTarget(rawURL, fv.AuthorizedHosts, nil)
	}
	if fv.RequestedStateChanging && !fv.Verified && fv.Reason != "" {
		sec.Limitations = append(sec.Limitations, fv.Reason)
	}
	sourceByObjID := make(map[string]string, len(surface.Objects))
	for _, o := range surface.Objects {
		if o.DiscoverySource != "" {
			sourceByObjID[o.ID] = o.DiscoverySource
		}
	}

	engine := bola.NewEngine(rt.Client, bola.Config{
		Timeout:          rt.Opts.Timeout,
		MaxBodyReadBytes: 1024 * 1024,
		UserAgent:        "Mozilla/5.0 (compatible; Felix-Auditor/1.0)",
	})
	actx := &bola.AssessmentContext{
		AssessmentID:            "asm-assess",
		ExecutionID:             "exec-assess",
		BaseURL:                 rt.TargetURL,
		Endpoints:               surface.Endpoints,
		Objects:                 surface.Objects,
		Identities:              bolaIdents,
		IdentityClients:         identClients,
		TestAllIdentities:       true,
		AllowStateChangingTests: allowStateChanging,
		SyntheticFixture:        rt.Opts.SyntheticFixture,
		AuthorizedFixtureHosts:  fv.AuthorizedHosts,
		IsFixtureTarget:         isFixtureFn,
		MaxObjects:              rt.Opts.AuthzMaxObjects,
		MaxRequests:             rt.Opts.AuthzMaxRequests,
		MaxRequestsPerIdentity:  rt.Opts.AuthzMaxPerIdentity,
		DispatchedRequests:      &rt.AuthzDispatchedRequests,
		IsAllowed:               rt.ScopeAllowed,
		Authorization:           buildCLIAuthRecord(rt),
	}

	results, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		sec.Status = "INCONCLUSIVE"
		sec.Limitations = append(sec.Limitations, fmt.Sprintf("BOLA engine error: %v", err))
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BOLA-001", intelligence.StrategyDifferentialBehavior, intelligence.OutcomeInconclusive, err.Error(), 0)
		return nil
	}

	if summary != nil {
		sec.TotalTests = summary.TotalTests
		sec.VerifiedCount = summary.VerifiedCount
		sec.CandidateCount = summary.CandidateCount
		sec.NotVulnerableCount = summary.NotVulnerableCount
		sec.InconclusiveCount = summary.InconclusiveCount
		sec.SkippedCount = summary.SkippedCount
	}

	var findings []report.Finding
	now := time.Now().UTC()
	for _, r := range results {
		bumpIdentityTestCount(rt, r.AccessorAlias, 1)
		rt.AuthzReport.CoverageItems = append(rt.AuthzReport.CoverageItems, report.AuthzItemCoverageEntry{
			Engine:          "BOLA",
			Item:            fmt.Sprintf("%s [%s]", r.Endpoint, r.ObjectID),
			Method:          r.Method,
			DiscoverySource: sourceByObjID[r.ObjectID],
			Outcome:         string(r.VerificationState),
			TestedAs:        []string{r.AccessorAlias},
			Reason:          secrets.RedactText(r.EvidenceSummary),
		})
		if (r.VerificationState == bola.StateVerified || r.VerificationState == bola.StateCandidate) && r.Finding != nil {
			f := *r.Finding
			f.Timestamp = now
			f.Source = "felix-bola"
			f.AuthContext = report.AuthContextAuthenticated
			findings = append(findings, report.SanitizeFinding(f))
		}
	}

	if sec.VerifiedCount > 0 {
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BOLA-001", intelligence.StrategyDifferentialBehavior, intelligence.OutcomeVulnerable, fmt.Sprintf("Confirmed %d cross-identity BOLA violations across dynamically discovered objects", sec.VerifiedCount), 50)
	} else if sec.NotVulnerableCount > 0 {
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BOLA-001", intelligence.StrategyDifferentialBehavior, intelligence.OutcomePassed, fmt.Sprintf("Object isolation verified enforced across %d checks", sec.NotVulnerableCount), 50)
	} else {
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BOLA-001", intelligence.StrategyDifferentialBehavior, intelligence.OutcomeInconclusive, "Object ownership/differential verification remained inconclusive", 15)
	}
	return findings
}

func runUnifiedBFLA(rt *AssessmentRuntimeContext) []report.Finding {
	identClients, profiles, _, _, hasAdmin := collectIdentityProfiles(rt)
	disc := ensureAuthzDiscovery(rt)

	bflaObs := make([]bfla.DiscoveryObservation, 0, len(disc.Observations))
	for _, o := range disc.Observations {
		bflaObs = append(bflaObs, bfla.DiscoveryObservation{
			Identity:        o.Identity,
			URL:             o.URL,
			Path:            o.Path,
			Method:          o.Method,
			StatusCode:      o.StatusCode,
			ContentType:     o.ContentType,
			Body:            o.Body,
			DiscoveryMethod: o.DiscoveryMethod,
			Classification:  o.Classification,
			AuthRequirement: o.AuthRequirement,
			FormFieldNames:  o.FormFieldNames,
		})
	}

	var bflaIdents []bfla.TestIdentity
	for _, p := range profiles {
		bflaIdents = append(bflaIdents, bfla.TestIdentity{
			Alias:          p.Alias,
			Role:           p.Role,
			PrivilegeLevel: p.PrivLevel,
		})
	}

	surface := bfla.DiscoverFunctionSurface(rt.TargetURL, bflaIdents, bflaObs, rt.Opts.AuthzMaxFunctions)
	var excludedDestructive []string
	for _, rec := range surface.Inventory {
		if rec.Testability == "EXCLUDED_DESTRUCTIVE" {
			excludedDestructive = append(excludedDestructive, rec.Method+" "+rec.Path)
			rt.AuthzReport.CoverageItems = append(rt.AuthzReport.CoverageItems, report.AuthzItemCoverageEntry{
				Engine:          "BFLA",
				Item:            rec.Path,
				Method:          rec.Method,
				DiscoverySource: rec.DiscoverySource,
				Outcome:         "SKIPPED",
				Reason:          rec.SkipReason,
			})
		}
	}

	sec := &report.BFLACoverageSection{
		Status:                       "TESTED",
		FunctionsDiscovered:          surface.TotalDiscovered,
		FunctionsWithEstablishedRole: surface.FunctionsWithEstablishedRole,
		ExcludedDestructive:          excludedDestructive,
	}
	rt.AuthzReport.BFLA = sec

	if !hasAdmin || len(identClients) < 2 {
		sec.Status = "NOT_CONFIGURED"
		sec.Limitations = append(sec.Limitations, "Admin identity (--auth-admin or roles-config admin) not configured alongside a lower-privilege identity; privileged positive control cannot be established")
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BFLA-001", intelligence.StrategyDifferentialBehavior, intelligence.OutcomeSkippedMissingMultiRole, sec.Limitations[0], 0)
		return nil
	}

	if len(surface.Policies) == 0 {
		sec.Limitations = append(sec.Limitations, "No privileged or restricted functions discovered within crawl scope")
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BFLA-001", intelligence.StrategyDifferentialBehavior, intelligence.OutcomePassed, "No exposed privileged function surface discovered", 20)
		return nil
	}

	fv := verifySyntheticFixtureTarget(rt)
	allowStateChanging := fv.Verified
	isFixtureFn := func(rawURL string) bool {
		return fv.Verified && auth.IsIsolatedFixtureTarget(rawURL, fv.AuthorizedHosts, nil)
	}
	if fv.RequestedStateChanging && !fv.Verified && fv.Reason != "" {
		sec.Limitations = append(sec.Limitations, fv.Reason)
	}
	sourceByFuncID := make(map[string]string, len(surface.Policies))
	for _, p := range surface.Policies {
		if p.DiscoverySource != "" {
			sourceByFuncID["bfla-"+p.FunctionID] = p.DiscoverySource
		}
	}

	engine := bfla.NewEngine(rt.Client, bfla.Config{
		Timeout:          rt.Opts.Timeout,
		MaxBodyReadBytes: 1024 * 1024,
		UserAgent:        "Mozilla/5.0 (compatible; Felix-Auditor/1.0)",
	})
	actx := &bfla.AssessmentContext{
		AssessmentID:            "asm-assess",
		ExecutionID:             "exec-assess",
		BaseURL:                 rt.TargetURL,
		Policies:                surface.Policies,
		Identities:              bflaIdents,
		IdentityClients:         identClients,
		TestAllIdentities:       true,
		AllowStateChangingTests: allowStateChanging,
		SyntheticFixture:        rt.Opts.SyntheticFixture,
		AuthorizedFixtureHosts:  fv.AuthorizedHosts,
		IsFixtureTarget:         isFixtureFn,
		MaxFunctions:            rt.Opts.AuthzMaxFunctions,
		MaxRequests:             rt.Opts.AuthzMaxRequests,
		MaxRequestsPerIdentity:  rt.Opts.AuthzMaxPerIdentity,
		DispatchedRequests:      &rt.AuthzDispatchedRequests,
		IsAllowed:               rt.ScopeAllowed,
		Authorization:           buildCLIAuthRecord(rt),
	}

	results, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		sec.Status = "INCONCLUSIVE"
		sec.Limitations = append(sec.Limitations, fmt.Sprintf("BFLA engine error: %v", err))
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BFLA-001", intelligence.StrategyDifferentialBehavior, intelligence.OutcomeInconclusive, err.Error(), 0)
		return nil
	}

	if summary != nil {
		sec.TotalTests = summary.TotalTests
		sec.VerifiedCount = summary.VerifiedCount
		sec.CandidateCount = summary.CandidateCount
		sec.NotVulnerableCount = summary.NotVulnerableCount
		sec.InconclusiveCount = summary.InconclusiveCount
		sec.SkippedCount = summary.SkippedCount
		sec.PrivilegeComparisons = summary.PrivilegeComparisons
	}

	var findings []report.Finding
	now := time.Now().UTC()
	for _, r := range results {
		bumpIdentityTestCount(rt, r.AccessorAlias, 1)
		rt.AuthzReport.CoverageItems = append(rt.AuthzReport.CoverageItems, report.AuthzItemCoverageEntry{
			Engine:          "BFLA",
			Item:            r.Endpoint,
			Method:          r.Method,
			DiscoverySource: sourceByFuncID[r.TestID],
			Outcome:         string(r.VerificationState),
			TestedAs:        []string{r.AccessorAlias},
			Reason:          secrets.RedactText(r.EvidenceSummary),
		})
		if (r.VerificationState == bfla.StateVerified || r.VerificationState == bfla.StateCandidate) && r.Finding != nil {
			f := *r.Finding
			f.Timestamp = now
			f.Source = "felix-bfla"
			f.AuthContext = report.AuthContextAuthenticated
			findings = append(findings, report.SanitizeFinding(f))
		}
	}

	if sec.VerifiedCount > 0 {
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BFLA-001", intelligence.StrategyDifferentialBehavior, intelligence.OutcomeVulnerable, fmt.Sprintf("Verified %d broken function-level authorization flaws", sec.VerifiedCount), 50)
	} else if sec.NotVulnerableCount > 0 {
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BFLA-001", intelligence.StrategyDifferentialBehavior, intelligence.OutcomePassed, fmt.Sprintf("Function-level RBAC enforced across %d comparisons", sec.NotVulnerableCount), 40)
	} else {
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BFLA-001", intelligence.StrategyDifferentialBehavior, intelligence.OutcomeInconclusive, "Function-level checks completed with inconclusive privilege boundaries", 15)
	}
	return findings
}

func runUnifiedBOPLA(rt *AssessmentRuntimeContext) []report.Finding {
	identClients, profiles, authIdents, _, _ := collectIdentityProfiles(rt)
	disc := ensureAuthzDiscovery(rt)

	boplaObs := make([]bopla.DiscoveryObservation, 0, len(disc.Observations))
	for _, o := range disc.Observations {
		boplaObs = append(boplaObs, bopla.DiscoveryObservation{
			Identity:        o.Identity,
			URL:             o.URL,
			Path:            o.Path,
			Method:          o.Method,
			StatusCode:      o.StatusCode,
			ContentType:     o.ContentType,
			Body:            o.Body,
			DiscoveryMethod: o.DiscoveryMethod,
			Classification:  o.Classification,
			FormFieldNames:  o.FormFieldNames,
		})
	}

	var boplaIdents []bopla.TestIdentity
	for _, p := range profiles {
		boplaIdents = append(boplaIdents, bopla.TestIdentity{
			Alias:          p.Alias,
			Role:           p.Role,
			PrivilegeLevel: p.PrivLevel,
		})
	}

	surface := bopla.DiscoverPropertySurface(rt.TargetURL, boplaIdents, boplaObs, rt.Opts.AuthzMaxProperties)
	fv := verifySyntheticFixtureTarget(rt)
	allowStateChanging := fv.Verified
	isFixtureFn := func(rawURL string) bool {
		return fv.Verified && auth.IsIsolatedFixtureTarget(rawURL, fv.AuthorizedHosts, nil)
	}

	sec := &report.BOPLACoverageSection{
		Status:               "TESTED",
		PropertiesDiscovered: surface.TotalDiscovered,
		PropertiesWithPolicy: surface.PropertiesWithPolicy,
		StateChangingGated:   !allowStateChanging,
	}
	if fv.RequestedStateChanging && !fv.Verified && fv.Reason != "" {
		sec.Limitations = append(sec.Limitations, fv.Reason)
	}
	rt.AuthzReport.BOPLA = sec

	if len(authIdents) == 0 || len(identClients) < 2 {
		sec.Status = "NOT_CONFIGURED"
		sec.Limitations = append(sec.Limitations, "Requires at least one authenticated identity plus a distinct comparison identity to verify object property authorization")
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BOPLA-001", intelligence.StrategyDynamicFuzzing, intelligence.OutcomeSkippedMissingMultiRole, sec.Limitations[0], 0)
		return nil
	}

	if len(surface.Policies) == 0 {
		sec.Limitations = append(sec.Limitations, "No restricted or mass-assignable object properties discovered in API JSON/OpenAPI surface")
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BOPLA-001", intelligence.StrategyDynamicFuzzing, intelligence.OutcomePassed, "No unauthorized property exposure or mass-assignment candidates discovered", 20)
		return nil
	}

	sourceByPropID := make(map[string]string, len(surface.Policies))
	for _, p := range surface.Policies {
		if p.DiscoverySource != "" {
			sourceByPropID["bopla-"+p.PropertyID] = p.DiscoverySource
		}
	}

	engine := bopla.NewEngine(rt.Client, bopla.Config{
		Timeout:          rt.Opts.Timeout,
		MaxResponseBytes: 2 * 1024 * 1024,
	})
	actx := &bopla.AssessmentContext{
		AssessmentID:            "asm-assess",
		ExecutionID:             "exec-assess",
		BaseURL:                 rt.TargetURL,
		Policies:                surface.Policies,
		Identities:              boplaIdents,
		IdentityClients:         identClients,
		TestAllIdentities:       true,
		AllowStateChangingTests: allowStateChanging,
		SyntheticFixture:        rt.Opts.SyntheticFixture,
		AuthorizedFixtureHosts:  fv.AuthorizedHosts,
		IsFixtureTarget:         isFixtureFn,
		MaxProperties:           rt.Opts.AuthzMaxProperties,
		MaxRequests:             rt.Opts.AuthzMaxRequests,
		MaxRequestsPerIdentity:  rt.Opts.AuthzMaxPerIdentity,
		DispatchedRequests:      &rt.AuthzDispatchedRequests,
		IsAllowed:               rt.ScopeAllowed,
		Authorization:           buildCLIAuthRecord(rt),
	}

	results, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		sec.Status = "INCONCLUSIVE"
		sec.Limitations = append(sec.Limitations, fmt.Sprintf("BOPLA engine error: %v", err))
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BOPLA-001", intelligence.StrategyDynamicFuzzing, intelligence.OutcomeInconclusive, err.Error(), 0)
		return nil
	}

	if summary != nil {
		sec.TotalTests = summary.TotalTests
		sec.ExposureTests = summary.ExposureTests
		sec.ModificationTests = summary.ModificationTests
		sec.VerifiedCount = summary.VerifiedCount
		sec.CandidateCount = summary.CandidateCount
		sec.NotVulnerableCount = summary.NotVulnerableCount
		sec.InconclusiveCount = summary.InconclusiveCount
		sec.SkippedCount = summary.SkippedCount
		sec.CleanupAttempted = summary.CleanupAttempted
		sec.CleanupRestored = summary.CleanupRestored
		sec.CleanupFailed = summary.CleanupFailed
		sec.CleanupUnverified = summary.CleanupUnverified
		seenWarn := make(map[string]bool)
		for _, w := range summary.CleanupWarnings {
			if w != "" && !seenWarn[w] {
				seenWarn[w] = true
				sec.Limitations = append(sec.Limitations, w)
			}
		}
	}

	var findings []report.Finding
	now := time.Now().UTC()
	for _, r := range results {
		bumpIdentityTestCount(rt, r.AccessorAlias, 1)
		reasonText := r.EvidenceSummary
		if r.CleanupWarning != "" {
			reasonText = fmt.Sprintf("%s [%s: %s]", reasonText, r.CleanupStatus, r.CleanupWarning)
		}
		rt.AuthzReport.CoverageItems = append(rt.AuthzReport.CoverageItems, report.AuthzItemCoverageEntry{
			Engine:          "BOPLA",
			Item:            fmt.Sprintf("%s [%s]", r.Endpoint, r.PropertyPath),
			Method:          r.Method,
			DiscoverySource: sourceByPropID[r.TestID],
			Outcome:         string(r.VerificationState),
			TestedAs:        []string{r.AccessorAlias},
			Reason:          secrets.RedactText(reasonText),
		})
		if (r.VerificationState == bopla.StateVerified || r.VerificationState == bopla.StateCandidate) && r.Finding != nil {
			f := *r.Finding
			f.Timestamp = now
			f.Source = "felix-bopla"
			f.AuthContext = report.AuthContextAuthenticated
			findings = append(findings, report.SanitizeFinding(f))
		}
	}

	if sec.VerifiedCount > 0 {
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BOPLA-001", intelligence.StrategyDynamicFuzzing, intelligence.OutcomeVulnerable, fmt.Sprintf("Verified %d property-level authorization exposures/mutations", sec.VerifiedCount), 50)
	} else if sec.NotVulnerableCount > 0 {
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BOPLA-001", intelligence.StrategyDynamicFuzzing, intelligence.OutcomePassed, fmt.Sprintf("Property-level access controls enforced across %d checks", sec.NotVulnerableCount), 40)
	} else if sec.SkippedCount > 0 && sec.TotalTests == sec.SkippedCount {
		sec.Limitations = append(sec.Limitations, "Property modification tests skipped because --allow-state-changing + --synthetic-fixture opt-in was not active")
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BOPLA-001", intelligence.StrategyDynamicFuzzing, intelligence.OutcomeInconclusive, sec.Limitations[len(sec.Limitations)-1], 10)
	} else {
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-BOPLA-001", intelligence.StrategyDynamicFuzzing, intelligence.OutcomeInconclusive, "Property-level checks yielded inconclusive outcomes", 15)
	}
	return findings
}

func runUnifiedAuthzCorrelation(rt *AssessmentRuntimeContext) []report.Finding {
	_, _, authIdents, hasDistinct, _ := collectIdentityProfiles(rt)
	rep := finalizeAuthzReport(rt)
	if !hasDistinct || len(authIdents) == 0 {
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-AUTH-001", intelligence.StrategyDifferentialBehavior, intelligence.OutcomeSkippedMissingMultiRole, "Requires configured distinct credentials across roles to validate multi-tenant authorization boundaries", 0)
		return nil
	}

	totalVerified := 0
	totalNotVuln := 0
	if rep.BOLA != nil {
		totalVerified += rep.BOLA.VerifiedCount
		totalNotVuln += rep.BOLA.NotVulnerableCount
	}
	if rep.BFLA != nil {
		totalVerified += rep.BFLA.VerifiedCount
		totalNotVuln += rep.BFLA.NotVulnerableCount
	}
	if rep.BOPLA != nil {
		totalVerified += rep.BOPLA.VerifiedCount
		totalNotVuln += rep.BOPLA.NotVulnerableCount
	}

	if totalVerified > 0 {
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-AUTH-001", intelligence.StrategyDifferentialBehavior, intelligence.OutcomeVulnerable, fmt.Sprintf("Cross-identity authorization testing confirmed %d violation(s) across BOLA/BFLA/BOPLA", totalVerified), 45)
	} else if totalNotVuln > 0 {
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-AUTH-001", intelligence.StrategyDifferentialBehavior, intelligence.OutcomePassed, fmt.Sprintf("Multi-identity authorization checks passed across %d enforced boundaries", totalNotVuln), 35)
	} else {
		rt.Tracker.RecordTest(rt.TargetAssetID, rt.TargetURL, "VULN-AUTH-001", intelligence.StrategyDifferentialBehavior, intelligence.OutcomeInconclusive, "Insufficient confirmed/enforced multi-role test outcomes to assert tenant isolation", 10)
	}
	return nil
}

func finalizeAuthzReport(rt *AssessmentRuntimeContext) *report.AuthorizationReportSummary {
	if rt == nil || rt.AuthzReport == nil {
		return nil
	}
	rep := rt.AuthzReport
	rep.RequestsSent = int(rt.AuthzDispatchedRequests)
	rep.FixtureVerification = verifySyntheticFixtureTarget(rt)

	// Populate quantitative coverage metrics across discovery, identities, and BOLA/BFLA/BOPLA outcomes
	uniqueEndpoints := make(map[string]bool)
	if rt.AuthzDiscoveryData != nil {
		for _, obs := range rt.AuthzDiscoveryData.Observations {
			if p := strings.TrimSpace(obs.Path); p != "" {
				uniqueEndpoints[strings.ToUpper(obs.Method)+" "+p] = true
			}
		}
	}
	if rt.VisibilityMatrix != nil {
		for ep := range rt.VisibilityMatrix.Endpoints {
			uniqueEndpoints[ep] = true
		}
	}

	qc := report.AuthzQuantitativeCoverage{
		EndpointsObserved: len(uniqueEndpoints),
	}
	for _, ic := range rep.IdentityCoverage {
		if ic.Configured {
			qc.IdentitiesConfigured++
		}
		if ic.Verified {
			qc.IdentitiesVerified++
		}
	}
	if rep.BOLA != nil {
		qc.ObjectsDiscovered = rep.BOLA.ObjectsDiscovered
		qc.TotalChecksPlanned += rep.BOLA.TotalTests
		qc.VerifiedTotal += rep.BOLA.VerifiedCount
		qc.CandidateTotal += rep.BOLA.CandidateCount
		qc.NotVulnerableTotal += rep.BOLA.NotVulnerableCount
		qc.InconclusiveTotal += rep.BOLA.InconclusiveCount
		qc.SkippedTotal += rep.BOLA.SkippedCount
	}
	if rep.BFLA != nil {
		qc.FunctionsDiscovered = rep.BFLA.FunctionsDiscovered
		qc.TotalChecksPlanned += rep.BFLA.TotalTests
		qc.VerifiedTotal += rep.BFLA.VerifiedCount
		qc.CandidateTotal += rep.BFLA.CandidateCount
		qc.NotVulnerableTotal += rep.BFLA.NotVulnerableCount
		qc.InconclusiveTotal += rep.BFLA.InconclusiveCount
		qc.SkippedTotal += rep.BFLA.SkippedCount
	}
	if rep.BOPLA != nil {
		qc.PropertiesDiscovered = rep.BOPLA.PropertiesDiscovered
		qc.TotalChecksPlanned += rep.BOPLA.TotalTests
		qc.VerifiedTotal += rep.BOPLA.VerifiedCount
		qc.CandidateTotal += rep.BOPLA.CandidateCount
		qc.NotVulnerableTotal += rep.BOPLA.NotVulnerableCount
		qc.InconclusiveTotal += rep.BOPLA.InconclusiveCount
		qc.SkippedTotal += rep.BOPLA.SkippedCount
	}

	exclSet := make(map[string]bool)
	for _, dr := range rt.DiscoveredResources {
		if dr.Classification == crawler.ClassificationExcludedDestructive {
			key := strings.ToUpper(dr.HTTPMethod) + " " + dr.Path
			exclSet[key] = true
		}
	}
	if rep.BFLA != nil {
		for _, ed := range rep.BFLA.ExcludedDestructive {
			exclSet[strings.TrimSpace(ed)] = true
		}
	}
	qc.ExcludedDestructiveCount = len(exclSet)

	if qc.TotalChecksPlanned >= qc.SkippedTotal {
		qc.TotalChecksExecuted = qc.TotalChecksPlanned - qc.SkippedTotal
	}
	if qc.TotalChecksPlanned > 0 {
		qc.ExecutionCoveragePct = math.Round(float64(qc.TotalChecksExecuted)*1000.0/float64(qc.TotalChecksPlanned)) / 10.0
	}
	if qc.TotalChecksExecuted > 0 {
		qc.DeterminativeOutcomePct = math.Round(float64(qc.VerifiedTotal+qc.NotVulnerableTotal)*1000.0/float64(qc.TotalChecksExecuted)) / 10.0
	}
	rep.QuantitativeCoverage = qc

	testedEngines := 0
	unconfiguredEngines := 0
	for _, st := range []string{
		func() string {
			if rep.BOLA != nil {
				return rep.BOLA.Status
			}
			return ""
		}(),
		func() string {
			if rep.BFLA != nil {
				return rep.BFLA.Status
			}
			return ""
		}(),
		func() string {
			if rep.BOPLA != nil {
				return rep.BOPLA.Status
			}
			return ""
		}(),
	} {
		if st == "TESTED" {
			testedEngines++
		} else if st == "NOT_CONFIGURED" || st == "SKIPPED" {
			unconfiguredEngines++
		}
	}

	switch {
	case testedEngines > 0 && unconfiguredEngines == 0:
		rep.Status = "TESTED"
	case testedEngines > 0:
		rep.Status = "PARTIAL"
		rep.Limitation = "One or more authorization checks lacked required identity roles or opt-in mutation flags"
	case unconfiguredEngines > 0:
		rep.Status = "NOT_CONFIGURED"
		rep.Limitation = "Required distinct multi-role identities were not configured for full authorization testing"
	default:
		rep.Status = "SKIPPED"
	}

	var notes []string
	if rep.Limitation != "" {
		notes = append(notes, rep.Limitation)
	}
	if rep.FixtureVerification != nil && rep.FixtureVerification.RequestedStateChanging && !rep.FixtureVerification.Verified && rep.FixtureVerification.Reason != "" {
		notes = append(notes, rep.FixtureVerification.Reason)
	}
	if rep.BOPLA != nil && (rep.BOPLA.CleanupFailed > 0 || rep.BOPLA.CleanupUnverified > 0) {
		notes = append(notes, fmt.Sprintf("BOPLA reversible mutation cleanup reported %d failure(s) and %d unverified restoration(s)", rep.BOPLA.CleanupFailed, rep.BOPLA.CleanupUnverified))
	}
	if len(notes) > 0 {
		rep.Limitation = strings.Join(notes, "; ")
	}
	return report.SanitizeAuthorizationReport(rep)
}

func minIntLocal(a, b int) int {
	if a < b {
		return a
	}
	return b
}
