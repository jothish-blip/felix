package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"felix/pkg/secrets"
)

// ClassificationOutcome represents the four distinct security classification outcomes
// defined by the Phase 3.5 shared framework assessment contract.
type ClassificationOutcome string

const (
	OutcomeInformational ClassificationOutcome = "INFORMATIONAL"
	OutcomeConfirmed     ClassificationOutcome = "CONFIRMED"
	OutcomeSuspected     ClassificationOutcome = "SUSPECTED"
	OutcomeInconclusive  ClassificationOutcome = "INCONCLUSIVE"
)

// IsValidClassificationOutcome checks if an outcome is one of the four canonical states.
func IsValidClassificationOutcome(o ClassificationOutcome) bool {
	switch o {
	case OutcomeInformational, OutcomeConfirmed, OutcomeSuspected, OutcomeInconclusive:
		return true
	default:
		return false
	}
}

// NormalizeClassificationOutcome standardizes a raw outcome string to a canonical enum.
// Unknown or empty input defaults to OutcomeInconclusive to avoid false security inferences.
func NormalizeClassificationOutcome(raw string) ClassificationOutcome {
	clean := strings.ToUpper(strings.TrimSpace(raw))
	switch ClassificationOutcome(clean) {
	case OutcomeInformational, "INFO", "OBSERVED", "INVENTORY":
		return OutcomeInformational
	case OutcomeConfirmed, "VERIFIED", "PROVEN":
		return OutcomeConfirmed
	case OutcomeSuspected, "DETECTED", "POTENTIAL", "CANDIDATE", "UNVERIFIED":
		return OutcomeSuspected
	case OutcomeInconclusive, "INDETERMINATE", "AMBIGUOUS", "UNDETERMINED":
		return OutcomeInconclusive
	default:
		return OutcomeInconclusive
	}
}

// ReachabilityStatus represents the empirical reachability of a probed framework endpoint.
type ReachabilityStatus string

const (
	ReachabilityConfirmedReachable    ReachabilityStatus = "CONFIRMED_REACHABLE"
	ReachabilityConfirmedInaccessible ReachabilityStatus = "CONFIRMED_INACCESSIBLE"
	ReachabilityInconclusive          ReachabilityStatus = "INCONCLUSIVE"
	ReachabilityUnknown               ReachabilityStatus = "UNKNOWN"
)

// IsValidReachabilityStatus checks if a reachability status is canonical.
func IsValidReachabilityStatus(r ReachabilityStatus) bool {
	switch r {
	case ReachabilityConfirmedReachable, ReachabilityConfirmedInaccessible, ReachabilityInconclusive, ReachabilityUnknown:
		return true
	default:
		return false
	}
}

// NormalizeReachability standardizes reachability to a canonical enum value.
// It explicitly evaluates transport status, errors, and reverse proxy / gateway indicators.
func NormalizeReachability(raw string, httpStatus int, err error) ReachabilityStatus {
	clean := strings.ToUpper(strings.TrimSpace(raw))
	switch ReachabilityStatus(clean) {
	case ReachabilityConfirmedReachable, "REACHABLE", "OPEN":
		return ReachabilityConfirmedReachable
	case ReachabilityConfirmedInaccessible, "INACCESSIBLE", "DENIED", "NOT_FOUND", "RESTRICTED", "BLOCKED":
		return ReachabilityConfirmedInaccessible
	case ReachabilityInconclusive, "AMBIGUOUS", "TIMEOUT", "GATEWAY_ERROR":
		return ReachabilityInconclusive
	case ReachabilityUnknown, "UNTESTED", "NOT_TESTED":
		return ReachabilityUnknown
	}

	// Reason reachability from transport error
	if err != nil {
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded") ||
			strings.Contains(errStr, "connection reset") || strings.Contains(errStr, "broken pipe") {
			return ReachabilityInconclusive
		}
		if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "no such host") ||
			strings.Contains(errStr, "tls") || strings.Contains(errStr, "certificate") {
			return ReachabilityConfirmedInaccessible
		}
		return ReachabilityInconclusive
	}

	// Reason reachability from HTTP status
	switch {
	case httpStatus >= 200 && httpStatus <= 299:
		return ReachabilityConfirmedReachable
	case httpStatus == http.StatusUnauthorized || httpStatus == http.StatusForbidden || httpStatus == http.StatusNotFound || httpStatus == http.StatusGone:
		return ReachabilityConfirmedInaccessible
	case httpStatus == http.StatusBadGateway || httpStatus == http.StatusServiceUnavailable || httpStatus == http.StatusGatewayTimeout:
		// Reverse proxy or gateway error obscures the underlying endpoint
		return ReachabilityInconclusive
	case httpStatus >= 300 && httpStatus <= 399:
		return ReachabilityConfirmedReachable
	case httpStatus == http.StatusInternalServerError:
		// Internal server error (e.g. Django/Go/Node debug crash) reached and responded from the application
		return ReachabilityConfirmedReachable
	case httpStatus > 0:
		return ReachabilityConfirmedReachable
	default:
		return ReachabilityUnknown
	}
}

// AuthenticationContext represents the access-control and authentication state observed on a framework endpoint.
type AuthenticationContext string

const (
	AuthContextRequired      AuthenticationContext = "AUTH_REQUIRED"
	AuthContextNoChallenge   AuthenticationContext = "NO_CHALLENGE"
	AuthContextAuthenticated AuthenticationContext = "AUTHENTICATED"
	AuthContextUnknown       AuthenticationContext = "UNKNOWN"
	AuthContextInconclusive  AuthenticationContext = "INCONCLUSIVE"
)

// IsValidAuthenticationContext checks if an authentication context is canonical.
func IsValidAuthenticationContext(a AuthenticationContext) bool {
	switch a {
	case AuthContextRequired, AuthContextNoChallenge, AuthContextAuthenticated, AuthContextUnknown, AuthContextInconclusive:
		return true
	default:
		return false
	}
}

// NormalizeAuthContext standardizes authentication context to a canonical enum value.
// It records authentication context strictly separate from reachability.
func NormalizeAuthContext(raw string, authState AuthState, httpStatus int, headers http.Header, body []byte) AuthenticationContext {
	clean := strings.ToUpper(strings.TrimSpace(raw))
	switch AuthenticationContext(clean) {
	case AuthContextRequired, "REQUIRED", "CHALLENGE":
		return AuthContextRequired
	case AuthContextNoChallenge, "NONE", "PUBLIC", "UNAUTHENTICATED":
		return AuthContextNoChallenge
	case AuthContextAuthenticated, "AUTHORIZED":
		return AuthContextAuthenticated
	case AuthContextInconclusive, "INDETERMINATE":
		return AuthContextInconclusive
	case AuthContextUnknown:
		return AuthContextUnknown
	}

	// Reason from AuthState if already evaluated
	switch authState {
	case AuthStateAuthRequired, AuthStateForbidden:
		return AuthContextRequired
	case AuthStatePublic:
		return AuthContextNoChallenge
	case AuthStateRedirect:
		return AuthContextRequired
	}

	// Reason from HTTP telemetry
	switch httpStatus {
	case http.StatusUnauthorized:
		return AuthContextRequired
	case http.StatusForbidden:
		return AuthContextRequired
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return AuthContextInconclusive
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
		// Check for HTML login redirection/form
		if len(body) > 0 {
			lower := strings.ToLower(string(body))
			if strings.Contains(lower, "login") && strings.Contains(lower, "password") && strings.Contains(lower, "<form") {
				return AuthContextRequired
			}
		}
		return AuthContextNoChallenge
	default:
		if httpStatus == 0 {
			return AuthContextUnknown
		}
		return AuthContextUnknown
	}
}

// NormalizeFrameworkEndpoint canonicalizes endpoint URLs/paths without destroying meaningful distinctions.
// Volatile tracking parameters are pruned, while material query parameters (e.g. ?debug=1) are sorted and preserved.
func NormalizeFrameworkEndpoint(rawEndpoint string) string {
	clean := strings.TrimSpace(rawEndpoint)
	if clean == "" {
		return ""
	}

	u, err := url.Parse(clean)
	if err != nil {
		return clean
	}

	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if u.Scheme == "http" && strings.HasSuffix(u.Host, ":80") {
		u.Host = strings.TrimSuffix(u.Host, ":80")
	} else if u.Scheme == "https" && strings.HasSuffix(u.Host, ":443") {
		u.Host = strings.TrimSuffix(u.Host, ":443")
	}

	// Canonicalize redundant slashes in path
	p := u.Path
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	// Normalize trailing slashes on non-empty paths
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	// Root slash normalization
	if p == "/" && u.RawQuery == "" && u.Fragment == "" {
		p = ""
	}
	u.Path = p

	// Filter volatile tracking query parameters while preserving material functional parameters
	if u.RawQuery != "" {
		q := u.Query()
		volatileKeys := map[string]bool{
			"utm_source":   true,
			"utm_medium":   true,
			"utm_campaign": true,
			"utm_term":     true,
			"utm_content":  true,
			"gclid":        true,
			"fbclid":       true,
			"_":            true,
			"timestamp":    true,
			"ts":           true,
			"cb":           true,
			"nocache":      true,
			"rnd":          true,
			"random":       true,
		}
		for k := range volatileKeys {
			q.Del(k)
		}

		if len(q) == 0 {
			u.RawQuery = ""
		} else {
			keys := make([]string, 0, len(q))
			for k := range q {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			var pairs []string
			for _, k := range keys {
				vals := q[k]
				sort.Strings(vals)
				for _, v := range vals {
					pairs = append(pairs, url.QueryEscape(k)+"="+url.QueryEscape(v))
				}
			}
			u.RawQuery = strings.Join(pairs, "&")
		}
	}

	return u.String()
}

// GenerateFrameworkFingerprint generates a stable, deterministic deduplication fingerprint.
func GenerateFrameworkFingerprint(category, endpoint, method, framework string) string {
	h := sha256.New()
	cleanFramework := strings.ToLower(strings.TrimSpace(framework))
	cleanCategory := strings.ToLower(strings.TrimSpace(category))
	cleanEndpoint := strings.ToLower(NormalizeFrameworkEndpoint(endpoint))
	cleanMethod := strings.ToUpper(strings.TrimSpace(method))
	if cleanMethod == "" {
		cleanMethod = "GET"
	}

	payload := fmt.Sprintf("%s|%s|%s|%s", cleanFramework, cleanCategory, cleanEndpoint, cleanMethod)
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

// DetectFramework returns the canonical framework name and version from category and finding details.
func DetectFramework(category string, details map[string]string) (framework string, version string) {
	if len(details) > 0 {
		if fw, ok := details["framework"]; ok && fw != "" {
			framework = strings.TrimSpace(fw)
		}
		if v, ok := details["framework_version"]; ok && v != "" {
			version = strings.TrimSpace(v)
		} else if v, ok := details["version"]; ok && v != "" {
			version = strings.TrimSpace(v)
		}
	}

	if framework != "" {
		return framework, version
	}

	cat := strings.ToLower(strings.TrimSpace(category))
	switch {
	case strings.Contains(cat, "actuator"):
		framework = "Spring Boot"
	case strings.Contains(cat, "django"):
		framework = "Django"
	case strings.Contains(cat, "fastapi"):
		framework = "FastAPI"
	case strings.Contains(cat, "laravel") || strings.Contains(cat, "ignition") || strings.Contains(cat, "telescope"):
		framework = "Laravel"
	case strings.Contains(cat, "node"):
		framework = "Node.js"
	case strings.Contains(cat, "go-") || strings.Contains(cat, "golang"):
		framework = "Go"
	default:
		framework = "generic"
	}

	return framework, version
}

// ComputeFrameworkRuleID derives a canonical rule identifier from framework and category.
func ComputeFrameworkRuleID(framework, category string) string {
	catClean := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(category), "_", "-"))
	if strings.HasPrefix(catClean, "API-") {
		return catClean
	}
	return "API-" + catClean
}

// ClassifyFrameworkEvidence implements the deterministic classification engine enforcing the 10 invariants.
func ClassifyFrameworkEvidence(f *APIFinding) {
	cat := strings.ToLower(strings.TrimSpace(f.Category))

	// Invariant 10 & Inconclusive handling:
	// If transport failed, gateway error occurred, or detector marked inconclusive, outcome MUST be Inconclusive
	if f.Reachability == ReachabilityInconclusive || f.Details["classification"] == "inconclusive" ||
		(f.Confidence == ConfidenceLow && strings.Contains(strings.ToLower(f.Evidence), "inconclusive")) {
		f.ClassificationOutcome = OutcomeInconclusive
		f.Severity = SeverityInfo
		f.Confidence = ConfidenceLow
		f.Limitations = appendIfNotExists(f.Limitations, "Evidence is ambiguous or affected by transport/intermediary behavior; operational exposure was not established.")
		return
	}

	// Evaluation of the Four Classification Outcomes across frameworks
	switch {
	// --- A. INFORMATIONAL OUTCOMES ---
	// 1. Framework/Runtime Header Identification (Invariant 2: Framework identification alone never proves a vulnerability)
	case cat == CategoryNodeRuntimeExposure || cat == CategoryGoRuntimeExposure || f.Details["interface"] == "runtime_header":
		f.ClassificationOutcome = OutcomeInformational
		f.Severity = SeverityInfo
		f.Confidence = ConfidenceHigh
		f.Limitations = appendIfNotExists(f.Limitations, "Framework identification header observed; no unauthenticated diagnostic interface or stack trace was disclosed.")

	// 2. Harmless Diagnostic Index (Invariant 7: Diagnostic endpoint existence does not establish high severity)
	case cat == CategoryGoPprofExposure && (f.Details["interface"] == "profiling_index" || f.Severity == SeverityLow || f.Severity == SeverityInfo):
		f.ClassificationOutcome = OutcomeInformational
		if f.Severity == SeverityCritical || f.Severity == SeverityHigh || f.Severity == SeverityMedium {
			f.Severity = SeverityInfo
		}
		f.Confidence = ConfidenceHigh
		f.Limitations = appendIfNotExists(f.Limitations, "Diagnostic index observed; live execution traces and memory dumps were not exposed.")

	// 3. Public Interactive Documentation & Route Visibility (Invariant 1 & 3: Reachability / route names alone do not prove unauthorized access)
	case cat == CategoryAPIDocsExposure || cat == CategoryFastAPIDocs || cat == CategoryDjangoBrowsableAPI:
		f.ClassificationOutcome = OutcomeInformational
		if f.Severity == SeverityCritical || f.Severity == SeverityHigh || f.Severity == SeverityMedium || f.Severity == "" {
			f.Severity = SeverityInfo
		}
		f.Confidence = ConfidenceHigh
		f.Limitations = appendIfNotExists(f.Limitations, "Public API documentation/interface observed; authorization checks apply to individual operational endpoints.")

	case cat == CategoryFastAPISensitivePaths:
		f.ClassificationOutcome = OutcomeInformational
		f.Severity = SeverityInfo
		if f.Confidence == "" {
			f.Confidence = ConfidenceLow
		}
		f.Limitations = appendIfNotExists(f.Limitations, "Route definitions cataloged from schema without recursive probing; reachability and authorization state of target routes remain unverified.")

	// 4. Routine Operational Telemetry without Sensitive Disclosure
	case cat == CategoryHealthExposure || cat == CategoryMetricsExposure:
		f.ClassificationOutcome = OutcomeInformational
		if f.Severity == SeverityCritical || f.Severity == SeverityHigh || f.Severity == SeverityMedium || f.Severity == "" {
			f.Severity = SeverityInfo
		}
		f.Confidence = ConfidenceHigh
		f.Limitations = appendIfNotExists(f.Limitations, "Standard operational health/metrics telemetry; administrative credential access not demonstrated.")

	case cat == CategoryGoVarsExposure && f.Details["candidate_material_status"] == "" && !strings.Contains(f.Evidence, "Candidate secret material observed"):
		f.ClassificationOutcome = OutcomeInformational
		f.Severity = SeverityInfo
		f.Confidence = ConfidenceHigh
		f.Limitations = appendIfNotExists(f.Limitations, "Operational metrics cataloged; sensitive environment credentials were not observed.")

	// 5. Access Restricted Endpoints
	case cat == CategoryActuatorRestricted || cat == CategoryLaravelTelescopeProtected:
		f.ClassificationOutcome = OutcomeInformational
		f.Severity = SeverityInfo
		f.Confidence = ConfidenceHigh
		f.Reachability = ReachabilityConfirmedInaccessible
		f.AuthContext = AuthContextRequired
		f.Limitations = appendIfNotExists(f.Limitations, "Access is restricted by authentication challenge or authorization refusal.")

	// 6. Laravel Telescope Dashboard Shell without Data
	case cat == CategoryLaravelTelescopeExposed:
		f.ClassificationOutcome = OutcomeInformational
		f.Severity = SeverityInfo
		f.Confidence = ConfidenceHigh
		f.Limitations = appendIfNotExists(f.Limitations, "Monitoring dashboard shell observed; unauthenticated access to sensitive operational telemetry was not verified.")

	// 7. Laravel Ignition Health Check only
	case cat == CategoryLaravelIgnitionDebug && f.Severity == SeverityInfo:
		f.ClassificationOutcome = OutcomeInformational
		f.Severity = SeverityInfo
		f.Confidence = ConfidenceHigh
		f.Limitations = appendIfNotExists(f.Limitations, "Diagnostic health-check interface observed; command execution was not tested and exploitability remains unconfirmed.")

	// --- B. CONFIRMED OUTCOMES ---
	// 1. Django Debug Mode confirmed via Technical 500 template
	case cat == CategoryDjangoDebugMode && f.Confidence == ConfidenceHigh:
		f.ClassificationOutcome = OutcomeConfirmed
		if f.Severity == "" {
			f.Severity = SeverityHigh
		}
		f.Confidence = ConfidenceHigh
		f.Limitations = appendIfNotExists(f.Limitations, "Django technical 500 debug page confirmed (DEBUG=True). All traceback paths and settings were bounded and redacted.")

	// 2. Django URLconf routing disclosure confirmed via Technical 404
	case cat == CategoryDjangoURLConfDisclosure:
		f.ClassificationOutcome = OutcomeConfirmed
		if f.Severity == "" {
			f.Severity = SeverityMedium
		}
		f.Confidence = ConfidenceHigh
		f.Limitations = appendIfNotExists(f.Limitations, "Django URLconf routing patterns exposed (DEBUG=True confirmed). Recursive route probing was not executed.")

	// 3. Laravel Ignition Interactive Debugger confirmed
	case cat == CategoryLaravelIgnitionDebug && f.Confidence == ConfidenceHigh && f.Severity != SeverityInfo:
		f.ClassificationOutcome = OutcomeConfirmed
		if f.Severity == "" {
			f.Severity = SeverityHigh
		}
		f.Confidence = ConfidenceHigh
		f.Limitations = appendIfNotExists(f.Limitations, "Laravel Ignition developer diagnostic interface confirmed. All stack trace frames and settings were bounded and redacted.")

	// 4. Laravel Telescope Sensitive Telemetry Data
	case cat == CategoryLaravelTelescopeData:
		f.ClassificationOutcome = OutcomeConfirmed
		f.Confidence = ConfidenceHigh
		if f.Severity == "" {
			f.Severity = SeverityHigh
		}
		f.Limitations = appendIfNotExists(f.Limitations, "Laravel Telescope telemetry records exposed unauthenticated. Credential validity and external network connectivity remain unverified.")

	// 5. FastAPI Sensitive Schema embedded secrets
	case cat == CategoryFastAPISensitiveSchema:
		f.ClassificationOutcome = OutcomeConfirmed
		if f.Severity == "" {
			f.Severity = SeverityHigh
		}
		if f.Confidence == "" {
			f.Confidence = ConfidenceMedium
		}
		f.Limitations = appendIfNotExists(f.Limitations, "Discovered secret values were redacted; credential validity and active authorization status were not verified.")

	// 6. Spring Boot Actuator Environment Property Disclosure
	case cat == CategoryActuatorEnv:
		f.ClassificationOutcome = OutcomeConfirmed
		if f.Severity == "" {
			f.Severity = SeverityHigh
		}
		f.Confidence = ConfidenceHigh
		f.Limitations = appendIfNotExists(f.Limitations, "Spring Boot Actuator environment properties exposed. Secret values were bounded and redacted; credential validity was not verified.")

	// 7. Spring Boot Actuator Mappings Disclosure
	case cat == CategoryActuatorMappings:
		f.ClassificationOutcome = OutcomeConfirmed
		if f.Severity == "" {
			f.Severity = SeverityMedium
		}
		f.Confidence = ConfidenceHigh
		f.Limitations = appendIfNotExists(f.Limitations, "Spring Boot Actuator route mappings exposed. Target endpoints were not recursively probed.")

	// 8. Go Active Profiling Data (goroutine / heap dump)
	case cat == CategoryGoPprofExposure && (f.Details["interface"] == "profiling_data" || f.Severity == SeverityHigh):
		f.ClassificationOutcome = OutcomeConfirmed
		if f.Severity == "" {
			f.Severity = SeverityHigh
		}
		f.Confidence = ConfidenceHigh
		f.Limitations = appendIfNotExists(f.Limitations, "Active Go runtime profiling data exposed. Full binary and heap dumps were bounded and not retained.")

	// 9. Full Stack Traces and Panic Dumps (Invariant 6: Stack trace does not automatically establish RCE)
	case cat == CategoryNodeStackTrace || cat == CategoryGoDebugPanic:
		f.ClassificationOutcome = OutcomeConfirmed
		if f.Severity == "" {
			f.Severity = SeverityMedium
		}
		f.Confidence = ConfidenceHigh
		f.Limitations = appendIfNotExists(f.Limitations, "Full runtime stack trace/panic dump exposed internal frames. Remote code execution was not demonstrated.")

	// 10. Isolated Filesystem and Source Paths (Invariant 6)
	case (cat == CategoryNodeDebugError && f.Details["has_stack_trace"] == "false") ||
		(cat == CategoryGoStackTrace && f.Details["has_panic_dump"] == "false"):
		f.ClassificationOutcome = OutcomeConfirmed
		if f.Severity == "" {
			f.Severity = SeverityLow
		}
		f.Confidence = ConfidenceHigh
		f.Limitations = appendIfNotExists(f.Limitations, "Isolated internal filesystem or source path disclosed without a full stack trace or panic dump.")

	case cat == CategoryNodeDebugError || cat == CategoryGoStackTrace:
		f.ClassificationOutcome = OutcomeConfirmed
		if f.Severity == "" {
			f.Severity = SeverityMedium
		}
		f.Confidence = ConfidenceHigh
		f.Limitations = appendIfNotExists(f.Limitations, "Diagnostic error output exposed internal frames or paths.")

	// 11. Go Expvar Exposure with Candidate Secrets (Invariant 5: Candidate credential validity remains unverified)
	case cat == CategoryGoVarsExposure:
		f.ClassificationOutcome = OutcomeConfirmed
		if f.Severity == "" || f.Severity == SeverityInfo || f.Severity == SeverityLow {
			f.Severity = SeverityCritical
		}
		f.Confidence = ConfidenceHigh
		f.Limitations = appendIfNotExists(f.Limitations, "Go expvar runtime variables exposed candidate secret material. Active credential validity and access remain unverified.")

	// --- C. SUSPECTED OUTCOMES ---
	// Suspected Debug Mode without developer template confirmation
	case (cat == CategoryDjangoDebugMode || cat == CategoryLaravelIgnitionDebug) && f.Confidence == ConfidenceMedium:
		f.ClassificationOutcome = OutcomeSuspected
		f.Severity = SeverityMedium
		f.Confidence = ConfidenceMedium
		f.Limitations = appendIfNotExists(f.Limitations, "Framework exception traceback observed without official developer template; debug configuration remains unconfirmed.")

	default:
		// Fallback classification based on existing severity and confidence
		if f.Severity == SeverityCritical || f.Severity == SeverityHigh {
			f.ClassificationOutcome = OutcomeConfirmed
		} else if f.Severity == SeverityMedium {
			if f.Confidence == ConfidenceLow {
				f.ClassificationOutcome = OutcomeSuspected
			} else {
				f.ClassificationOutcome = OutcomeConfirmed
			}
		} else {
			f.ClassificationOutcome = OutcomeInformational
			if f.Severity == "" {
				f.Severity = SeverityInfo
			}
		}
	}

	// Invariant 5: Candidate-secret pattern matching never proves credential validity
	if f.Details["candidate_material_status"] != "" || f.Details["credential_validity"] != "" ||
		strings.Contains(strings.ToLower(f.Evidence), "candidate") || cat == CategoryFastAPISensitiveSchema {
		f.Details["credential_validity"] = "unverified"
		f.Limitations = appendIfNotExists(f.Limitations, "Candidate credential validity and active authorization status remain unverified.")
	}

	// Invariant 1: An informational finding must not retain a vulnerability severity such as Medium, High, or Critical.
	// Use the project's existing informational severity convention (SeverityInfo).
	if f.ClassificationOutcome == OutcomeInformational {
		if f.Severity == SeverityCritical || f.Severity == SeverityHigh || f.Severity == SeverityMedium || f.Severity == "" {
			f.Severity = SeverityInfo
		}
	}
}

// NormalizeFrameworkFinding runs a single APIFinding through the 10-step shared normalization pipeline.
// The function is idempotent and deterministic.
func NormalizeFrameworkFinding(f APIFinding) APIFinding {
	norm := f

	// 1. Detect and normalize framework and version
	norm.Framework, norm.FrameworkVersion = DetectFramework(norm.Category, norm.Details)

	// 2. Normalize endpoint (strip volatile tracking params, sort material params, canonicalize slashes)
	norm.Endpoint = NormalizeFrameworkEndpoint(norm.Endpoint)

	// 3. Normalize HTTP method
	m := strings.ToUpper(strings.TrimSpace(norm.Method))
	if m == "" {
		m = "GET"
	}
	norm.Method = m

	// 4. Derive canonical rule identifier
	norm.RuleID = ComputeFrameworkRuleID(norm.Framework, norm.Category)

	// 5. Normalize reachability
	if norm.Reachability == "" {
		norm.Reachability = NormalizeReachability(norm.Details["reachability"], norm.HTTPStatus, nil)
	} else {
		norm.Reachability = NormalizeReachability(string(norm.Reachability), norm.HTTPStatus, nil)
	}

	// 6. Normalize authentication context
	if norm.AuthContext == "" {
		norm.AuthContext = NormalizeAuthContext(norm.Details["auth_context"], norm.AuthState, norm.HTTPStatus, nil, nil)
	} else {
		norm.AuthContext = NormalizeAuthContext(string(norm.AuthContext), norm.AuthState, norm.HTTPStatus, nil, nil)
	}

	// 7. Sanitize and bound evidence (prevent credential leakage, bound wire excerpts to 4096 chars)
	norm.Evidence = secrets.RedactText(strings.TrimSpace(norm.Evidence))
	if len(norm.Evidence) > 4096 {
		norm.Evidence = norm.Evidence[:4096] + " ... [TRUNCATED_BOUNDED_EVIDENCE]"
	}
	norm.NegativeEvidence = secrets.RedactText(strings.TrimSpace(norm.NegativeEvidence))
	norm.Description = secrets.RedactText(strings.TrimSpace(norm.Description))

	if len(norm.Details) > 0 {
		cleanDetails := make(map[string]string, len(norm.Details))
		for k, v := range norm.Details {
			if secrets.IsSensitiveKey(k) || secrets.IsSensitiveHeader(k) {
				cleanDetails[k] = "[REDACTED]"
			} else {
				cleanDetails[k] = secrets.RedactText(v)
			}
		}
		norm.Details = cleanDetails
	} else {
		norm.Details = make(map[string]string)
	}

	// 8. Evaluate evidence using explicit classification rules
	ClassifyFrameworkEvidence(&norm)

	// 9. Synchronize details map for backward compatibility
	if norm.Details["framework"] == "" {
		norm.Details["framework"] = norm.Framework
	}
	if norm.FrameworkVersion != "" && norm.Details["framework_version"] == "" {
		norm.Details["framework_version"] = norm.FrameworkVersion
	}
	if norm.Details["classification_outcome"] == "" {
		norm.Details["classification_outcome"] = string(norm.ClassificationOutcome)
	}
	if norm.Details["reachability"] == "" {
		norm.Details["reachability"] = string(norm.Reachability)
	}
	if norm.Details["auth_context"] == "" {
		norm.Details["auth_context"] = string(norm.AuthContext)
	}
	if len(norm.Limitations) > 0 && norm.Details["limitations"] == "" {
		norm.Details["limitations"] = strings.Join(norm.Limitations, "; ")
	}

	// 10. Compute deterministic deduplication fingerprint
	norm.Fingerprint = GenerateFrameworkFingerprint(norm.Category, norm.Endpoint, norm.Method, norm.Framework)

	return norm
}

// DeduplicateFrameworkFindings merges duplicate framework findings deterministically.
func DeduplicateFrameworkFindings(findings []APIFinding) []APIFinding {
	if len(findings) == 0 {
		return nil
	}

	seen := make(map[string]*APIFinding)
	var order []string

	for _, f := range findings {
		norm := NormalizeFrameworkFinding(f)
		fp := norm.Fingerprint

		if existing, exists := seen[fp]; exists {
			// Merge evidence strings if different
			if norm.Evidence != "" && !strings.Contains(existing.Evidence, norm.Evidence) {
				if existing.Evidence == "" {
					existing.Evidence = norm.Evidence
				} else {
					existing.Evidence = existing.Evidence + "; Also: " + norm.Evidence
				}
			}
			// Merge negative evidence
			if existing.NegativeEvidence == "" {
				existing.NegativeEvidence = norm.NegativeEvidence
			} else if norm.NegativeEvidence != "" && !strings.Contains(existing.NegativeEvidence, norm.NegativeEvidence) {
				existing.NegativeEvidence = existing.NegativeEvidence + " " + norm.NegativeEvidence
			}
			// Merge limitations
			for _, lim := range norm.Limitations {
				existing.Limitations = appendIfNotExists(existing.Limitations, lim)
			}
			// Merge details
			for k, v := range norm.Details {
				if _, has := existing.Details[k]; !has {
					existing.Details[k] = v
				}
			}
			// Precedence rules: higher severity and confidence take precedence
			if frameworkSeverityRank(norm.Severity) > frameworkSeverityRank(existing.Severity) {
				existing.Severity = norm.Severity
			}
			if frameworkConfidenceRank(norm.Confidence) > frameworkConfidenceRank(existing.Confidence) {
				existing.Confidence = norm.Confidence
			}
			if frameworkOutcomeRank(norm.ClassificationOutcome) > frameworkOutcomeRank(existing.ClassificationOutcome) {
				existing.ClassificationOutcome = norm.ClassificationOutcome
			}
		} else {
			clone := norm
			seen[fp] = &clone
			order = append(order, fp)
		}
	}

	result := make([]APIFinding, 0, len(order))
	for _, fp := range order {
		result = append(result, *seen[fp])
	}
	return result
}

func appendIfNotExists(slice []string, val string) []string {
	clean := strings.TrimSpace(val)
	if clean == "" {
		return slice
	}
	for _, s := range slice {
		if s == clean {
			return slice
		}
	}
	return append(slice, clean)
}

func frameworkSeverityRank(sev string) int {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

func frameworkConfidenceRank(conf string) int {
	switch strings.ToUpper(strings.TrimSpace(conf)) {
	case "HIGH":
		return 3
	case "MEDIUM", "MED":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func frameworkOutcomeRank(outcome ClassificationOutcome) int {
	switch outcome {
	case OutcomeConfirmed:
		return 4
	case OutcomeSuspected:
		return 3
	case OutcomeInformational:
		return 2
	case OutcomeInconclusive:
		return 1
	default:
		return 0
	}
}
