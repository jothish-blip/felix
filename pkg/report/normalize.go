package report

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"felix/pkg/api"
	"felix/pkg/secrets"
)

// NormalizeURL canonicalizes a target or endpoint URL without destroying path semantics.
func NormalizeURL(rawURL string) string {
	clean := strings.TrimSpace(rawURL)
	if clean == "" {
		return ""
	}

	u, err := url.Parse(clean)
	if err != nil {
		return clean
	}

	// Lowercase scheme and host
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)

	// Remove default ports
	if u.Scheme == "http" && strings.HasSuffix(u.Host, ":80") {
		u.Host = strings.TrimSuffix(u.Host, ":80")
	} else if u.Scheme == "https" && strings.HasSuffix(u.Host, ":443") {
		u.Host = strings.TrimSuffix(u.Host, ":443")
	}

	// Canonicalize root slash: https://example.com/ -> https://example.com
	// But preserve non-root trailing slash: https://example.com/api/ vs https://example.com/api
	if u.Path == "/" && u.RawQuery == "" && u.Fragment == "" {
		u.Path = ""
	}

	return u.String()
}

// NormalizeMethod standardizes HTTP method strings to uppercase.
func NormalizeMethod(method string) string {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		return "GET"
	}
	return m
}

// NormalizeCategory standardizes finding category names to lowercase kebab-case.
func NormalizeCategory(cat string) string {
	c := strings.ToLower(strings.TrimSpace(cat))
	c = strings.ReplaceAll(c, "_", "-")
	c = strings.ReplaceAll(c, " ", "-")
	return c
}

// NormalizeConfidence standardizes confidence ratings to HIGH, MEDIUM, or LOW.
func NormalizeConfidence(conf string) string {
	c := strings.ToUpper(strings.TrimSpace(conf))
	switch c {
	case ConfidenceHigh:
		return ConfidenceHigh
	case ConfidenceMedium, "MED":
		return ConfidenceMedium
	case ConfidenceLow:
		return ConfidenceLow
	case ConfidenceUnknown, "NONE":
		return ConfidenceUnknown
	default:
		return ConfidenceMedium
	}
}

// ParseFindingStatus parses a raw status string into a canonical FindingStatus.
// Returns an error if the status is unknown, empty, or malformed.
func ParseFindingStatus(s string) (FindingStatus, error) {
	clean := strings.ToUpper(strings.TrimSpace(s))
	switch clean {
	case string(FindingStatusConfirmed), "VERIFIED", "PROVEN":
		return FindingStatusConfirmed, nil
	case string(FindingStatusSuspected), "DETECTED", "CANDIDATE", "POTENTIAL", "UNVERIFIED":
		return FindingStatusSuspected, nil
	case string(FindingStatusInconclusive), "INDETERMINATE", "UNDETERMINED", "NOT_EXPOSED":
		return FindingStatusInconclusive, nil
	case string(FindingStatusNotTested), "NOT-TESTED", "NOTTESTED", "BLOCKED", "SKIPPED", "OMITTED", "UNTESTED":
		return FindingStatusNotTested, nil
	case string(FindingStatusError), "FAIL", "FAILED", "FAILURE", "ERR", "CRASH", "TIMEOUT":
		return FindingStatusError, nil
	case "":
		return FindingStatusInconclusive, errors.New("empty finding status")
	default:
		return FindingStatusInconclusive, fmt.Errorf("unknown finding status %q", s)
	}
}

// NormalizeFindingStatus canonicalizes finding status to one of the canonical states.
// Recognizes standard aliases while preserving honest security semantics.
// Unknown or malformed input explicitly defaults to INCONCLUSIVE, ensuring invalid inputs
// can never silently be promoted to a legitimate SUSPECTED or CONFIRMED vulnerability.
func NormalizeFindingStatus(s FindingStatus) FindingStatus {
	st, err := ParseFindingStatus(string(s))
	if err != nil {
		return FindingStatusInconclusive
	}
	return st
}

// FindingStatusRank returns an ordering rank for finding statuses (higher is more definitive).
// Deterministic precedence: CONFIRMED > SUSPECTED > INCONCLUSIVE > NOT_TESTED > ERROR.
func FindingStatusRank(s FindingStatus) int {
	switch NormalizeFindingStatus(s) {
	case FindingStatusConfirmed:
		return 5
	case FindingStatusSuspected:
		return 4
	case FindingStatusInconclusive:
		return 3
	case FindingStatusNotTested:
		return 2
	case FindingStatusError:
		return 1
	default:
		return 0
	}
}

// FindingStatusFromVerification maps a verification status to its corresponding finding status.
func FindingStatusFromVerification(v VerificationStatus) FindingStatus {
	switch NormalizeVerificationStatus(v) {
	case VerificationVerified:
		return FindingStatusConfirmed
	case VerificationDetected:
		return FindingStatusSuspected
	case VerificationObserved:
		return FindingStatusConfirmed
	case VerificationNotVerified:
		return FindingStatusSuspected
	case VerificationNotExposed:
		return FindingStatusInconclusive
	default:
		return FindingStatusSuspected
	}
}

// VerificationFromFindingStatus maps a finding status to its closest verification status.
func VerificationFromFindingStatus(s FindingStatus) VerificationStatus {
	switch NormalizeFindingStatus(s) {
	case FindingStatusConfirmed:
		return VerificationVerified
	case FindingStatusSuspected:
		return VerificationDetected
	case FindingStatusInconclusive:
		return VerificationNotExposed
	case FindingStatusNotTested, FindingStatusError:
		return VerificationNotVerified
	default:
		return VerificationObserved
	}
}

// ConfidenceRank returns an integer rank for deterministic sorting (higher is more confident).
func ConfidenceRank(conf string) int {
	switch NormalizeConfidence(conf) {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// NormalizeSource standardizes finding source names.
func NormalizeSource(src string) string {
	s := strings.ToLower(strings.TrimSpace(src))
	switch s {
	case SourceCrawler:
		return SourceCrawler
	case SourceSecrets:
		return SourceSecrets
	case SourceCloud:
		return SourceCloud
	case SourceAPI:
		return SourceAPI
	case SourceCorrelated:
		return SourceCorrelated
	default:
		return SourceAPI
	}
}

// NormalizeVerificationStatus canonicalizes verification status to one of the canonical states.
func NormalizeVerificationStatus(v VerificationStatus) VerificationStatus {
	s := strings.ToUpper(strings.TrimSpace(string(v)))
	switch VerificationStatus(s) {
	case VerificationVerified:
		return VerificationVerified
	case VerificationDetected:
		return VerificationDetected
	case VerificationObserved:
		return VerificationObserved
	case VerificationNotVerified:
		return VerificationNotVerified
	case VerificationNotExposed:
		return VerificationNotExposed
	default:
		return VerificationObserved
	}
}

// VerificationRank returns an ordering rank for verification statuses (higher is more verified).
// Deterministic precedence: VERIFIED > DETECTED > NOT_VERIFIED > OBSERVED > NOT_EXPOSED.
func VerificationRank(v VerificationStatus) int {
	switch NormalizeVerificationStatus(v) {
	case VerificationVerified:
		return 4
	case VerificationDetected:
		return 3
	case VerificationNotVerified:
		return 2
	case VerificationObserved:
		return 1
	case VerificationNotExposed:
		return 0
	default:
		return 0
	}
}

// DefaultDetectionMethod infers a suitable detection method string from source and category.
func DefaultDetectionMethod(source, category string) string {
	src := NormalizeSource(source)
	cat := NormalizeCategory(category)
	switch {
	case src == SourceSecrets:
		if strings.Contains(cat, "entropy") {
			return "shannon_entropy_heuristic"
		}
		return "static_pattern_signature"
	case src == SourceCrawler:
		return "asset_ingestion"
	case strings.HasPrefix(cat, "missing-") || cat == "cors-wildcard":
		return "header_inspection"
	default:
		return "active_probe"
	}
}

// NormalizeFinding applies all normalization rules to a single finding.
func NormalizeFinding(f Finding) Finding {
	f.Target = NormalizeURL(f.Target)
	f.Endpoint = NormalizeURL(f.Endpoint)
	f.Method = NormalizeMethod(f.Method)
	f.Category = NormalizeCategory(f.Category)
	f.Severity = MapSeverity(f.Category, f.Severity)
	f.Confidence = NormalizeConfidence(f.Confidence)
	f.Source = NormalizeSource(f.Source)
	f.Title = secrets.RedactText(strings.TrimSpace(f.Title))
	f.Description = secrets.RedactText(strings.TrimSpace(f.Description))
	f.Evidence = secrets.RedactText(strings.TrimSpace(f.Evidence))
	f.RuleID = strings.TrimSpace(f.RuleID)
	f.PrimaryAssetID = strings.TrimSpace(f.PrimaryAssetID)

	// Normalize Status
	if f.Status == "" {
		f.Status = FindingStatusFromVerification(f.Verification.Status)
	} else {
		f.Status = NormalizeFindingStatus(f.Status)
	}

	// Normalize Framework Classification fields
	if f.ClassificationOutcome == "" {
		switch f.Status {
		case FindingStatusConfirmed:
			if f.Severity == SeverityInfo || f.Severity == SeverityLow {
				f.ClassificationOutcome = OutcomeInformational
			} else {
				f.ClassificationOutcome = OutcomeConfirmed
			}
		case FindingStatusSuspected:
			f.ClassificationOutcome = OutcomeSuspected
		case FindingStatusInconclusive:
			f.ClassificationOutcome = OutcomeInconclusive
		default:
			f.ClassificationOutcome = OutcomeInconclusive
		}
	} else {
		f.ClassificationOutcome = api.NormalizeClassificationOutcome(string(f.ClassificationOutcome))
	}

	// Invariant 1: An informational finding must not retain a vulnerability severity such as Medium, High, or Critical.
	// Use the project's existing informational severity convention (SeverityInfo).
	if f.ClassificationOutcome == OutcomeInformational {
		if f.Severity == SeverityCritical || f.Severity == SeverityHigh || f.Severity == SeverityMedium || f.Severity == "" {
			f.Severity = SeverityInfo
		}
	}

	if f.Reachability == "" {
		f.Reachability = api.NormalizeReachability("", f.EvidenceDetails.HTTPStatus, nil)
	} else {
		f.Reachability = api.NormalizeReachability(string(f.Reachability), f.EvidenceDetails.HTTPStatus, nil)
	}

	if f.AuthContext == "" {
		f.AuthContext = api.NormalizeAuthContext("", "", f.EvidenceDetails.HTTPStatus, nil, nil)
	} else {
		f.AuthContext = api.NormalizeAuthContext(string(f.AuthContext), "", f.EvidenceDetails.HTTPStatus, nil, nil)
	}

	if f.Framework == "" {
		f.Framework, f.FrameworkVersion = api.DetectFramework(f.Category, f.EvidenceDetails.Details)
	}

	// Normalize AnalysisMethod
	if f.AnalysisMethod == "" {
		if f.Verification.AnalysisMethod != "" {
			f.AnalysisMethod = NormalizeAnalysisMethod(f.Verification.AnalysisMethod)
		} else if f.Provenance != nil && f.Provenance.AnalysisMethod != "" {
			f.AnalysisMethod = NormalizeAnalysisMethod(f.Provenance.AnalysisMethod)
		} else if f.EvidenceDetails.Provenance != nil && f.EvidenceDetails.Provenance.AnalysisMethod != "" {
			f.AnalysisMethod = NormalizeAnalysisMethod(f.EvidenceDetails.Provenance.AnalysisMethod)
		} else {
			f.AnalysisMethod = DefaultAnalysisMethod(f.Source, f.EvidenceDetails.DetectionMethod)
		}
	} else {
		f.AnalysisMethod = NormalizeAnalysisMethod(f.AnalysisMethod)
	}
	if f.Verification.AnalysisMethod == "" {
		f.Verification.AnalysisMethod = f.AnalysisMethod
	} else {
		f.Verification.AnalysisMethod = NormalizeAnalysisMethod(f.Verification.AnalysisMethod)
	}

	// Normalize AffectedAssetIDs: deduplicate and sort
	if len(f.AffectedAssetIDs) > 0 {
		seenAssets := make(map[string]struct{}, len(f.AffectedAssetIDs))
		var uniqueAssets []string
		for _, ast := range f.AffectedAssetIDs {
			clean := strings.TrimSpace(ast)
			if clean == "" {
				continue
			}
			if _, exists := seenAssets[clean]; !exists {
				seenAssets[clean] = struct{}{}
				uniqueAssets = append(uniqueAssets, clean)
			}
		}
		sort.Strings(uniqueAssets)
		f.AffectedAssetIDs = uniqueAssets
	}

	// Normalize EvidenceDetails
	f.EvidenceDetails.Observation = secrets.RedactText(strings.TrimSpace(f.EvidenceDetails.Observation))
	f.EvidenceDetails.Location = secrets.SanitizeURL(strings.TrimSpace(f.EvidenceDetails.Location))
	f.EvidenceDetails.DetectionMethod = strings.TrimSpace(f.EvidenceDetails.DetectionMethod)
	f.EvidenceDetails.NegativeEvidence = secrets.RedactText(strings.TrimSpace(f.EvidenceDetails.NegativeEvidence))

	if len(f.EvidenceDetails.Details) > 0 {
		cleanDetails := make(map[string]string, len(f.EvidenceDetails.Details))
		for k, v := range f.EvidenceDetails.Details {
			if secrets.IsSensitiveKey(k) || secrets.IsSensitiveHeader(k) {
				cleanDetails[k] = "[REDACTED]"
			} else {
				cleanDetails[k] = secrets.RedactText(v)
			}
		}
		f.EvidenceDetails.Details = cleanDetails
	}

	if f.EvidenceDetails.Observation == "" && f.Evidence != "" {
		f.EvidenceDetails.Observation = f.Evidence
	}
	if f.EvidenceDetails.Location == "" {
		f.EvidenceDetails.Location = f.Endpoint
	}
	if f.EvidenceDetails.DetectionMethod == "" {
		f.EvidenceDetails.DetectionMethod = DefaultDetectionMethod(f.Source, f.Category)
	}
	if f.Evidence == "" && f.EvidenceDetails.Observation != "" {
		f.Evidence = f.EvidenceDetails.Observation
	}

	// Normalize VerificationRecord
	f.Verification.Status = NormalizeVerificationStatus(f.Verification.Status)
	f.Verification.Result = strings.TrimSpace(f.Verification.Result)
	if f.Verification.Result == "" {
		f.Verification.Result = f.Description
	}

	// Remediation and RemediationAdvice
	if f.Remediation == "" {
		f.Remediation = RemediationFor(f.Category, f.Title)
	}
	if f.RemediationAdvice == nil && f.Remediation != "" {
		f.RemediationAdvice = &RemediationAdvice{Summary: f.Remediation}
	} else if f.RemediationAdvice != nil && f.Remediation == "" {
		f.Remediation = f.RemediationAdvice.Summary
	}

	if f.Fingerprint == "" {
		f.Fingerprint = ComputeFingerprint(f.Target, f.Category, f.Endpoint, f.Method, f.Title)
	}

	if f.ID == "" {
		f.ID = ComputeStableFindingID(f.Target, f.RuleID, f.Category, f.Endpoint, f.Method, f.Fingerprint)
	}

	// Synchronize and enrich structured EvidenceProvenance
	if f.Provenance == nil && f.EvidenceDetails.Provenance != nil {
		f.Provenance = f.EvidenceDetails.Provenance
	} else if f.Provenance != nil && f.EvidenceDetails.Provenance == nil {
		f.EvidenceDetails.Provenance = f.Provenance
	}

	if f.Provenance == nil {
		rawEv := f.Evidence
		if rawEv == "" {
			rawEv = f.EvidenceDetails.Observation
		}
		loc := f.EvidenceDetails.Location
		if loc == "" {
			loc = f.Endpoint
		}
		prov := NewEvidenceProvenance(
			f.Source,
			f.RuleID,
			f.ID,
			f.PrimaryAssetID,
			DefaultEvidenceType(f.Source),
			loc,
			f.EvidenceDetails.DetectionMethod,
			rawEv,
		)
		if !f.Timestamp.IsZero() {
			prov.CollectedAt = f.Timestamp
		}
		prov.AnalysisMethod = f.AnalysisMethod
		f.Provenance = &prov
		f.EvidenceDetails.Provenance = &prov
	} else {
		if f.Provenance.SourceEngine == "" {
			f.Provenance.SourceEngine = f.Source
		}
		if f.Provenance.RuleID == "" {
			f.Provenance.RuleID = f.RuleID
		}
		if f.Provenance.FindingID == "" {
			f.Provenance.FindingID = f.ID
		}
		if f.Provenance.AssetID == "" && f.PrimaryAssetID != "" {
			f.Provenance.AssetID = f.PrimaryAssetID
		}
		if f.Provenance.Location == "" {
			loc := f.EvidenceDetails.Location
			if loc == "" {
				loc = f.Endpoint
			}
			f.Provenance.Location = loc
		}
		if f.Provenance.EvidenceType == "" {
			f.Provenance.EvidenceType = DefaultEvidenceType(f.Source)
		}
		if f.Provenance.CollectionMethod == "" {
			f.Provenance.CollectionMethod = f.EvidenceDetails.DetectionMethod
			if f.Provenance.CollectionMethod == "" {
				f.Provenance.CollectionMethod = DefaultCollectionMethod(f.Source)
			}
		}
		if f.Provenance.AnalysisMethod == "" {
			f.Provenance.AnalysisMethod = f.AnalysisMethod
		} else {
			f.Provenance.AnalysisMethod = NormalizeAnalysisMethod(f.Provenance.AnalysisMethod)
		}
		if f.Provenance.EvidenceID == "" {
			f.Provenance.EvidenceID = ComputeEvidenceID(f.Provenance.SourceEngine, f.Provenance.RuleID, f.Provenance.FindingID, f.Provenance.Location, f.Provenance.EvidenceType)
		}
		if f.Provenance.ContentDigest == "" {
			rawEv := f.Evidence
			if rawEv == "" {
				rawEv = f.EvidenceDetails.Observation
			}
			if rawEv != "" {
				f.Provenance.ContentDigest = ComputeContentDigest(rawEv)
			}
		}
		if f.Provenance.CollectedAt.IsZero() && !f.Timestamp.IsZero() {
			f.Provenance.CollectedAt = f.Timestamp
		}
		f.EvidenceDetails.Provenance = f.Provenance
	}

	expl := ExplainFindingScore(f)
	f.Score = expl.Score
	f.ScoreExplanation = &expl
	if f.EvidenceDetails.Details == nil {
		f.EvidenceDetails.Details = make(map[string]string)
	}
	f.EvidenceDetails.Details["score_formula"] = expl.Formula
	f.EvidenceDetails.Details["score_rationale"] = expl.Rationale

	return f
}

// RemediationFor provides tailored, defensive remediation guidance for each finding category.
func RemediationFor(category, title string) string {
	cat := NormalizeCategory(category)
	switch {
	// Privileged Cloud & Service Secrets
	case strings.Contains(cat, "service-key"), strings.Contains(cat, "service-role"):
		return "Immediately revoke and rotate the exposed service_role key in the provider dashboard. Ensure administrative operations run exclusively on server-side functions and never bundle privileged keys in client-accessible assets."

	case strings.Contains(cat, "aws-secret"), strings.Contains(cat, "aws-access"):
		return "Revoke the exposed AWS IAM credentials immediately in AWS IAM console. Rotate access keys, restrict permissions via least-privilege IAM policies, and review AWS CloudTrail for unauthorized API calls."

	case strings.Contains(cat, "stripe-live"):
		return "Revoke and roll the live Stripe secret key in Stripe Dashboard Developers > API keys. Move payment intent creation strictly server-side and only expose publishable keys (pk_live_) to clients."

	case strings.Contains(cat, "github-token"):
		return "Revoke the exposed Personal Access Token or OAuth token immediately in GitHub Settings > Developer settings. Audit audit logs for anomalous repository activity."

	case strings.Contains(cat, "slack-token"):
		return "Revoke the compromised Slack bot/user token via the Slack API dashboard. Reissue with minimal necessary OAuth scopes."

	case strings.Contains(cat, "openai-key"):
		return "Revoke the OpenAI API key in OpenAI Platform dashboard. Route all AI model requests through a secure backend proxy to prevent quota draining and unauthorized queries."

	case strings.Contains(cat, "private-key"):
		return "Immediately decommission and rotate the compromised private key. Revoke associated TLS/SSH certificates or public keys and investigate git repository history for leakage."

	case strings.Contains(cat, "jwt"):
		return "Verify whether the token contains sensitive claims or signing keys. If sensitive or long-lived, invalidate existing sessions, rotate the signing secret, and shorten token lifetimes."

	// Cloud & BaaS
	case cat == "supabase-unauthorized-access":
		return "Enable Row Level Security (RLS) on all exposed tables and define explicit policies (`CREATE POLICY`) to prevent unauthorized public read/write access."

	case cat == "supabase-anon-key":
		return "The anon key is intended for client usage; verify that Row Level Security (RLS) is strictly enforced on all tables accessible via the Supabase REST/PostgREST API."

	case cat == "firebase-open-database":
		return "Update Firebase Realtime Database Security Rules to restrict unauthorized access (e.g. set `.read: false` or require authentication `auth != null`)."

	case cat == "s3-public-listing", cat == "gcs-public-listing":
		return "Enable 'Block Public Access' on the storage bucket and adjust Bucket Policy/IAM permissions to disallow anonymous `s3:ListBucket` or `storage.objects.list`."

	// Modern API & Endpoints
	case cat == "graphql-introspection":
		return "Disable GraphQL schema introspection in production environments (e.g. set `introspection: false` in Apollo/Yoga/GraphQL server configuration) unless the API is explicitly designed for public consumption."

	case cat == "cors-origin-reflection":
		return "Avoid reflecting the client-supplied `Origin` header blindly. Implement an explicit allowlist of authorized origin domains and strictly disallow `Access-Control-Allow-Credentials: true` with dynamic origins."

	case cat == "cors-wildcard":
		return "Verify whether the resource is intended for public consumption. Do not use wildcard `*` origins on endpoints returning sensitive or tenant-specific data."

	case cat == "env-exposure":
		return "Immediately remove `.env` and environment configuration files from web server document roots. Rotate all credentials declared in the file and configure web server rules (e.g. Nginx, Apache) to block access to hidden files (`.*`)."

	case cat == "git-metadata-exposure":
		return "Remove `.git` directories from the public document root immediately. Configure web server access controls to deny access to `/.git/` and verify that source code has not been cloned."

	case cat == "api-docs-exposure":
		return "Determine whether API specifications (/swagger.json, /openapi.json) are intended for public consumers. If internal, place documentation behind authentication and restrict route access."

	case cat == "health-endpoint", cat == "metrics-exposure":
		return "Restrict access to internal monitoring endpoints (/actuator, /metrics). Place them on private network interfaces or behind strict administrative authentication."

	case cat == "actuator-health-detailed":
		return "Set management.endpoint.health.show-details=never (or when-authorized) in Spring Boot configuration to prevent leaking internal component, database, and infrastructure status."

	case cat == "actuator-env-exposure":
		return "Disable /actuator/env in production (management.endpoints.web.exposure.exclude=env) or place it behind strict administrative authentication with restrictive access controls."

	case cat == "actuator-mappings-exposure":
		return "Disable /actuator/mappings in production (management.endpoints.web.exposure.exclude=mappings) or restrict access to internal management interfaces."

	// Django Diagnostic Interfaces
	case cat == "django-debug-mode":
		return "Set DEBUG = False in production django settings.py. Configure secure error handlers (handler500) and never expose technical exception tracebacks or environment settings to unauthenticated users."

	case cat == "django-urlconf-disclosure":
		return "Set DEBUG = False in production django settings.py to serve standard 404 error responses instead of revealing internal URLconf routing patterns."

	case cat == "django-browsable-api":
		return "Configure DEFAULT_RENDERER_CLASSES in Django REST Framework settings to disable BrowsableAPIRenderer in production deployments, restricting API output to JSON."

	// FastAPI / OpenAPI Documentation Interfaces
	case cat == "fastapi-docs-exposure":
		return "Determine whether FastAPI documentation interfaces (/docs, /redoc, /openapi.json) are intended for public consumers. If internal, configure docs_url=None, redoc_url=None, openapi_url=None or restrict access via authentication middleware."

	case cat == "fastapi-sensitive-paths":
		return "Set include_in_schema=False on internal, administrative, or debug route declarations in FastAPI to omit sensitive endpoints from public OpenAPI schemas."

	case cat == "fastapi-sensitive-schema":
		return "Remove sensitive credentials, tokens, passwords, or private configuration defaults from OpenAPI field descriptions, summaries, and schema examples."

	// Laravel Ignition & Telescope Diagnostic Interfaces
	case cat == "laravel-ignition-debug":
		return "Set APP_DEBUG=false in production .env configuration and ensure ignition is installed strictly as a development dependency (--dev) in composer.json."

	case cat == "laravel-telescope-exposure", cat == "laravel-telescope-sensitive-data":
		return "Restrict access to Laravel Telescope using the Telescope::auth gate in TelescopeServiceProvider to authorize only specific administrators, or disable the package in production."

	case cat == "laravel-telescope-restricted":
		return "Ensure Laravel Telescope access rules continue to be enforced strictly via Telescope::auth with multi-factor administrative authentication."

	// Node.js & Framework Diagnostic Interfaces
	case cat == "node-debug-error", cat == "node-stack-trace":
		return "Ensure NODE_ENV is set to 'production' in your deployment environment. Implement a custom error handler in Express (or your chosen framework) that logs full stack traces internally to secure logging infrastructure and returns generic, sanitized error responses to clients."

	case cat == "node-runtime-exposure":
		return "Disable framework signature headers (e.g., call `app.disable('x-powered-by')` in Express) to prevent exposing runtime framework technology to unauthenticated clients."

	// Go Runtime & Framework Diagnostic Interfaces
	case cat == "go-debug-panic", cat == "go-stack-trace":
		return "Configure custom recovery middleware (such as gin.Recovery() or custom panic handlers) in Go HTTP servers to log panic details internally and return a generic HTTP 500 error without exposing goroutine stack traces or internal source paths."

	case cat == "go-pprof-exposure":
		return "Do not expose net/http/pprof endpoints on public HTTP listeners. Bind diagnostic profiling endpoints to a dedicated internal management port or loopback interface (127.0.0.1), or place them behind strict administrative authentication."

	case cat == "go-vars-exposure":
		return "Restrict access to the Go expvar endpoint (/debug/vars). Place it behind administrative authentication or bind it exclusively to internal management network interfaces."

	case cat == "go-runtime-exposure":
		return "Suppress unnecessary server identifying headers in Go framework configurations to minimize technological reconnaissance."

	// Defensive Security Headers
	case cat == "missing-csp":
		return "Deploy a robust Content-Security-Policy (CSP) header restricting script execution, styles, and object embeds to trusted sources. Begin with `Content-Security-Policy-Report-Only` during staging."

	case cat == "missing-hsts":
		return "Enable HTTP Strict-Transport-Security (HSTS) with a directive such as `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` on all HTTPS responses."

	case cat == "missing-x-frame-options":
		return "Configure `X-Frame-Options: DENY` or `SAMEORIGIN`, or implement CSP `frame-ancestors` directive to mitigate clickjacking attacks."

	case cat == "missing-x-content-type-options":
		return "Add `X-Content-Type-Options: nosniff` header across all responses to prevent browser MIME-type sniffing."

	case cat == "missing-permissions-policy":
		return "Configure a `Permissions-Policy` header explicitly disabling unnecessary browser capabilities (e.g. `camera=(), microphone=(), geolocation=()`)."

	case cat == "source-map-exposure":
		return "Remove `.map` files from public production deployments or restrict source map access to authenticated internal debugging tools."

	default:
		return "Review the observed endpoint and asset configurations, adhere to principle of least privilege, and restrict unauthorized access."
	}
}
