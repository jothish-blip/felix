package report

import (
	"net/url"
	"strings"
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
	default:
		return ConfidenceMedium
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
	f.Title = strings.TrimSpace(f.Title)
	f.Description = strings.TrimSpace(f.Description)
	f.Evidence = strings.TrimSpace(f.Evidence)

	// Normalize EvidenceDetails
	f.EvidenceDetails.Observation = strings.TrimSpace(f.EvidenceDetails.Observation)
	f.EvidenceDetails.Location = strings.TrimSpace(f.EvidenceDetails.Location)
	f.EvidenceDetails.DetectionMethod = strings.TrimSpace(f.EvidenceDetails.DetectionMethod)
	f.EvidenceDetails.NegativeEvidence = strings.TrimSpace(f.EvidenceDetails.NegativeEvidence)

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

	if f.Remediation == "" {
		f.Remediation = RemediationFor(f.Category, f.Title)
	}

	if f.Fingerprint == "" {
		f.Fingerprint = ComputeFingerprint(f.Target, f.Category, f.Endpoint, f.Method, f.Title)
	}

	f.Score = CalculateFindingScore(f)

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
