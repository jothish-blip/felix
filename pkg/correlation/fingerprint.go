package correlation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"felix/pkg/discovery"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

// AlgorithmVersion identifies the canonical stable fingerprint algorithm.
const AlgorithmVersion = "v2"

// DomainSeparationPrefix prefixes all canonical fingerprint identity payloads.
const DomainSeparationPrefix = "felix:fp:v2"

// FingerprintArchetype categorizes the finding to determine its canonical identity formula.
type FingerprintArchetype string

const (
	ArchetypeHTTP       FingerprintArchetype = "HTTP_API"
	ArchetypeHardening  FingerprintArchetype = "CONFIGURATION_HARDENING"
	ArchetypeCloud      FingerprintArchetype = "CLOUD_RESOURCE"
	ArchetypeMobile     FingerprintArchetype = "MOBILE_APPLICATION"
	ArchetypeSecrets    FingerprintArchetype = "SECRET_EXPOSURE"
	ArchetypeAmbiguous  FingerprintArchetype = "INSUFFICIENT_IDENTITY"
)

// FingerprintTrustPolicy defines how existing finding fingerprints are treated.
type FingerprintTrustPolicy int

const (
	// TrustPolicyPreserveExisting trusts any non-empty existing fingerprint.
	TrustPolicyPreserveExisting FingerprintTrustPolicy = iota

	// TrustPolicyRecomputeIfLegacy recomputes the fingerprint if the existing fingerprint is empty
	// or matches a known ad-hoc legacy pattern.
	TrustPolicyRecomputeIfLegacy

	// TrustPolicyForceRecompute always recomputes the canonical stable fingerprint.
	TrustPolicyForceRecompute
)

// FingerprintDetails encapsulates the full provenance, components, and explainability of a finding fingerprint.
type FingerprintDetails struct {
	Value            string               `json:"value"`                       // 64-character lowercase SHA-256 hex digest
	Version          string               `json:"version"`                     // "v2"
	Archetype        FingerprintArchetype `json:"archetype"`                   // Archetype category
	AssetKey         string               `json:"asset_key"`                   // Canonical asset identity (origin, bucket, package, etc.)
	VulnerabilityKey string               `json:"vulnerability_key"`           // Normalized RuleID or Category
	EndpointKey      string               `json:"endpoint_key,omitempty"`      // Method + Normalized Endpoint
	DiscriminatorKey string               `json:"discriminator_key,omitempty"` // Specific parameter, header, permission, or secret type
	CanonicalPayload string               `json:"canonical_payload"`           // Unhashed canonical identity string
	IsConservative   bool                 `json:"is_conservative"`             // True if established with full identity confidence
	IsAmbiguous      bool                 `json:"is_ambiguous"`                // True if evidence was insufficient
	AmbiguityReason  string               `json:"ambiguity_reason,omitempty"`  // Explanation if ambiguous
}

// ComputeStableFingerprint generates a stable, deterministic 64-character SHA-256 fingerprint for a finding.
func ComputeStableFingerprint(f report.Finding) string {
	details := ComputeFingerprintDetails(f, nil)
	return details.Value
}

// ComputeFingerprintWithInventory generates a stable fingerprint utilizing the assessment inventory if available.
func ComputeFingerprintWithInventory(f report.Finding, inv *discovery.Inventory) (string, FingerprintDetails) {
	details := ComputeFingerprintDetails(f, inv)
	return details.Value, details
}

// ComputeFingerprintDetails constructs the full FingerprintDetails explaining every identity component.
func ComputeFingerprintDetails(f report.Finding, inv *discovery.Inventory) FingerprintDetails {
	archetype := DetectArchetype(f)

	// 1. Resolve canonical asset identity
	var assetKey string
	var boundaryKey string
	var canonAsset *CanonicalAsset

	if inv != nil {
		ca, _ := ResolveFindingAsset(f, inv)
		canonAsset = ca
	} else {
		ca, _ := ResolveFindingAsset(f, nil)
		canonAsset = ca
	}

	tenantID := ""
	accountID := ""
	if f.EvidenceDetails.Details != nil {
		tenantID = strings.TrimSpace(f.EvidenceDetails.Details["tenant_id"])
		accountID = strings.TrimSpace(f.EvidenceDetails.Details["account_id"])
	}
	if canonAsset != nil {
		if tenantID == "" {
			tenantID = canonAsset.TenantID
		}
		if accountID == "" {
			accountID = canonAsset.AccountID
		}
	}
	boundaryKey = formatBoundaryKey(tenantID, accountID)

	primaryAsset := strings.TrimSpace(f.PrimaryAssetID)

	if canonAsset != nil && canonAsset.Basis == "EXPLICIT_INVENTORY" && canonAsset.CanonicalKey != "" {
		assetKey = canonAsset.CanonicalKey
	} else if primaryAsset != "" {
		if boundaryKey != "" {
			assetKey = fmt.Sprintf("%s:%s", boundaryKey, primaryAsset)
		} else {
			assetKey = primaryAsset
		}
	} else if canonAsset != nil && canonAsset.CanonicalKey != "" &&
		!strings.HasPrefix(canonAsset.CanonicalKey, "unresolved") &&
		!strings.HasPrefix(canonAsset.CanonicalKey, "malformed") {
		assetKey = canonAsset.CanonicalKey
	} else {
		assetKey = extractFallbackAssetKey(f, boundaryKey)
	}

	// 2. Resolve vulnerability identifier
	vulnKey := extractVulnerabilityKey(f)

	// 3. Resolve endpoint and discriminator according to archetype
	endpointKey, discKey, isAmbiguous, ambiguityReason := extractEndpointAndDiscriminator(f, archetype, assetKey)

	// 4. Handle ambiguous/insufficient findings conservatively
	if isAmbiguous {
		// Conservative fallback: Do NOT merge unrelated findings with incomplete evidence!
		// Synthesize a unique discriminator containing the finding's unique token/ID so separate ambiguous findings remain distinct.
		fndToken := strings.TrimSpace(f.ID)
		if fndToken == "" {
			fndToken = strings.TrimSpace(f.Title)
		}
		if fndToken == "" {
			fndToken = "anon"
		}
		cleanToken := cleanIdentityToken(fndToken)
		payload := encodeCanonicalPayload(DomainSeparationPrefix, "ambiguous", assetKey, vulnKey, cleanToken)
		sum := sha256.Sum256([]byte(payload))
		val := hex.EncodeToString(sum[:])
		return FingerprintDetails{
			Value:            val,
			Version:          AlgorithmVersion,
			Archetype:        ArchetypeAmbiguous,
			AssetKey:         assetKey,
			VulnerabilityKey: vulnKey,
			EndpointKey:      endpointKey,
			DiscriminatorKey: discKey,
			CanonicalPayload: payload,
			IsConservative:   true,
			IsAmbiguous:      true,
			AmbiguityReason:  ambiguityReason,
		}
	}

	// 5. Construct canonical payload with length-prefixed framing to eliminate delimiter collision
	canonicalPayload := encodeCanonicalPayload(
		DomainSeparationPrefix,
		string(archetype),
		assetKey,
		vulnKey,
		endpointKey,
		discKey,
	)

	sum := sha256.Sum256([]byte(canonicalPayload))
	fpVal := hex.EncodeToString(sum[:])

	return FingerprintDetails{
		Value:            fpVal,
		Version:          AlgorithmVersion,
		Archetype:        archetype,
		AssetKey:         assetKey,
		VulnerabilityKey: vulnKey,
		EndpointKey:      endpointKey,
		DiscriminatorKey: discKey,
		CanonicalPayload: canonicalPayload,
		IsConservative:   true,
		IsAmbiguous:      false,
	}
}

// DetectArchetype classifies a finding into one of the 5 canonical security archetypes.
func DetectArchetype(f report.Finding) FingerprintArchetype {
	cat := strings.ToLower(report.NormalizeCategory(f.Category))
	src := strings.ToLower(strings.TrimSpace(f.Source))
	rule := strings.ToUpper(strings.TrimSpace(f.RuleID))
	ep := strings.ToLower(strings.TrimSpace(f.Endpoint))
	tgt := strings.ToLower(strings.TrimSpace(f.Target))

	// Secrets detection
	if src == report.SourceSecrets ||
		strings.Contains(cat, "secret") ||
		strings.Contains(cat, "entropy") ||
		strings.Contains(cat, "api-key") ||
		strings.Contains(cat, "credential") ||
		strings.HasPrefix(rule, "SEC-") {
		return ArchetypeSecrets
	}

	// Mobile application findings
	if src == "apk" ||
		strings.Contains(cat, "apk") ||
		strings.Contains(cat, "mobile") ||
		strings.Contains(cat, "android") ||
		strings.HasPrefix(rule, "APK-") {
		return ArchetypeMobile
	}

	// Cloud resource misconfigurations
	if src == report.SourceCloud ||
		strings.HasPrefix(ep, "s3://") || strings.HasPrefix(tgt, "s3://") ||
		strings.HasPrefix(ep, "gs://") || strings.HasPrefix(tgt, "gs://") ||
		strings.Contains(cat, "s3") ||
		strings.Contains(cat, "bucket") ||
		strings.Contains(cat, "database") ||
		strings.Contains(cat, "supabase") ||
		strings.Contains(cat, "cloud") ||
		strings.HasPrefix(rule, "CLD-") {
		return ArchetypeCloud
	}

	// Configuration & security hardening
	if strings.Contains(cat, "missing-") ||
		strings.Contains(cat, "header") ||
		strings.Contains(cat, "cookie") ||
		strings.Contains(cat, "cors") ||
		strings.Contains(cat, "tls") ||
		strings.Contains(cat, "cipher") ||
		strings.Contains(cat, "hsts") ||
		strings.Contains(cat, "csp") ||
		strings.HasPrefix(rule, "HDR-") ||
		strings.HasPrefix(rule, "TLS-") ||
		strings.HasPrefix(rule, "CFG-") {
		return ArchetypeHardening
	}

	// Default to HTTP / API vulnerability
	return ArchetypeHTTP
}

// extractVulnerabilityKey extracts the stable vulnerability type or rule identifier.
func extractVulnerabilityKey(f report.Finding) string {
	rule := strings.ToUpper(strings.TrimSpace(f.RuleID))
	if rule != "" && !strings.HasPrefix(rule, "GENERIC") {
		return rule
	}

	cat := report.NormalizeCategory(f.Category)
	if cat != "" {
		return strings.ToUpper(cat)
	}

	return "UNKNOWN_VULN"
}

// extractFallbackAssetKey provides a reliable asset key if CanonicalAsset was unavailable.
func extractFallbackAssetKey(f report.Finding, boundaryKey string) string {
	ep := f.Endpoint
	if ep == "" {
		ep = f.Target
	}

	if canonURL, err := CanonicalizeURL(ep); err == nil && canonURL.Origin != "" {
		if boundaryKey != "" {
			return fmt.Sprintf("%s:%s", boundaryKey, canonURL.Origin)
		}
		return canonURL.Origin
	}

	// Fallback to normalized host or target
	cleanTarget := report.NormalizeURL(f.Target)
	if cleanTarget == "" {
		cleanTarget = "unknown_asset"
	}
	if boundaryKey != "" {
		return fmt.Sprintf("%s:%s", boundaryKey, cleanTarget)
	}
	return cleanTarget
}

// extractEndpointAndDiscriminator produces the normalized endpoint and security discriminator for the archetype.
func extractEndpointAndDiscriminator(f report.Finding, archetype FingerprintArchetype, assetKey string) (string, string, bool, string) {
	details := f.EvidenceDetails.Details
	if details == nil {
		details = make(map[string]string)
	}

	switch archetype {
	case ArchetypeHardening:
		// TargetEndpoint: Canonical Path (or origin if host-wide)
		endpointKey := "/"
		if canonURL, err := CanonicalizeURL(f.Endpoint); err == nil && canonURL.Path != "" {
			endpointKey = canonURL.Path
		} else if f.Endpoint != "" {
			endpointKey = report.NormalizeURL(f.Endpoint)
		}

		// Discriminator: specific header, cookie, or TLS property
		discKey := extractHardeningDiscriminator(f, details)
		return endpointKey, discKey, false, ""

	case ArchetypeCloud:
		// TargetEndpoint: resource identifier (bucket, project, instance)
		resID := details["bucket"]
		if resID == "" {
			resID = details["bucket_name"]
		}
		if resID == "" {
			resID = details["project_id"]
		}
		if resID == "" {
			resID = details["database_name"]
		}
		if resID == "" {
			resID = f.Endpoint
		}
		endpointKey := strings.ToLower(strings.TrimSpace(resID))

		// Discriminator: permission, action, or specific misconfiguration
		discKey := extractCloudDiscriminator(f, details)
		return endpointKey, discKey, false, ""

	case ArchetypeMobile:
		// TargetEndpoint: component name or package
		pkgName := details["package_name"]
		if pkgName == "" {
			pkgName = details["app_id"]
		}
		endpointKey := strings.ToLower(strings.TrimSpace(pkgName))

		// Discriminator: exported activity, service, receiver, or permission
		discKey := extractMobileDiscriminator(f, details)
		return endpointKey, discKey, false, ""

	case ArchetypeSecrets:
		// TargetEndpoint: relative file path or route (strip volatile line numbers!)
		loc := details["file_path"]
		if loc == "" {
			loc = details["location"]
		}
		if loc == "" {
			loc = f.Endpoint
		}
		cleanLoc := cleanPathOrLocation(loc)

		// Discriminator: secret type or pattern
		discKey := extractSecretDiscriminator(f, details)
		return cleanLoc, discKey, false, ""

	case ArchetypeHTTP:
		fallthrough
	default:
		// Check for missing/insufficient evidence
		ep := f.Endpoint
		if ep == "" {
			ep = f.Target
		}
		if strings.TrimSpace(ep) == "" && strings.TrimSpace(f.Target) == "" {
			return "", "", true, "Missing both endpoint and target identity"
		}

		// Method & Canonical Endpoint
		method := report.NormalizeMethod(f.Method)
		canonURL, err := CanonicalizeURL(ep)
		if err != nil || canonURL == nil {
			if strings.TrimSpace(ep) == "" {
				return "", "", true, "Malformed or empty endpoint URL"
			}
			return fmt.Sprintf("%s:%s", method, ep), extractHTTPDiscriminator(f, details), false, ""
		}

		// Canonical endpoint route: Method:Path (preserve semantic query params keys if any)
		var endpointRoute string
		if canonURL.Path != "" {
			endpointRoute = canonURL.Path
		} else {
			endpointRoute = "/"
		}

		// If query parameters define route/action semantics (e.g. ?action=read), include sorted keys
		if canonURL.RawURL != "" {
			if u, err := url.Parse(canonURL.RawURL); err == nil && u.RawQuery != "" {
				q := u.Query()
				var keys []string
				for k := range q {
					lowerK := strings.ToLower(k)
					// Exclude volatile session tokens and timestamps from route keys
					if !secrets.IsSensitiveQueryParam(lowerK) && lowerK != "_" && lowerK != "t" && lowerK != "timestamp" {
						keys = append(keys, lowerK)
					}
				}
				if len(keys) > 0 {
					sort.Strings(keys)
					endpointRoute = fmt.Sprintf("%s?keys=%s", endpointRoute, strings.Join(keys, ","))
				}
			}
		}

		endpointKey := fmt.Sprintf("%s:%s", method, endpointRoute)
		discKey := extractHTTPDiscriminator(f, details)
		return endpointKey, discKey, false, ""
	}
}

// extractHardeningDiscriminator identifies the specific header, cookie, or configuration setting.
func extractHardeningDiscriminator(f report.Finding, details map[string]string) string {
	keys := []string{"header", "missing_header", "header_name", "setting", "cookie", "cookie_name", "cipher", "tls_version"}
	for _, k := range keys {
		if v, ok := details[k]; ok && strings.TrimSpace(v) != "" {
			return fmt.Sprintf("%s:%s", k, strings.ToLower(strings.TrimSpace(v)))
		}
	}

	cat := strings.ToLower(report.NormalizeCategory(f.Category))
	switch {
	case strings.Contains(cat, "csp") || strings.Contains(cat, "content-security-policy"):
		return "header:content-security-policy"
	case strings.Contains(cat, "hsts") || strings.Contains(cat, "strict-transport-security"):
		return "header:strict-transport-security"
	case strings.Contains(cat, "x-frame-options") || strings.Contains(cat, "clickjacking"):
		return "header:x-frame-options"
	case strings.Contains(cat, "x-content-type-options") || strings.Contains(cat, "nosniff"):
		return "header:x-content-type-options"
	case strings.Contains(cat, "referrer-policy"):
		return "header:referrer-policy"
	case strings.Contains(cat, "permissions-policy"):
		return "header:permissions-policy"
	case strings.Contains(cat, "cors"):
		return "policy:cors-configuration"
	case strings.Contains(cat, "cookie"):
		return "policy:cookie-security"
	}

	return "disc:default_hardening"
}

// extractCloudDiscriminator identifies the specific cloud permission or misconfiguration.
func extractCloudDiscriminator(f report.Finding, details map[string]string) string {
	keys := []string{"permission", "action", "policy", "misconfiguration", "role", "acl", "access_level"}
	for _, k := range keys {
		if v, ok := details[k]; ok && strings.TrimSpace(v) != "" {
			return fmt.Sprintf("%s:%s", k, strings.ToLower(strings.TrimSpace(v)))
		}
	}

	cat := strings.ToLower(report.NormalizeCategory(f.Category))
	if strings.Contains(cat, "public-read") || strings.Contains(cat, "open") {
		return "perm:public_read"
	} else if strings.Contains(cat, "public-write") {
		return "perm:public_write"
	} else if strings.Contains(cat, "unauthenticated") {
		return "perm:unauthenticated_access"
	}

	return "disc:default_cloud"
}

// extractMobileDiscriminator identifies the specific mobile component or permission.
func extractMobileDiscriminator(f report.Finding, details map[string]string) string {
	keys := []string{"component", "activity", "service", "receiver", "provider", "permission", "exported_component"}
	for _, k := range keys {
		if v, ok := details[k]; ok && strings.TrimSpace(v) != "" {
			return fmt.Sprintf("%s:%s", k, strings.ToLower(strings.TrimSpace(v)))
		}
	}

	cat := strings.ToLower(report.NormalizeCategory(f.Category))
	return fmt.Sprintf("disc:%s", cat)
}

// extractSecretDiscriminator identifies the secret type, pattern, or non-volatile location key.
func extractSecretDiscriminator(f report.Finding, details map[string]string) string {
	sType := details["secret_type"]
	if sType == "" {
		sType = details["type"]
	}
	if sType == "" {
		sType = f.Category
	}
	cleanType := strings.ToLower(strings.TrimSpace(sType))

	varName := details["variable_name"]
	if varName == "" {
		varName = details["identifier"]
	}
	if varName != "" {
		return fmt.Sprintf("type:%s:var:%s", cleanType, strings.ToLower(strings.TrimSpace(varName)))
	}

	return fmt.Sprintf("type:%s", cleanType)
}

// extractHTTPDiscriminator identifies the specific vulnerable parameter, field, or bypass method.
func extractHTTPDiscriminator(f report.Finding, details map[string]string) string {
	keys := []string{"parameter", "param", "field", "vulnerable_parameter", "param_name", "object_id_param", "header"}
	for _, k := range keys {
		if v, ok := details[k]; ok && strings.TrimSpace(v) != "" {
			return fmt.Sprintf("param:%s", strings.ToLower(strings.TrimSpace(v)))
		}
	}

	// Check if title or evidence explicitly names a parameter: e.g. "parameter 'id'" or "param id"
	param := findParameterInProse(f.Title, f.Evidence)
	if param != "" {
		return fmt.Sprintf("param:%s", param)
	}

	return "disc:none"
}

// findParameterInProse inspects title and evidence for explicitly stated parameter names.
func findParameterInProse(title, evidence string) string {
	combined := title + " " + evidence
	patterns := []string{"parameter '", "parameter \"", "param '", "param \"", "field '", "field \""}
	for _, p := range patterns {
		if idx := strings.Index(combined, p); idx != -1 {
			start := idx + len(p)
			end := strings.IndexAny(combined[start:], "'\" ,;\n")
			if end != -1 {
				val := strings.TrimSpace(combined[start : start+end])
				if len(val) > 0 && len(val) < 64 {
					return strings.ToLower(val)
				}
			}
		}
	}
	return ""
}

// cleanPathOrLocation strips volatile line numbers and normalizes file/URL paths.
func cleanPathOrLocation(loc string) string {
	trimmed := strings.TrimSpace(loc)
	if trimmed == "" {
		return "unknown_location"
	}

	// Strip line numbers: e.g. "app.js:42" -> "app.js"
	if idx := strings.LastIndex(trimmed, ":"); idx != -1 && idx < len(trimmed)-1 {
		suffix := trimmed[idx+1:]
		isAllDigits := true
		for _, r := range suffix {
			if r < '0' || r > '9' {
				isAllDigits = false
				break
			}
		}
		if isAllDigits {
			trimmed = trimmed[:idx]
		}
	}

	trimmed = path.Clean(trimmed)
	return strings.ToLower(trimmed)
}

// cleanIdentityToken cleans an identifier to safe alphanumeric and underscore characters.
func cleanIdentityToken(id string) string {
	clean := strings.TrimSpace(id)
	clean = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, clean)
	if len(clean) > 32 {
		clean = clean[:32]
	}
	return clean
}

// encodeCanonicalPayload encodes structured fingerprint components into an unambiguous,
// collision-free representation using length-prefixed framing:
// <prefix>\n<len(f1)>:<f1>\n<len(f2)>:<f2>...
// This guarantees that values containing colons, slashes, or other delimiters cannot collide.
func encodeCanonicalPayload(prefix string, fields ...string) string {
	var b strings.Builder
	b.WriteString(prefix)
	for _, f := range fields {
		b.WriteByte('\n')
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteByte(':')
		b.WriteString(f)
	}
	return b.String()
}

// IsValidFingerprint verifies whether a fingerprint matches the canonical fingerprint for finding f.
// It detects and rejects stale, legacy, corrupted, or cross-copied fingerprints.
func IsValidFingerprint(f report.Finding, fp string) bool {
	cleanFP := strings.TrimSpace(fp)
	if len(cleanFP) != 64 || !isHexString(cleanFP) {
		return false
	}
	return cleanFP == ComputeStableFingerprint(f)
}

// EnsureFindingFingerprint guarantees that a finding has a valid stable fingerprint according to the trust policy.
func EnsureFindingFingerprint(f *report.Finding, policy FingerprintTrustPolicy) {
	if f == nil {
		return
	}

	switch policy {
	case TrustPolicyPreserveExisting:
		if f.Fingerprint != "" {
			return
		}
		f.Fingerprint = ComputeStableFingerprint(*f)

	case TrustPolicyRecomputeIfLegacy:
		if f.Fingerprint != "" {
			if strings.TrimSpace(f.Target) != "" || strings.TrimSpace(f.Endpoint) != "" || strings.TrimSpace(f.EvidenceDetails.Location) != "" {
				if IsValidFingerprint(*f, f.Fingerprint) {
					return
				}
			} else {
				// Finding lacks sufficient attributes to recompute/validate; preserve explicit fingerprint
				return
			}
		}
		f.Fingerprint = ComputeStableFingerprint(*f)

	case TrustPolicyForceRecompute:
		f.Fingerprint = ComputeStableFingerprint(*f)
	}

	if f.EvidenceDetails.Details == nil {
		f.EvidenceDetails.Details = make(map[string]string)
	}
	f.EvidenceDetails.Details["fingerprint_version"] = AlgorithmVersion
}

// isHexString checks if a string consists entirely of valid hexadecimal characters.
func isHexString(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// -----------------------------------------------------------------------------
// Cross-Assessment Finding Comparison & Lifecycle Tracking (Phase 7.3)
// -----------------------------------------------------------------------------

// FindingLifecycleStatus defines the status of a finding across assessment runs.
type FindingLifecycleStatus string

const (
	LifecycleNew        FindingLifecycleStatus = "NEW"        // Discovered in current, not present in baseline
	LifecycleActive     FindingLifecycleStatus = "ACTIVE"     // Previously observed and remains present
	LifecycleRecurring  FindingLifecycleStatus = "ACTIVE"     // Backwards-compatible alias for ACTIVE
	LifecycleResolved   FindingLifecycleStatus = "RESOLVED"   // Conclusively verified mitigated in completed, scoped current assessment
	LifecycleRegressed  FindingLifecycleStatus = "REGRESSED"  // Previously resolved finding detected again
	LifecycleUnassessed FindingLifecycleStatus = "UNASSESSED" // Missing in current, but current run failed, was cancelled, or did not scope the target
)

// DeltaClassification defines the high-level delta status of a security finding between assessment runs.
type DeltaClassification string

const (
	DeltaNew        DeltaClassification = "NEW"        // Discovered in current assessment, absent in baseline
	DeltaResolved   DeltaClassification = "RESOLVED"   // Conclusively verified mitigated in scoped, completed current run
	DeltaPersistent DeltaClassification = "PERSISTENT" // Observed in both assessments with substantially unchanged characteristics
	DeltaRegressed  DeltaClassification = "REGRESSED"  // Worsened severity or reappearance of previously resolved finding
	DeltaChanged    DeltaClassification = "CHANGED"    // Meaningfully modified characteristics without qualifying as regression
	DeltaUnverified DeltaClassification = "UNVERIFIED" // Absent in current run, but current run had incomplete/failed/unscoped coverage
)

// RegressionReason explains why a finding was classified as REGRESSED.
const (
	RegressionReappeared       = "REAPPEARED"        // Previously resolved finding detected again
	RegressionSeverityWorsened = "SEVERITY_WORSENED" // Severity rank increased compared to baseline
)

// ChangeReason explains why a finding was classified as CHANGED.
const (
	ChangeSeverityDecreased = "SEVERITY_DECREASED" // Severity rank decreased
	ChangeConfidenceChanged = "CONFIDENCE_CHANGED" // Confidence level changed
	ChangeStatusChanged     = "STATUS_CHANGED"     // Status or verification status changed
	ChangeEndpointChanged   = "ENDPOINT_CHANGED"   // Target endpoint or HTTP method changed
	ChangeEvidenceChanged   = "EVIDENCE_CHANGED"   // Material evidence or remediation advice updated
)

// IsValidLifecycleStatus returns true if status is one of the valid canonical lifecycle states.
func IsValidLifecycleStatus(s FindingLifecycleStatus) bool {
	switch s {
	case LifecycleNew, LifecycleActive, LifecycleResolved, LifecycleRegressed, LifecycleUnassessed:
		return true
	default:
		return false
	}
}

// NormalizeLifecycleStatus normalizes an arbitrary string into a canonical FindingLifecycleStatus.
func NormalizeLifecycleStatus(s string) FindingLifecycleStatus {
	clean := strings.ToUpper(strings.TrimSpace(s))
	switch clean {
	case "NEW":
		return LifecycleNew
	case "ACTIVE", "RECURRING":
		return LifecycleActive
	case "RESOLVED":
		return LifecycleResolved
	case "REGRESSED":
		return LifecycleRegressed
	case "UNASSESSED":
		return LifecycleUnassessed
	default:
		return LifecycleNew
	}
}

// P10.8 Canonical Lifecycle & Severity Classifications
const (
	ClassificationNew               = "new"
	ClassificationResolved          = "resolved"
	ClassificationPersistent        = "persistent"
	ClassificationSeverityIncreased = "severity_increased"
	ClassificationSeverityDecreased = "severity_decreased"
	ClassificationChanged           = "changed"
	ClassificationUnchanged         = "unchanged"
	ClassificationUnknown           = "unknown"
)

// P10.8 Severity Deltas
const (
	SeverityDeltaIncreased = "severity_increased"
	SeverityDeltaDecreased = "severity_decreased"
	SeverityDeltaUnchanged = "unchanged"
)

// FindingComparisonItem details the comparison of a specific finding across assessments.
type FindingComparisonItem struct {
	Fingerprint      string                 `json:"fingerprint"`
	Classification   DeltaClassification    `json:"classification"`
	RegressionReason string                 `json:"regression_reason,omitempty"`
	ChangeReason     string                 `json:"change_reason,omitempty"`
	LifecycleStatus  FindingLifecycleStatus `json:"lifecycle_status"`
	CanonicalDelta   string                 `json:"canonical_delta,omitempty"`
	SeverityDelta    string                 `json:"severity_delta,omitempty"`
	AttributeChanges []string               `json:"attribute_changes,omitempty"`
	IdentityBasis    string                 `json:"identity_basis,omitempty"`
	Title            string                 `json:"title"`
	Severity         string                 `json:"severity"`
	Category         string                 `json:"category"`
	TargetEndpoint   string                 `json:"target_endpoint"`
	BaselineFinding  *report.Finding        `json:"baseline_finding,omitempty"`
	CurrentFinding   *report.Finding        `json:"current_finding,omitempty"`
	StatusChange     string                 `json:"status_change,omitempty"`     // e.g. "SUSPECTED -> CONFIRMED"
	SeverityChange   string                 `json:"severity_change,omitempty"`   // e.g. "MEDIUM -> HIGH"
	ConfidenceChange string                 `json:"confidence_change,omitempty"` // e.g. "LOW -> HIGH"
	VerificationRank int                    `json:"verification_rank_delta,omitempty"`
	ScoreDelta       int                    `json:"score_delta"`
	Explanation      string                 `json:"explanation"`
}

// ComparisonOptions defines execution context and scope constraints for cross-assessment diffing.
type ComparisonOptions struct {
	// CurrentCompleted indicates whether the current assessment execution completed successfully.
	// When false (e.g. execution failed, was cancelled, or was interrupted), baseline findings
	// missing from current are categorized as UNASSESSED / UNVERIFIED rather than RESOLVED, preventing false mitigation claims.
	CurrentCompleted bool

	// ScopedTargets defines the target URLs or host origins evaluated during the current assessment.
	// When non-empty, baseline findings on targets outside this scope remain UNASSESSED / UNVERIFIED.
	ScopedTargets []string

	// ScopedCategories defines specific check or detector categories evaluated during the current assessment.
	// When non-empty, baseline findings in categories outside this scope remain UNASSESSED / UNVERIFIED.
	ScopedCategories []string

	// Inconclusive indicates whether the current assessment was marked inconclusive or had invalidated coverage.
	Inconclusive bool

	// AssessedTargets defines targets that completed assessment successfully without error.
	// When non-empty, baseline findings on targets not in this list remain UNASSESSED / UNVERIFIED.
	AssessedTargets []string

	// FailedTargets defines targets that encountered connection failures, timeouts, or transport errors.
	// Any baseline finding whose affected targets include a failed target remains UNASSESSED / UNVERIFIED.
	FailedTargets []string

	// SkippedTargets defines targets omitted or skipped during execution.
	SkippedTargets []string

	// FailedCategories defines check/detector categories that failed or had execution errors.
	FailedCategories []string

	// SkippedCategories defines check/detector categories that were disabled or skipped.
	SkippedCategories []string

	// ResolvedFingerprints tracks fingerprints that have verified historical resolution evidence.
	// When a current finding is absent from baseline, but its fingerprint is in ResolvedFingerprints,
	// it is classified as REGRESSED (REAPPEARED) rather than NEW.
	ResolvedFingerprints map[string]bool
}

// DefaultComparisonOptions returns default comparison options assuming a completed execution.
func DefaultComparisonOptions() ComparisonOptions {
	return ComparisonOptions{
		CurrentCompleted: true,
	}
}

// AssessmentComparison records the complete diff between a baseline and current assessment.
type AssessmentComparison struct {
	BaselineExecutionID    string                  `json:"baseline_execution_id,omitempty"`
	CurrentExecutionID     string                  `json:"current_execution_id,omitempty"`
	BaselineSnapshotID     string                  `json:"baseline_snapshot_id,omitempty"`
	CurrentSnapshotID      string                  `json:"current_snapshot_id,omitempty"`
	ComparisonStatus       string                  `json:"comparison_status"` // "COMPLETE" or "PARTIAL"
	ComparisonReason       string                  `json:"comparison_reason,omitempty"`
	BaselineCount          int                     `json:"baseline_count"`
	CurrentCount           int                     `json:"current_count"`
	NewCount               int                     `json:"new_count"`
	ActiveCount            int                     `json:"active_count"` // backwards compat
	PersistentCount        int                     `json:"persistent_count"`
	ChangedCount           int                     `json:"changed_count"`
	RecurringCount         int                     `json:"recurring_count"` // backwards compat
	ResolvedCount          int                     `json:"resolved_count"`
	RegressedCount         int                     `json:"regressed_count"`
	UnassessedCount        int                     `json:"unassessed_count"` // backwards compat
	UnverifiedCount        int                     `json:"unverified_count"`
	SeverityIncreasedCount int                     `json:"severity_increased_count"`
	SeverityDecreasedCount int                     `json:"severity_decreased_count"`
	UnchangedCount         int                     `json:"unchanged_count"`
	UnknownCount           int                     `json:"unknown_count"`
	NetRiskScoreDelta      int                     `json:"net_risk_score_delta"`
	Items                  []FindingComparisonItem `json:"items"`
}

// CompareFindings evaluates findings from two assessment runs by fingerprint using default completed options.
func CompareFindings(baseline, current []report.Finding) AssessmentComparison {
	return CompareFindingsWithOptions(baseline, current, DefaultComparisonOptions())
}

var (
	isoTimestampRegex = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?`)
	uuidRegex         = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
)

func sanitizeVolatileEvidence(s string) string {
	if s == "" {
		return ""
	}
	cleaned := isoTimestampRegex.ReplaceAllString(s, "")
	cleaned = uuidRegex.ReplaceAllString(cleaned, "")
	return strings.Join(strings.Fields(cleaned), " ")
}

func hasMaterialDetailsDiff(d1, d2 map[string]string) bool {
	volatile := map[string]bool{
		"timestamp":           true,
		"time":                true,
		"date":                true,
		"request_id":          true,
		"req_id":              true,
		"id":                  true,
		"execution_id":        true,
		"exec_id":             true,
		"assessment_id":       true,
		"scan_id":             true,
		"run_id":              true,
		"duration":            true,
		"elapsed":             true,
		"duration_ms":         true,
		"latency":             true,
		"latency_ms":          true,
		"nonce":               true,
		"trace_id":            true,
		"span_id":             true,
		"fingerprint_version": true,
		"lifecycle_status":    true,
	}
	for k, v1 := range d1 {
		if volatile[strings.ToLower(k)] {
			continue
		}
		v2, ok := d2[k]
		if !ok || strings.TrimSpace(v1) != strings.TrimSpace(v2) {
			return true
		}
	}
	for k := range d2 {
		if volatile[strings.ToLower(k)] {
			continue
		}
		if _, ok := d1[k]; !ok {
			return true
		}
	}
	return false
}

// hasMaterialEvidenceChange determines if two findings have material, non-volatile evidence differences.
func hasMaterialEvidenceChange(base, cur report.Finding) bool {
	// 1. Check HTTP status code
	if base.EvidenceDetails.HTTPStatus != 0 && cur.EvidenceDetails.HTTPStatus != 0 &&
		base.EvidenceDetails.HTTPStatus != cur.EvidenceDetails.HTTPStatus {
		return true
	}
	// 2. Check Content-Type
	if base.EvidenceDetails.ContentType != "" && cur.EvidenceDetails.ContentType != "" &&
		!strings.EqualFold(base.EvidenceDetails.ContentType, cur.EvidenceDetails.ContentType) {
		return true
	}
	// 3. Check Observation or ObservedBehavior
	baseObs := sanitizeVolatileEvidence(base.EvidenceDetails.Observation)
	curObs := sanitizeVolatileEvidence(cur.EvidenceDetails.Observation)
	if baseObs != "" && curObs != "" && baseObs != curObs {
		return true
	}
	baseBeh := sanitizeVolatileEvidence(base.EvidenceDetails.ObservedBehavior)
	curBeh := sanitizeVolatileEvidence(cur.EvidenceDetails.ObservedBehavior)
	if baseBeh != "" && curBeh != "" && baseBeh != curBeh {
		return true
	}
	// 4. Check Details map (excluding volatile keys)
	if hasMaterialDetailsDiff(base.EvidenceDetails.Details, cur.EvidenceDetails.Details) {
		return true
	}
	// 5. Check Raw Evidence string if details were empty
	baseEv := sanitizeVolatileEvidence(base.Evidence)
	curEv := sanitizeVolatileEvidence(cur.Evidence)
	if baseEv != "" && curEv != "" && baseEv != curEv {
		return true
	}
	// 6. Check Remediation advice
	if strings.TrimSpace(base.Remediation) != "" && strings.TrimSpace(cur.Remediation) != "" &&
		strings.TrimSpace(base.Remediation) != strings.TrimSpace(cur.Remediation) {
		return true
	}
	return false
}

func classificationRank(c DeltaClassification) int {
	switch c {
	case DeltaRegressed:
		return 6
	case DeltaNew:
		return 5
	case DeltaChanged:
		return 4
	case DeltaPersistent:
		return 3
	case DeltaUnverified:
		return 2
	case DeltaResolved:
		return 1
	default:
		return 0
	}
}

// extractExplicitTrackingID extracts an explicit tracking or issue identity from finding details.
func extractExplicitTrackingID(f report.Finding) string {
	if f.EvidenceDetails.Details == nil {
		return ""
	}
	for _, k := range []string{"tracking_id", "issue_id", "canonical_identity", "finding_track_id"} {
		if v := strings.TrimSpace(f.EvidenceDetails.Details[k]); v != "" {
			return v
		}
	}
	return ""
}

// CompareFindingsWithOptions evaluates findings with execution lifecycle and scope constraints.
func CompareFindingsWithOptions(baseline, current []report.Finding, opts ComparisonOptions) AssessmentComparison {
	baselineMap := make(map[string]report.Finding, len(baseline))
	for _, f := range baseline {
		fp := f.Fingerprint
		if fp == "" || !IsValidFingerprint(f, fp) {
			fp = ComputeStableFingerprint(f)
		}
		baselineMap[fp] = f
	}

	currentMap := make(map[string]report.Finding, len(current))
	for _, f := range current {
		fp := f.Fingerprint
		if fp == "" || !IsValidFingerprint(f, fp) {
			fp = ComputeStableFingerprint(f)
		}
		currentMap[fp] = f
	}

	// Secondary matching for explicit tracking identifiers:
	// When a finding's endpoint changes across versions (e.g. /api/v1/users -> /api/v2/users),
	// its canonical fingerprint changes because the endpoint path is an intrinsic identity component.
	// However, if both baseline and current findings carry an explicit, matching tracking identifier
	// on the same asset and category/rule in a strict unambiguous 1-to-1 relationship, they can be safely linked.
	matchedBaseByCurrentFP := make(map[string]report.Finding)
	claimedBaseFPs := make(map[string]bool)

	type trackCandidate struct {
		fp      string
		finding report.Finding
	}
	baseCandidatesByTrack := make(map[string][]trackCandidate)
	for baseFP, baseF := range baselineMap {
		if _, inCur := currentMap[baseFP]; !inCur {
			if tid := extractExplicitTrackingID(baseF); tid != "" {
				baseCandidatesByTrack[tid] = append(baseCandidatesByTrack[tid], trackCandidate{fp: baseFP, finding: baseF})
			}
		}
	}

	for curFP, curF := range currentMap {
		if _, inBase := baselineMap[curFP]; !inBase {
			if tid := extractExplicitTrackingID(curF); tid != "" {
				if candidates, exists := baseCandidatesByTrack[tid]; exists && len(candidates) == 1 {
					cand := candidates[0]
					sameAsset := (cand.finding.Target == curF.Target) ||
						(cand.finding.PrimaryAssetID != "" && cand.finding.PrimaryAssetID == curF.PrimaryAssetID)
					sameCat := strings.EqualFold(report.NormalizeCategory(cand.finding.Category), report.NormalizeCategory(curF.Category)) ||
						(cand.finding.RuleID != "" && strings.EqualFold(cand.finding.RuleID, curF.RuleID))
					if sameAsset && sameCat && !claimedBaseFPs[cand.fp] {
						matchedBaseByCurrentFP[curFP] = cand.finding
						claimedBaseFPs[cand.fp] = true
					}
				}
			}
		}
	}

	var items []FindingComparisonItem
	newCount := 0
	activeCount := 0
	persistentCount := 0
	changedCount := 0
	recurringCount := 0
	resolvedCount := 0
	regressedCount := 0
	unassessedCount := 0
	unverifiedCount := 0
	severityIncreasedCount := 0
	severityDecreasedCount := 0
	unchangedCount := 0
	unknownCount := 0
	netScoreDelta := 0

	// 1. Evaluate current findings (NEW, PERSISTENT, CHANGED, or REGRESSED)
	for fp, cur := range currentMap {
		curCopy := cur
		curScore := cur.Score
		if curScore <= 0 {
			curScore = report.CalculateFindingScore(cur)
		}

		base, exists := baselineMap[fp]
		matchedViaTracking := false
		if !exists {
			base, exists = matchedBaseByCurrentFP[fp]
			if exists {
				matchedViaTracking = true
			}
		}

		idBasis := "CANONICAL_FINGERPRINT"
		if matchedViaTracking {
			idBasis = "EXPLICIT_TRACKING_ID"
		}

		if exists {
			baseCopy := base
			baseScore := base.Score
			if baseScore <= 0 {
				baseScore = report.CalculateFindingScore(base)
			}
			scoreDelta := curScore - baseScore
			netScoreDelta += scoreDelta

			statusChange := ""
			if base.Status != cur.Status {
				statusChange = fmt.Sprintf("%s -> %s", base.Status, cur.Status)
			}

			sevChange := ""
			if base.Severity != cur.Severity {
				sevChange = fmt.Sprintf("%s -> %s", base.Severity, cur.Severity)
			}

			confChange := ""
			curConfRank := report.ConfidenceRank(cur.Confidence)
			baseConfRank := report.ConfidenceRank(base.Confidence)
			if curConfRank != baseConfRank || !strings.EqualFold(cur.Confidence, base.Confidence) {
				confChange = fmt.Sprintf("%s -> %s", base.Confidence, cur.Confidence)
			}

			baseTargets := extractFindingTargets(base)
			curTargets := extractFindingTargets(cur)
			targetFootprintNote := ""
			if len(baseTargets) > 0 && len(curTargets) > 0 && strings.Join(baseTargets, ",") != strings.Join(curTargets, ",") {
				targetFootprintNote = fmt.Sprintf("; target footprint shifted: [%s] -> [%s]", strings.Join(baseTargets, ", "), strings.Join(curTargets, ", "))
			}

			curSevRank := report.SeverityRank(cur.Severity)
			baseSevRank := report.SeverityRank(base.Severity)

			var itemSeverityDelta string
			if curSevRank > baseSevRank {
				itemSeverityDelta = SeverityDeltaIncreased
			} else if curSevRank < baseSevRank {
				itemSeverityDelta = SeverityDeltaDecreased
			} else {
				itemSeverityDelta = SeverityDeltaUnchanged
			}

			var attributeChanges []string
			if base.Title != cur.Title {
				attributeChanges = append(attributeChanges, "title")
			}
			if curConfRank != baseConfRank || !strings.EqualFold(cur.Confidence, base.Confidence) {
				attributeChanges = append(attributeChanges, "confidence")
			}
			if cur.Status != base.Status || cur.Verification.Status != base.Verification.Status {
				attributeChanges = append(attributeChanges, "status")
			}
			if cur.Endpoint != base.Endpoint || (cur.Method != "" && base.Method != "" && !strings.EqualFold(cur.Method, base.Method)) {
				attributeChanges = append(attributeChanges, "endpoint")
			}
			if hasMaterialEvidenceChange(base, cur) {
				attributeChanges = append(attributeChanges, "evidence")
			}

			// Precedence rules for delta classification:
			// 1. REGRESSED (REAPPEARED): Baseline was previously resolved and is detected again.
			// 2. REGRESSED (SEVERITY_WORSENED / severity_increased): Severity rank increased.
			// 3. CHANGED (SEVERITY_DECREASED / severity_decreased): Severity rank decreased.
			// 4. CHANGED: Non-severity attributes modified while severity unchanged.
			// 5. UNCHANGED: Characteristics materially identical.

			isBaseResolved := base.LifecycleStatus == string(LifecycleResolved)
			if !isBaseResolved && base.EvidenceDetails.Details != nil {
				isBaseResolved = base.EvidenceDetails.Details["lifecycle_status"] == string(LifecycleResolved)
			}
			if !isBaseResolved && strings.EqualFold(string(base.Status), "RESOLVED") {
				isBaseResolved = true
			}

			var itemClassification DeltaClassification
			var itemStatus FindingLifecycleStatus
			var itemCanonicalDelta string
			var itemRegressionReason string
			var itemChangeReason string
			var itemExplanation string

			if isBaseResolved {
				regressedCount++
				itemClassification = DeltaRegressed
				itemStatus = LifecycleRegressed
				itemCanonicalDelta = ClassificationNew
				itemRegressionReason = RegressionReappeared
				itemExplanation = fmt.Sprintf("Vulnerability REGRESSED: previously resolved finding detected again (Fingerprint: %s%s).", fp[:16], targetFootprintNote)
			} else if curSevRank > baseSevRank {
				regressedCount++
				severityIncreasedCount++
				itemClassification = DeltaRegressed
				itemStatus = LifecycleRegressed
				itemCanonicalDelta = ClassificationSeverityIncreased
				itemRegressionReason = RegressionSeverityWorsened
				itemExplanation = fmt.Sprintf("Vulnerability REGRESSED: severity worsened from %s to %s (Fingerprint: %s%s).", base.Severity, cur.Severity, fp[:16], targetFootprintNote)
			} else if curSevRank < baseSevRank {
				changedCount++
				activeCount++
				recurringCount++
				severityDecreasedCount++
				itemClassification = DeltaChanged
				itemStatus = LifecycleActive
				itemCanonicalDelta = ClassificationSeverityDecreased
				itemChangeReason = ChangeSeverityDecreased
				itemExplanation = fmt.Sprintf("Vulnerability CHANGED: severity decreased from %s to %s (Fingerprint: %s%s).", base.Severity, cur.Severity, fp[:16], targetFootprintNote)
			} else if len(attributeChanges) > 0 {
				changedCount++
				activeCount++
				recurringCount++
				itemClassification = DeltaChanged
				itemStatus = LifecycleActive
				itemCanonicalDelta = ClassificationChanged
				if containsString(attributeChanges, "title") {
					itemChangeReason = "TITLE_CHANGED"
					itemExplanation = fmt.Sprintf("Vulnerability CHANGED: title updated from %q to %q (Fingerprint: %s%s).", base.Title, cur.Title, fp[:16], targetFootprintNote)
				} else if containsString(attributeChanges, "confidence") {
					itemChangeReason = ChangeConfidenceChanged
					itemExplanation = fmt.Sprintf("Vulnerability CHANGED: confidence changed from %s to %s (Fingerprint: %s%s).", base.Confidence, cur.Confidence, fp[:16], targetFootprintNote)
				} else if containsString(attributeChanges, "status") {
					itemChangeReason = ChangeStatusChanged
					itemExplanation = fmt.Sprintf("Vulnerability CHANGED: status changed (%s) (Fingerprint: %s%s).", statusChange, fp[:16], targetFootprintNote)
				} else if containsString(attributeChanges, "endpoint") {
					itemChangeReason = ChangeEndpointChanged
					itemExplanation = fmt.Sprintf("Vulnerability CHANGED: endpoint/method changed from %s %s to %s %s (Fingerprint: %s%s).", base.Method, base.Endpoint, cur.Method, cur.Endpoint, fp[:16], targetFootprintNote)
				} else {
					itemChangeReason = ChangeEvidenceChanged
					itemExplanation = fmt.Sprintf("Vulnerability CHANGED: material evidence or remediation updated (Fingerprint: %s%s).", fp[:16], targetFootprintNote)
				}
			} else {
				persistentCount++
				activeCount++
				recurringCount++
				unchangedCount++
				itemClassification = DeltaPersistent
				itemStatus = LifecycleActive
				itemCanonicalDelta = ClassificationUnchanged
				itemExplanation = fmt.Sprintf("Active vulnerability persistent and unchanged across assessments (Fingerprint: %s%s).", fp[:16], targetFootprintNote)
			}

			items = append(items, FindingComparisonItem{
				Fingerprint:      fp,
				Classification:   itemClassification,
				RegressionReason: itemRegressionReason,
				ChangeReason:     itemChangeReason,
				LifecycleStatus:  itemStatus,
				CanonicalDelta:   itemCanonicalDelta,
				SeverityDelta:    itemSeverityDelta,
				AttributeChanges: attributeChanges,
				IdentityBasis:    idBasis,
				Title:            cur.Title,
				Severity:         cur.Severity,
				Category:         cur.Category,
				TargetEndpoint:   cur.Endpoint,
				BaselineFinding:  &baseCopy,
				CurrentFinding:   &curCopy,
				StatusChange:     statusChange,
				SeverityChange:   sevChange,
				ConfidenceChange: confChange,
				ScoreDelta:       scoreDelta,
				Explanation:      itemExplanation,
			})
		} else {
			// Check if finding was previously verified as resolved in qualifying assessment
			isReappeared := false
			if opts.ResolvedFingerprints != nil && opts.ResolvedFingerprints[fp] {
				isReappeared = true
			} else if cur.LifecycleStatus == string(LifecycleRegressed) {
				isReappeared = true
			} else if cur.EvidenceDetails.Details != nil && cur.EvidenceDetails.Details["lifecycle_status"] == string(LifecycleRegressed) {
				isReappeared = true
			}

			if isReappeared {
				regressedCount++
				netScoreDelta += curScore
				items = append(items, FindingComparisonItem{
					Fingerprint:      fp,
					Classification:   DeltaRegressed,
					LifecycleStatus:  LifecycleRegressed,
					CanonicalDelta:   ClassificationNew,
					RegressionReason: RegressionReappeared,
					IdentityBasis:    idBasis,
					Title:            cur.Title,
					Severity:         cur.Severity,
					Category:         cur.Category,
					TargetEndpoint:   cur.Endpoint,
					CurrentFinding:   &curCopy,
					ScoreDelta:       curScore,
					Explanation:      fmt.Sprintf("Vulnerability REGRESSED: previously resolved finding detected again (Fingerprint: %s).", fp[:16]),
				})
			} else {
				newCount++
				netScoreDelta += curScore
				items = append(items, FindingComparisonItem{
					Fingerprint:     fp,
					Classification:  DeltaNew,
					LifecycleStatus: LifecycleNew,
					CanonicalDelta:  ClassificationNew,
					IdentityBasis:   idBasis,
					Title:           cur.Title,
					Severity:        cur.Severity,
					Category:        cur.Category,
					TargetEndpoint:  cur.Endpoint,
					CurrentFinding:  &curCopy,
					ScoreDelta:      curScore,
					Explanation:     fmt.Sprintf("New vulnerability introduced in current assessment (Fingerprint: %s).", fp[:16]),
				})
			}
		}
	}

	// 2. Evaluate findings present in baseline but missing in current
	for fp, base := range baselineMap {
		if claimedBaseFPs[fp] {
			// Matched to current finding via secondary matching (e.g. endpoint migration with explicit tracking ID); skip missing check
			continue
		}
		if _, exists := currentMap[fp]; !exists {
			baseCopy := base
			baseScore := base.Score
			if baseScore <= 0 {
				baseScore = report.CalculateFindingScore(base)
			}

			// Condition A: If the current assessment did not complete or was marked inconclusive,
			// missing findings cannot be considered resolved.
			if !opts.CurrentCompleted || opts.Inconclusive {
				unassessedCount++
				unverifiedCount++
				unknownCount++
				items = append(items, FindingComparisonItem{
					Fingerprint:     fp,
					Classification:  DeltaUnverified,
					LifecycleStatus: LifecycleUnassessed,
					CanonicalDelta:  ClassificationUnknown,
					IdentityBasis:   "CANONICAL_FINGERPRINT",
					Title:           base.Title,
					Severity:        base.Severity,
					Category:        base.Category,
					TargetEndpoint:  base.Endpoint,
					BaselineFinding: &baseCopy,
					ScoreDelta:      0,
					Explanation:     fmt.Sprintf("Current assessment execution was incomplete, failed, cancelled, or inconclusive; previously detected vulnerability cannot be marked resolved (Fingerprint: %s).", fp[:16]),
				})
				continue
			}

			// Condition B: If the baseline finding's target was not scoped in the current assessment,
			// it cannot be considered resolved.
			if len(opts.ScopedTargets) > 0 && !isTargetInScope(base, opts.ScopedTargets) {
				unassessedCount++
				unverifiedCount++
				unknownCount++
				unscoped := findUnscopedTarget(base, opts.ScopedTargets)
				if unscoped == "" {
					unscoped = base.Target
				}
				items = append(items, FindingComparisonItem{
					Fingerprint:     fp,
					Classification:  DeltaUnverified,
					LifecycleStatus: LifecycleUnassessed,
					CanonicalDelta:  ClassificationUnknown,
					IdentityBasis:   "CANONICAL_FINGERPRINT",
					Title:           base.Title,
					Severity:        base.Severity,
					Category:        base.Category,
					TargetEndpoint:  base.Endpoint,
					BaselineFinding: &baseCopy,
					ScoreDelta:      0,
					Explanation:     fmt.Sprintf("Target asset %q was not evaluated in the current assessment scope; vulnerability remains unassessed (Fingerprint: %s).", unscoped, fp[:16]),
				})
				continue
			}

			// Condition C: Check target execution failures or skipped targets
			baseTargets := extractFindingTargets(base)
			if len(opts.FailedTargets) > 0 {
				hasFailed := false
				var failedTgt string
				for _, bt := range baseTargets {
					if isSingleTargetInScope(bt, opts.FailedTargets) {
						hasFailed = true
						failedTgt = bt
						break
					}
				}
				if hasFailed {
					unassessedCount++
					unverifiedCount++
					unknownCount++
					items = append(items, FindingComparisonItem{
						Fingerprint:     fp,
						Classification:  DeltaUnverified,
						LifecycleStatus: LifecycleUnassessed,
						CanonicalDelta:  ClassificationUnknown,
						IdentityBasis:   "CANONICAL_FINGERPRINT",
						Title:           base.Title,
						Severity:        base.Severity,
						Category:        base.Category,
						TargetEndpoint:  base.Endpoint,
						BaselineFinding: &baseCopy,
						ScoreDelta:      0,
						Explanation:     fmt.Sprintf("Target asset %q encountered execution failure, transport error, or timeout; vulnerability remains unassessed (Fingerprint: %s).", failedTgt, fp[:16]),
					})
					continue
				}
			}

			if len(opts.SkippedTargets) > 0 {
				hasSkipped := false
				var skippedTgt string
				for _, bt := range baseTargets {
					if isSingleTargetInScope(bt, opts.SkippedTargets) {
						hasSkipped = true
						skippedTgt = bt
						break
					}
				}
				if hasSkipped {
					unassessedCount++
					unverifiedCount++
					unknownCount++
					items = append(items, FindingComparisonItem{
						Fingerprint:     fp,
						Classification:  DeltaUnverified,
						LifecycleStatus: LifecycleUnassessed,
						CanonicalDelta:  ClassificationUnknown,
						IdentityBasis:   "CANONICAL_FINGERPRINT",
						Title:           base.Title,
						Severity:        base.Severity,
						Category:        base.Category,
						TargetEndpoint:  base.Endpoint,
						BaselineFinding: &baseCopy,
						ScoreDelta:      0,
						Explanation:     fmt.Sprintf("Target asset %q was skipped or omitted during execution; vulnerability remains unassessed (Fingerprint: %s).", skippedTgt, fp[:16]),
					})
					continue
				}
			}

			// Condition D: Successful assessment verification (if assessed targets tracked)
			if len(opts.AssessedTargets) > 0 {
				allAssessed := true
				var unassessedTgt string
				for _, bt := range baseTargets {
					if !isSingleTargetInScope(bt, opts.AssessedTargets) {
						allAssessed = false
						unassessedTgt = bt
						break
					}
				}
				if !allAssessed {
					unassessedCount++
					unverifiedCount++
					unknownCount++
					items = append(items, FindingComparisonItem{
						Fingerprint:     fp,
						Classification:  DeltaUnverified,
						LifecycleStatus: LifecycleUnassessed,
						CanonicalDelta:  ClassificationUnknown,
						IdentityBasis:   "CANONICAL_FINGERPRINT",
						Title:           base.Title,
						Severity:        base.Severity,
						Category:        base.Category,
						TargetEndpoint:  base.Endpoint,
						BaselineFinding: &baseCopy,
						ScoreDelta:      0,
						Explanation:     fmt.Sprintf("Target asset %q was not successfully assessed; vulnerability remains unassessed (Fingerprint: %s).", unassessedTgt, fp[:16]),
					})
					continue
				}
			}

			// Condition E: Check category / detector failures and omissions
			normCat := strings.ToLower(report.NormalizeCategory(base.Category))
			if len(opts.FailedCategories) > 0 {
				hasFailedCat := false
				for _, fc := range opts.FailedCategories {
					if strings.EqualFold(normCat, strings.ToLower(report.NormalizeCategory(fc))) {
						hasFailedCat = true
						break
					}
				}
				if hasFailedCat {
					unassessedCount++
					unverifiedCount++
					unknownCount++
					items = append(items, FindingComparisonItem{
						Fingerprint:     fp,
						Classification:  DeltaUnverified,
						LifecycleStatus: LifecycleUnassessed,
						CanonicalDelta:  ClassificationUnknown,
						IdentityBasis:   "CANONICAL_FINGERPRINT",
						Title:           base.Title,
						Severity:        base.Severity,
						Category:        base.Category,
						TargetEndpoint:  base.Endpoint,
						BaselineFinding: &baseCopy,
						ScoreDelta:      0,
						Explanation:     fmt.Sprintf("Check category %q failed during assessment execution; vulnerability remains unassessed (Fingerprint: %s).", base.Category, fp[:16]),
					})
					continue
				}
			}

			if len(opts.SkippedCategories) > 0 {
				hasSkippedCat := false
				for _, sc := range opts.SkippedCategories {
					if strings.EqualFold(normCat, strings.ToLower(report.NormalizeCategory(sc))) {
						hasSkippedCat = true
						break
					}
				}
				if hasSkippedCat {
					unassessedCount++
					unverifiedCount++
					unknownCount++
					items = append(items, FindingComparisonItem{
						Fingerprint:     fp,
						Classification:  DeltaUnverified,
						LifecycleStatus: LifecycleUnassessed,
						CanonicalDelta:  ClassificationUnknown,
						IdentityBasis:   "CANONICAL_FINGERPRINT",
						Title:           base.Title,
						Severity:        base.Severity,
						Category:        base.Category,
						TargetEndpoint:  base.Endpoint,
						BaselineFinding: &baseCopy,
						ScoreDelta:      0,
						Explanation:     fmt.Sprintf("Check category %q was skipped or disabled in current assessment; vulnerability remains unassessed (Fingerprint: %s).", base.Category, fp[:16]),
					})
					continue
				}
			}

			// Condition F: If ScopedCategories is non-empty and finding's category was not evaluated
			if len(opts.ScopedCategories) > 0 && !isCategoryInScope(base.Category, opts.ScopedCategories) {
				unassessedCount++
				unverifiedCount++
				unknownCount++
				items = append(items, FindingComparisonItem{
					Fingerprint:     fp,
					Classification:  DeltaUnverified,
					LifecycleStatus: LifecycleUnassessed,
					CanonicalDelta:  ClassificationUnknown,
					IdentityBasis:   "CANONICAL_FINGERPRINT",
					Title:           base.Title,
					Severity:        base.Severity,
					Category:        base.Category,
					TargetEndpoint:  base.Endpoint,
					BaselineFinding: &baseCopy,
					ScoreDelta:      0,
					Explanation:     fmt.Sprintf("Check category %q was not executed in the current assessment; vulnerability remains unassessed (Fingerprint: %s).", base.Category, fp[:16]),
				})
				continue
			}

			// Condition G: Finding was in scope and evaluated in a successfully completed assessment, but not detected -> RESOLVED
			resolvedCount++
			netScoreDelta -= baseScore

			items = append(items, FindingComparisonItem{
				Fingerprint:     fp,
				Classification:  DeltaResolved,
				LifecycleStatus: LifecycleResolved,
				CanonicalDelta:  ClassificationResolved,
				IdentityBasis:   "CANONICAL_FINGERPRINT",
				Title:           base.Title,
				Severity:        base.Severity,
				Category:        base.Category,
				TargetEndpoint:  base.Endpoint,
				BaselineFinding: &baseCopy,
				ScoreDelta:      -baseScore,
				Explanation:     fmt.Sprintf("Previously observed vulnerability successfully mitigated or resolved (Fingerprint: %s).", fp[:16]),
			})
		}
	}

	// Sort items deterministically by Classification (REGRESSED > NEW > CHANGED > PERSISTENT > UNVERIFIED > RESOLVED),
	// then SeverityRank descending, then Fingerprint ascending
	sort.Slice(items, func(i, j int) bool {
		rankClassI := classificationRank(items[i].Classification)
		rankClassJ := classificationRank(items[j].Classification)
		if rankClassI != rankClassJ {
			return rankClassI > rankClassJ
		}
		rankI := report.SeverityRank(items[i].Severity)
		rankJ := report.SeverityRank(items[j].Severity)
		if rankI != rankJ {
			return rankI > rankJ
		}
		return items[i].Fingerprint < items[j].Fingerprint
	})

	comparisonStatus := "COMPLETE"
	comparisonReason := ""
	if unverifiedCount > 0 || !opts.CurrentCompleted || opts.Inconclusive || len(opts.FailedTargets) > 0 || len(opts.FailedCategories) > 0 {
		comparisonStatus = "PARTIAL"
		comparisonReason = "Assessment execution had incomplete coverage, failed targets/categories, or unverified findings"
	}

	return AssessmentComparison{
		ComparisonStatus:       comparisonStatus,
		ComparisonReason:       comparisonReason,
		BaselineCount:          len(baseline),
		CurrentCount:           len(current),
		NewCount:               newCount,
		ActiveCount:            activeCount,
		PersistentCount:        persistentCount,
		ChangedCount:           changedCount,
		RecurringCount:         recurringCount,
		ResolvedCount:          resolvedCount,
		RegressedCount:         regressedCount,
		UnassessedCount:        unassessedCount,
		UnverifiedCount:        unverifiedCount,
		SeverityIncreasedCount: severityIncreasedCount,
		SeverityDecreasedCount: severityDecreasedCount,
		UnchangedCount:         unchangedCount,
		UnknownCount:           unknownCount,
		NetRiskScoreDelta:      netScoreDelta,
		Items:                  items,
	}
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// extractFindingTargets extracts all targets associated with a finding, including its primary Target,
// Endpoint, and any targets recorded in EvidenceDetails.Details["associated_targets"].
func extractFindingTargets(f report.Finding) []string {
	targetSet := make(map[string]struct{})
	if t := strings.TrimSpace(f.Target); t != "" {
		targetSet[t] = struct{}{}
	}
	if f.EvidenceDetails.Details != nil {
		if raw := f.EvidenceDetails.Details["associated_targets"]; raw != "" {
			for _, part := range strings.Split(raw, ",") {
				if part = strings.TrimSpace(part); part != "" {
					targetSet[part] = struct{}{}
				}
			}
		}
	}
	if len(targetSet) == 0 {
		if ep := strings.TrimSpace(f.Endpoint); ep != "" {
			targetSet[ep] = struct{}{}
		}
	}
	var res []string
	for t := range targetSet {
		res = append(res, t)
	}
	sort.Strings(res)
	return res
}

func isSingleTargetInScope(tgt string, scopedTargets []string) bool {
	cleanTgt := strings.TrimSpace(tgt)
	if cleanTgt == "" {
		return false
	}
	canonTgt, err := CanonicalizeURL(cleanTgt)
	tgtOrigin := ""
	if err == nil && canonTgt != nil {
		tgtOrigin = strings.ToLower(canonTgt.Origin)
	} else {
		tgtOrigin = strings.ToLower(cleanTgt)
	}

	for _, st := range scopedTargets {
		cleanST := strings.TrimSpace(st)
		if cleanST == "" {
			continue
		}
		if strings.EqualFold(cleanTgt, cleanST) {
			return true
		}
		canonST, err := CanonicalizeURL(cleanST)
		stOrigin := ""
		if err == nil && canonST != nil {
			stOrigin = strings.ToLower(canonST.Origin)
		} else {
			stOrigin = strings.ToLower(cleanST)
		}

		if (tgtOrigin != "" && stOrigin != "" && tgtOrigin == stOrigin) ||
			strings.HasPrefix(strings.ToLower(cleanTgt), strings.ToLower(cleanST)) ||
			strings.HasPrefix(strings.ToLower(cleanST), strings.ToLower(cleanTgt)) {
			return true
		}
	}
	return false
}

// isTargetInScope checks whether ALL affected targets of a baseline finding fall within the current assessment's target scope.
// For multi-target findings, every affected target must be evaluated in the current assessment before the finding
// can be considered in scope for resolution. If any affected target was not evaluated, returns false.
func isTargetInScope(f report.Finding, scopedTargets []string) bool {
	if len(scopedTargets) == 0 {
		return true
	}
	allTargets := extractFindingTargets(f)
	if len(allTargets) == 0 {
		return false
	}
	for _, tgt := range allTargets {
		if !isSingleTargetInScope(tgt, scopedTargets) {
			return false
		}
	}
	return true
}

// findUnscopedTarget returns the first affected target of a baseline finding that is not within scopedTargets,
// or empty string if all targets are in scope.
func findUnscopedTarget(f report.Finding, scopedTargets []string) string {
	if len(scopedTargets) == 0 {
		return ""
	}
	allTargets := extractFindingTargets(f)
	for _, tgt := range allTargets {
		if !isSingleTargetInScope(tgt, scopedTargets) {
			return tgt
		}
	}
	return ""
}

func isCategoryInScope(cat string, scopedCategories []string) bool {
	cleanCat := strings.ToLower(strings.TrimSpace(cat))
	for _, sc := range scopedCategories {
		cleanSC := strings.ToLower(strings.TrimSpace(sc))
		if cleanSC == cleanCat || cleanSC == "all" || cleanSC == "*" {
			return true
		}
	}
	return false
}

// IsSingleTargetInScope checks whether a target URL matches any of the scoped targets.
func IsSingleTargetInScope(tgt string, scopedTargets []string) bool {
	return isSingleTargetInScope(tgt, scopedTargets)
}

// IsTargetInScope checks whether all affected targets of a baseline finding fall within the target scope.
func IsTargetInScope(f report.Finding, scopedTargets []string) bool {
	return isTargetInScope(f, scopedTargets)
}

// ExtractFindingTargets extracts all targets associated with a finding.
func ExtractFindingTargets(f report.Finding) []string {
	return extractFindingTargets(f)
}

// IsCategoryInScope checks whether a category is included within the scoped categories list.
func IsCategoryInScope(cat string, scopedCategories []string) bool {
	return isCategoryInScope(cat, scopedCategories)
}
