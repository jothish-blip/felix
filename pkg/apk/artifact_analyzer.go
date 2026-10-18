package apk

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"felix/pkg/report"
	"felix/pkg/secrets"
)

// ArtifactAnalysisResult encapsulates the static intelligence outcome of Android artifact inspection.
type ArtifactAnalysisResult struct {
	DexFilesAnalyzed     []string                `json:"dex_files_analyzed"`
	DexMetadata          []DEXFile               `json:"dex_metadata,omitempty"`
	ConfigsAnalyzed      []string                `json:"configs_analyzed"`
	FindingsCount        int                     `json:"findings_count"`
	Findings             []report.Finding        `json:"findings"`
	Limitations          []string                `json:"limitations,omitempty"`
	UnsupportedArtifacts []string                `json:"unsupported_artifacts,omitempty"`
	PartialAnalysis      bool                    `json:"partial_analysis"`
	Summary              ArtifactAnalysisSummary `json:"summary"`
}

// ArtifactAnalysisSummary provides categorical counts of discovered static intelligence indicators.
type ArtifactAnalysisSummary struct {
	SecretsCount   int `json:"secrets_count"`
	ServicesCount  int `json:"services_count"`
	EndpointsCount int `json:"endpoints_count"`
	GraphQLCount   int `json:"graphql_count"`
}

// Pre-compiled regular expressions for static indicator discovery
var (
	awsAccessKeyRegex   = regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`)
	googleAPIKeyRegex   = regexp.MustCompile(`\b(AIza[0-9A-Za-z-_]{35,40})\b`)
	stripeLiveKeyRegex  = regexp.MustCompile(`\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b`)
	githubTokenRegex    = regexp.MustCompile(`\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b`)
	slackTokenRegex     = regexp.MustCompile(`\b(xoxb-[0-9a-zA-Z-]{20,})\b`)
	openaiKeyRegex      = regexp.MustCompile(`\b(sk-proj-[a-zA-Z0-9_\-]{48,}|sk-[a-zA-Z0-9]{48})\b`)
	privateKeyRegex     = regexp.MustCompile(`(?s)-----BEGIN (?:[A-Z0-9_\-]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9_\-]+ )?PRIVATE KEY-----`)
	jwtTokenRegex       = regexp.MustCompile(`\b(ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`)
	dbURIRegex          = regexp.MustCompile(`(?i)\b(mongodb(?:\+srv)?|redis|rediss|postgres(?:ql)?|mysql)://([^:/\s?#@]+):([^/\s?#@]+)@([a-zA-Z0-9_.-]+(?::[0-9]+)?)(?:/([^?\s#]*))?`)
	redisTokenURIRegex  = regexp.MustCompile(`(?i)\b(rediss?://):?([^:/\s?#@]+)@([a-zA-Z0-9_.-]+(?::[0-9]+)?)(?:/([^?\s#]*))?`)
	httpURLRegex        = regexp.MustCompile(`(?i)\bhttps?://(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::[0-9]+)?(?:/[a-zA-Z0-9_.~!$&'()*+,;=:@%/-]*)?`)
	versionedRouteRegex = regexp.MustCompile(`^/(?:api/)?v[0-9]+(?:/[a-zA-Z0-9_.~-]+)+$`)
	graphqlQueryRegex   = regexp.MustCompile(`(?s)\b(?:query|mutation|subscription)\s*(?:[A-Za-z0-9_]+\s*)?\{.*?\}`)

	// AWS Service Indicators
	awsS3BucketRegex    = regexp.MustCompile(`(?i)\b([a-z0-9.-]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com)\b`)
	awsCognitoRegex     = regexp.MustCompile(`(?i)\b([a-z0-9-]+(?:\.cognito-idp|\.cognito-identity)\.[a-z0-9-]+\.amazonaws\.com)\b`)
	awsAPIGatewayRegex  = regexp.MustCompile(`(?i)\b([a-z0-9-]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com)\b`)
	firebaseHostRegex   = regexp.MustCompile(`(?i)\b([a-z0-9-]+\.firebaseio\.com)\b`)
	mongoHostRegex      = regexp.MustCompile(`(?i)\bmongodb(?:\+srv)?://(?:[^@/\s]+@)?([a-zA-Z0-9_.-]+(?::[0-9]+)?)`)
	redisHostRegex      = regexp.MustCompile(`(?i)\brediss?://(?:[^@/\s]+@)?([a-zA-Z0-9_.-]+(?::[0-9]+)?)`)
)

// isBenignURL identifies XML namespaces, vendor documentation schemas, and search engines that must not be flagged as API endpoints.
func isBenignURL(u string) bool {
	uLower := strings.ToLower(u)
	benignPrefixes := []string{
		"http://schemas.android.com",
		"https://schemas.android.com",
		"http://www.w3.org",
		"https://www.w3.org",
		"http://xmlpull.org",
		"https://xmlpull.org",
		"http://xml.org",
		"https://xml.org",
		"http://apache.org",
		"https://apache.org",
		"http://www.apache.org",
		"https://www.apache.org",
		"http://java.sun.com",
		"https://java.sun.com",
		"http://xmlns.jcp.org",
		"https://xmlns.jcp.org",
		"http://maven.apache.org",
		"https://maven.apache.org",
		"http://play.google.com",
		"https://play.google.com",
		"http://support.google.com",
		"https://support.google.com",
		"https://policies.google.com",
		"http://policies.google.com",
		"http://plus.google.com",
		"https://plus.google.com",
		"http://www.google.com",
		"https://www.google.com",
		"http://google.com",
		"https://google.com",
		"http://github.com",
		"https://github.com",
	}

	for _, p := range benignPrefixes {
		if strings.HasPrefix(uLower, p) {
			return true
		}
	}
	return false
}

// isPublicConfigurationIdentifier returns true if a key-value pair is an intentionally public mobile configuration property.
func isPublicConfigurationIdentifier(key, val string) bool {
	kLower := strings.ToLower(key)
	vLower := strings.ToLower(val)

	// Firebase and Google mobile public configuration attributes
	if strings.Contains(kLower, "project_id") ||
		strings.Contains(kLower, "project_number") ||
		strings.Contains(kLower, "storage_bucket") ||
		strings.Contains(kLower, "firebase_url") ||
		strings.Contains(kLower, "mobilesdk_app_id") ||
		strings.Contains(kLower, "client_type") ||
		strings.Contains(kLower, "package_name") {
		return true
	}

	// Google OAuth Client IDs for Android (ending in .apps.googleusercontent.com) are public client identifiers
	if strings.HasSuffix(vLower, ".apps.googleusercontent.com") {
		return true
	}

	// Android package names and permission names
	if strings.HasPrefix(vLower, "android.permission.") || strings.HasPrefix(vLower, "com.android.") || strings.HasPrefix(vLower, "androidx.") {
		return true
	}

	// Resource IDs, hex colors, placeholders
	if strings.HasPrefix(val, "@string/") || strings.HasPrefix(val, "@drawable/") || strings.HasPrefix(val, "@layout/") {
		return true
	}
	if strings.HasPrefix(val, "#") && (len(val) == 7 || len(val) == 9) {
		return true
	}
	if strings.HasPrefix(vLower, "todo") || strings.HasPrefix(vLower, "your_") || strings.HasPrefix(vLower, "example") {
		return true
	}

	return false
}

// isSensitiveAssignmentKey checks whether a configuration key denotes a secret or credential.
func isSensitiveAssignmentKey(k string) bool {
	kLower := strings.ToLower(k)
	sensitiveKeys := []string{
		"secret", "secret_key", "secretkey", "client_secret", "clientsecret",
		"api_key", "apikey", "api_token", "apitoken", "access_token", "accesstoken",
		"auth_token", "authtoken", "private_key", "privatekey",
		"password", "passwd", "db_password", "database_password",
		"aws_secret_access_key", "stripe_secret",
	}
	for _, sk := range sensitiveKeys {
		if kLower == sk || strings.HasSuffix(kLower, "."+sk) || strings.HasSuffix(kLower, "_"+sk) {
			return true
		}
	}
	return false
}

// AnalyzeArtifacts inspects Dalvik executables (DEX), embedded configurations, and resources for static security intelligence.
func AnalyzeArtifacts(ctx context.Context, ws *Workspace, limits Limits) (*ArtifactAnalysisResult, error) {
	if ws == nil || ws.Dir == "" {
		return nil, WrapError("analyze_artifacts", "workspace is nil or uninitialized", ErrInvalidInput)
	}

	targetPackage := resolveTargetPackage(ws, limits)

	result := &ArtifactAnalysisResult{
		DexFilesAnalyzed:     make([]string, 0),
		DexMetadata:          make([]DEXFile, 0),
		ConfigsAnalyzed:      make([]string, 0),
		Findings:             make([]report.Finding, 0),
		Limitations:          make([]string, 0),
		UnsupportedArtifacts: make([]string, 0),
	}

	// 1. Identify and Parse DEX Files
	dexFiles := ws.DexFiles
	if len(dexFiles) == 0 {
		dexFiles = discoverDEXFiles(ws)
	}

	var allDexStrings []string
	stringSourceMap := make(map[string][]string) // string -> list of dex file names

	for _, dexRel := range dexFiles {
		if err := ctx.Err(); err != nil {
			return nil, WrapError("analyze_artifacts", "context cancelled during DEX inspection", err)
		}

		dexBytes, err := readWorkspaceOrArchiveEntry(ws, dexRel, limits.MaxEntrySize)
		if err != nil {
			result.Limitations = append(result.Limitations, fmt.Sprintf("Failed reading DEX entry %q: %v", dexRel, err))
			result.UnsupportedArtifacts = append(result.UnsupportedArtifacts, dexRel)
			result.PartialAnalysis = true
			continue
		}

		dexFile, err := ParseDEX(ctx, dexRel, dexBytes, limits)
		if err != nil {
			result.Limitations = append(result.Limitations, fmt.Sprintf("DEX file %q could not be parsed: %v", dexRel, err))
			result.UnsupportedArtifacts = append(result.UnsupportedArtifacts, fmt.Sprintf("%s (%v)", dexRel, err))
			result.PartialAnalysis = true
			continue
		}

		result.DexFilesAnalyzed = append(result.DexFilesAnalyzed, dexRel)
		result.DexMetadata = append(result.DexMetadata, *dexFile)

		for _, s := range dexFile.Strings {
			if len(s) >= 4 {
				if _, exists := stringSourceMap[s]; !exists {
					allDexStrings = append(allDexStrings, s)
				}
				stringSourceMap[s] = append(stringSourceMap[s], dexRel)
			}
		}
	}

	// 2. Discover and Extract Embedded Resources & Configurations
	artifacts, configLimitations, err := DiscoverAndExtractArtifacts(ctx, ws, limits)
	if err != nil {
		result.Limitations = append(result.Limitations, fmt.Sprintf("Error extracting embedded resources: %v", err))
		result.PartialAnalysis = true
	}
	result.Limitations = append(result.Limitations, configLimitations...)

	for _, art := range artifacts {
		result.ConfigsAnalyzed = append(result.ConfigsAnalyzed, art.RelPath)
	}

	// 3. Collect and Analyze Static Intelligence Indicators
	findingsMap := make(map[string]report.Finding) // fingerprint -> Finding

	// A. Analyze DEX Strings
	for _, s := range allDexStrings {
		sources := stringSourceMap[s]
		origin := "classes.dex"
		if len(sources) > 0 {
			origin = sources[0]
		}

		inspectStringForIntelligence(s, origin, sources, targetPackage, findingsMap)
	}

	// B. Analyze Structured Artifacts (google-services.json, XML, properties, YAML, JS)
	for _, art := range artifacts {
		inspectArtifactForIntelligence(art, targetPackage, findingsMap)
	}

	// 4. Assemble Final Results and Summary
	for _, f := range findingsMap {
		result.Findings = append(result.Findings, f)
		switch {
		case strings.HasPrefix(f.RuleID, "APK-ART-SECRET-"):
			result.Summary.SecretsCount++
		case strings.HasPrefix(f.RuleID, "APK-ART-SERVICE-"):
			result.Summary.ServicesCount++
		case f.RuleID == "APK-ART-API-BASE-URL" || f.RuleID == "APK-ART-API-ENDPOINT":
			result.Summary.EndpointsCount++
		case f.RuleID == "APK-ART-GRAPHQL":
			result.Summary.GraphQLCount++
		}
	}
	result.FindingsCount = len(result.Findings)

	// Sort findings deterministically (by severity descending, then Title, then ID)
	sort.Slice(result.Findings, func(i, j int) bool {
		rI := severityRank(result.Findings[i].Severity)
		rJ := severityRank(result.Findings[j].Severity)
		if rI != rJ {
			return rI < rJ
		}
		if result.Findings[i].Title != result.Findings[j].Title {
			return result.Findings[i].Title < result.Findings[j].Title
		}
		return result.Findings[i].ID < result.Findings[j].ID
	})
	sort.Strings(result.ConfigsAnalyzed)

	return result, nil
}

func severityRank(s string) int {
	switch strings.ToUpper(s) {
	case report.SeverityCritical:
		return 1
	case report.SeverityHigh:
		return 2
	case report.SeverityMedium:
		return 3
	case report.SeverityLow:
		return 4
	default:
		return 5
	}
}

// inspectStringForIntelligence scans a single string token for secrets, endpoints, services, or GraphQL patterns.
func inspectStringForIntelligence(s string, origin string, sources []string, target string, out map[string]report.Finding) {
	// 1. AWS Access Key
	if match := awsAccessKeyRegex.FindString(s); match != "" {
		redactedVal := secrets.RedactSecret(match)
		obs := fmt.Sprintf("Discovered candidate AWS Access Key ID: %s in %s", redactedVal, origin)
		addFinding(out, buildArtifactFinding(
			"APK-ART-SECRET-AWS-KEY",
			"credential-exposure",
			"Discovered Candidate AWS Access Key ID",
			report.SeverityHigh,
			report.ConfidenceHigh,
			target,
			origin,
			"A static string matching the Amazon Web Services Access Key ID pattern (AKIA...) was identified in the application artifacts. Hardcoded cloud credentials in client APKs risk unauthorized infrastructure access.",
			obs,
			"Remove hardcoded AWS credentials from mobile code. Use AWS Cognito Identity Pools, STS temporary credentials, or backend API proxies with strict IAM role boundaries.",
			map[string]string{
				"file_origin":    origin,
				"sources":        strings.Join(sources, ", "),
				"redacted_value": redactedVal,
			},
			report.FindingStatusConfirmed,
		))
	}

	// 2. Google API Key
	if match := googleAPIKeyRegex.FindString(s); match != "" {
		redactedVal := secrets.RedactSecret(match)
		obs := fmt.Sprintf("Discovered candidate Google API Key: %s in %s", redactedVal, origin)
		addFinding(out, buildArtifactFinding(
			"APK-ART-SECRET-GOOGLE-KEY",
			"credential-exposure",
			"Discovered Candidate Google API Key",
			report.SeverityMedium,
			report.ConfidenceHigh,
			target,
			origin,
			"A static string matching the Google API Key format (AIza...) was discovered. In mobile applications, Google API keys are commonly embedded for Maps and Firebase client services, but must be restricted to package name and SHA-1 certificate fingerprints in the Google Cloud Console.",
			obs,
			"Verify Google Cloud Console API key restrictions: configure application restrictions (Android package name + SHA-1 signing fingerprint) and restrict API access to necessary services only.",
			map[string]string{
				"file_origin":    origin,
				"sources":        strings.Join(sources, ", "),
				"redacted_value": redactedVal,
			},
			report.FindingStatusConfirmed,
		))
	}

	// 3. Stripe Live Secret Key
	if match := stripeLiveKeyRegex.FindString(s); match != "" {
		redactedVal := secrets.RedactSecret(match)
		obs := fmt.Sprintf("Discovered candidate Stripe Live Secret Key: %s in %s", redactedVal, origin)
		addFinding(out, buildArtifactFinding(
			"APK-ART-SECRET-STRIPE",
			"credential-exposure",
			"Discovered Candidate Stripe Live Secret Key",
			report.SeverityCritical,
			report.ConfidenceHigh,
			target,
			origin,
			"A live secret key for Stripe (sk_live_... / rk_live_...) was identified in application bytecode. Embedding live merchant secret keys in distributed client applications allows unauthorized charge creation and financial API access.",
			obs,
			"Immediately revoke the exposed Stripe secret key in the Stripe Dashboard. Client mobile apps should exclusively use publishable keys (pk_live_...) and delegate payment processing to a trusted backend.",
			map[string]string{
				"file_origin":    origin,
				"sources":        strings.Join(sources, ", "),
				"redacted_value": redactedVal,
			},
			report.FindingStatusConfirmed,
		))
	}

	// 4. GitHub Personal Access Token
	if match := githubTokenRegex.FindString(s); match != "" {
		redactedVal := secrets.RedactSecret(match)
		obs := fmt.Sprintf("Discovered candidate GitHub Personal Access Token: %s in %s", redactedVal, origin)
		addFinding(out, buildArtifactFinding(
			"APK-ART-SECRET-GITHUB",
			"credential-exposure",
			"Discovered Candidate GitHub Access Token",
			report.SeverityHigh,
			report.ConfidenceHigh,
			target,
			origin,
			"A GitHub personal access token (ghp_... or github_pat_...) was identified in the application artifacts. Storing source control tokens in client applications risks unauthorized repository and CI/CD access.",
			obs,
			"Revoke the token immediately via GitHub settings and inspect access logs. Authenticate users via standard OAuth flows without embedding developer credentials in the APK.",
			map[string]string{
				"file_origin":    origin,
				"sources":        strings.Join(sources, ", "),
				"redacted_value": redactedVal,
			},
			report.FindingStatusConfirmed,
		))
	}

	// 5. Slack Bot Token
	if match := slackTokenRegex.FindString(s); match != "" {
		redactedVal := secrets.RedactSecret(match)
		obs := fmt.Sprintf("Discovered candidate Slack Bot Token: %s in %s", redactedVal, origin)
		addFinding(out, buildArtifactFinding(
			"APK-ART-SECRET-SLACK",
			"credential-exposure",
			"Discovered Candidate Slack Bot Token",
			report.SeverityHigh,
			report.ConfidenceHigh,
			target,
			origin,
			"A Slack bot token (xoxb-...) was identified in application artifacts. Embedded workspace tokens allow reading workspace conversations and sending unauthorized messages.",
			obs,
			"Revoke the Slack bot token in the Slack API dashboard. Transmit notifications through an authenticated server-side webhook rather than embedding bot tokens directly in client apps.",
			map[string]string{
				"file_origin":    origin,
				"sources":        strings.Join(sources, ", "),
				"redacted_value": redactedVal,
			},
			report.FindingStatusConfirmed,
		))
	}

	// 6. OpenAI Key
	if match := openaiKeyRegex.FindString(s); match != "" {
		redactedVal := secrets.RedactSecret(match)
		obs := fmt.Sprintf("Discovered candidate OpenAI API Key: %s in %s", redactedVal, origin)
		addFinding(out, buildArtifactFinding(
			"APK-ART-SECRET-OPENAI",
			"credential-exposure",
			"Discovered Candidate OpenAI API Key",
			report.SeverityHigh,
			report.ConfidenceHigh,
			target,
			origin,
			"An OpenAI API key (sk-...) was identified in application artifacts. Client-side OpenAI keys can be extracted and abused, leading to unauthorized API quota consumption.",
			obs,
			"Revoke the key in the OpenAI platform console. Route all AI model requests through an authenticated backend proxy that enforces user quotas and authorization.",
			map[string]string{
				"file_origin":    origin,
				"sources":        strings.Join(sources, ", "),
				"redacted_value": redactedVal,
			},
			report.FindingStatusConfirmed,
		))
	}

	// 7. Private Cryptographic Key
	if privateKeyRegex.MatchString(s) {
		obs := fmt.Sprintf("Discovered embedded private cryptographic key in %s", origin)
		addFinding(out, buildArtifactFinding(
			"APK-ART-SECRET-PRIVATE-KEY",
			"credential-exposure",
			"Discovered Embedded Private Cryptographic Key",
			report.SeverityCritical,
			report.ConfidenceHigh,
			target,
			origin,
			"A private cryptographic key (PEM block) was identified in application artifacts. Hardcoded private keys undermine TLS mutual authentication, digital signing, and data decryption security.",
			obs,
			"Generate unique cryptographic key pairs inside the Android Keystore system on the device, or store private keys exclusively on secure backend servers.",
			map[string]string{
				"file_origin": origin,
				"sources":     strings.Join(sources, ", "),
			},
			report.FindingStatusConfirmed,
		))
	}

	// 8. Database Connection URI with credentials
	if dbMatches := dbURIRegex.FindStringSubmatch(s); len(dbMatches) >= 5 {
		scheme := dbMatches[1]
		sanitizedURI := secrets.SanitizeURL(dbMatches[0])
		host := dbMatches[4]
		obs := fmt.Sprintf("Discovered database connection URI with embedded credentials: %s in %s", sanitizedURI, origin)

		addFinding(out, buildArtifactFinding(
			"APK-ART-SECRET-DB-URI",
			"credential-exposure",
			fmt.Sprintf("Discovered %s Connection URI with Embedded Credentials", strings.ToUpper(scheme)),
			report.SeverityCritical,
			report.ConfidenceHigh,
			target,
			origin,
			fmt.Sprintf("A database connection string (%s://) with embedded authentication credentials was discovered in application artifacts. Direct database connections from mobile clients expose backend data to full compromise.", scheme),
			obs,
			"Rotate the database credentials immediately. Never connect mobile applications directly to relational or NoSQL database servers; access data via authenticated REST/GraphQL API services.",
			map[string]string{
				"file_origin":    origin,
				"scheme":         scheme,
				"host":           host,
				"sanitized_uri":  sanitizedURI,
				"redacted_value": "[REDACTED_DATABASE_CREDENTIALS]",
			},
			report.FindingStatusConfirmed,
		))

		// Also record service indicator
		addServiceIndicator(scheme, host, sanitizedURI, origin, sources, target, out)
	} else if redisMatches := redisTokenURIRegex.FindStringSubmatch(s); len(redisMatches) >= 4 {
		sanitizedURI := secrets.SanitizeURL(redisMatches[0])
		host := redisMatches[3]
		obs := fmt.Sprintf("Discovered Redis connection URI with embedded auth token: %s in %s", sanitizedURI, origin)

		addFinding(out, buildArtifactFinding(
			"APK-ART-SECRET-DB-URI",
			"credential-exposure",
			"Discovered Redis Connection URI with Embedded Auth Token",
			report.SeverityCritical,
			report.ConfidenceHigh,
			target,
			origin,
			"A Redis connection URI containing an embedded authentication token was identified. Direct cache access from client applications exposes session data and cache infrastructure.",
			obs,
			"Rotate the Redis authorization token. Restrict Redis access to internal virtual networks and interface via backend application services.",
			map[string]string{
				"file_origin":    origin,
				"scheme":         "redis",
				"host":           host,
				"sanitized_uri":  sanitizedURI,
				"redacted_value": "[REDACTED_REDIS_TOKEN]",
			},
			report.FindingStatusConfirmed,
		))

		addServiceIndicator("redis", host, sanitizedURI, origin, sources, target, out)
	}

	// 9. Service Indicators (AWS, Firebase, MongoDB, Redis)
	if s3Match := awsS3BucketRegex.FindString(s); s3Match != "" {
		obs := fmt.Sprintf("Discovered AWS S3 bucket reference: %s in %s", s3Match, origin)
		addFinding(out, buildArtifactFinding(
			"APK-ART-SERVICE-AWS",
			"service-indicator",
			"Discovered AWS S3 Storage Bucket Indicator",
			report.SeverityInfo,
			report.ConfidenceHigh,
			target,
			origin,
			"An Amazon Web Services S3 storage bucket endpoint was identified in application artifacts. This is an informational service discovery finding; it does not indicate misconfiguration or unauthorized access.",
			obs,
			"Ensure S3 bucket access policies enforce Block Public Access unless public read is explicitly required for static public assets.",
			map[string]string{
				"service":     "AWS S3",
				"bucket_host": s3Match,
				"file_origin": origin,
			},
			report.FindingStatusConfirmed,
		))
	}

	if cognitoMatch := awsCognitoRegex.FindString(s); cognitoMatch != "" {
		obs := fmt.Sprintf("Discovered AWS Cognito identity reference: %s in %s", cognitoMatch, origin)
		addFinding(out, buildArtifactFinding(
			"APK-ART-SERVICE-AWS",
			"service-indicator",
			"Discovered AWS Cognito Service Indicator",
			report.SeverityInfo,
			report.ConfidenceHigh,
			target,
			origin,
			"An AWS Cognito user pool or identity pool endpoint was identified. This is an informational service indicator.",
			obs,
			"Ensure Cognito unauthenticated identity pool roles adhere to the principle of least privilege.",
			map[string]string{
				"service":      "AWS Cognito",
				"cognito_host": cognitoMatch,
				"file_origin":  origin,
			},
			report.FindingStatusConfirmed,
		))
	}

	if apiGwMatch := awsAPIGatewayRegex.FindString(s); apiGwMatch != "" {
		obs := fmt.Sprintf("Discovered AWS API Gateway endpoint: %s in %s", apiGwMatch, origin)
		addFinding(out, buildArtifactFinding(
			"APK-ART-SERVICE-AWS",
			"service-indicator",
			"Discovered AWS API Gateway Indicator",
			report.SeverityInfo,
			report.ConfidenceHigh,
			target,
			origin,
			"An AWS API Gateway endpoint was identified in application artifacts.",
			obs,
			"Ensure API Gateway routes validate authentication tokens and rate limits are configured.",
			map[string]string{
				"service":        "AWS API Gateway",
				"apigateway_host": apiGwMatch,
				"file_origin":    origin,
			},
			report.FindingStatusConfirmed,
		))
	}

	if fbMatch := firebaseHostRegex.FindString(s); fbMatch != "" {
		obs := fmt.Sprintf("Discovered Firebase Realtime Database reference: %s in %s", fbMatch, origin)
		addFinding(out, buildArtifactFinding(
			"APK-ART-SERVICE-FIREBASE",
			"service-indicator",
			"Discovered Firebase Service Indicator",
			report.SeverityInfo,
			report.ConfidenceHigh,
			target,
			origin,
			"A Firebase Realtime Database reference was identified in static artifacts. Public Firebase project identifiers identify the backend ecosystem and are not credentials.",
			obs,
			"Verify Firebase Realtime Database security rules to ensure unauthorized read/write is prevented.",
			map[string]string{
				"service":       "Firebase",
				"firebase_host": fbMatch,
				"file_origin":   origin,
			},
			report.FindingStatusConfirmed,
		))
	}

	// 10. API Base URLs & Endpoints
	if urlMatch := httpURLRegex.FindString(s); urlMatch != "" && !isBenignURL(urlMatch) {
		sanitizedURL := secrets.SanitizeURL(urlMatch)
		u, err := url.Parse(sanitizedURL)
		if err == nil && u.Host != "" {
			u.Fragment = "" // Strip fragments
			cleanBaseURL := u.Scheme + "://" + u.Host
			if u.Path != "" && u.Path != "/" {
				cleanBaseURL += u.Path
			}

			// Check for GraphQL endpoint
			if strings.Contains(strings.ToLower(u.Path), "graphql") {
				obs := fmt.Sprintf("Discovered GraphQL endpoint reference: %s in %s", sanitizedURL, origin)
				addFinding(out, buildArtifactFinding(
					"APK-ART-GRAPHQL",
					"api-endpoint",
					"Discovered GraphQL Endpoint Reference",
					report.SeverityInfo,
					report.ConfidenceHigh,
					target,
					origin,
					"A GraphQL API endpoint reference was identified in application artifacts.",
					obs,
					"Ensure GraphQL schemas disable introspection in production and apply field-level authorization and depth limits.",
					map[string]string{
						"endpoint_url": sanitizedURL,
						"file_origin":  origin,
					},
					report.FindingStatusConfirmed,
				))
			} else {
				obs := fmt.Sprintf("Discovered API Base URL: %s in %s", cleanBaseURL, origin)
				addFinding(out, buildArtifactFinding(
					"APK-ART-API-BASE-URL",
					"api-endpoint",
					"Discovered API Base URL Reference",
					report.SeverityInfo,
					report.ConfidenceHigh,
					target,
					origin,
					"An HTTP/HTTPS API base URL was identified in application artifacts. Identifying backend hosts assists in asset inventory and endpoint posture evaluation.",
					obs,
					"Ensure all communication is enforced over HTTPS with valid certificates.",
					map[string]string{
						"base_url":    cleanBaseURL,
						"file_origin": origin,
					},
					report.FindingStatusConfirmed,
				))
			}
		}
	}

	// 11. Versioned Route Paths (e.g. /api/v1/users)
	if versionedRouteRegex.MatchString(s) {
		obs := fmt.Sprintf("Discovered versioned API endpoint route: %s in %s", s, origin)
		addFinding(out, buildArtifactFinding(
			"APK-ART-API-ENDPOINT",
			"api-endpoint",
			fmt.Sprintf("Discovered Versioned API Route: %s", s),
			report.SeverityInfo,
			report.ConfidenceHigh,
			target,
			origin,
			"A versioned API path structure (/api/v... or /v...) was identified in application artifacts.",
			obs,
			"Ensure endpoints enforce authentication and access controls.",
			map[string]string{
				"route":       s,
				"file_origin": origin,
			},
			report.FindingStatusConfirmed,
		))
	}

	// 12. GraphQL Query Operation Strings and Path References
	if graphqlQueryRegex.MatchString(s) || s == "/graphql" || (strings.HasPrefix(s, "/") && strings.HasSuffix(strings.ToLower(s), "/graphql")) {
		obs := fmt.Sprintf("Discovered static GraphQL reference in %s: %s", origin, s)
		addFinding(out, buildArtifactFinding(
			"APK-ART-GRAPHQL",
			"api-endpoint",
			"Discovered Static GraphQL Reference",
			report.SeverityInfo,
			report.ConfidenceHigh,
			target,
			origin,
			"A static GraphQL query, endpoint path (/graphql), or operation definition was identified in application artifacts.",
			obs,
			"Ensure server-side GraphQL resolvers enforce strict field authorization.",
			map[string]string{
				"file_origin": origin,
				"reference":   s,
			},
			report.FindingStatusConfirmed,
		))
	}
}

// inspectArtifactForIntelligence analyzes structured configuration files (google-services.json, XML, properties, YAML, JS).
func inspectArtifactForIntelligence(art ExtractedArtifact, target string, out map[string]report.Finding) {
	origin := art.RelPath

	// 1. Google Services JSON
	if art.Type == "google-services" || path.Base(art.RelPath) == "google-services.json" {
		var cfg GoogleServicesConfig
		if err := json.Unmarshal(art.Content, &cfg); err == nil {
			// Record Firebase service indicator
			if cfg.ProjectInfo.ProjectID != "" {
				obs := fmt.Sprintf("Firebase project configured: project_id=%s, storage_bucket=%s",
					cfg.ProjectInfo.ProjectID, cfg.ProjectInfo.StorageBucket)
				addFinding(out, buildArtifactFinding(
					"APK-ART-SERVICE-FIREBASE",
					"service-indicator",
					"Discovered Firebase Backend Configuration",
					report.SeverityInfo,
					report.ConfidenceHigh,
					target,
					origin,
					"Firebase backend configuration was discovered in google-services.json. Public project identifiers identify the backend ecosystem and are not credentials.",
					obs,
					"Verify Firebase Realtime Database and Cloud Storage security rules.",
					map[string]string{
						"project_id":     cfg.ProjectInfo.ProjectID,
						"project_number": cfg.ProjectInfo.ProjectNumber,
						"storage_bucket": cfg.ProjectInfo.StorageBucket,
						"firebase_url":   cfg.ProjectInfo.FirebaseURL,
						"file_origin":    origin,
					},
					report.FindingStatusConfirmed,
				))
			}

			// Inspect Client API Keys
			for _, client := range cfg.Client {
				for _, k := range client.APIKey {
					if k.CurrentKey != "" {
						redactedKey := secrets.RedactSecret(k.CurrentKey)
						obs := fmt.Sprintf("Discovered Google API key in google-services.json: %s", redactedKey)
						addFinding(out, buildArtifactFinding(
							"APK-ART-SECRET-GOOGLE-KEY",
							"credential-exposure",
							"Discovered Google API Key in Configuration",
							report.SeverityMedium,
							report.ConfidenceHigh,
							target,
							origin,
							"A Google API Key was extracted from google-services.json. While standard for Android client setup, keys must be restricted in the Google Cloud Console to the package name and signing certificate fingerprint.",
							obs,
							"Configure Google Cloud API key restrictions for the app package name and SHA-1 certificate fingerprint.",
							map[string]string{
								"file_origin":    origin,
								"redacted_value": redactedKey,
							},
							report.FindingStatusConfirmed,
						))
					}
				}
			}
		}
	}

	// 2. Key-Value Analysis (Properties, INI, YAML, Strings.xml, JSON)
	for k, v := range art.KeyValue {
		// Check for public identifiers first
		if isPublicConfigurationIdentifier(k, v) {
			continue
		}

		// Check for sensitive assignments
		if isSensitiveAssignmentKey(k) {
			// Calculate entropy to filter out placeholders or simple text
			ent := secrets.ShannonEntropy(v)
			if len(v) >= 16 && ent >= 3.5 {
				redactedVal := secrets.RedactText(v)
				obs := fmt.Sprintf("Discovered candidate credential in config: key=%s value=%s in %s", k, redactedVal, origin)
				addFinding(out, buildArtifactFinding(
					"APK-ART-SECRET-GENERIC",
					"credential-exposure",
					fmt.Sprintf("Discovered High-Entropy Secret in %s: %s", path.Base(origin), k),
					report.SeverityMedium,
					report.ConfidenceMedium,
					target,
					origin,
					fmt.Sprintf("A high-entropy candidate secret (%s) was identified in %s configuration. Client-accessible secrets can be extracted by static reverse engineering.", k, origin),
					obs,
					"Remove configuration secrets from distributed client APKs. Delegate privileged API calls to a trusted backend service.",
					map[string]string{
						"file_origin":    origin,
						"config_key":     k,
						"redacted_value": redactedVal,
						"entropy":        fmt.Sprintf("%.2f", ent),
					},
					report.FindingStatusConfirmed,
				))
			}
		}

		// Also scan value as standalone string for other indicators
		inspectStringForIntelligence(v, origin, []string{origin}, target, out)
	}

	// 3. Scan Raw Content for Text/Bundle/JS Files
	if art.Type == "javascript" || art.Type == "text" {
		contentStr := string(art.Content)
		// Extract URLs from bundle
		for _, urlMatch := range httpURLRegex.FindAllString(contentStr, -1) {
			inspectStringForIntelligence(urlMatch, origin, []string{origin}, target, out)
		}
		// Extract API Keys from bundle
		for _, akMatch := range awsAccessKeyRegex.FindAllString(contentStr, -1) {
			inspectStringForIntelligence(akMatch, origin, []string{origin}, target, out)
		}
		for _, gkMatch := range googleAPIKeyRegex.FindAllString(contentStr, -1) {
			inspectStringForIntelligence(gkMatch, origin, []string{origin}, target, out)
		}
		for _, stMatch := range stripeLiveKeyRegex.FindAllString(contentStr, -1) {
			inspectStringForIntelligence(stMatch, origin, []string{origin}, target, out)
		}
		for _, ghMatch := range githubTokenRegex.FindAllString(contentStr, -1) {
			inspectStringForIntelligence(ghMatch, origin, []string{origin}, target, out)
		}
		for _, slMatch := range slackTokenRegex.FindAllString(contentStr, -1) {
			inspectStringForIntelligence(slMatch, origin, []string{origin}, target, out)
		}
		for _, oaMatch := range openaiKeyRegex.FindAllString(contentStr, -1) {
			inspectStringForIntelligence(oaMatch, origin, []string{origin}, target, out)
		}
		for _, dbMatch := range dbURIRegex.FindAllString(contentStr, -1) {
			inspectStringForIntelligence(dbMatch, origin, []string{origin}, target, out)
		}
	}
}

// addServiceIndicator records a database or cache service indicator.
func addServiceIndicator(scheme, host, sanitizedURI, origin string, sources []string, target string, out map[string]report.Finding) {
	ruleID := "APK-ART-SERVICE-DB"
	title := fmt.Sprintf("Discovered %s Service Indicator", strings.ToUpper(scheme))
	desc := fmt.Sprintf("A %s database service endpoint was identified in application artifacts.", scheme)

	if strings.HasPrefix(strings.ToLower(scheme), "mongo") {
		ruleID = "APK-ART-SERVICE-MONGODB"
		title = "Discovered MongoDB Service Indicator"
		desc = "A MongoDB connection URI or host reference was identified in application artifacts. This is an informational service discovery finding."
	} else if strings.HasPrefix(strings.ToLower(scheme), "redis") {
		ruleID = "APK-ART-SERVICE-REDIS"
		title = "Discovered Redis Service Indicator"
		desc = "A Redis host endpoint reference was identified in application artifacts. This is an informational service discovery finding."
	}

	obs := fmt.Sprintf("Discovered %s service endpoint: host=%s in %s", scheme, host, origin)
	addFinding(out, buildArtifactFinding(
		ruleID,
		"service-indicator",
		title,
		report.SeverityInfo,
		report.ConfidenceHigh,
		target,
		origin,
		desc,
		obs,
		"Ensure database instances are not exposed directly to public internet traffic without firewall and network ACL boundaries.",
		map[string]string{
			"scheme":        scheme,
			"host":          host,
			"sanitized_uri": sanitizedURI,
			"file_origin":   origin,
			"sources":       strings.Join(sources, ", "),
		},
		report.FindingStatusConfirmed,
	))
}

// addFinding inserts or merges a finding into out by fingerprint.
func addFinding(out map[string]report.Finding, f report.Finding) {
	if existing, exists := out[f.Fingerprint]; exists {
		// If already present, merge location provenance
		origLoc := existing.EvidenceDetails.Details["file_origin"]
		newLoc := f.EvidenceDetails.Details["file_origin"]
		if origLoc != "" && newLoc != "" && !strings.Contains(origLoc, newLoc) {
			existing.EvidenceDetails.Details["additional_locations"] = origLoc + ", " + newLoc
			out[f.Fingerprint] = existing
		}
		return
	}
	out[f.Fingerprint] = f
}

// buildArtifactFinding formats a normalized, evidence-backed report.Finding adhering to FELIX conventions.
func buildArtifactFinding(
	ruleID string,
	category string,
	title string,
	severity string,
	confidence string,
	target string,
	endpoint string,
	description string,
	observation string,
	remediation string,
	details map[string]string,
	status report.FindingStatus,
) report.Finding {
	// Ensure all fields and detail values are strictly redacted before serialization
	cleanObs := secrets.RedactText(observation)
	cleanTitle := secrets.RedactText(title)
	cleanDesc := secrets.RedactText(description)
	cleanRemediation := secrets.RedactText(remediation)
	cleanEndpoint := secrets.SanitizeURL(endpoint)
	cleanTarget := secrets.RedactText(target)

	cleanDetails := make(map[string]string, len(details))
	for k, v := range details {
		cleanDetails[k] = secrets.RedactText(v)
	}

	hasher := sha256.New()
	hasher.Write([]byte(ruleID))
	hasher.Write([]byte(category))
	hasher.Write([]byte(cleanTitle))
	hasher.Write([]byte(cleanEndpoint))
	hasher.Write([]byte(cleanObs))
	hashHex := hex.EncodeToString(hasher.Sum(nil))[:12]

	id := fmt.Sprintf("apk-art-%s-%s", strings.ToLower(ruleID), hashHex)

	return report.Finding{
		ID:                    id,
		RuleID:                ruleID,
		Status:                status,
		ClassificationOutcome: report.OutcomeConfirmed,
		AnalysisMethod:        report.AnalysisMethodStatic,
		Category:              category,
		Title:                 cleanTitle,
		Severity:              severity,
		Confidence:            confidence,
		Target:                cleanTarget,
		Endpoint:              cleanEndpoint,
		Method:                "STATIC_ANALYSIS",
		Description:           cleanDesc,
		Evidence:              cleanObs,
		EvidenceDetails: report.EvidenceDetails{
			Observation:     cleanObs,
			Location:        cleanEndpoint,
			DetectionMethod: "static_artifact_intelligence",
			Details:         cleanDetails,
		},
		Remediation: cleanRemediation,
		RemediationAdvice: &report.RemediationAdvice{
			Summary: cleanRemediation,
		},
		Source:      "apk",
		Fingerprint: hashHex,
		Score:       report.SeverityRank(severity) * 20,
		Timestamp:   time.Now().UTC(),
	}
}

// resolveTargetPackage retrieves the Android application package name from the workspace manifest if available.
func resolveTargetPackage(ws *Workspace, limits Limits) string {
	if ws == nil {
		return "android.application"
	}
	if ws.ManifestPath != "" {
		targetManifestPath, err := VerifyExtractionTarget(ws.Dir, ws.ManifestPath)
		if err == nil {
			data, err := os.ReadFile(targetManifestPath)
			if err == nil && len(data) > 0 {
				format := DetectManifestFormat(data)
				var rawRoot *RawElement
				var err error
				if format == FormatAXML {
					rawRoot, err = ParseAXML(data, limits)
				} else if format == FormatXML {
					rawRoot, err = ParseTextualManifest(data, limits)
				}
				if err == nil && rawRoot != nil {
					doc := ExtractManifestDocument(rawRoot, format)
					if doc != nil && doc.PackageName != "" {
						return doc.PackageName
					}
				}
			}
		}
	}

	if ws.APKPath != "" {
		base := filepath.Base(ws.APKPath)
		return strings.TrimSuffix(base, filepath.Ext(base))
	}
	return "android.application"
}

// discoverDEXFiles finds all .dex file entries in the workspace or archive.
func discoverDEXFiles(ws *Workspace) []string {
	var results []string
	if ws == nil {
		return results
	}

	// Check ws.Dir
	_ = filepath.Walk(ws.Dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi == nil || fi.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(fi.Name()), ".dex") {
			rel, rErr := filepath.Rel(ws.Dir, p)
			if rErr == nil {
				results = append(results, filepath.ToSlash(rel))
			}
		}
		return nil
	})

	if len(results) > 0 {
		sort.Strings(results)
		return results
	}

	// Fallback to reading central directory from ws.APKPath
	if ws.APKPath != "" {
		f, err := os.Open(ws.APKPath)
		if err == nil {
			defer f.Close()
			fi, err := f.Stat()
			if err == nil {
				zr, err := zip.NewReader(f, fi.Size())
				if err == nil {
					for _, entry := range zr.File {
						if strings.HasSuffix(strings.ToLower(entry.Name), ".dex") {
							results = append(results, entry.Name)
						}
					}
				}
			}
		}
	}

	sort.Strings(results)
	return results
}

// readWorkspaceOrArchiveEntry reads the content of an entry from ws.Dir or streams it from ws.APKPath.
func readWorkspaceOrArchiveEntry(ws *Workspace, relPath string, maxSize int64) ([]byte, error) {
	if ws == nil {
		return nil, ErrInvalidInput
	}

	targetPath, err := VerifyExtractionTarget(ws.Dir, relPath)
	if err == nil {
		fi, err := os.Stat(targetPath)
		if err == nil && !fi.IsDir() {
			if fi.Size() > maxSize {
				return nil, fmt.Errorf("%w: file %q size %d exceeds limit %d", ErrLimitExceeded, relPath, fi.Size(), maxSize)
			}
			return os.ReadFile(targetPath)
		}
	}

	// Read from archive if not present on disk
	if ws.APKPath != "" {
		f, err := os.Open(ws.APKPath)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		fi, err := f.Stat()
		if err != nil {
			return nil, err
		}

		zr, err := zip.NewReader(f, fi.Size())
		if err != nil {
			return nil, err
		}

		for _, entry := range zr.File {
			if entry.Name == relPath {
				if int64(entry.UncompressedSize64) > maxSize {
					return nil, fmt.Errorf("%w: entry %q size %d exceeds limit %d", ErrLimitExceeded, relPath, entry.UncompressedSize64, maxSize)
				}
				er, err := entry.Open()
				if err != nil {
					return nil, err
				}
				defer er.Close()
				return io.ReadAll(io.LimitReader(er, maxSize+1))
			}
		}
	}

	return nil, os.ErrNotExist
}
