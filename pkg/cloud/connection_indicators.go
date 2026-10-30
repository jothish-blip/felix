package cloud

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"felix/pkg/crawler"
	"felix/pkg/secrets"
)

// IndicatorType categorizes the syntactic form of a detected connection indicator.
type IndicatorType string

const (
	IndicatorTypeConnectionString     IndicatorType = "CONNECTION_STRING"
	IndicatorTypeEndpointReference    IndicatorType = "ENDPOINT_REFERENCE"
	IndicatorTypeCredentialAssignment IndicatorType = "CREDENTIAL_ASSIGNMENT"
	IndicatorTypeConfigDatasource     IndicatorType = "CONFIG_DATASOURCE"
)

// SourceType defines the origin medium of an indicator.
type SourceType string

const (
	SourceTypeConfigFile          SourceType = "config_file"
	SourceTypeEnvironmentVariable SourceType = "environment_variable"
	SourceTypeCodeArtifact        SourceType = "code_artifact"
	SourceTypeAssessmentInput     SourceType = "assessment_input"
	SourceTypeUnknown             SourceType = "unknown"
)

// IndicatorSource captures the source location, line attribution, and sanitized context.
type IndicatorSource struct {
	Type        SourceType `json:"type"`
	Identifier  string     `json:"identifier"`            // e.g. .env, database.yml, DATABASE_URL, index.js
	LineNumber  int        `json:"line_number,omitempty"` // 1-based line number (0 if unknown or non-text)
	ContextLine string     `json:"context_line,omitempty"` // Redacted snippet of the matching line
}

// ConnectionIndicator records a detected database, cloud storage, or backend service reference.
// It adheres to strict classification semantics:
// Indicator detected != Service detected != Authentication observed != Access verified != Exposure confirmed.
type ConnectionIndicator struct {
	Technology         ServiceTechnology `json:"technology"`
	Family             ServiceFamily     `json:"family"`
	Type               IndicatorType     `json:"type"`
	SanitizedValue     string            `json:"sanitized_value"`     // Fully scrubbed connection string / reference
	Endpoint           string            `json:"endpoint"`            // Normalized endpoint (e.g. host:port or URL)
	Host               string            `json:"host,omitempty"`
	Port               int               `json:"port,omitempty"`
	Protocol           string            `json:"protocol,omitempty"` // tcp, http, https
	Database           string            `json:"database,omitempty"` // database or bucket name if parsed
	HasCredentials     bool              `json:"has_credentials"`
	CredentialUsername string            `json:"credential_username,omitempty"` // Benign username or [REDACTED]
	RedactedFields     []string          `json:"redacted_fields,omitempty"`     // Names of fields scrubbed
	Source             IndicatorSource   `json:"source"`
	Fingerprint        string            `json:"fingerprint"`
	DetectedAt         time.Time         `json:"detected_at"`
}

// Maximum limits for safe bounded scanning to prevent unbounded memory growth and ReDoS.
const (
	MaxScanInputBytes   = 5 * 1024 * 1024 // 5 MB per asset
	MaxIndicatorsPerFile = 1000
	MaxLineScanLength   = 8192
)

var (
	// Standard database URI scheme pre-filters
	uriSchemeRegex = regexp.MustCompile(`(?i)\b(jdbc:)?(postgres|postgresql|mongodb|mongodb\+srv|redis|rediss|mysql)://[^\s"'` + "`" + `<>]+`)

	// Go MySQL DSN pattern: [user[:password]@][tcp[(host:port)]]/dbname[?options]
	mysqlDSNRegex = regexp.MustCompile(`(?i)(?:["'` + "`" + `=:\s]|^)([a-zA-Z0-9_\-\.\%]+(?::[^\r\n@\s"'` + "`" + `]*)?@(?:tcp\([a-zA-Z0-9_\.\-]+:\d+\)|unix\([^\)]+\)|)/[a-zA-Z0-9_\.\-]+(?:\?[^\s"'` + "`" + `\r\n]*)?)`)

	// Azure Blob Storage connection strings
	azureConnStringRegex = regexp.MustCompile(`(?i)\b(DefaultEndpointsProtocol=(?:https|http);(?:[^\s;"'` + "`" + `]+;)*AccountName=([a-zA-Z0-9]+);(?:[^\s;"'` + "`" + `]+;)*AccountKey=([^;\s"'` + "`" + `]+)(?:;[^\s"'` + "`" + `]+)*)`)

	// Azure Blob Storage endpoints (including container path and optional SAS query parameters)
	azureBlobEndpointRegex = regexp.MustCompile(`(?i)https://([a-zA-Z0-9_\-]+)\.blob\.core\.windows\.net(/[^\s"'` + "`" + `<>]*)?`)

	// AWS S3 URI and endpoint references
	s3URIRegex  = regexp.MustCompile(`(?i)\bs3://([a-zA-Z0-9_\.\-]+)(?:/([^\s"'` + "`" + `]*))?`)
	s3HTTPRegex = regexp.MustCompile(`(?i)https?://([a-zA-Z0-9_\.\-]+)\.s3(?:[.-][a-zA-Z0-9_\-]+)?\.amazonaws\.com(?:/([^\s"'` + "`" + `]*))?`)
	s3PathHTTPRegex = regexp.MustCompile(`(?i)https?://s3(?:[.-][a-zA-Z0-9_\-]+)?\.amazonaws\.com/([a-zA-Z0-9_\.\-]+)(?:/([^\s"'` + "`" + `]*))?`)

	// Google Cloud Storage URI and endpoint references
	gcsURIRegex  = regexp.MustCompile(`(?i)\bgs://([a-zA-Z0-9_\.\-]+)(?:/([^\s"'` + "`" + `]*))?`)
	gcsHTTPRegex = regexp.MustCompile(`(?i)https?://storage\.googleapis\.com/([a-zA-Z0-9_\.\-]+)(?:/([^\s"'` + "`" + `]*))?`)
	gcsSubHTTPRegex = regexp.MustCompile(`(?i)https?://([a-zA-Z0-9_\.\-]+)\.storage\.googleapis\.com(?:/([^\s"'` + "`" + `]*))?`)

	// MinIO endpoint references (default port 9000 API, 9001 console, or minio hostname)
	minioEndpointRegex = regexp.MustCompile(`(?i)https?://([a-zA-Z0-9_\.\-]+):(9000|9001)\b`)

	// Firebase RTDB endpoints (including path and optional auth token query parameter)
	firebaseRTDBRegex = regexp.MustCompile(`(?i)https://([a-zA-Z0-9_\-]+)\.firebaseio\.com(/[^\s"'` + "`" + `<>]*)?`)
	firebaseAppRTDBRegex = regexp.MustCompile(`(?i)https://([a-zA-Z0-9_\-]+(?:-default-rtdb)?(?:\.[a-zA-Z0-9_\-]+)?\.firebasedatabase\.app)(/[^\s"'` + "`" + `<>]*)?`)

	// Firestore endpoint references
	firestoreEndpointRegex = regexp.MustCompile(`(?i)https://firestore\.googleapis\.com/v1/projects/([a-zA-Z0-9_\-]+)/databases/\(default\)/documents`)

	// Supabase endpoints
	supabaseHostRegex = regexp.MustCompile(`(?i)https://([a-zA-Z0-9_\-]+)\.supabase\.(?:co|in)`)
	supabasePostgresHostRegex = regexp.MustCompile(`(?i)db\.([a-zA-Z0-9_\-]+)\.supabase\.(?:co|in)`)

	// Hasura GraphQL endpoints
	hasuraEndpointRegex = regexp.MustCompile(`(?i)https?://([a-zA-Z0-9_\.\-]+(?::\d+)?)/v1(?:alpha1)?/graphql`)

	// Prisma schema datasource block
	prismaDatasourceBlockRegex = regexp.MustCompile(`(?s)datasource\s+([a-zA-Z0-9_]+)\s*\{([^}]+)\}`)
	prismaProviderRegex        = regexp.MustCompile(`(?i)provider\s*=\s*["']([a-zA-Z0-9_\-]+)["']`)
	prismaURLRegex             = regexp.MustCompile(`(?i)url\s*=\s*(?:env\(["']([a-zA-Z0-9_]+)["']\)|["']([^"']+)["'])`)

	// Sensitive environment variable assignments mapping to the 16 target services
	envAssignRegex = regexp.MustCompile(`(?i)(?:^|\b)(?:export\s+)?([a-zA-Z0-9_]+)\s*=\s*(?:(")([^"\r\n]*)"|(')([^'\r\n]*)'|(\x60)([^\x60\r\n]*)\x60|([^#\s\r\n]+))`)
)

// GenerateIndicatorFingerprint produces a deterministic SHA-256 fingerprint for deduplication.
// It intentionally never consumes raw credentials or tokens.
func GenerateIndicatorFingerprint(tech ServiceTechnology, indType IndicatorType, sanitizedVal, sourceID string, line int) string {
	h := sha256.New()
	cleanTech := strings.ToLower(strings.TrimSpace(string(tech)))
	cleanType := strings.ToLower(strings.TrimSpace(string(indType)))
	cleanVal := strings.ToLower(strings.TrimSpace(sanitizedVal))
	cleanSrc := strings.ToLower(strings.TrimSpace(sourceID))
	fmt.Fprintf(h, "%s:%s:%s:%s:%d", cleanTech, cleanType, cleanVal, cleanSrc, line)
	return hex.EncodeToString(h.Sum(nil))
}

// DetermineSourceType determines the SourceType based on file name or variable naming convention.
func DetermineSourceType(identifier string) SourceType {
	clean := strings.ToLower(strings.TrimSpace(identifier))
	if clean == "" {
		return SourceTypeUnknown
	}

	// Environment variable name convention (all caps with underscores)
	if isEnvVarName(identifier) {
		return SourceTypeEnvironmentVariable
	}

	// URL assessment target
	if strings.HasPrefix(clean, "http://") || strings.HasPrefix(clean, "https://") {
		return SourceTypeAssessmentInput
	}

	// Config file extensions
	if strings.HasPrefix(clean, ".env") ||
		strings.HasSuffix(clean, ".env") ||
		strings.Contains(clean, ".env.") ||
		strings.HasSuffix(clean, ".yml") ||
		strings.HasSuffix(clean, ".yaml") ||
		strings.HasSuffix(clean, ".json") ||
		strings.HasSuffix(clean, ".toml") ||
		strings.HasSuffix(clean, ".ini") ||
		strings.HasSuffix(clean, ".conf") ||
		strings.HasSuffix(clean, ".cfg") ||
		strings.HasSuffix(clean, ".properties") ||
		strings.HasSuffix(clean, "docker-compose.yml") ||
		strings.HasSuffix(clean, "docker-compose.yaml") {
		return SourceTypeConfigFile
	}

	// Code artifact extensions
	if strings.HasSuffix(clean, ".js") ||
		strings.HasSuffix(clean, ".ts") ||
		strings.HasSuffix(clean, ".jsx") ||
		strings.HasSuffix(clean, ".tsx") ||
		strings.HasSuffix(clean, ".go") ||
		strings.HasSuffix(clean, ".py") ||
		strings.HasSuffix(clean, ".rb") ||
		strings.HasSuffix(clean, ".php") ||
		strings.HasSuffix(clean, ".java") ||
		strings.HasSuffix(clean, ".cs") ||
		strings.HasSuffix(clean, ".html") ||
		strings.HasSuffix(clean, ".htm") ||
		strings.HasSuffix(clean, ".vue") ||
		strings.HasSuffix(clean, ".svelte") ||
		strings.HasSuffix(clean, ".prisma") {
		return SourceTypeCodeArtifact
	}

	return SourceTypeUnknown
}

func isEnvVarName(s string) bool {
	if len(s) < 2 {
		return false
	}
	hasUpper := false
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			if r >= 'A' && r <= 'Z' {
				hasUpper = true
			}
			continue
		}
		return false
	}
	return hasUpper
}

// IndicatorDetector coordinates scanning, structural parsing, and safe redaction across all 16 target services.
type IndicatorDetector struct {
	mu sync.RWMutex
}

// NewIndicatorDetector creates a new connection indicator detector.
func NewIndicatorDetector() *IndicatorDetector {
	return &IndicatorDetector{}
}

// DetectIndicatorsFromAssets scans crawled assets and extracts unique connection indicators.
func (d *IndicatorDetector) DetectIndicatorsFromAssets(assets []crawler.Asset) []ConnectionIndicator {
	var all []ConnectionIndicator
	seen := make(map[string]struct{})

	for _, a := range assets {
		if len(a.Content) == 0 {
			continue
		}
		srcType := DetermineSourceType(a.URL)
		source := IndicatorSource{
			Type:       srcType,
			Identifier: a.URL,
		}
		findings := d.DetectIndicators(source, a.Content)
		for _, f := range findings {
			if _, exists := seen[f.Fingerprint]; !exists {
				seen[f.Fingerprint] = struct{}{}
				all = append(all, f)
			}
		}
	}
	return all
}

// DetectIndicators scans arbitrary content (text, files, env dumps) attributing to the given source.
func (d *IndicatorDetector) DetectIndicators(source IndicatorSource, content []byte) []ConnectionIndicator {
	if len(content) == 0 {
		return nil
	}

	// Bounded input enforcement
	scanContent := content
	if len(scanContent) > MaxScanInputBytes {
		scanContent = scanContent[:MaxScanInputBytes]
	}

	if source.Type == "" || source.Type == SourceTypeUnknown {
		source.Type = DetermineSourceType(source.Identifier)
	}

	var results []ConnectionIndicator
	seen := make(map[string]struct{})

	addIndicator := func(ci ConnectionIndicator, rawLine string) {
		if len(results) >= MaxIndicatorsPerFile {
			return
		}
		if ci.Source.ContextLine == "" && rawLine != "" {
			ci.Source.ContextLine = secrets.RedactText(strings.TrimSpace(rawLine))
		}
		if ci.Fingerprint == "" {
			ci.Fingerprint = GenerateIndicatorFingerprint(ci.Technology, ci.Type, ci.SanitizedValue, ci.Source.Identifier, ci.Source.LineNumber)
		}
		if _, exists := seen[ci.Fingerprint]; !exists {
			seen[ci.Fingerprint] = struct{}{}
			results = append(results, ci)
		}
	}

	// 1. Prisma schema block scanning (multiline config)
	if bytes.Contains(scanContent, []byte("datasource ")) {
		for _, ind := range d.scanPrismaBlocks(source, scanContent) {
			addIndicator(ind, "")
		}
	}

	// 2. Line-by-line scanning with line attribution and context redaction
	scanner := bufio.NewScanner(bytes.NewReader(scanContent))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		lineBytes := scanner.Bytes()
		if len(lineBytes) > MaxLineScanLength {
			lineBytes = lineBytes[:MaxLineScanLength]
		}
		trimmed := bytes.TrimSpace(lineBytes)
		if len(trimmed) == 0 || bytes.HasPrefix(trimmed, []byte("//")) || (bytes.HasPrefix(trimmed, []byte("#")) && !bytes.Contains(trimmed, []byte("="))) {
			// Skip pure comment lines unless they look like commented assignments
			continue
		}

		hasColon := bytes.IndexByte(lineBytes, ':') != -1
		hasAt := bytes.IndexByte(lineBytes, '@') != -1
		hasEqual := bytes.IndexByte(lineBytes, '=') != -1
		hasScheme := bytes.Contains(lineBytes, []byte("://"))

		// Fast reject: skip lines that cannot possibly contain any connection indicator
		if !hasColon && !hasAt && !hasEqual && !bytes.Contains(lineBytes, []byte("s3://")) && !bytes.Contains(lineBytes, []byte("gs://")) {
			continue
		}

		line := string(lineBytes)

		lineSource := source
		lineSource.LineNumber = lineNum

		// A. Standard URIs (postgres, mongo, redis, mysql, etc.)
		if hasScheme {
			for _, ind := range d.scanURIs(lineSource, line) {
				addIndicator(ind, line)
			}
		}

		// B. MySQL Go DSNs: requires @ and (tcp( or unix( or /)
		if hasAt && (strings.Contains(line, "tcp(") || strings.Contains(line, "unix(") || strings.Contains(line, "@/")) {
			for _, ind := range d.scanMySQLDSN(lineSource, line) {
				addIndicator(ind, line)
			}
		}

		// C. Azure Connection Strings & Endpoints
		if strings.Contains(line, "DefaultEndpointsProtocol") || strings.Contains(line, ".blob.core.windows.net") {
			for _, ind := range d.scanAzureIndicators(lineSource, line) {
				addIndicator(ind, line)
			}
		}

		// D. Cloud Storage Indicators (S3, GCS, MinIO)
		if strings.Contains(line, "s3://") || strings.Contains(line, ".s3.") || strings.Contains(line, "s3.amazonaws.com") ||
			strings.Contains(line, "gs://") || strings.Contains(line, "storage.googleapis.com") ||
			(hasColon && strings.Contains(strings.ToLower(line), "minio")) {
			for _, ind := range d.scanStorageIndicators(lineSource, line) {
				addIndicator(ind, line)
			}
		}

		// E. Firebase & Firestore Indicators
		if strings.Contains(line, "firebaseio.com") || strings.Contains(line, "firebasedatabase.app") || strings.Contains(line, "firestore.googleapis.com") {
			for _, ind := range d.scanFirebaseIndicators(lineSource, line) {
				addIndicator(ind, line)
			}
		}

		// F. Backend & Admin Indicators (Supabase, PostgREST, Hasura, Mongo Express, Elasticsearch)
		if strings.Contains(line, "supabase.co") || strings.Contains(line, "supabase.in") ||
			strings.Contains(line, "/graphql") ||
			strings.Contains(line, "mongo-express") || strings.Contains(line, "me_config") ||
			strings.Contains(line, ":9200") {
			for _, ind := range d.scanBackendAndAdminIndicators(lineSource, line) {
				addIndicator(ind, line)
			}
		}

		// G. Environment Variable Assignments
		if hasEqual && d.lineMightContainEnv(line) {
			for _, ind := range d.scanEnvAssignments(lineSource, line) {
				addIndicator(ind, line)
			}
		}
	}

	return results
}

// scanURIs extracts and structurally parses standard connection URIs.
func (d *IndicatorDetector) scanURIs(source IndicatorSource, line string) []ConnectionIndicator {
	var indicators []ConnectionIndicator

	matches := uriSchemeRegex.FindAllString(line, -1)
	for _, raw := range matches {
		clean := strings.Trim(raw, "\"'`(),; \t\r\n")
		ci, ok := d.parseStandardURI(source, clean)
		if ok {
			if ci.HasCredentials && ci.Source.ContextLine == "" {
				ci.Source.ContextLine = secrets.RedactText(strings.Replace(line, clean, ci.SanitizedValue, 1))
			}
			indicators = append(indicators, ci)
		}
	}

	return indicators
}

// parseStandardURI structurally parses and sanitizes a standard URI string.
func (d *IndicatorDetector) parseStandardURI(source IndicatorSource, raw string) (ConnectionIndicator, bool) {
	isJDBC := false
	workURL := raw
	if strings.HasPrefix(strings.ToLower(workURL), "jdbc:") {
		isJDBC = true
		workURL = workURL[5:]
	}

	u, err := url.Parse(workURL)
	if err != nil || u.Host == "" {
		// Fallback for malformed or truncated URIs (e.g. invalid host characters or bracket syntax)
		schemeIdx := strings.Index(workURL, "://")
		if schemeIdx == -1 {
			return ConnectionIndicator{}, false
		}
		var (
			tech        ServiceTechnology
			family      ServiceFamily
			defaultPort int
		)
		schemeStr := strings.ToLower(workURL[:schemeIdx])
		switch schemeStr {
		case "postgres", "postgresql":
			tech = TechPostgreSQL
			family = FamilyDirectDatabase
			defaultPort = 5432
			if strings.Contains(strings.ToLower(workURL), "supabase.co") || strings.Contains(strings.ToLower(workURL), "supabase.in") {
				tech = TechSupabase
				family = FamilyBackendInterface
			}
		case "mongodb", "mongodb+srv":
			tech = TechMongoDB
			family = FamilyDirectDatabase
			defaultPort = 27017
		case "redis", "rediss":
			tech = TechRedis
			family = FamilyDirectDatabase
			defaultPort = 6379
		case "mysql":
			tech = TechMySQL
			family = FamilyDirectDatabase
			defaultPort = 3306
		default:
			return ConnectionIndicator{}, false
		}

		sanitized := secrets.SanitizeURL(workURL)
		if isJDBC {
			sanitized = "jdbc:" + sanitized
		}
		hasCreds := strings.Contains(sanitized, "[REDACTED]")

		src := source
		if hasCreds {
			src.ContextLine = secrets.RedactText(strings.Replace(source.ContextLine, raw, sanitized, 1))
		}

		return ConnectionIndicator{
			Technology:     tech,
			Family:         family,
			Type:           IndicatorTypeConnectionString,
			SanitizedValue: sanitized,
			Endpoint:       sanitized,
			Port:           defaultPort,
			Protocol:       "tcp",
			HasCredentials: hasCreds,
			Source:         src,
			Fingerprint:    GenerateIndicatorFingerprint(tech, IndicatorTypeConnectionString, sanitized, source.Identifier, source.LineNumber),
			DetectedAt:     time.Now().UTC(),
		}, true
	}

	var (
		tech       ServiceTechnology
		family     ServiceFamily
		hasCreds   bool
		userStr    string
		redFields  []string
		defaultPort int
		protocol   = "tcp"
	)

	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "postgres", "postgresql":
		tech = TechPostgreSQL
		family = FamilyDirectDatabase
		defaultPort = 5432
		// Check if host indicates Supabase direct postgres connection
		if strings.Contains(strings.ToLower(u.Host), "supabase.co") || strings.Contains(strings.ToLower(u.Host), "supabase.in") {
			tech = TechSupabase
			family = FamilyBackendInterface
		}
	case "mongodb", "mongodb+srv":
		tech = TechMongoDB
		family = FamilyDirectDatabase
		defaultPort = 27017
	case "redis", "rediss":
		tech = TechRedis
		family = FamilyDirectDatabase
		defaultPort = 6379
	case "mysql":
		tech = TechMySQL
		family = FamilyDirectDatabase
		defaultPort = 3306
	default:
		return ConnectionIndicator{}, false
	}

	// Structural UserInfo analysis & redaction
	if u.User != nil {
		uName := u.User.Username()
		_, passSet := u.User.Password()
		if passSet {
			hasCreds = true
			redFields = append(redFields, "password")
			if secrets.IsSensitiveKey(uName) {
				userStr = "[REDACTED]"
			} else {
				userStr = uName
			}
			u.User = url.UserPassword(userStr, "[REDACTED]")
		} else if uName != "" {
			if tech == TechRedis || secrets.IsSensitiveKey(uName) {
				hasCreds = true
				redFields = append(redFields, "token")
				userStr = "[REDACTED]"
				u.User = url.User("[REDACTED]")
			} else {
				userStr = uName
			}
		}
	}

	// Query parameter inspection and redaction
	if u.RawQuery != "" {
		q := u.Query()
		modified := false
		for k, vv := range q {
			if secrets.IsSensitiveQueryParam(k) {
				hasCreds = true
				redFields = append(redFields, k)
				q.Set(k, "[REDACTED]")
				modified = true
			} else {
				for i, v := range vv {
					if red := secrets.RedactText(v); red != v {
						vv[i] = red
						modified = true
						hasCreds = true
						redFields = append(redFields, k)
					}
				}
				if modified {
					q[k] = vv
				}
			}
		}
		if modified {
			enc := q.Encode()
			enc = strings.ReplaceAll(enc, "%5BREDACTED%5D", "[REDACTED]")
			u.RawQuery = enc
		}
	}

	port := defaultPort
	host := u.Hostname()
	if pStr := u.Port(); pStr != "" {
		if p, err := strconv.Atoi(pStr); err == nil {
			port = p
		}
	}

	dbName := strings.TrimPrefix(u.Path, "/")
	if idx := strings.Index(dbName, "/"); idx != -1 {
		dbName = dbName[:idx]
	}

	sanitized := u.String()
	sanitized = strings.ReplaceAll(sanitized, "%5BREDACTED%5D", "[REDACTED]")
	if isJDBC {
		sanitized = "jdbc:" + sanitized
	}

	endpoint := net.JoinHostPort(host, strconv.Itoa(port))
	if host == "" {
		endpoint = u.Host
	}

	ci := ConnectionIndicator{
		Technology:         tech,
		Family:             family,
		Type:               IndicatorTypeConnectionString,
		SanitizedValue:     sanitized,
		Endpoint:           endpoint,
		Host:               host,
		Port:               port,
		Protocol:           protocol,
		Database:           dbName,
		HasCredentials:     hasCreds,
		CredentialUsername: userStr,
		RedactedFields:     redFields,
		Source:             source,
		Fingerprint:        GenerateIndicatorFingerprint(tech, IndicatorTypeConnectionString, sanitized, source.Identifier, source.LineNumber),
		DetectedAt:         time.Now().UTC(),
	}

	return ci, true
}

// scanMySQLDSN extracts Go MySQL DSN patterns: user:pass@tcp(host:port)/dbname
func (d *IndicatorDetector) scanMySQLDSN(source IndicatorSource, line string) []ConnectionIndicator {
	var indicators []ConnectionIndicator

	matches := mysqlDSNRegex.FindAllStringSubmatch(line, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		rawDSN := m[1]
		clean := strings.Trim(rawDSN, "\"'`(),; \t\r\n")

		// Must contain '@' and either 'tcp(' or '/'
		atIdx := strings.Index(clean, "@")
		if atIdx == -1 {
			continue
		}

		userPass := clean[:atIdx]
		rest := clean[atIdx+1:]

		var (
			user     string
			hasCreds bool
			redFields []string
		)

		if colIdx := strings.Index(userPass, ":"); colIdx != -1 {
			user = userPass[:colIdx]
			hasCreds = true
			redFields = append(redFields, "password")
		} else {
			user = userPass
		}

		if secrets.IsSensitiveKey(user) {
			user = "[REDACTED]"
			hasCreds = true
		}

		sanitizedUserPass := user
		if hasCreds {
			sanitizedUserPass = user + ":[REDACTED]"
		}

		host := "127.0.0.1"
		port := 3306
		proto := "tcp"

		afterAt := rest
		if strings.HasPrefix(afterAt, "tcp(") {
			endParen := strings.Index(afterAt, ")")
			if endParen != -1 {
				addr := afterAt[4:endParen]
				if h, pStr, err := net.SplitHostPort(addr); err == nil {
					host = h
					if p, err := strconv.Atoi(pStr); err == nil {
						port = p
					}
				} else {
					host = addr
				}
				afterAt = afterAt[endParen+1:]
			}
		} else if strings.HasPrefix(afterAt, "unix(") {
			proto = "unix"
			endParen := strings.Index(afterAt, ")")
			if endParen != -1 {
				host = afterAt[5:endParen]
				port = 0
				afterAt = afterAt[endParen+1:]
			}
		}

		dbName := ""
		if strings.HasPrefix(afterAt, "/") {
			dbPart := afterAt[1:]
			if qIdx := strings.Index(dbPart, "?"); qIdx != -1 {
				dbName = dbPart[:qIdx]
			} else {
				dbName = dbPart
			}
		}

		sanitizedDSN := sanitizedUserPass + "@" + rest
		if hasCreds {
			sanitizedDSN = sanitizedUserPass + "@" + rest
		}

		endpoint := host
		if port > 0 {
			endpoint = net.JoinHostPort(host, strconv.Itoa(port))
		}

		src := source
		if hasCreds {
			src.ContextLine = secrets.RedactText(strings.Replace(line, rawDSN, sanitizedDSN, 1))
		}

		ci := ConnectionIndicator{
			Technology:         TechMySQL,
			Family:             FamilyDirectDatabase,
			Type:               IndicatorTypeConnectionString,
			SanitizedValue:     sanitizedDSN,
			Endpoint:           endpoint,
			Host:               host,
			Port:               port,
			Protocol:           proto,
			Database:           dbName,
			HasCredentials:     hasCreds,
			CredentialUsername: user,
			RedactedFields:     redFields,
			Source:             src,
			Fingerprint:        GenerateIndicatorFingerprint(TechMySQL, IndicatorTypeConnectionString, sanitizedDSN, source.Identifier, source.LineNumber),
			DetectedAt:         time.Now().UTC(),
		}
		indicators = append(indicators, ci)
	}

	return indicators
}

// scanAzureIndicators extracts Azure storage connection strings and blob URLs.
func (d *IndicatorDetector) scanAzureIndicators(source IndicatorSource, line string) []ConnectionIndicator {
	var indicators []ConnectionIndicator

	// 1. Connection strings
	for _, m := range azureConnStringRegex.FindAllStringSubmatch(line, -1) {
		if len(m) < 4 {
			continue
		}
		account := m[2]
		rawConn := m[1]

		// Structural replacement of AccountKey
		sanitized := strings.Replace(rawConn, m[3], "[REDACTED]", 1)
		endpoint := fmt.Sprintf("https://%s.blob.core.windows.net", account)

		src := source
		src.ContextLine = secrets.RedactText(strings.Replace(line, rawConn, sanitized, 1))

		ci := ConnectionIndicator{
			Technology:         TechAzureBlob,
			Family:             FamilyObjectStorage,
			Type:               IndicatorTypeConnectionString,
			SanitizedValue:     sanitized,
			Endpoint:           endpoint,
			Host:               fmt.Sprintf("%s.blob.core.windows.net", account),
			Port:               443,
			Protocol:           "https",
			Database:           account,
			HasCredentials:     true,
			CredentialUsername: account,
			RedactedFields:     []string{"AccountKey"},
			Source:             src,
			Fingerprint:        GenerateIndicatorFingerprint(TechAzureBlob, IndicatorTypeConnectionString, sanitized, source.Identifier, source.LineNumber),
			DetectedAt:         time.Now().UTC(),
		}
		indicators = append(indicators, ci)
	}

	// 2. Blob Endpoints
	for _, m := range azureBlobEndpointRegex.FindAllStringSubmatch(line, -1) {
		if len(m) < 2 {
			continue
		}
		account := m[1]
		fullURL := m[0]
		endpoint := fmt.Sprintf("https://%s.blob.core.windows.net", account)
		cleanVal := secrets.SanitizeURL(fullURL)
		hasCreds := strings.Contains(cleanVal, "[REDACTED]")

		container := ""
		if len(m) > 2 && m[2] != "" {
			trimmedPath := strings.TrimPrefix(m[2], "/")
			if qIdx := strings.Index(trimmedPath, "?"); qIdx != -1 {
				trimmedPath = trimmedPath[:qIdx]
			}
			parts := strings.Split(trimmedPath, "/")
			if len(parts) > 0 {
				container = parts[0]
			}
		}

		src := source
		if hasCreds {
			src.ContextLine = secrets.RedactText(strings.Replace(line, fullURL, cleanVal, 1))
		}

		var redFields []string
		if hasCreds {
			redFields = []string{"sig"}
		}

		ci := ConnectionIndicator{
			Technology:     TechAzureBlob,
			Family:         FamilyObjectStorage,
			Type:           IndicatorTypeEndpointReference,
			SanitizedValue: cleanVal,
			Endpoint:       endpoint,
			Host:           fmt.Sprintf("%s.blob.core.windows.net", account),
			Port:           443,
			Protocol:       "https",
			Database:       container,
			HasCredentials: hasCreds,
			RedactedFields: redFields,
			Source:         src,
			Fingerprint:    GenerateIndicatorFingerprint(TechAzureBlob, IndicatorTypeEndpointReference, cleanVal, source.Identifier, source.LineNumber),
			DetectedAt:     time.Now().UTC(),
		}
		indicators = append(indicators, ci)
	}

	return indicators
}

// scanStorageIndicators extracts S3, GCS, and MinIO storage references.
func (d *IndicatorDetector) scanStorageIndicators(source IndicatorSource, line string) []ConnectionIndicator {
	var indicators []ConnectionIndicator

	// 1. AWS S3 URIs (s3://bucket)
	for _, m := range s3URIRegex.FindAllStringSubmatch(line, -1) {
		if len(m) < 2 {
			continue
		}
		bucket := m[1]
		cleanVal := fmt.Sprintf("s3://%s", bucket)
		endpoint := fmt.Sprintf("https://%s.s3.amazonaws.com", bucket)

		indicators = append(indicators, ConnectionIndicator{
			Technology:     TechAWSS3,
			Family:         FamilyObjectStorage,
			Type:           IndicatorTypeEndpointReference,
			SanitizedValue: cleanVal,
			Endpoint:       endpoint,
			Host:           fmt.Sprintf("%s.s3.amazonaws.com", bucket),
			Port:           443,
			Protocol:       "https",
			Database:       bucket,
			HasCredentials: false,
			Source:         source,
			Fingerprint:    GenerateIndicatorFingerprint(TechAWSS3, IndicatorTypeEndpointReference, cleanVal, source.Identifier, source.LineNumber),
			DetectedAt:     time.Now().UTC(),
		})
	}

	// 2. AWS S3 HTTP endpoints
	for _, m := range s3HTTPRegex.FindAllStringSubmatch(line, -1) {
		if len(m) < 2 {
			continue
		}
		bucket := m[1]
		endpoint := fmt.Sprintf("https://%s.s3.amazonaws.com", bucket)
		cleanVal := secrets.SanitizeURL(m[0])
		hasCreds := strings.Contains(cleanVal, "[REDACTED]")

		src := source
		if hasCreds {
			src.ContextLine = secrets.RedactText(strings.Replace(line, m[0], cleanVal, 1))
		}

		indicators = append(indicators, ConnectionIndicator{
			Technology:     TechAWSS3,
			Family:         FamilyObjectStorage,
			Type:           IndicatorTypeEndpointReference,
			SanitizedValue: cleanVal,
			Endpoint:       endpoint,
			Host:           fmt.Sprintf("%s.s3.amazonaws.com", bucket),
			Port:           443,
			Protocol:       "https",
			Database:       bucket,
			HasCredentials: hasCreds,
			Source:         src,
			Fingerprint:    GenerateIndicatorFingerprint(TechAWSS3, IndicatorTypeEndpointReference, endpoint, source.Identifier, source.LineNumber),
			DetectedAt:     time.Now().UTC(),
		})
	}
	for _, m := range s3PathHTTPRegex.FindAllStringSubmatch(line, -1) {
		if len(m) < 2 {
			continue
		}
		bucket := m[1]
		endpoint := fmt.Sprintf("https://s3.amazonaws.com/%s", bucket)
		cleanVal := secrets.SanitizeURL(m[0])

		indicators = append(indicators, ConnectionIndicator{
			Technology:     TechAWSS3,
			Family:         FamilyObjectStorage,
			Type:           IndicatorTypeEndpointReference,
			SanitizedValue: cleanVal,
			Endpoint:       endpoint,
			Host:           "s3.amazonaws.com",
			Port:           443,
			Protocol:       "https",
			Database:       bucket,
			HasCredentials: strings.Contains(cleanVal, "[REDACTED]"),
			Source:         source,
			Fingerprint:    GenerateIndicatorFingerprint(TechAWSS3, IndicatorTypeEndpointReference, endpoint, source.Identifier, source.LineNumber),
			DetectedAt:     time.Now().UTC(),
		})
	}

	// 3. Google Cloud Storage URIs (gs://bucket)
	for _, m := range gcsURIRegex.FindAllStringSubmatch(line, -1) {
		if len(m) < 2 {
			continue
		}
		bucket := m[1]
		cleanVal := fmt.Sprintf("gs://%s", bucket)
		endpoint := fmt.Sprintf("https://storage.googleapis.com/%s", bucket)

		indicators = append(indicators, ConnectionIndicator{
			Technology:     TechGCS,
			Family:         FamilyObjectStorage,
			Type:           IndicatorTypeEndpointReference,
			SanitizedValue: cleanVal,
			Endpoint:       endpoint,
			Host:           "storage.googleapis.com",
			Port:           443,
			Protocol:       "https",
			Database:       bucket,
			HasCredentials: false,
			Source:         source,
			Fingerprint:    GenerateIndicatorFingerprint(TechGCS, IndicatorTypeEndpointReference, cleanVal, source.Identifier, source.LineNumber),
			DetectedAt:     time.Now().UTC(),
		})
	}

	// 4. GCS HTTP endpoints
	for _, m := range gcsHTTPRegex.FindAllStringSubmatch(line, -1) {
		if len(m) < 2 {
			continue
		}
		bucket := m[1]
		endpoint := fmt.Sprintf("https://storage.googleapis.com/%s", bucket)
		cleanVal := secrets.SanitizeURL(m[0])

		indicators = append(indicators, ConnectionIndicator{
			Technology:     TechGCS,
			Family:         FamilyObjectStorage,
			Type:           IndicatorTypeEndpointReference,
			SanitizedValue: cleanVal,
			Endpoint:       endpoint,
			Host:           "storage.googleapis.com",
			Port:           443,
			Protocol:       "https",
			Database:       bucket,
			HasCredentials: strings.Contains(cleanVal, "[REDACTED]"),
			Source:         source,
			Fingerprint:    GenerateIndicatorFingerprint(TechGCS, IndicatorTypeEndpointReference, endpoint, source.Identifier, source.LineNumber),
			DetectedAt:     time.Now().UTC(),
		})
	}
	for _, m := range gcsSubHTTPRegex.FindAllStringSubmatch(line, -1) {
		if len(m) < 2 {
			continue
		}
		bucket := m[1]
		endpoint := fmt.Sprintf("https://%s.storage.googleapis.com", bucket)
		cleanVal := secrets.SanitizeURL(m[0])

		indicators = append(indicators, ConnectionIndicator{
			Technology:     TechGCS,
			Family:         FamilyObjectStorage,
			Type:           IndicatorTypeEndpointReference,
			SanitizedValue: cleanVal,
			Endpoint:       endpoint,
			Host:           fmt.Sprintf("%s.storage.googleapis.com", bucket),
			Port:           443,
			Protocol:       "https",
			Database:       bucket,
			HasCredentials: strings.Contains(cleanVal, "[REDACTED]"),
			Source:         source,
			Fingerprint:    GenerateIndicatorFingerprint(TechGCS, IndicatorTypeEndpointReference, endpoint, source.Identifier, source.LineNumber),
			DetectedAt:     time.Now().UTC(),
		})
	}

	// 5. MinIO endpoints (port 9000 or 9001 with minio context)
	if strings.Contains(strings.ToLower(line), "minio") {
		for _, m := range minioEndpointRegex.FindAllStringSubmatch(line, -1) {
			if len(m) < 3 {
				continue
			}
			host := m[1]
			port, _ := strconv.Atoi(m[2])
			endpoint := net.JoinHostPort(host, strconv.Itoa(port))
			cleanVal := fmt.Sprintf("http://%s:%d", host, port)

			indicators = append(indicators, ConnectionIndicator{
				Technology:     TechMinIO,
				Family:         FamilyObjectStorage,
				Type:           IndicatorTypeEndpointReference,
				SanitizedValue: cleanVal,
				Endpoint:       endpoint,
				Host:           host,
				Port:           port,
				Protocol:       "http",
				HasCredentials: false,
				Source:         source,
				Fingerprint:    GenerateIndicatorFingerprint(TechMinIO, IndicatorTypeEndpointReference, cleanVal, source.Identifier, source.LineNumber),
				DetectedAt:     time.Now().UTC(),
			})
		}
	}

	return indicators
}

// scanFirebaseIndicators extracts Firebase RTDB and Firestore endpoint references.
func (d *IndicatorDetector) scanFirebaseIndicators(source IndicatorSource, line string) []ConnectionIndicator {
	var indicators []ConnectionIndicator

	// 1. Firebase RTDB (firebaseio.com)
	for _, m := range firebaseRTDBRegex.FindAllStringSubmatch(line, -1) {
		if len(m) < 2 {
			continue
		}
		project := m[1]
		fullURL := m[0]
		endpoint := fmt.Sprintf("https://%s.firebaseio.com", project)
		cleanVal := secrets.SanitizeURL(fullURL)
		hasCreds := strings.Contains(cleanVal, "[REDACTED]")

		src := source
		if hasCreds {
			src.ContextLine = secrets.RedactText(strings.Replace(line, fullURL, cleanVal, 1))
		}

		indicators = append(indicators, ConnectionIndicator{
			Technology:         TechFirebaseRTDB,
			Family:             FamilyFirebase,
			Type:               IndicatorTypeEndpointReference,
			SanitizedValue:     cleanVal,
			Endpoint:           endpoint,
			Host:               fmt.Sprintf("%s.firebaseio.com", project),
			Port:               443,
			Protocol:           "https",
			Database:           project,
			HasCredentials:     hasCreds,
			RedactedFields:     ifSlice(hasCreds, []string{"auth"}),
			Source:             src,
			Fingerprint:        GenerateIndicatorFingerprint(TechFirebaseRTDB, IndicatorTypeEndpointReference, endpoint, source.Identifier, source.LineNumber),
			DetectedAt:         time.Now().UTC(),
		})
	}

	// 2. Firebase RTDB (firebasedatabase.app)
	for _, m := range firebaseAppRTDBRegex.FindAllStringSubmatch(line, -1) {
		if len(m) < 2 {
			continue
		}
		domain := m[1]
		fullURL := m[0]
		endpoint := fmt.Sprintf("https://%s", domain)
		cleanVal := secrets.SanitizeURL(fullURL)
		hasCreds := strings.Contains(cleanVal, "[REDACTED]")

		src := source
		if hasCreds {
			src.ContextLine = secrets.RedactText(strings.Replace(line, fullURL, cleanVal, 1))
		}

		indicators = append(indicators, ConnectionIndicator{
			Technology:     TechFirebaseRTDB,
			Family:         FamilyFirebase,
			Type:           IndicatorTypeEndpointReference,
			SanitizedValue: cleanVal,
			Endpoint:       endpoint,
			Host:           domain,
			Port:           443,
			Protocol:       "https",
			HasCredentials: hasCreds,
			RedactedFields: ifSlice(hasCreds, []string{"auth"}),
			Source:         src,
			Fingerprint:    GenerateIndicatorFingerprint(TechFirebaseRTDB, IndicatorTypeEndpointReference, endpoint, source.Identifier, source.LineNumber),
			DetectedAt:     time.Now().UTC(),
		})
	}

	// 3. Firestore Endpoints
	for _, m := range firestoreEndpointRegex.FindAllStringSubmatch(line, -1) {
		if len(m) < 2 {
			continue
		}
		project := m[1]
		endpoint := "https://firestore.googleapis.com"
		cleanVal := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents", project)

		indicators = append(indicators, ConnectionIndicator{
			Technology:     TechFirestore,
			Family:         FamilyFirebase,
			Type:           IndicatorTypeEndpointReference,
			SanitizedValue: cleanVal,
			Endpoint:       endpoint,
			Host:           "firestore.googleapis.com",
			Port:           443,
			Protocol:       "https",
			Database:       project,
			HasCredentials: false,
			Source:         source,
			Fingerprint:    GenerateIndicatorFingerprint(TechFirestore, IndicatorTypeEndpointReference, cleanVal, source.Identifier, source.LineNumber),
			DetectedAt:     time.Now().UTC(),
		})
	}

	return indicators
}

// scanBackendAndAdminIndicators extracts Supabase, PostgREST, Hasura, and Mongo Express indicators.
func (d *IndicatorDetector) scanBackendAndAdminIndicators(source IndicatorSource, line string) []ConnectionIndicator {
	var indicators []ConnectionIndicator

	// 1. Supabase HTTP endpoints
	for _, m := range supabaseHostRegex.FindAllStringSubmatch(line, -1) {
		if len(m) < 2 {
			continue
		}
		project := m[1]
		cleanVal := fmt.Sprintf("https://%s.supabase.co", project)

		indicators = append(indicators, ConnectionIndicator{
			Technology:     TechSupabase,
			Family:         FamilyBackendInterface,
			Type:           IndicatorTypeEndpointReference,
			SanitizedValue: cleanVal,
			Endpoint:       cleanVal,
			Host:           fmt.Sprintf("%s.supabase.co", project),
			Port:           443,
			Protocol:       "https",
			Database:       project,
			HasCredentials: false,
			Source:         source,
			Fingerprint:    GenerateIndicatorFingerprint(TechSupabase, IndicatorTypeEndpointReference, cleanVal, source.Identifier, source.LineNumber),
			DetectedAt:     time.Now().UTC(),
		})
	}

	// 2. Hasura GraphQL Endpoints
	for _, m := range hasuraEndpointRegex.FindAllStringSubmatch(line, -1) {
		if len(m) < 2 {
			continue
		}
		cleanVal := m[0]
		hostPort := m[1]
		host := hostPort
		port := 443
		if h, pStr, err := net.SplitHostPort(hostPort); err == nil {
			host = h
			if p, err := strconv.Atoi(pStr); err == nil {
				port = p
			}
		}

		indicators = append(indicators, ConnectionIndicator{
			Technology:     TechHasura,
			Family:         FamilyBackendInterface,
			Type:           IndicatorTypeEndpointReference,
			SanitizedValue: cleanVal,
			Endpoint:       cleanVal,
			Host:           host,
			Port:           port,
			Protocol:       "http",
			HasCredentials: false,
			Source:         source,
			Fingerprint:    GenerateIndicatorFingerprint(TechHasura, IndicatorTypeEndpointReference, cleanVal, source.Identifier, source.LineNumber),
			DetectedAt:     time.Now().UTC(),
		})
	}

	// 3. Mongo Express Indicators
	lowerLine := strings.ToLower(line)
	if strings.Contains(lowerLine, "mongo-express") || strings.Contains(lowerLine, "me_config") {
		if strings.Contains(lowerLine, ":8081") {
			endpoint := "http://localhost:8081"
			indicators = append(indicators, ConnectionIndicator{
				Technology:     TechMongoExpress,
				Family:         FamilyDatabaseAdmin,
				Type:           IndicatorTypeEndpointReference,
				SanitizedValue: endpoint,
				Endpoint:       endpoint,
				Host:           "localhost",
				Port:           8081,
				Protocol:       "http",
				HasCredentials: false,
				Source:         source,
				Fingerprint:    GenerateIndicatorFingerprint(TechMongoExpress, IndicatorTypeEndpointReference, endpoint, source.Identifier, source.LineNumber),
				DetectedAt:     time.Now().UTC(),
			})
		}
	}

	// 4. Elasticsearch HTTP on 9200
	if strings.Contains(line, ":9200") {
		esRegex := regexp.MustCompile(`https?://([a-zA-Z0-9_\.\-]+):9200`)
		for _, m := range esRegex.FindAllStringSubmatch(line, -1) {
			if len(m) < 2 {
				continue
			}
			host := m[1]
			endpoint := fmt.Sprintf("http://%s:9200", host)
			cleanVal := endpoint

			indicators = append(indicators, ConnectionIndicator{
				Technology:     TechElasticsearch,
				Family:         FamilyDirectDatabase,
				Type:           IndicatorTypeEndpointReference,
				SanitizedValue: cleanVal,
				Endpoint:       endpoint,
				Host:           host,
				Port:           9200,
				Protocol:       "http",
				HasCredentials: false,
				Source:         source,
				Fingerprint:    GenerateIndicatorFingerprint(TechElasticsearch, IndicatorTypeEndpointReference, cleanVal, source.Identifier, source.LineNumber),
				DetectedAt:     time.Now().UTC(),
			})
		}
	}

	return indicators
}

// scanPrismaBlocks extracts Prisma schema datasource definitions.
func (d *IndicatorDetector) scanPrismaBlocks(source IndicatorSource, content []byte) []ConnectionIndicator {
	var indicators []ConnectionIndicator

	blocks := prismaDatasourceBlockRegex.FindAllSubmatch(content, -1)
	for _, block := range blocks {
		if len(block) < 3 {
			continue
		}
		body := string(block[2])

		provMatch := prismaProviderRegex.FindStringSubmatch(body)
		urlMatch := prismaURLRegex.FindStringSubmatch(body)

		provider := ""
		if len(provMatch) > 1 {
			provider = strings.ToLower(provMatch[1])
		}

		rawURL := ""
		isEnvRef := false
		if len(urlMatch) > 1 && urlMatch[1] != "" {
			rawURL = urlMatch[1]
			isEnvRef = true
		} else if len(urlMatch) > 2 && urlMatch[2] != "" {
			rawURL = urlMatch[2]
		}

		tech := TechPrisma
		family := FamilyBackendInterface

		sanitizedVal := fmt.Sprintf("datasource db { provider = %q url = ... }", provider)
		hasCreds := false
		endpoint := "schema.prisma"

		if isEnvRef {
			sanitizedVal = fmt.Sprintf("datasource db { provider = %q url = env(%q) }", provider, rawURL)
		} else if rawURL != "" {
			// Embedded raw connection string inside schema.prisma
			cleanURL := secrets.SanitizeURL(rawURL)
			sanitizedVal = fmt.Sprintf("datasource db { provider = %q url = %q }", provider, cleanURL)
			if strings.Contains(cleanURL, "[REDACTED]") {
				hasCreds = true
			}
			endpoint = cleanURL
		}

		ci := ConnectionIndicator{
			Technology:     tech,
			Family:         family,
			Type:           IndicatorTypeConfigDatasource,
			SanitizedValue: sanitizedVal,
			Endpoint:       endpoint,
			Database:       provider,
			HasCredentials: hasCreds,
			Source:         source,
			Fingerprint:    GenerateIndicatorFingerprint(tech, IndicatorTypeConfigDatasource, sanitizedVal, source.Identifier, source.LineNumber),
			DetectedAt:     time.Now().UTC(),
		}
		indicators = append(indicators, ci)
	}

	return indicators
}

// lineMightContainEnv checks if a line contains any variable names associated with the 16 target services.
func (d *IndicatorDetector) lineMightContainEnv(line string) bool {
	eqIdx := strings.Index(line, "=")
	if eqIdx == -1 {
		return false
	}
	keyPart := strings.TrimSpace(line[:eqIdx])
	if strings.HasPrefix(keyPart, "export ") {
		keyPart = strings.TrimSpace(keyPart[7:])
	}
	keyUpper := strings.ToUpper(keyPart)
	return strings.Contains(keyUpper, "DATABASE") ||
		strings.Contains(keyUpper, "POSTGRES") ||
		strings.Contains(keyUpper, "PG") ||
		strings.Contains(keyUpper, "MYSQL") ||
		strings.Contains(keyUpper, "MONGO") ||
		strings.Contains(keyUpper, "REDIS") ||
		strings.Contains(keyUpper, "ELASTIC") ||
		strings.Contains(keyUpper, "BONSAI") ||
		strings.Contains(keyUpper, "SEARCHBOX") ||
		strings.Contains(keyUpper, "ME_CONFIG") ||
		strings.Contains(keyUpper, "SUPABASE") ||
		strings.Contains(keyUpper, "PGRST") ||
		strings.Contains(keyUpper, "HASURA") ||
		strings.Contains(keyUpper, "PRISMA") ||
		strings.Contains(keyUpper, "FIREBASE") ||
		strings.Contains(keyUpper, "FIRESTORE") ||
		strings.Contains(keyUpper, "AWS_") ||
		strings.Contains(keyUpper, "AZURE_") ||
		strings.Contains(keyUpper, "MINIO_") ||
		strings.Contains(keyUpper, "GCS_")
}

func isDirectDBEnvKey(key string) bool {
	switch key {
	case "DATABASE_URL", "POSTGRES_URL", "PGDATABASE_URL",
		"MYSQL_URL", "JAWSDB_URL", "CLEARDB_DATABASE_URL",
		"MONGODB_URI", "MONGO_URL", "MONGO_URI", "MONGODB_URL",
		"REDIS_URL", "REDIS_TLS_URL", "REDISTOGO_URL",
		"ELASTICSEARCH_URL", "ELASTIC_URL", "BONSAI_URL", "SEARCHBOX_URL", "ES_URL":
		return true
	default:
		return false
	}
}

// scanEnvAssignments parses environment variable assignments for the 16 target services.
func (d *IndicatorDetector) scanEnvAssignments(source IndicatorSource, line string) []ConnectionIndicator {
	var indicators []ConnectionIndicator

	matches := envAssignRegex.FindAllStringSubmatch(line, -1)
	for _, m := range matches {
		if len(m) < 9 {
			continue
		}
		key := m[1]
		val := ""
		for idx := 3; idx <= 8; idx++ {
			if m[idx] != "" {
				val = m[idx]
				break
			}
		}

		cleanKey := strings.ToUpper(strings.TrimSpace(key))
		cleanVal := strings.TrimSpace(val)

		// Avoid duplicate indicators if a direct DB URL is already handled by scanURIs/scanMySQLDSN
		if isDirectDBEnvKey(cleanKey) && (strings.Contains(cleanVal, "://") || strings.Contains(cleanVal, "@tcp(") || strings.Contains(cleanVal, "@unix(")) {
			continue
		}

		ci, ok := d.mapEnvToIndicator(source, cleanKey, cleanVal)
		if ok {
			indicators = append(indicators, ci)
		}
	}

	return indicators
}

// mapEnvToIndicator maps known environment variables to corresponding targets and redacts secrets.
func (d *IndicatorDetector) mapEnvToIndicator(source IndicatorSource, key, val string) (ConnectionIndicator, bool) {
	var (
		tech      ServiceTechnology
		family    ServiceFamily
		indType   = IndicatorTypeCredentialAssignment
		endpoint  = key
		hasCreds  = true
		redVal    string
		redFields = []string{key}
	)

	switch key {
	// 1. Direct Databases
	case "DATABASE_URL", "POSTGRES_URL", "PGDATABASE_URL":
		tech = TechPostgreSQL
		family = FamilyDirectDatabase
		indType = IndicatorTypeConnectionString
		if strings.Contains(strings.ToLower(val), "supabase") {
			tech = TechSupabase
			family = FamilyBackendInterface
		}
	case "PGPASSWORD":
		tech = TechPostgreSQL
		family = FamilyDirectDatabase
	case "MYSQL_URL", "JAWSDB_URL", "CLEARDB_DATABASE_URL":
		tech = TechMySQL
		family = FamilyDirectDatabase
		indType = IndicatorTypeConnectionString
	case "MYSQL_PWD":
		tech = TechMySQL
		family = FamilyDirectDatabase
	case "MONGODB_URI", "MONGO_URL", "MONGO_URI", "MONGODB_URL":
		tech = TechMongoDB
		family = FamilyDirectDatabase
		indType = IndicatorTypeConnectionString
	case "REDIS_URL", "REDIS_TLS_URL", "REDISTOGO_URL":
		tech = TechRedis
		family = FamilyDirectDatabase
		indType = IndicatorTypeConnectionString
	case "REDIS_PASSWORD", "REDIS_AUTH":
		tech = TechRedis
		family = FamilyDirectDatabase
	case "ELASTICSEARCH_URL", "ELASTIC_URL", "BONSAI_URL", "SEARCHBOX_URL", "ES_URL":
		tech = TechElasticsearch
		family = FamilyDirectDatabase
		indType = IndicatorTypeConnectionString

	// 2. Admin & Backend
	case "ME_CONFIG_BASICAUTH_PASSWORD":
		tech = TechMongoExpress
		family = FamilyDatabaseAdmin
	case "ME_CONFIG_MONGODB_SERVER":
		tech = TechMongoExpress
		family = FamilyDatabaseAdmin
		indType = IndicatorTypeEndpointReference
		hasCreds = false
		endpoint = val
	case "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_SECRET_KEY":
		tech = TechSupabase
		family = FamilyBackendInterface
	case "SUPABASE_URL", "NEXT_PUBLIC_SUPABASE_URL":
		tech = TechSupabase
		family = FamilyBackendInterface
		indType = IndicatorTypeEndpointReference
		hasCreds = false
		endpoint = val
	case "PGRST_DB_URI":
		tech = TechPostgREST
		family = FamilyBackendInterface
		indType = IndicatorTypeConnectionString
	case "PGRST_JWT_SECRET":
		tech = TechPostgREST
		family = FamilyBackendInterface
	case "HASURA_GRAPHQL_ADMIN_SECRET":
		tech = TechHasura
		family = FamilyBackendInterface
	case "HASURA_GRAPHQL_ENDPOINT":
		tech = TechHasura
		family = FamilyBackendInterface
		indType = IndicatorTypeEndpointReference
		hasCreds = false
		endpoint = val
	case "PRISMA_DATABASE_URL", "PRISMA_URL":
		tech = TechPrisma
		family = FamilyBackendInterface
		indType = IndicatorTypeConnectionString

	// 3. Firebase & Storage
	case "FIREBASE_DATABASE_URL":
		tech = TechFirebaseRTDB
		family = FamilyFirebase
		indType = IndicatorTypeEndpointReference
		hasCreds = false
		endpoint = val
	case "FIRESTORE_EMULATOR_HOST":
		tech = TechFirestore
		family = FamilyFirebase
		indType = IndicatorTypeEndpointReference
		hasCreds = false
		endpoint = val
	case "AWS_SECRET_ACCESS_KEY":
		tech = TechAWSS3
		family = FamilyObjectStorage
	case "AZURE_STORAGE_CONNECTION_STRING":
		tech = TechAzureBlob
		family = FamilyObjectStorage
		indType = IndicatorTypeConnectionString
	case "AZURE_STORAGE_KEY":
		tech = TechAzureBlob
		family = FamilyObjectStorage
	case "MINIO_ROOT_PASSWORD", "MINIO_SECRET_KEY":
		tech = TechMinIO
		family = FamilyObjectStorage
	case "MINIO_ENDPOINT":
		tech = TechMinIO
		family = FamilyObjectStorage
		indType = IndicatorTypeEndpointReference
		hasCreds = false
		endpoint = val
	default:
		return ConnectionIndicator{}, false
	}

	if hasCreds {
		if indType == IndicatorTypeConnectionString {
			redVal = fmt.Sprintf("%s=%s", key, secrets.SanitizeURL(val))
		} else {
			redVal = fmt.Sprintf("%s=[REDACTED]", key)
		}
	} else {
		redVal = fmt.Sprintf("%s=%s", key, val)
	}

	ci := ConnectionIndicator{
		Technology:     tech,
		Family:         family,
		Type:           indType,
		SanitizedValue: redVal,
		Endpoint:       endpoint,
		HasCredentials: hasCreds,
		RedactedFields: redFields,
		Source: IndicatorSource{
			Type:        SourceTypeEnvironmentVariable,
			Identifier:  key,
			LineNumber:  source.LineNumber,
			ContextLine: secrets.RedactText(source.ContextLine),
		},
		Fingerprint: GenerateIndicatorFingerprint(tech, indType, redVal, key, source.LineNumber),
		DetectedAt:  time.Now().UTC(),
	}

	return ci, true
}

func ifSlice(cond bool, s []string) []string {
	if cond {
		return s
	}
	return nil
}

// ToCloudFinding converts a ConnectionIndicator into a standardized CloudFinding.
// It rigorously enforces non-conflation: AnalysisMethodStatic, FindingStatusSuspected,
// and explicit NegativeEvidence that reachability and exposure remain unverified.
func (ci ConnectionIndicator) ToCloudFinding(inScope ...bool) CloudFinding {
	if len(inScope) > 0 && !inScope[0] {
		category := "Discovered Cloud Service (Out of Scope)"
		return CloudFinding{
			Provider:    Provider(ci.Technology),
			Category:    category,
			Endpoint:    ci.Endpoint,
			Description: fmt.Sprintf("Discovered %s service reference in client assets; active probing skipped (outside authorized assessment scope)", ci.Technology),
			Evidence:    ci.SanitizedValue,
			Severity:    SeverityInfo,
			Confidence:  ConfidenceHigh,
			Fingerprint: GenerateFingerprint(Provider(ci.Technology), ci.Endpoint, category),
		}
	}

	category := fmt.Sprintf("Connection Indicator: %s", ci.Technology)
	if ci.HasCredentials {
		category = fmt.Sprintf("Connection Indicator (%s) with Credentials", ci.Technology)
	}

	severity := SeverityLow
	if ci.HasCredentials {
		severity = SeverityHigh
	} else if ci.Type == IndicatorTypeConnectionString {
		severity = SeverityMedium
	}

	confidence := ConfidenceHigh
	if ci.Type == IndicatorTypeEndpointReference {
		confidence = ConfidenceMedium
	}

	desc := fmt.Sprintf("Detected %s %s in %s. Service connectivity, authentication validity, and resource exposure remain unverified.",
		ci.Technology, strings.ToLower(string(ci.Type)), ci.Source.Identifier)

	lineInfo := ""
	if ci.Source.LineNumber > 0 {
		lineInfo = fmt.Sprintf(" (line %d)", ci.Source.LineNumber)
	}

	evidence := fmt.Sprintf("Matched %s indicator in %s%s: %s",
		ci.Technology, ci.Source.Identifier, lineInfo, ci.SanitizedValue)

	negEvidence := "Static analysis only. Zero active network connections or DNS queries were made. " +
		"Service reachability, credential validity, and resource exposure remain unverified."

	details := map[string]string{
		"indicator_type":      string(ci.Type),
		"technology":          string(ci.Technology),
		"family":              string(ci.Family),
		"has_credentials":     fmt.Sprintf("%t", ci.HasCredentials),
		"sanitized_value":     ci.SanitizedValue,
		"endpoint":            ci.Endpoint,
		"source_type":         string(ci.Source.Type),
		"source_identifier":   ci.Source.Identifier,
		"analysis_method":     "STATIC_ANALYSIS",
		"verification_status": "UNVERIFIED",
	}
	if ci.Source.LineNumber > 0 {
		details["source_line"] = fmt.Sprintf("%d", ci.Source.LineNumber)
	}
	if ci.Database != "" {
		details["database"] = ci.Database
	}
	if len(ci.RedactedFields) > 0 {
		details["redacted_fields"] = strings.Join(ci.RedactedFields, ", ")
	}

	return CloudFinding{
		Provider:         Provider(ci.Technology),
		Category:         category,
		Endpoint:         ci.Endpoint,
		Description:      desc,
		Evidence:         evidence,
		Severity:         severity,
		Confidence:       confidence,
		Fingerprint:      ci.Fingerprint,
		NegativeEvidence: negEvidence,
		Details:          details,
	}
}
