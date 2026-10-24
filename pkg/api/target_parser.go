package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	MaxProfileFileSize   = 1024 * 1024 // 1 MB limit
	MaxTenantsCount      = 50
	MaxComparisonsCount  = 200
	MaxResourceIDsCount  = 100
	MaxProfileStringLen  = 512
)

var (
	rxValidEnvVar = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

	allowedNonDestructiveMethods = map[string]bool{
		"GET":     true,
		"HEAD":    true,
		"OPTIONS": true,
	}

	prohibitedMutatingMethods = map[string]bool{
		"POST":   true,
		"PUT":    true,
		"DELETE": true,
		"PATCH":  true,
	}

	validTopLevelKeys = map[string]bool{
		"version":            true,
		"target":             true,
		"safety":             true,
		"tenants":            true,
		"cross_tenant_tests": true,
		"monitoring":         true,
	}

	validMonitoringKeys = map[string]bool{
		"enabled":            true,
		"snapshot_directory": true,
		"retain_snapshots":   true,
		"retain_events":      true,
		"notify_on":          true,
		"webhooks":           true,
	}

	validWebhookKeys = map[string]bool{
		"id":                  true,
		"provider":            true,
		"credential_env":      true,
		"url":                 true,
		"enabled":             true,
		"allow_insecure_http": true,
		"allow_loopback":      true,
		"allow_private_ips":   true,
	}

	validTargetKeys = map[string]bool{
		"name":            true,
		"base_urls":       true,
		"allowed_hosts":   true,
		"allowed_methods": true,
	}

	validSafetyKeys = map[string]bool{
		"mode":                           true,
		"require_explicit_authorization": true,
		"allow_cross_tenant_checks":       true,
		"max_requests":                   true,
		"requests_per_second":            true,
		"timeout_seconds":                true,
		"follow_redirects":               true,
	}

	validTenantKeys = map[string]bool{
		"id":             true,
		"identity":       true,
		"credential_env": true,
		"headers":        true,
		"resource_ids":   true,
	}

	validCrossTenantTestKeys = map[string]bool{
		"enabled":     true,
		"comparisons": true,
	}

	validComparisonKeys = map[string]bool{
		"requester_tenant":      true,
		"resource_owner_tenant": true,
		"resource_id":           true,
		"path":                  true,
		"method":                true,
		"expected_marker":       true,
	}
)

// LoadTargetProfile loads and strictly validates a felix.target.yml file from disk.
func LoadTargetProfile(filePath string) (*TargetProfile, error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open profile %s: %w", filePath, err)
	}

	if info.Size() > MaxProfileFileSize {
		return nil, fmt.Errorf("profile file size (%d bytes) exceeds maximum ceiling of %d bytes", info.Size(), MaxProfileFileSize)
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read profile %s: %w", filePath, err)
	}

	return ParseTargetProfile(data)
}

// ParseTargetProfile parses and validates profile data from raw YAML or JSON bytes.
func ParseTargetProfile(data []byte) (*TargetProfile, error) {
	if len(data) == 0 {
		return nil, errors.New("empty profile data provided")
	}

	if int64(len(data)) > MaxProfileFileSize {
		return nil, fmt.Errorf("profile data exceeds maximum size limit of %d bytes", MaxProfileFileSize)
	}

	trimmed := strings.TrimSpace(string(data))

	var profile TargetProfile

	// 1. If JSON document, parse using strict decoder with unknown field rejection
	if strings.HasPrefix(trimmed, "{") {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&profile); err != nil {
			return nil, fmt.Errorf("malformed JSON profile: %w", err)
		}
	} else {
		// 2. Parse YAML using strict structural line scanner
		parsed, err := parseYAMLProfile(data)
		if err != nil {
			return nil, fmt.Errorf("malformed YAML profile: %w", err)
		}
		profile = *parsed
	}

	// 3. Apply deterministic defaults
	applyProfileDefaults(&profile)

	// 4. Strict semantic validation
	if err := ValidateProfile(&profile); err != nil {
		return nil, err
	}

	return &profile, nil
}

// parseYAMLProfile parses YAML into TargetProfile with strict unknown field checking and bounds.
func parseYAMLProfile(data []byte) (*TargetProfile, error) {
	lines := strings.Split(string(data), "\n")
	prof := &TargetProfile{
		Version: 1,
	}

	type parseState int
	const (
		stateTop parseState = iota
		stateTarget
		stateSafety
		stateTenants
		stateTenantItem
		stateTenantHeaders
		stateCrossTenant
		stateComparisonItem
		stateMonitoring
		stateMonitorWebhookItem
	)

	var (
		curState         parseState
		curTenantIdx     = -1
		curComparisonIdx = -1
		curWebhookIdx    = -1
		activeStrList    *[]string
		activeListIndent int
	)

	for lineIdx, rawLine := range lines {
		lineNum := lineIdx + 1
		line := rawLine

		// Strip comments
		if idx := strings.Index(line, "#"); idx != -1 {
			line = line[:idx]
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " \t"))

		// Check if we are in stateTenantHeaders and indent decreased
		if curState == stateTenantHeaders && indent <= 4 {
			curState = stateTenantItem
		}

		// List item handling (- ...)
		if strings.HasPrefix(trimmed, "- ") {
			itemContent := strings.TrimSpace(trimmed[2:])

			subKey, _, subVal, isKV := splitYAMLKeyValue(itemContent)

			// If we have an active string list and this item is a scalar value (not key-value struct start)
			if activeStrList != nil && !isKV {
				cleanVal := strings.Trim(itemContent, `"'`)
				*activeStrList = append(*activeStrList, cleanVal)
				continue
			}

			// Clear active string list since a new struct list item is encountered
			activeStrList = nil

			// List item for Tenants: e.g. - id: "t1"
			if curState == stateTenants || curState == stateTenantItem || curState == stateTenantHeaders {
				prof.Tenants = append(prof.Tenants, TenantConfig{})
				curTenantIdx = len(prof.Tenants) - 1
				curState = stateTenantItem

				if isKV {
					if !validTenantKeys[subKey] {
						return nil, fmt.Errorf("line %d: unknown field %q in tenant section", lineNum, subKey)
					}
					applyTenantField(&prof.Tenants[curTenantIdx], subKey, subVal, &activeStrList, &activeListIndent, indent)
				}
				continue
			}

			// List item for Comparisons: e.g. - requester_tenant: "t1"
			if curState == stateCrossTenant || curState == stateComparisonItem {
				prof.CrossTenantTests.Comparisons = append(prof.CrossTenantTests.Comparisons, TenantComparison{})
				curComparisonIdx = len(prof.CrossTenantTests.Comparisons) - 1
				curState = stateComparisonItem

				if isKV {
					if !validComparisonKeys[subKey] {
						return nil, fmt.Errorf("line %d: unknown field %q in comparison section", lineNum, subKey)
					}
					applyComparisonField(&prof.CrossTenantTests.Comparisons[curComparisonIdx], subKey, subVal)
				}
				continue
			}

			// List item for Webhooks: e.g. - id: "security-slack"
			if curState == stateMonitoring || curState == stateMonitorWebhookItem {
				if prof.Monitoring == nil {
					prof.Monitoring = &MonitoringConfig{
						Enabled:           true,
						RetainSnapshots:   30,
						RetainEvents:      1000,
						SnapshotDirectory: "./felix-state",
					}
				}
				prof.Monitoring.Webhooks = append(prof.Monitoring.Webhooks, MonitorWebhookConfig{Enabled: true})
				curWebhookIdx = len(prof.Monitoring.Webhooks) - 1
				curState = stateMonitorWebhookItem

				if isKV {
					if !validWebhookKeys[subKey] {
						return nil, fmt.Errorf("line %d: unknown field %q in webhook section", lineNum, subKey)
					}
					if err := applyWebhookField(&prof.Monitoring.Webhooks[curWebhookIdx], subKey, subVal); err != nil {
						return nil, fmt.Errorf("line %d: invalid value for %s: %v", lineNum, subKey, err)
					}
				}
				continue
			}

			// If target list continuation (- "http://...")
			if curState == stateTarget && activeStrList != nil {
				cleanVal := strings.Trim(itemContent, `"'`)
				*activeStrList = append(*activeStrList, cleanVal)
				continue
			}

			return nil, fmt.Errorf("line %d: unexpected list item outside valid list context", lineNum)
		}

		// Key: value line
		key, rawKey, val, isKV := splitYAMLKeyValue(trimmed)
		if !isKV {
			return nil, fmt.Errorf("line %d: syntax error, expected 'key: value'", lineNum)
		}

		// Top-level key transition (indent == 0)
		if indent == 0 {
			activeStrList = nil
			if !validTopLevelKeys[key] {
				return nil, fmt.Errorf("line %d: unknown top-level field %q", lineNum, key)
			}

			switch key {
			case "version":
				v, err := strconv.Atoi(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: invalid integer for version: %v", lineNum, err)
				}
				prof.Version = v
				curState = stateTop
			case "target":
				curState = stateTarget
			case "safety":
				curState = stateSafety
			case "tenants":
				curState = stateTenants
			case "cross_tenant_tests":
				curState = stateCrossTenant
			case "monitoring":
				curState = stateMonitoring
				if prof.Monitoring == nil {
					prof.Monitoring = &MonitoringConfig{
						Enabled:           true,
						RetainSnapshots:   30,
						RetainEvents:      1000,
						SnapshotDirectory: "./felix-state",
					}
				}
			}
			continue
		}

		// State-specific parsing
		switch curState {
		case stateTarget:
			if !validTargetKeys[key] {
				return nil, fmt.Errorf("line %d: unknown field %q in target section", lineNum, key)
			}
			switch key {
			case "name":
				prof.Target.Name = val
			case "base_urls":
				activeStrList = &prof.Target.BaseURLs
				activeListIndent = indent + 2
				if val != "" && val != "[]" {
					prof.Target.BaseURLs = append(prof.Target.BaseURLs, parseInlineList(val)...)
				}
			case "allowed_hosts":
				activeStrList = &prof.Target.AllowedHosts
				activeListIndent = indent + 2
				if val != "" && val != "[]" {
					prof.Target.AllowedHosts = append(prof.Target.AllowedHosts, parseInlineList(val)...)
				}
			case "allowed_methods":
				activeStrList = &prof.Target.AllowedMethods
				activeListIndent = indent + 2
				if val != "" && val != "[]" {
					prof.Target.AllowedMethods = append(prof.Target.AllowedMethods, parseInlineList(val)...)
				}
			}

		case stateSafety:
			if !validSafetyKeys[key] {
				return nil, fmt.Errorf("line %d: unknown field %q in safety section", lineNum, key)
			}
			switch key {
			case "mode":
				prof.Safety.Mode = val
			case "require_explicit_authorization":
				b, err := parseBoolStrict(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: invalid boolean for %s: %v", lineNum, key, err)
				}
				prof.Safety.RequireExplicitAuthorization = b
			case "allow_cross_tenant_checks":
				b, err := parseBoolStrict(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: invalid boolean for %s: %v", lineNum, key, err)
				}
				prof.Safety.AllowCrossTenantChecks = b
			case "max_requests":
				n, err := strconv.Atoi(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: invalid integer for max_requests: %v", lineNum, err)
				}
				prof.Safety.MaxRequests = n
			case "requests_per_second":
				f, err := strconv.ParseFloat(val, 64)
				if err != nil {
					return nil, fmt.Errorf("line %d: invalid float for requests_per_second: %v", lineNum, err)
				}
				prof.Safety.RequestsPerSecond = f
			case "timeout_seconds":
				n, err := strconv.Atoi(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: invalid integer for timeout_seconds: %v", lineNum, err)
				}
				prof.Safety.TimeoutSeconds = n
			case "follow_redirects":
				b, err := parseBoolStrict(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: invalid boolean for follow_redirects: %v", lineNum, err)
				}
				prof.Safety.FollowRedirects = b
			}

		case stateTenantHeaders:
			if curTenantIdx < 0 || curTenantIdx >= len(prof.Tenants) {
				return nil, fmt.Errorf("line %d: header declared without tenant item", lineNum)
			}
			if prof.Tenants[curTenantIdx].Headers == nil {
				prof.Tenants[curTenantIdx].Headers = make(map[string]string)
			}
			prof.Tenants[curTenantIdx].Headers[rawKey] = val

		case stateTenants, stateTenantItem:
			if curTenantIdx < 0 || curTenantIdx >= len(prof.Tenants) {
				return nil, fmt.Errorf("line %d: tenant field %q declared without tenant item", lineNum, key)
			}
			if key == "headers" {
				if prof.Tenants[curTenantIdx].Headers == nil {
					prof.Tenants[curTenantIdx].Headers = make(map[string]string)
				}
				activeStrList = nil
				curState = stateTenantHeaders
				continue
			}
			if !validTenantKeys[key] {
				return nil, fmt.Errorf("line %d: unknown field %q in tenant section", lineNum, key)
			}
			applyTenantField(&prof.Tenants[curTenantIdx], key, val, &activeStrList, &activeListIndent, indent)

		case stateCrossTenant, stateComparisonItem:
			if key == "enabled" {
				b, err := parseBoolStrict(val)
				if err != nil {
					return nil, fmt.Errorf("line %d: invalid boolean for enabled: %v", lineNum, err)
				}
				prof.CrossTenantTests.Enabled = b
				continue
			}
			if key == "comparisons" {
				activeStrList = nil
				continue
			}
			if curComparisonIdx < 0 || curComparisonIdx >= len(prof.CrossTenantTests.Comparisons) {
				return nil, fmt.Errorf("line %d: comparison field %q declared without comparison item", lineNum, key)
			}
			if !validComparisonKeys[key] {
				return nil, fmt.Errorf("line %d: unknown field %q in comparison section", lineNum, key)
			}
			applyComparisonField(&prof.CrossTenantTests.Comparisons[curComparisonIdx], key, val)

		case stateMonitoring:
			if prof.Monitoring == nil {
				prof.Monitoring = &MonitoringConfig{
					Enabled:           true,
					RetainSnapshots:   30,
					RetainEvents:      1000,
					SnapshotDirectory: "./felix-state",
				}
			}
			if key == "webhooks" {
				activeStrList = nil
				curState = stateMonitorWebhookItem
				continue
			}
			if !validMonitoringKeys[key] {
				return nil, fmt.Errorf("line %d: unknown field %q in monitoring section", lineNum, key)
			}
			if err := applyMonitoringField(prof.Monitoring, key, val, &activeStrList, &activeListIndent, indent); err != nil {
				return nil, fmt.Errorf("line %d: invalid value for %s: %v", lineNum, key, err)
			}

		case stateMonitorWebhookItem:
			if prof.Monitoring == nil || curWebhookIdx < 0 || curWebhookIdx >= len(prof.Monitoring.Webhooks) {
				return nil, fmt.Errorf("line %d: webhook field %q declared without webhook item", lineNum, key)
			}
			if !validWebhookKeys[key] {
				return nil, fmt.Errorf("line %d: unknown field %q in webhook section", lineNum, key)
			}
			if err := applyWebhookField(&prof.Monitoring.Webhooks[curWebhookIdx], key, val); err != nil {
				return nil, fmt.Errorf("line %d: invalid value for %s: %v", lineNum, key, err)
			}
		}
	}

	return prof, nil
}

func applyMonitoringField(m *MonitoringConfig, key, val string, activeList **[]string, activeListIndent *int, curIndent int) error {
	switch key {
	case "enabled":
		b, err := parseBoolStrict(val)
		if err != nil {
			return err
		}
		m.Enabled = b
	case "snapshot_directory":
		m.SnapshotDirectory = val
	case "retain_snapshots":
		n, err := strconv.Atoi(val)
		if err != nil {
			return err
		}
		m.RetainSnapshots = n
	case "retain_events":
		n, err := strconv.Atoi(val)
		if err != nil {
			return err
		}
		m.RetainEvents = n
	case "notify_on":
		*activeList = &m.NotifyOn
		*activeListIndent = curIndent + 2
		if val != "" && val != "[]" {
			m.NotifyOn = append(m.NotifyOn, parseInlineList(val)...)
		}
	}
	return nil
}

func applyWebhookField(w *MonitorWebhookConfig, key, val string) error {
	switch key {
	case "id":
		w.ID = val
	case "provider":
		w.Provider = strings.ToLower(val)
	case "credential_env":
		w.CredentialEnv = val
	case "url":
		w.URL = val
	case "enabled":
		b, err := parseBoolStrict(val)
		if err != nil {
			return err
		}
		w.Enabled = b
	case "allow_insecure_http":
		b, err := parseBoolStrict(val)
		if err != nil {
			return err
		}
		w.AllowInsecureHTTP = b
	case "allow_loopback":
		b, err := parseBoolStrict(val)
		if err != nil {
			return err
		}
		w.AllowLoopback = b
	case "allow_private_ips":
		b, err := parseBoolStrict(val)
		if err != nil {
			return err
		}
		w.AllowPrivateIPs = b
	}
	return nil
}

func applyTenantField(t *TenantConfig, key, val string, activeList **[]string, activeListIndent *int, curIndent int) {
	switch key {
	case "id":
		t.ID = val
		*activeList = nil
	case "identity":
		t.Identity = val
		*activeList = nil
	case "credential_env":
		t.CredentialEnv = val
		*activeList = nil
	case "resource_ids":
		*activeList = &t.ResourceIDs
		*activeListIndent = curIndent + 2
		if val != "" && val != "[]" {
			t.ResourceIDs = append(t.ResourceIDs, parseInlineList(val)...)
		}
	case "headers":
		*activeList = nil
		if t.Headers == nil {
			t.Headers = make(map[string]string)
		}
	}
}

func applyComparisonField(c *TenantComparison, key, val string) {
	switch key {
	case "requester_tenant":
		c.RequesterTenant = val
	case "resource_owner_tenant":
		c.ResourceOwnerTenant = val
	case "resource_id":
		c.ResourceID = val
	case "path":
		c.Path = val
	case "method":
		c.Method = strings.ToUpper(val)
	case "expected_marker":
		c.ExpectedMarker = val
	}
}

func parseBoolStrict(s string) (bool, error) {
	lower := strings.ToLower(strings.TrimSpace(s))
	switch lower {
	case "true", "yes", "on", "1":
		return true, nil
	case "false", "no", "off", "0":
		return false, nil
	default:
		return false, fmt.Errorf("expected boolean value, got %q", s)
	}
}

func parseInlineList(s string) []string {
	clean := strings.Trim(s, "[]")
	if strings.TrimSpace(clean) == "" {
		return nil
	}
	parts := strings.Split(clean, ",")
	var result []string
	for _, p := range parts {
		item := strings.Trim(strings.TrimSpace(p), `"'`)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

func applyProfileDefaults(p *TargetProfile) {
	if p.Version == 0 {
		p.Version = 1
	}
	if p.Safety.Mode == "" {
		p.Safety.Mode = "non_destructive"
	}
	if p.Safety.MaxRequests <= 0 {
		p.Safety.MaxRequests = 100
	}
	if p.Safety.RequestsPerSecond <= 0 {
		p.Safety.RequestsPerSecond = 5.0
	}
	if p.Safety.TimeoutSeconds <= 0 {
		p.Safety.TimeoutSeconds = 10
	}
	if len(p.Target.AllowedMethods) == 0 {
		p.Target.AllowedMethods = []string{"GET", "HEAD", "OPTIONS"}
	}
	if len(p.Target.AllowedHosts) == 0 {
		for _, rawURL := range p.Target.BaseURLs {
			if u, err := url.Parse(rawURL); err == nil && u.Hostname() != "" {
				p.Target.AllowedHosts = append(p.Target.AllowedHosts, strings.ToLower(u.Hostname()))
			}
		}
	}

	if p.Monitoring != nil {
		if p.Monitoring.SnapshotDirectory == "" {
			p.Monitoring.SnapshotDirectory = "./felix-state"
		}
		if p.Monitoring.RetainSnapshots <= 0 {
			p.Monitoring.RetainSnapshots = 30
		}
		if p.Monitoring.RetainEvents <= 0 {
			p.Monitoring.RetainEvents = 1000
		}
	}
}

// ValidateProfile validates all constraints, safety boundaries, and cross-references of a TargetProfile.
func ValidateProfile(p *TargetProfile) error {
	if p == nil {
		return errors.New("profile cannot be nil")
	}

	// 1. Version validation
	if p.Version != 1 {
		return fmt.Errorf("unsupported profile version %d (supported: 1)", p.Version)
	}

	// 2. Target validation
	if len(p.Target.BaseURLs) == 0 {
		return errors.New("target.base_urls cannot be empty; at least one base URL is required")
	}

	for _, rawURL := range p.Target.BaseURLs {
		if len(rawURL) > MaxProfileStringLen {
			return fmt.Errorf("base_url exceeds max length of %d", MaxProfileStringLen)
		}
		u, err := url.Parse(rawURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("invalid target base_url %q", rawURL)
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" {
			return fmt.Errorf("unsupported scheme %q in base_url %q; only http and https are permitted", scheme, rawURL)
		}
		if u.User != nil {
			return fmt.Errorf("target base_url %q must not contain embedded user credentials", rawURL)
		}
	}

	for _, method := range p.Target.AllowedMethods {
		upper := strings.ToUpper(strings.TrimSpace(method))
		if prohibitedMutatingMethods[upper] {
			return fmt.Errorf("destructive/mutating method %q is strictly prohibited in allowed_methods", upper)
		}
		if !allowedNonDestructiveMethods[upper] {
			return fmt.Errorf("unsupported method %q in allowed_methods; only GET, HEAD, OPTIONS are permitted", upper)
		}
	}

	// 3. Safety validation
	if p.Safety.Mode != "" && p.Safety.Mode != "non_destructive" {
		return fmt.Errorf("invalid safety mode %q; only 'non_destructive' is permitted", p.Safety.Mode)
	}
	if p.Safety.MaxRequests <= 0 || p.Safety.MaxRequests > 10000 {
		return fmt.Errorf("safety.max_requests must be between 1 and 10000 (got %d)", p.Safety.MaxRequests)
	}
	if p.Safety.RequestsPerSecond <= 0 || p.Safety.RequestsPerSecond > 500 {
		return fmt.Errorf("safety.requests_per_second must be between 0.1 and 500 (got %f)", p.Safety.RequestsPerSecond)
	}
	if p.Safety.TimeoutSeconds <= 0 || p.Safety.TimeoutSeconds > 300 {
		return fmt.Errorf("safety.timeout_seconds must be between 1 and 300 (got %d)", p.Safety.TimeoutSeconds)
	}

	// 4. Tenant validation
	if len(p.Tenants) > MaxTenantsCount {
		return fmt.Errorf("exceeded maximum tenant limit of %d (got %d)", MaxTenantsCount, len(p.Tenants))
	}

	tenantMap := make(map[string]TenantConfig)
	for i, t := range p.Tenants {
		tid := strings.TrimSpace(t.ID)
		if tid == "" {
			return fmt.Errorf("tenant[%d] has missing or empty id", i)
		}
		if len(tid) > MaxProfileStringLen {
			return fmt.Errorf("tenant id %q exceeds max length of %d", tid, MaxProfileStringLen)
		}
		if _, exists := tenantMap[tid]; exists {
			return fmt.Errorf("duplicate tenant id %q declared in profile", tid)
		}

		if t.CredentialEnv != "" && !rxValidEnvVar.MatchString(t.CredentialEnv) {
			return fmt.Errorf("invalid credential_env variable name %q for tenant %q", t.CredentialEnv, tid)
		}

		if len(t.ResourceIDs) > MaxResourceIDsCount {
			return fmt.Errorf("tenant %q exceeds maximum resource_ids limit of %d", tid, MaxResourceIDsCount)
		}

		tenantMap[tid] = t
	}

	// 5. Cross-tenant test validation
	if len(p.CrossTenantTests.Comparisons) > MaxComparisonsCount {
		return fmt.Errorf("exceeded maximum comparison limit of %d (got %d)", MaxComparisonsCount, len(p.CrossTenantTests.Comparisons))
	}

	seenComparisons := make(map[string]bool)

	for i, c := range p.CrossTenantTests.Comparisons {
		reqTenant := strings.TrimSpace(c.RequesterTenant)
		if reqTenant == "" {
			return fmt.Errorf("comparison[%d] missing requester_tenant", i)
		}
		ownerTenant := strings.TrimSpace(c.ResourceOwnerTenant)
		if ownerTenant == "" {
			return fmt.Errorf("comparison[%d] missing resource_owner_tenant", i)
		}

		if reqTenant == ownerTenant {
			return fmt.Errorf("comparison[%d]: requester_tenant (%q) cannot be the same as resource_owner_tenant", i, reqTenant)
		}

		if _, exists := tenantMap[reqTenant]; !exists {
			return fmt.Errorf("comparison[%d]: unknown requester_tenant %q not declared in tenants", i, reqTenant)
		}
		owner, exists := tenantMap[ownerTenant]
		if !exists {
			return fmt.Errorf("comparison[%d]: unknown resource_owner_tenant %q not declared in tenants", i, ownerTenant)
		}

		resID := strings.TrimSpace(c.ResourceID)
		if resID == "" {
			return fmt.Errorf("comparison[%d] missing resource_id", i)
		}

		// Verify resource ownership: resource_id must be declared in owner's resource_ids
		hasResource := false
		for _, rid := range owner.ResourceIDs {
			if rid == resID {
				hasResource = true
				break
			}
		}
		if !hasResource {
			return fmt.Errorf("comparison[%d]: resource_id %q is not owned by or declared in resource_owner_tenant %q", i, resID, ownerTenant)
		}

		if c.Method != "" {
			upper := strings.ToUpper(strings.TrimSpace(c.Method))
			if prohibitedMutatingMethods[upper] {
				return fmt.Errorf("comparison[%d]: mutating method %q is prohibited", i, upper)
			}
			if !allowedNonDestructiveMethods[upper] {
				return fmt.Errorf("comparison[%d]: unsupported method %q", i, upper)
			}
		}

		compKey := fmt.Sprintf("%s|%s|%s|%s|%s", reqTenant, ownerTenant, resID, c.Path, c.Method)
		if seenComparisons[compKey] {
			return fmt.Errorf("duplicate comparison definition: requester %q, owner %q, resource %q", reqTenant, ownerTenant, resID)
		}
		seenComparisons[compKey] = true
	}

	// 6. Monitoring validation (P14.5)
	if p.Monitoring != nil && p.Monitoring.Enabled {
		if p.Monitoring.RetainSnapshots < 0 {
			return fmt.Errorf("monitoring.retain_snapshots cannot be negative")
		}
		if p.Monitoring.RetainEvents < 0 {
			return fmt.Errorf("monitoring.retain_events cannot be negative")
		}
		seenWebhooks := make(map[string]bool)
		for wi, w := range p.Monitoring.Webhooks {
			wid := strings.TrimSpace(w.ID)
			if wid == "" {
				return fmt.Errorf("webhook[%d] missing id", wi)
			}
			if seenWebhooks[wid] {
				return fmt.Errorf("duplicate webhook id %q in monitoring", wid)
			}
			seenWebhooks[wid] = true

			prov := strings.ToLower(strings.TrimSpace(w.Provider))
			if prov != "" && prov != "slack" && prov != "discord" && prov != "teams" && prov != "webhook" {
				return fmt.Errorf("webhook %q: unsupported provider %q (supported: slack, discord, teams, webhook)", wid, prov)
			}
			if w.CredentialEnv != "" && !rxValidEnvVar.MatchString(w.CredentialEnv) {
				return fmt.Errorf("webhook %q: invalid credential_env variable name %q", wid, w.CredentialEnv)
			}
		}
	}

	return nil
}

func splitYAMLKeyValue(s string) (string, string, string, bool) {
	// A quoted string is not a key: value line
	if strings.HasPrefix(s, "\"") || strings.HasPrefix(s, "'") {
		return "", "", "", false
	}
	colonIdx := strings.Index(s, ":")
	if colonIdx == -1 {
		return "", "", "", false
	}
	// Colon must be followed by space or end of line (e.g. key: val or key:)
	if colonIdx < len(s)-1 && s[colonIdx+1] != ' ' && s[colonIdx+1] != '\t' {
		return "", "", "", false
	}
	rawKey := strings.TrimSpace(s[:colonIdx])
	key := strings.ToLower(rawKey)
	val := strings.Trim(strings.TrimSpace(s[colonIdx+1:]), `"'`)
	return key, rawKey, val, true
}
