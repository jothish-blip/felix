package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"felix/pkg/policy"
	"felix/pkg/secrets"
)

// SafeConfigAllowlist defines non-sensitive, provenance-relevant configuration keys.
var SafeConfigAllowlist = map[string]bool{
	"timeout_seconds":     true,
	"concurrency":         true,
	"scope_mode":          true,
	"max_assets":          true,
	"max_size_bytes":      true,
	"user_agent":          true,
	"felix_version":       true,
	"allow_loopback":      true,
	"allow_private_ips":   true,
	"active_verification": true,
	"scope_rules":         true,
	"exclusions":          true,
	"rate_limit":          true,
}

// ComputeConfigDigest canonicalizes safe configuration fields and computes a deterministic SHA-256 digest.
// It guarantees that:
// 1. Equivalent configurations produce the exact same digest regardless of map ordering.
// 2. Secret-bearing fields (tokens, passwords, headers, keys) are strictly excluded and never hashed or stored.
// 3. Changing a provenance-relevant field produces a distinct digest.
func ComputeConfigDigest(rawConfig any) (digest string, sanitized map[string]any, err error) {
	if rawConfig == nil {
		return "", nil, nil
	}

	// Convert rawConfig to an intermediate map via JSON round-trip
	data, err := json.Marshal(rawConfig)
	if err != nil {
		return "", nil, fmt.Errorf("failed marshaling raw config: %w", err)
	}

	var rawMap map[string]any
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return "", nil, fmt.Errorf("failed unmarshaling config to map: %w", err)
	}

	sanitized = make(map[string]any)
	for k, v := range rawMap {
		cleanKey := strings.ToLower(strings.TrimSpace(k))
		// Enforce allowlist and reject any sensitive keys
		if SafeConfigAllowlist[cleanKey] && !secrets.IsSensitiveKey(cleanKey) {
			switch val := v.(type) {
			case string:
				sanitized[cleanKey] = secrets.RedactText(val)
			case []any:
				var strList []string
				for _, item := range val {
					if s, ok := item.(string); ok {
						strList = append(strList, secrets.RedactText(s))
					}
				}
				sort.Strings(strList)
				sanitized[cleanKey] = strList
			default:
				sanitized[cleanKey] = val
			}
		}
	}

	// Canonicalize: sort keys and format deterministically
	keys := make([]string, 0, len(sanitized))
	for k := range sanitized {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	canonicalMap := make(map[string]any, len(keys))
	for _, k := range keys {
		canonicalMap[k] = sanitized[k]
	}

	canonicalJSON, err := json.Marshal(canonicalMap)
	if err != nil {
		return "", nil, fmt.Errorf("failed marshaling canonical config: %w", err)
	}

	h := sha256.New()
	h.Write(canonicalJSON)
	digest = "sha256:" + hex.EncodeToString(h.Sum(nil))

	return digest, sanitized, nil
}

// ComputePolicyDigest computes a deterministic SHA-256 digest of a security threshold policy.
// Changes to policy thresholds, baseline rules, or limits yield distinct digests.
func ComputePolicyDigest(pol *policy.ThresholdPolicy) string {
	if pol == nil {
		return ""
	}
	d := pol.Digest()
	if !strings.HasPrefix(d, "sha256:") {
		return "sha256:" + d
	}
	return d
}

// ComputeArtifactDigest computes the SHA-256 digest of an artifact file on disk.
func ComputeArtifactDigest(content []byte) string {
	if len(content) == 0 {
		return ""
	}
	h := sha256.New()
	h.Write(content)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
