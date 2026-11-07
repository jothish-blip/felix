package mobile

import (
	"fmt"
	"strings"
)

// RuntimeFindingsEvaluator inspects collected RuntimeEvents and derives evidence-backed MobileFindings.
type RuntimeFindingsEvaluator struct{}

// NewRuntimeFindingsEvaluator creates a new findings evaluator instance.
func NewRuntimeFindingsEvaluator() *RuntimeFindingsEvaluator {
	return &RuntimeFindingsEvaluator{}
}

// EvaluateEvents maps observed runtime behaviors to structured MobileFinding instances.
func (e *RuntimeFindingsEvaluator) EvaluateEvents(packageID string, events []RuntimeEvent) []MobileFinding {
	var findings []MobileFinding
	seenRules := make(map[string]bool)

	for _, evt := range events {
		switch evt.Type {
		case EventTypeCrypto:
			fList := e.evaluateCryptoEvent(packageID, evt)
			for _, f := range fList {
				key := f.RuleID + ":" + f.ComponentOrKey + ":" + f.ObservedValue
				if !seenRules[key] {
					seenRules[key] = true
					findings = append(findings, f)
				}
			}

		case EventTypeNetwork:
			f := e.evaluateNetworkEvent(packageID, evt)
			if f != nil {
				key := f.RuleID + ":" + f.ComponentOrKey + ":" + f.ObservedValue
				if !seenRules[key] {
					seenRules[key] = true
					findings = append(findings, *f)
				}
			}

		case EventTypeTLS:
			f := e.evaluateTLSEvent(packageID, evt)
			if f != nil {
				key := f.RuleID + ":" + f.ComponentOrKey + ":" + f.ObservedValue
				if !seenRules[key] {
					seenRules[key] = true
					findings = append(findings, *f)
				}
			}

		case EventTypeStorage:
			f := e.evaluateStorageEvent(packageID, evt)
			if f != nil {
				key := f.RuleID + ":" + f.ComponentOrKey + ":" + f.ObservedValue
				if !seenRules[key] {
					seenRules[key] = true
					findings = append(findings, *f)
				}
			}
		}
	}

	SortFindings(findings)
	return findings
}

func (e *RuntimeFindingsEvaluator) evaluateCryptoEvent(packageID string, evt RuntimeEvent) []MobileFinding {
	var results []MobileFinding
	if evt.Details == nil {
		return nil
	}

	// 1. Weak Cryptographic Algorithm or Insecure Mode
	transform, _ := evt.Details["transformation"].(string)
	alg, _ := evt.Details["algorithm"].(string)
	keyAlg, _ := evt.Details["key_algorithm"].(string)
	if transform == "" && alg != "" {
		transform = alg
	}
	if transform == "" && keyAlg != "" {
		transform = keyAlg
	}

	upperTransform := strings.ToUpper(transform)
	if upperTransform != "" {
		if strings.Contains(upperTransform, "ECB") || strings.Contains(upperTransform, "/ECB/") {
			loc := fmt.Sprintf("%s#%s", evt.Class, evt.Method)
			f := MobileFinding{
				ID:             ComputeDeterministicFindingID(PlatformAndroid, packageID, "RUNTIME-CRYPTO-WEAK-ALGORITHM", loc),
				RuleID:         "RUNTIME-CRYPTO-WEAK-ALGORITHM",
				Title:          "[Android Runtime] Electronic Codebook (ECB) Mode Observed in Cipher",
				Platform:       PlatformAndroid,
				PackageID:      packageID,
				ComponentOrKey: loc,
				ObservedValue:  fmt.Sprintf("Transformation: %s", transform),
				ExpectedValue:  "Authenticated encryption modes such as AES/GCM/NoPadding or randomized CBC with HMAC",
				Severity:       "HIGH",
				Confidence:     "HIGH",
				Classification: ClassificationConfirmed,
				EvidenceSource: fmt.Sprintf("Frida hook: %s#%s at %s", evt.Class, evt.Method, evt.Timestamp.Format("15:04:05.000")),
				Explanation:    fmt.Sprintf("Target application dynamically invoked %s with %s. ECB mode encrypts identical plaintext blocks into identical ciphertext blocks, leaking semantic structure.", evt.Class, transform),
				Remediation:    "Use AES-GCM or AES-CBC with a cryptographically random initialization vector.",
			}
			results = append(results, f)
		} else if strings.HasPrefix(upperTransform, "DES") || strings.Contains(upperTransform, "/DES/") || upperTransform == "RC4" {
			loc := fmt.Sprintf("%s#%s", evt.Class, evt.Method)
			f := MobileFinding{
				ID:             ComputeDeterministicFindingID(PlatformAndroid, packageID, "RUNTIME-CRYPTO-WEAK-ALGORITHM", loc),
				RuleID:         "RUNTIME-CRYPTO-WEAK-ALGORITHM",
				Title:          "[Android Runtime] Insecure Legacy Cipher Algorithm Observed",
				Platform:       PlatformAndroid,
				PackageID:      packageID,
				ComponentOrKey: loc,
				ObservedValue:  fmt.Sprintf("Algorithm: %s", transform),
				ExpectedValue:  "Industry-standard symmetric encryption algorithms such as AES-256 or ChaCha20",
				Severity:       "CRITICAL",
				Confidence:     "HIGH",
				Classification: ClassificationConfirmed,
				EvidenceSource: fmt.Sprintf("Frida hook: %s#%s at %s", evt.Class, evt.Method, evt.Timestamp.Format("15:04:05.000")),
				Explanation:    fmt.Sprintf("Target application dynamically initialized legacy cipher algorithm %s. Legacy ciphers provide inadequate cryptographic security margins and are vulnerable to cryptanalysis.", transform),
				Remediation:    "Migrate to AES-256 with GCM or CBC mode.",
			}
			results = append(results, f)
		}
	}

	// 2. Static / All-Zero Initialization Vector
	ivZeros, _ := evt.Details["iv_all_zeros"].(bool)
	ivLen, _ := evt.Details["iv_length_bytes"].(float64)
	if !ivZeros {
		// check integer format
		if iz, ok := evt.Details["iv_all_zeros"].(int); ok && iz == 1 {
			ivZeros = true
		}
	}

	if ivZeros {
		loc := fmt.Sprintf("%s#%s", evt.Class, evt.Method)
		f := MobileFinding{
			ID:             ComputeDeterministicFindingID(PlatformAndroid, packageID, "RUNTIME-STATIC-IV", loc),
			RuleID:         "RUNTIME-STATIC-IV",
			Title:          "[Android Runtime] All-Zero Initialization Vector (IV) Passed to Cipher",
			Platform:       PlatformAndroid,
			PackageID:      packageID,
			ComponentOrKey: loc,
			ObservedValue:  fmt.Sprintf("All-Zero IV (%d bytes)", int(ivLen)),
			ExpectedValue:  "Cryptographically random initialization vectors generated via SecureRandom for each operation",
			Severity:       "MEDIUM",
			Confidence:     "HIGH",
			Classification: ClassificationConfirmed,
			EvidenceSource: fmt.Sprintf("Frida hook: %s#%s at %s", evt.Class, evt.Method, evt.Timestamp.Format("15:04:05.000")),
			Explanation:    fmt.Sprintf("Target application dynamically passed an all-zero IV (%d bytes) to %s. Static IV reuse breaks semantic confidentiality across cipher operations.", int(ivLen), loc),
			Remediation:    "Generate fresh, random 16-byte IVs for each encryption operation using SecureRandom.",
		}
		results = append(results, f)
	}

	return results
}

func (e *RuntimeFindingsEvaluator) evaluateNetworkEvent(packageID string, evt RuntimeEvent) *MobileFinding {
	if evt.Details == nil {
		return nil
	}

	cleartext, _ := evt.Details["cleartext"].(bool)
	host, _ := evt.Details["host"].(string)
	proto, _ := evt.Details["protocol"].(string)
	path, _ := evt.Details["path"].(string)

	if cleartext || proto == "http" {
		// Suppress localhost / mock loopbacks from high severity
		isLocal := host == "localhost" || host == "127.0.0.1" || host == "10.0.2.2"
		sev := "HIGH"
		cls := ClassificationConfirmed
		if isLocal {
			sev = "MEDIUM"
		}

		loc := fmt.Sprintf("%s:%s", host, path)
		return &MobileFinding{
			ID:             ComputeDeterministicFindingID(PlatformAndroid, packageID, "RUNTIME-CLEARTEXT-HTTP", loc),
			RuleID:         "RUNTIME-CLEARTEXT-HTTP",
			Title:          "[Android Runtime] Plaintext HTTP Network Request Observed",
			Platform:       PlatformAndroid,
			PackageID:      packageID,
			ComponentOrKey: loc,
			ObservedValue:  fmt.Sprintf("http://%s%s", host, path),
			ExpectedValue:  "Encrypted HTTPS transport using TLS 1.2+",
			Severity:       sev,
			Confidence:     "HIGH",
			Classification: cls,
			EvidenceSource: fmt.Sprintf("Frida hook: %s#%s at %s", evt.Class, evt.Method, evt.Timestamp.Format("15:04:05.000")),
			Explanation:    fmt.Sprintf("Target application initiated unencrypted HTTP communication with %s. Plaintext traffic is subject to interception and tampering.", loc),
			Remediation:    "Enforce HTTPS across all network endpoints and declare cleartextTrafficPermitted=false in Network Security Configuration.",
		}
	}

	return nil
}

func (e *RuntimeFindingsEvaluator) evaluateTLSEvent(packageID string, evt RuntimeEvent) *MobileFinding {
	if evt.Details == nil {
		return nil
	}

	insecureTrust, _ := evt.Details["insecure_trust"].(bool)
	if insecureTrust {
		loc := fmt.Sprintf("%s#%s", evt.Class, evt.Method)
		return &MobileFinding{
			ID:             ComputeDeterministicFindingID(PlatformAndroid, packageID, "RUNTIME-INSECURE-TRUST-MANAGER", loc),
			RuleID:         "RUNTIME-INSECURE-TRUST-MANAGER",
			Title:          "[Android Runtime] Empty X509TrustManager (Bypass All Certificates)",
			Platform:       PlatformAndroid,
			PackageID:      packageID,
			ComponentOrKey: loc,
			ObservedValue:  "Empty checkServerTrusted implementation observed accepting all certificates",
			ExpectedValue:  "Standard system TrustManager enforcing valid CA chains and certificate validation",
			Severity:       "CRITICAL",
			Confidence:     "HIGH",
			Classification: ClassificationConfirmed,
			EvidenceSource: fmt.Sprintf("Frida hook: %s#%s at %s", evt.Class, evt.Method, evt.Timestamp.Format("15:04:05.000")),
			Explanation:    "The application implements an empty or dummy X509TrustManager that blindly validates all server certificates, exposing users to trivial Machine-in-the-Middle (MitM) attacks.",
			Remediation:    "Remove custom TrustManager implementations and use Android's default network security config.",
		}
	}

	return nil
}

func (e *RuntimeFindingsEvaluator) evaluateStorageEvent(packageID string, evt RuntimeEvent) *MobileFinding {
	if evt.Details == nil {
		return nil
	}

	isSensitive, _ := evt.Details["sensitive"].(bool)
	key, _ := evt.Details["key"].(string)
	valPreview, _ := evt.Details["value_preview"].(string)

	if isSensitive {
		loc := fmt.Sprintf("SharedPreferences:%s", key)
		return &MobileFinding{
			ID:             ComputeDeterministicFindingID(PlatformAndroid, packageID, "RUNTIME-INSECURE-STORAGE", loc),
			RuleID:         "RUNTIME-INSECURE-STORAGE",
			Title:          "[Android Runtime] Plaintext Sensitive Data Written to SharedPreferences",
			Platform:       PlatformAndroid,
			PackageID:      packageID,
			ComponentOrKey: loc,
			ObservedValue:  fmt.Sprintf("Key: %s | Redacted Value: %s", key, valPreview),
			ExpectedValue:  "EncryptedSharedPreferences or Android Keystore backed encryption for sensitive data",
			Severity:       "MEDIUM",
			Confidence:     "HIGH",
			Classification: ClassificationConfirmed,
			EvidenceSource: fmt.Sprintf("Frida hook: %s#%s at %s", evt.Class, evt.Method, evt.Timestamp.Format("15:04:05.000")),
			Explanation:    fmt.Sprintf("Application persisted sensitive key %q to SharedPreferences in unencrypted XML format.", key),
			Remediation:    "Use EncryptedSharedPreferences from Android Jetpack Security.",
		}
	}

	return nil
}

// RedactSensitiveHeaders sanitizes authentication tokens, cookies, and API keys.
func RedactSensitiveHeaders(headers map[string]string) map[string]string {
	sanitized := make(map[string]string, len(headers))
	sensitiveKeys := []string{"authorization", "cookie", "set-cookie", "x-api-key", "token", "auth"}

	for k, v := range headers {
		lower := strings.ToLower(k)
		isSens := false
		for _, s := range sensitiveKeys {
			if strings.Contains(lower, s) {
				isSens = true
				break
			}
		}
		if isSens {
			sanitized[k] = RedactSecret(v)
		} else {
			sanitized[k] = v
		}
	}
	return sanitized
}

// RedactSensitiveMap sanitizes sensitive keys within generic data maps.
func RedactSensitiveMap(data map[string]any) map[string]any {
	out := make(map[string]any, len(data))
	for k, v := range data {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "password") || strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "key_bytes") {
			if strVal, ok := v.(string); ok {
				out[k] = RedactSecret(strVal)
			} else {
				out[k] = "[REDACTED]"
			}
		} else {
			out[k] = v
		}
	}
	return out
}
