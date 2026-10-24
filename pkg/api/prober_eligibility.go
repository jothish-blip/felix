package api

import (
	"fmt"
	"net/url"
	"strings"
)

var (
	// Potentially destructive or state-changing keywords in path
	mutatingKeywords = map[string]bool{
		"delete":    true,
		"drop":      true,
		"destroy":   true,
		"kill":      true,
		"purge":     true,
		"reset":     true,
		"reboot":    true,
		"shutdown":  true,
		"cancel":    true,
		"terminate": true,
		"pay":       true,
		"checkout":  true,
		"transfer":  true,
		"mutate":    true,
		"execute":   true,
		"run":       true,
		"modify":    true,
		"update":    true,
		"set":       true,
		"revoke":    true,
		"ban":       true,
		"lock":      true,
		"uninstall": true,
		"remove":    true,
		"clear":     true,
	}

	// Strictly prohibited methods for automated live exploitability probing
	prohibitedProbeMethods = map[string]bool{
		"POST":   true,
		"PUT":    true,
		"DELETE": true,
		"PATCH":  true,
	}
)

// ProbeEligibility evaluates whether a candidate can be safely and legitimately probed.
type ProbeEligibility struct {
	IsEligible     bool
	ResolvedURL    string
	SelectedMethod string // "HEAD", "OPTIONS", "GET", or ""
	Reason         string
	IsScopeBlocked bool
	IsSafeRefusal  bool
}

// EvaluateEligibility evaluates an API candidate against target scope, safety policy, and safe method rules.
func EvaluateEligibility(candidatePath string, candidateMethod string, targetBaseURL string, opts ProberOptions) ProbeEligibility {
	trimmedPath := strings.TrimSpace(candidatePath)
	if trimmedPath == "" {
		return ProbeEligibility{
			IsEligible:    false,
			IsSafeRefusal: true,
			Reason:        "Candidate path is empty",
		}
	}

	// 1. Resolve full destination URL
	var resolvedURL string
	var destHost string

	if strings.HasPrefix(trimmedPath, "http://") || strings.HasPrefix(trimmedPath, "https://") {
		// Absolute URL candidate
		parsed, err := url.Parse(trimmedPath)
		if err != nil {
			return ProbeEligibility{
				IsEligible:    false,
				IsSafeRefusal: true,
				Reason:        fmt.Sprintf("Malformed absolute URL candidate: %v", err),
			}
		}
		resolvedURL = trimmedPath
		destHost = strings.ToLower(parsed.Hostname())
	} else {
		// Relative path candidate: resolve against target base URL
		if targetBaseURL == "" {
			return ProbeEligibility{
				IsEligible:    false,
				IsSafeRefusal: true,
				Reason:        "Missing target base URL for relative candidate path",
			}
		}
		baseParsed, err := url.Parse(targetBaseURL)
		if err != nil {
			return ProbeEligibility{
				IsEligible:    false,
				IsSafeRefusal: true,
				Reason:        fmt.Sprintf("Invalid target base URL: %v", err),
			}
		}

		cleanRel := trimmedPath
		if !strings.HasPrefix(cleanRel, "/") {
			cleanRel = "/" + cleanRel
		}

		resolvedURL = strings.TrimRight(targetBaseURL, "/") + cleanRel
		destHost = strings.ToLower(baseParsed.Hostname())
	}

	// 2. Validate Scheme: only http and https are permitted
	if !strings.HasPrefix(resolvedURL, "http://") && !strings.HasPrefix(resolvedURL, "https://") {
		return ProbeEligibility{
			IsEligible:    false,
			IsSafeRefusal: true,
			Reason:        fmt.Sprintf("Unsupported or unsafe URI scheme: %s", resolvedURL),
		}
	}

	// 3. Target Scope and Authorization Check (P14.3-A)
	if opts.ScopeHost != "" {
		allowedHost := strings.ToLower(opts.ScopeHost)
		if destHost != allowedHost && !strings.HasSuffix(destHost, "."+allowedHost) {
			return ProbeEligibility{
				IsEligible:     false,
				IsScopeBlocked: true,
				Reason:         fmt.Sprintf("Destination host %q is outside authorized target scope (%s)", destHost, opts.ScopeHost),
			}
		}
	}

	if opts.IsAllowed != nil && !opts.IsAllowed(resolvedURL) {
		return ProbeEligibility{
			IsEligible:     false,
			IsScopeBlocked: true,
			Reason:         fmt.Sprintf("Destination URL %s is not permitted by assessment scope rules", resolvedURL),
		}
	}

	if opts.IsExcluded != nil && opts.IsExcluded(resolvedURL) {
		return ProbeEligibility{
			IsEligible:     false,
			IsScopeBlocked: true,
			Reason:         fmt.Sprintf("Destination URL %s matches configured exclusion pattern", resolvedURL),
		}
	}

	// 4. Check for unresolvable dynamic parameter placeholders in path
	if strings.Contains(trimmedPath, "{param}") || strings.Contains(trimmedPath, "{id}") || strings.Contains(trimmedPath, "{userId}") {
		// Do not invent fake identifiers or attempt parameter injection; use OPTIONS or HEAD for safe structural check
		if opts.EnableOPTIONS {
			return ProbeEligibility{
				IsEligible:     true,
				ResolvedURL:    resolvedURL,
				SelectedMethod: "OPTIONS",
				Reason:         "Unresolved dynamic parameter in path; restricted to non-destructive OPTIONS metadata check",
			}
		} else if opts.EnableHEAD {
			return ProbeEligibility{
				IsEligible:     true,
				ResolvedURL:    resolvedURL,
				SelectedMethod: "HEAD",
				Reason:         "Unresolved dynamic parameter in path; restricted to non-destructive HEAD check",
			}
		} else {
			return ProbeEligibility{
				IsEligible:    false,
				IsSafeRefusal: true,
				Reason:        "Unresolved dynamic path parameter cannot be safely constructed without identifier injection",
			}
		}
	}

	// 5. Check for mutating keywords in path (P14.3-E)
	hasMutatingKeyword := false
	pathSegments := strings.Split(strings.ToLower(trimmedPath), "/")
	for _, seg := range pathSegments {
		cleanSeg := strings.Trim(seg, ".-_?=&")
		if mutatingKeywords[cleanSeg] {
			hasMutatingKeyword = true
			break
		}
	}

	upperCandidateMethod := strings.ToUpper(strings.TrimSpace(candidateMethod))

	// 6. Select non-destructive probe method
	// If candidate method is inherently mutating (POST, PUT, DELETE, PATCH), NEVER issue a mutating probe
	if prohibitedProbeMethods[upperCandidateMethod] || hasMutatingKeyword {
		if opts.EnableOPTIONS {
			return ProbeEligibility{
				IsEligible:     true,
				ResolvedURL:    resolvedURL,
				SelectedMethod: "OPTIONS",
				Reason:         fmt.Sprintf("Candidate operation (%s) or path has potential mutation side effects; restricted to safe OPTIONS probe", upperCandidateMethod),
			}
		} else if opts.EnableHEAD {
			return ProbeEligibility{
				IsEligible:     true,
				ResolvedURL:    resolvedURL,
				SelectedMethod: "HEAD",
				Reason:         fmt.Sprintf("Candidate operation (%s) or path has potential mutation side effects; restricted to safe HEAD probe", upperCandidateMethod),
			}
		} else {
			return ProbeEligibility{
				IsEligible:    false,
				IsSafeRefusal: true,
				Reason:        fmt.Sprintf("Candidate operation (%s) has potential side effects; skipped by safe-probe policy", upperCandidateMethod),
			}
		}
	}

	// For standard read operations, default to safe GET if enabled, else HEAD or OPTIONS
	if opts.EnableSafeGET && (upperCandidateMethod == "GET" || upperCandidateMethod == "UNKNOWN" || upperCandidateMethod == "") {
		return ProbeEligibility{
			IsEligible:     true,
			ResolvedURL:    resolvedURL,
			SelectedMethod: "GET",
			Reason:         "Candidate is an eligible non-destructive read operation",
		}
	}

	if opts.EnableHEAD {
		return ProbeEligibility{
			IsEligible:     true,
			ResolvedURL:    resolvedURL,
			SelectedMethod: "HEAD",
			Reason:         "Safe HEAD probe selected by prober options",
		}
	}

	if opts.EnableOPTIONS {
		return ProbeEligibility{
			IsEligible:     true,
			ResolvedURL:    resolvedURL,
			SelectedMethod: "OPTIONS",
			Reason:         "Safe OPTIONS probe selected by prober options",
		}
	}

	return ProbeEligibility{
		IsEligible:    false,
		IsSafeRefusal: true,
		Reason:        "No safe non-destructive probe method enabled in configuration",
	}
}
