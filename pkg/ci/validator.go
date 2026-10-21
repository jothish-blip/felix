package ci

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"felix/pkg/policy"
)

var dangerousMetachars = []string{";", "&", "|", "`", "$", "<", ">", "\n", "\r", "\x00"}

// SanitizeUntrustedInput validates that an untrusted workflow input does not contain
// command-injection sequences, control characters, or malicious shell metacharacters.
func SanitizeUntrustedInput(field, val string) error {
	for _, m := range dangerousMetachars {
		if strings.Contains(val, m) {
			return fmt.Errorf("invalid %s: contains prohibited control or shell character %q", field, m)
		}
	}
	return nil
}

// ValidateConfig verifies that the CI configuration is complete, well-formed, and secure.
func ValidateConfig(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// 1. Target scope selection: exactly one of TargetURL or AssessmentRef must be provided
	hasTarget := strings.TrimSpace(cfg.TargetURL) != ""
	hasAsm := strings.TrimSpace(cfg.AssessmentRef) != ""

	if !hasTarget && !hasAsm {
		return fmt.Errorf("either target URL (--target) or assessment project reference (--assessment) must be configured")
	}
	if hasTarget && hasAsm {
		return fmt.Errorf("cannot configure both --target and --assessment; select exactly one execution target")
	}

	// 2. Validate Target URL
	if hasTarget {
		raw := strings.TrimSpace(cfg.TargetURL)
		if err := SanitizeUntrustedInput("target_url", raw); err != nil {
			return err
		}

		u, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("invalid target URL %q: %w", raw, err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("target URL scheme must be http or https, got %q", u.Scheme)
		}
		if u.Hostname() == "" {
			return fmt.Errorf("target URL %q must include a valid host name", raw)
		}
		cfg.TargetURL = raw
	}

	// 3. Validate Assessment Reference
	if hasAsm {
		raw := strings.TrimSpace(cfg.AssessmentRef)
		if err := SanitizeUntrustedInput("assessment_ref", raw); err != nil {
			return err
		}
		if strings.Contains(raw, "..") || strings.Contains(raw, "/") || strings.Contains(raw, "\\") {
			return fmt.Errorf("invalid assessment reference %q: contains path traversal characters", raw)
		}
		cfg.AssessmentRef = raw
	}

	// 4. Validate Policy Path
	if strings.TrimSpace(cfg.PolicyPath) != "" {
		p := filepath.Clean(strings.TrimSpace(cfg.PolicyPath))
		info, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("configured policy file not found at %q: %w", p, err)
		}
		if info.IsDir() {
			return fmt.Errorf("policy path %q is a directory, expected a policy file", p)
		}
		// Load and validate the policy to fail early on configuration errors
		if _, err := policy.LoadPolicy(p); err != nil {
			return fmt.Errorf("invalid threshold policy file %q: %w", p, err)
		}
		cfg.PolicyPath = p
	}

	// 5. Validate Baseline Reference and Scope
	if strings.TrimSpace(cfg.BaselineRef) != "" {
		rawBase := strings.TrimSpace(cfg.BaselineRef)
		if err := SanitizeUntrustedInput("baseline_ref", rawBase); err != nil {
			return err
		}
		cfg.BaselineRef = rawBase
	}

	if strings.TrimSpace(cfg.BaselineScope) != "" {
		scope := strings.ToLower(strings.TrimSpace(cfg.BaselineScope))
		switch scope {
		case "all", "new", "new_and_regressed":
			cfg.BaselineScope = scope
		default:
			return fmt.Errorf("invalid baseline-scope %q: must be one of 'all', 'new', 'new_and_regressed'", scope)
		}
	} else {
		cfg.BaselineScope = "all"
	}

	// 6. Validate Output Directory
	if strings.TrimSpace(cfg.OutputDir) == "" {
		cfg.OutputDir = "felix-reports"
	}
	cfg.OutputDir = filepath.Clean(strings.TrimSpace(cfg.OutputDir))
	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create report output directory %q: %w", cfg.OutputDir, err)
	}

	// 7. Validate Report Filenames
	if strings.TrimSpace(cfg.SARIFFile) == "" {
		cfg.SARIFFile = "felix.sarif"
	}
	if strings.TrimSpace(cfg.JSONFile) == "" {
		cfg.JSONFile = "felix.json"
	}
	if strings.TrimSpace(cfg.HTMLFile) == "" {
		cfg.HTMLFile = "felix.html"
	}

	// Prevent directory escape in filenames
	cfg.SARIFFile = filepath.Base(cfg.SARIFFile)
	cfg.JSONFile = filepath.Base(cfg.JSONFile)
	cfg.HTMLFile = filepath.Base(cfg.HTMLFile)

	// 8. Validate Feedback Configuration
	if cfg.FeedbackFailurePolicy != "" {
		pol := strings.ToLower(strings.TrimSpace(cfg.FeedbackFailurePolicy))
		if pol != "warn" && pol != "fail" {
			return fmt.Errorf("invalid feedback-failure-policy %q: must be 'warn' or 'fail'", cfg.FeedbackFailurePolicy)
		}
		cfg.FeedbackFailurePolicy = pol
	} else {
		cfg.FeedbackFailurePolicy = "warn"
	}

	if cfg.PRNumber < 0 {
		return fmt.Errorf("invalid pr-number %d: cannot be negative", cfg.PRNumber)
	}

	if strings.TrimSpace(cfg.GitHubRepo) != "" {
		repo := strings.TrimSpace(cfg.GitHubRepo)
		if err := SanitizeUntrustedInput("repo", repo); err != nil {
			return err
		}
		parts := strings.Split(repo, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("invalid repository format %q; expected 'owner/repo'", repo)
		}
		cfg.GitHubRepo = repo
	}

	if strings.TrimSpace(cfg.GitHubAPIBaseURL) != "" {
		raw := strings.TrimSpace(cfg.GitHubAPIBaseURL)
		if err := SanitizeUntrustedInput("github-api-url", raw); err != nil {
			return err
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("invalid github-api-url %q: must be valid http or https URL", raw)
		}
	}

	if strings.TrimSpace(cfg.CommentTag) != "" {
		if err := SanitizeUntrustedInput("comment-tag", cfg.CommentTag); err != nil {
			return err
		}
	}

	return nil
}
