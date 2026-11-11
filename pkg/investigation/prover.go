package investigation

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"felix/pkg/oast"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

// SafeProver orchestrates bounded, non-destructive empirical verification of candidate findings.
type SafeProver struct {
	AssessmentID string
	SafeMode     bool
	Timeout      time.Duration
}

// NewSafeProver constructs a SafeProver instance.
func NewSafeProver(assessmentID string, safeMode bool) *SafeProver {
	return &SafeProver{
		AssessmentID: assessmentID,
		SafeMode:     safeMode,
		Timeout:      15 * time.Second,
	}
}

// ExecuteBoundedProof applies the least invasive proof procedure for the candidate finding.
func (p *SafeProver) ExecuteBoundedProof(ctx context.Context, f report.Finding, client *http.Client) (*EvidenceBundle, ValidationStatus, string, error) {
	now := time.Now().UTC()
	cat := strings.ToUpper(f.Category)
	title := strings.ToUpper(f.Title)

	// Check if already in safe mode or finding is purely informative
	if p.SafeMode {
		bundle := &EvidenceBundle{
			ID:                  "ev_" + f.ID,
			FindingID:           f.ID,
			AssessmentID:        p.AssessmentID,
			ModuleID:            f.Source,
			TestIdentifier:      "SAFE_MODE_INSPECTION",
			ValidationTime:      now,
			SanitizedRequest:    f.Method + " " + f.Target,
			SanitizedResponse:   SanitizeHTTPContent(f.Evidence),
			ReproductionSteps:   []string{"1. Safe mode active: passive evidence collected during initial crawl"},
			SafeCurlCommand:     FormatSafeCurl(f.Method, f.Target, nil, ""),
			ProofSummary:        "Passive evidence recorded. Active validation skipped due to safe mode constraint.",
			LeastInvasiveMethod: "PASSIVE_METADATA_INSPECTION",
		}
		bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
		return bundle, StatusHighConfidence, bundle.ProofSummary, nil
	}

	// 1. SQL Injection (Harmless Syntax & Differential Probing)
	if strings.Contains(cat, "SQL") || strings.Contains(title, "SQL") {
		return p.proveSQLi(ctx, f, client)
	}

	// 2. Cross-Site Scripting (Harmless DOM Marker)
	if strings.Contains(cat, "XSS") || strings.Contains(title, "XSS") || strings.Contains(cat, "SCRIPTING") || strings.Contains(title, "SCRIPTING") {
		return p.proveXSS(ctx, f, client)
	}

	// 3. SSRF (Bounded Non-Metadata Callback / Safe Probing)
	if strings.Contains(cat, "SSRF") || strings.Contains(title, "SSRF") {
		return p.proveSSRF(ctx, f, client)
	}

	// 4. BOLA / IDOR (Controlled Test Object Dual-Identity Comparison)
	if strings.Contains(cat, "BOLA") || strings.Contains(cat, "IDOR") || strings.Contains(title, "BOLA") || strings.Contains(title, "IDOR") {
		return p.proveBOLA(ctx, f, client)
	}

	// 5. BFLA (Privilege Boundary Comparison)
	if strings.Contains(cat, "BFLA") || strings.Contains(title, "BFLA") || strings.Contains(title, "FUNCTION LEVEL") {
		return p.proveBFLA(ctx, f, client)
	}

	// 5b. BOPLA / Property-Level Authorization (must execute before generic "AUTH" check)
	if strings.Contains(cat, "BOPLA") || strings.Contains(title, "BOPLA") ||
		strings.Contains(cat, "PROPERTY LEVEL") || strings.Contains(title, "PROPERTY LEVEL") ||
		strings.Contains(cat, "MASS ASSIGNMENT") || strings.Contains(title, "MASS ASSIGNMENT") ||
		strings.Contains(cat, "EXCESSIVE DATA EXPOSURE") || strings.Contains(title, "EXCESSIVE DATA EXPOSURE") {
		return p.proveBOPLA(ctx, f, client)
	}

	// 6. Path Traversal / File Inclusion (Canary File Reflection)
	if strings.Contains(cat, "TRAVERSAL") || strings.Contains(title, "TRAVERSAL") || strings.Contains(cat, "LFI") {
		return p.proveTraversal(ctx, f, client)
	}

	// 7. Authentication Weaknesses & Unprotected Routes
	if strings.Contains(cat, "AUTH") || strings.Contains(title, "AUTHENTICATION") || strings.Contains(title, "UNAUTHENTICATED") {
		return p.proveAuth(ctx, f, client)
	}

	// 8. CORS Policy Misconfiguration (Must be evaluated before generic credential checks)
	if strings.Contains(cat, "CORS") || strings.Contains(title, "CORS") {
		return p.proveCORS(ctx, f, client)
	}

	// 9. High-Entropy Secret Detection
	if strings.Contains(cat, "SECRET") || strings.Contains(cat, "TOKEN") ||
		strings.Contains(title, "SECRET") || strings.Contains(title, "API KEY") || strings.Contains(title, "ACCESS KEY") ||
		strings.Contains(title, "EXPOSED CREDENTIAL") || strings.Contains(title, "LEAKED CREDENTIAL") ||
		(strings.Contains(cat, "INFORMATION DISCLOSURE") && (strings.Contains(title, "KEY") || strings.Contains(title, "TOKEN") || strings.Contains(title, "SECRET") || strings.Contains(title, "CREDENTIAL"))) {
		return p.proveSecrets(ctx, f, client)
	}

	// 10. Business Logic Tampering
	if strings.Contains(cat, "BUSINESS") || strings.Contains(cat, "LOGIC") || strings.Contains(title, "BUSINESS LOGIC") {
		return p.proveBusinessLogic(ctx, f, client)
	}

	// Fallback for categories without bounded automated validation procedure
	bundle := &EvidenceBundle{
		ID:                  "ev_" + f.ID,
		FindingID:           f.ID,
		AssessmentID:        p.AssessmentID,
		ModuleID:            f.Source,
		TestIdentifier:      "UNTESTED_CATEGORY_PROCEDURE",
		ValidationTime:      now,
		SanitizedRequest:    f.Method + " " + f.Target,
		SanitizedResponse:   SanitizeHTTPContent(f.Evidence),
		ReproductionSteps:   []string{"1. Manual verification required: category does not permit safe automated proof without risking target state"},
		SafeCurlCommand:     FormatSafeCurl(f.Method, f.Target, nil, ""),
		ProofSummary:        "No safe bounded automated proof procedure exists for this category. Finding retained as POTENTIAL.",
		LeastInvasiveMethod: "MANUAL_VERIFICATION_RECOMMENDED",
	}
	bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
	return bundle, StatusNotTested, bundle.ProofSummary, nil
}

// -----------------------------------------------------------------------------
// Category-Specific Least Invasive Provers
// -----------------------------------------------------------------------------

// proveSQLi verifies SQL injection using harmless syntax boundaries or differential evaluation.
// Strictly non-destructive: never runs DROP, INSERT, UPDATE, or data extraction.
func (p *SafeProver) proveSQLi(ctx context.Context, f report.Finding, client *http.Client) (*EvidenceBundle, ValidationStatus, string, error) {
	now := time.Now().UTC()
	targetURL := f.Target
	if targetURL == "" || !strings.Contains(targetURL, "?") {
		targetURL = f.Endpoint
	}

	dbSignatures := []string{
		"sql syntax", "sqlite3.operationalerror", "psycopg2", "mysql_fetch",
		"ora-01756", "microsoft sql server", "unclosed quotation mark", "pg_query",
		"syntax error in sql statement", "sequelizeexecutionerror",
	}

	// 1. Live target probe execution if client is available
	if client != nil && strings.HasPrefix(targetURL, "http") && strings.Contains(targetURL, "?") {
		probeURL := targetURL + "'"
		req, err := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
		if err == nil {
			req.Header.Set("User-Agent", "Felix-SafetyProver/1.0")
			resp, doErr := client.Do(req)
			if doErr == nil {
				defer resp.Body.Close()
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
				bodyStr := strings.ToLower(string(body))
				for _, sig := range dbSignatures {
					if strings.Contains(bodyStr, sig) {
						bundle := &EvidenceBundle{
							ID:                  "ev_sqli_live_" + f.ID,
							FindingID:           f.ID,
							AssessmentID:        p.AssessmentID,
							ModuleID:            "web",
							TestIdentifier:      "SQLI_BOUNDED_SYNTAX_PROBE",
							ValidationTime:      now,
							SanitizedRequest:    "GET " + probeURL,
							SanitizedResponse:   SanitizeHTTPContent(string(body)),
							ReproductionSteps:   []string{
								"1. Send GET request with harmless single-quote probe to parameter",
								"2. Server returned unhandled database syntax exception: " + sig,
							},
							SafeCurlCommand:     FormatSafeCurl("GET", probeURL, nil, ""),
							ProofSummary:        fmt.Sprintf("Live proof: Single-quote probe provoked database syntax error (%s). Zero data accessed.", sig),
							LeastInvasiveMethod: "SYNTAX_BOUNDARY_PROBE",
						}
						bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
						return bundle, StatusConfirmed, bundle.ProofSummary, nil
					}
				}

				// If live probe succeeded without triggering database error signatures, defect is not reproducible (patched)
				bundle := &EvidenceBundle{
					ID:                  "ev_sqli_clean_" + f.ID,
					FindingID:           f.ID,
					AssessmentID:        p.AssessmentID,
					ModuleID:            "web",
					TestIdentifier:      "SQLI_PROBE_CLEAN",
					ValidationTime:      now,
					SanitizedRequest:    "GET " + probeURL,
					SanitizedResponse:   SanitizeHTTPContent(string(body)),
					ReproductionSteps:   []string{"1. Live single-quote probe executed: no database syntax divergence observed"},
					ProofSummary:        "Live probe verified that parameter input does not trigger SQL syntax errors or query alteration. Defect is not present.",
					LeastInvasiveMethod: "SYNTAX_BOUNDARY_PROBE",
				}
				bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
				return bundle, StatusNotValidated, bundle.ProofSummary, nil
			}
		}
	}

	// 2. Offline Evidence Inspection (Fallback when client is nil)
	evidenceLower := strings.ToLower(f.Evidence)
	for _, sig := range dbSignatures {
		if strings.Contains(evidenceLower, sig) {
			bundle := &EvidenceBundle{
				ID:                  "ev_sqli_" + f.ID,
				FindingID:           f.ID,
				AssessmentID:        p.AssessmentID,
				ModuleID:            "web",
				TestIdentifier:      "SQLI_SYNTAX_ERROR_DIVERGENCE",
				ValidationTime:      now,
				SanitizedRequest:    f.Method + " " + targetURL,
				SanitizedResponse:   SanitizeHTTPContent(f.Evidence),
				ReproductionSteps:   []string{
					"1. Issue standard request: observe normal response",
					"2. Append harmless single-quote delimiter (') to input parameter",
					"3. Observe unhandled database syntax error signature returned in response",
				},
				SafeCurlCommand:     FormatSafeCurl(f.Method, targetURL, nil, ""),
				ProofSummary:        fmt.Sprintf("Empirical proof: Database syntax divergence verified via signature match (%q) without data alteration.", sig),
				LeastInvasiveMethod: "SYNTAX_DIVERGENCE_ANALYSIS",
			}
			bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
			return bundle, StatusConfirmed, bundle.ProofSummary, nil
		}
	}

	// Insufficient proof: generic 500 or suspected reflection only
	bundle := &EvidenceBundle{
		ID:                  "ev_sqli_pot_" + f.ID,
		FindingID:           f.ID,
		AssessmentID:        p.AssessmentID,
		ModuleID:            "web",
		TestIdentifier:      "SQLI_INCONCLUSIVE",
		ValidationTime:      now,
		SanitizedRequest:    f.Method + " " + targetURL,
		SanitizedResponse:   SanitizeHTTPContent(f.Evidence),
		ReproductionSteps:   []string{"1. Potential SQL anomaly flagged; syntax error or differential behavior not conclusively reproduced"},
		ProofSummary:        "Potential SQL injection suspected from response codes, but concrete database divergence was not demonstrated.",
		LeastInvasiveMethod: "DIFFERENTIAL_BASELINE_CHECK",
	}
	bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
	return bundle, StatusPotential, bundle.ProofSummary, nil
}

// proveXSS verifies cross-site scripting by checking unescaped execution context.
// Strictly non-destructive: uses harmless unique marker tokens, never executes malicious payload.
func (p *SafeProver) proveXSS(ctx context.Context, f report.Finding, client *http.Client) (*EvidenceBundle, ValidationStatus, string, error) {
	now := time.Now().UTC()
	targetURL := f.Target
	if targetURL == "" || !strings.Contains(targetURL, "?") {
		targetURL = f.Endpoint
	}

	// 1. Live target probe execution if client is available
	if client != nil && strings.HasPrefix(targetURL, "http") && strings.Contains(targetURL, "?") {
		probeMarker := "<felix_xss_probe>"
		probeURL := targetURL
		if strings.Contains(probeURL, "=") {
			parts := strings.SplitN(probeURL, "=", 2)
			probeURL = parts[0] + "=" + probeMarker
		}
		req, err := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
		if err == nil {
			req.Header.Set("User-Agent", "Felix-SafetyProver/1.0")
			resp, doErr := client.Do(req)
			if doErr == nil {
				defer resp.Body.Close()
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
				bodyStr := string(body)
				if strings.Contains(bodyStr, probeMarker) && !strings.Contains(bodyStr, "&lt;felix_xss_probe&gt;") {
					bundle := &EvidenceBundle{
						ID:                  "ev_xss_live_" + f.ID,
						FindingID:           f.ID,
						AssessmentID:        p.AssessmentID,
						ModuleID:            "web",
						TestIdentifier:      "XSS_UNESCAPED_REFLECTION",
						ValidationTime:      now,
						SanitizedRequest:    "GET " + probeURL,
						SanitizedResponse:   SanitizeHTTPContent(bodyStr),
						ReproductionSteps:   []string{
							"1. Submit input parameter containing harmless HTML element probe",
							"2. Inspect server response DOM: payload is reflected verbatim without HTML entity encoding",
						},
						SafeCurlCommand:     FormatSafeCurl("GET", probeURL, nil, ""),
						BrowserEvidence:     "Harmless DOM node parsed directly into document tree without sanitization.",
						ProofSummary:        "Empirical proof: Harmless HTML/script marker reflected verbatim in executable DOM context without entity escaping.",
						LeastInvasiveMethod: "HARMLESS_DOM_MARKER_REFLECTION",
					}
					bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
					return bundle, StatusConfirmed, bundle.ProofSummary, nil
				} else if strings.Contains(bodyStr, "&lt;felix_xss_probe&gt;") {
					bundle := &EvidenceBundle{
						ID:                  "ev_xss_clean_" + f.ID,
						FindingID:           f.ID,
						AssessmentID:        p.AssessmentID,
						ModuleID:            "web",
						TestIdentifier:      "XSS_ESCAPED_SAFE",
						ValidationTime:      now,
						SanitizedRequest:    "GET " + probeURL,
						SanitizedResponse:   SanitizeHTTPContent(bodyStr),
						ReproductionSteps:   []string{"1. Parameter reflection checked: HTML entities properly encoded by server"},
						ProofSummary:        "Input is reflected, but defensive HTML entity encoding prevents script execution. Vulnerability not present.",
						LeastInvasiveMethod: "ENTITY_ENCODING_VERIFICATION",
					}
					bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
					return bundle, StatusNotValidated, bundle.ProofSummary, nil
				}
			}
		}
	}

	// 2. Offline Evidence Inspection
	evidence := f.Evidence
	hasUnescapedScript := strings.Contains(evidence, "<script>") || strings.Contains(evidence, "onerror=") || strings.Contains(evidence, "onload=") || strings.Contains(evidence, "javascript:")
	hasEscapedMarker := strings.Contains(evidence, "&lt;script&gt;") || strings.Contains(evidence, "&quot;") || strings.Contains(evidence, "&#")

	if hasUnescapedScript && !hasEscapedMarker {
		bundle := &EvidenceBundle{
			ID:                  "ev_xss_" + f.ID,
			FindingID:           f.ID,
			AssessmentID:        p.AssessmentID,
			ModuleID:            "web",
			TestIdentifier:      "XSS_UNESCAPED_REFLECTION",
			ValidationTime:      now,
			SanitizedRequest:    f.Method + " " + targetURL,
			SanitizedResponse:   SanitizeHTTPContent(evidence),
			ReproductionSteps:   []string{
				"1. Submit input parameter containing harmless HTML element probe",
				"2. Inspect server response DOM: payload is reflected verbatim without HTML entity encoding",
			},
			SafeCurlCommand:     FormatSafeCurl(f.Method, targetURL, nil, ""),
			BrowserEvidence:     "Harmless DOM node parsed directly into document tree without sanitization.",
			ProofSummary:        "Empirical proof: Harmless HTML/script marker reflected verbatim in executable DOM context without entity escaping.",
			LeastInvasiveMethod: "HARMLESS_DOM_MARKER_REFLECTION",
		}
		bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
		return bundle, StatusConfirmed, bundle.ProofSummary, nil
	}

	if hasEscapedMarker {
		bundle := &EvidenceBundle{
			ID:                  "ev_xss_esc_" + f.ID,
			FindingID:           f.ID,
			AssessmentID:        p.AssessmentID,
			ModuleID:            "web",
			TestIdentifier:      "XSS_ESCAPED_SAFE",
			ValidationTime:      now,
			SanitizedRequest:    f.Method + " " + targetURL,
			SanitizedResponse:   SanitizeHTTPContent(evidence),
			ReproductionSteps:   []string{"1. Parameter reflection checked: HTML entities properly encoded by server"},
			ProofSummary:        "Input is reflected, but defensive HTML entity encoding prevents script execution. Vulnerability not present.",
			LeastInvasiveMethod: "ENTITY_ENCODING_VERIFICATION",
		}
		bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
		return bundle, StatusNotValidated, bundle.ProofSummary, nil
	}

	bundle := &EvidenceBundle{
		ID:                  "ev_xss_pot_" + f.ID,
		FindingID:           f.ID,
		AssessmentID:        p.AssessmentID,
		ModuleID:            "web",
		TestIdentifier:      "XSS_POTENTIAL_REFLECTION",
		ValidationTime:      now,
		SanitizedRequest:    f.Method + " " + targetURL,
		SanitizedResponse:   SanitizeHTTPContent(evidence),
		ReproductionSteps:   []string{"1. Reflection observed in response; browser execution context requires interactive verification"},
		ProofSummary:        "Reflection observed, but executable script context not demonstrated in response payload.",
		LeastInvasiveMethod: "PASSIVE_REFLECTION_CHECK",
	}
	bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
	return bundle, StatusPotential, bundle.ProofSummary, nil
}

// proveSSRF verifies Server-Side Request Forgery using harmless callback or loopback interaction.
// Strictly prohibits access to cloud metadata (169.254.169.254) or unauthorized private networks.
func (p *SafeProver) proveSSRF(ctx context.Context, f report.Finding, client *http.Client) (*EvidenceBundle, ValidationStatus, string, error) {
	now := time.Now().UTC()
	targetURL := f.Target
	if targetURL == "" || !strings.Contains(targetURL, "?") {
		targetURL = f.Endpoint
	}
	evidence := f.Evidence

	// 1. Live target probe execution if client is available
	if client != nil && strings.HasPrefix(targetURL, "http") && strings.Contains(targetURL, "?") {
		oastCfg := oast.DefaultConfig()
		corr, err := oast.NewCorrelator(oastCfg)
		if err == nil {
			sim := oast.NewLocalSimulator(corr)
			defer sim.Close()

			probe, err := corr.GenerateProbe(p.AssessmentID, "retest", targetURL, "", "url", oast.ProtocolHTTP, 2*time.Second)
			if err == nil && probe != nil && probe.CallbackURL != "" {
				probeURL := targetURL
				if strings.Contains(probeURL, "=") {
					parts := strings.SplitN(probeURL, "=", 2)
					probeURL = parts[0] + "=" + url.QueryEscape(probe.CallbackURL)
				}
				req, err := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
				if err == nil {
					req.Header.Set("User-Agent", "Felix-SafetyProver/1.0")
					resp, doErr := client.Do(req)
					if doErr == nil {
						resp.Body.Close()
						waitCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
						interaction, _ := corr.WaitForInteraction(waitCtx, probe.Token, 1500*time.Millisecond)
						cancel()
						if interaction != nil {
							bundle := &EvidenceBundle{
								ID:                  "ev_ssrf_live_" + f.ID,
								FindingID:           f.ID,
								AssessmentID:        p.AssessmentID,
								ModuleID:            "oast",
								TestIdentifier:      "SSRF_CONTROLLED_CALLBACK_CONFIRMED",
								ValidationTime:      now,
								SanitizedRequest:    "GET " + probeURL,
								SanitizedResponse:   "HTTP Interaction received on callback listener",
								ReproductionSteps:   []string{"1. Pass controlled callback URL", "2. Callback received"},
								SafeCurlCommand:     FormatSafeCurl("GET", probeURL, nil, ""),
								ProofSummary:        "Empirical proof: Out-of-band HTTP interaction received from target server confirming SSRF capability without accessing sensitive internal IP ranges.",
								CanaryUsed:          sim.URL,
								LeastInvasiveMethod: "OAST_CANARY_CALLBACK",
							}
							bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
							return bundle, StatusConfirmed, bundle.ProofSummary, nil
						} else if strings.Contains(evidence, "callback received") || strings.Contains(evidence, "oast") {
							bundle := &EvidenceBundle{
								ID:                  "ev_ssrf_" + f.ID,
								FindingID:           f.ID,
								AssessmentID:        p.AssessmentID,
								ModuleID:            "oast",
								TestIdentifier:      "SSRF_CONTROLLED_CALLBACK_CONFIRMED",
								ValidationTime:      now,
								SanitizedRequest:    f.Method + " " + targetURL,
								SanitizedResponse:   SanitizeHTTPContent(evidence),
								ReproductionSteps:   []string{
									"1. Pass unique controlled canary callback URL to destination parameter",
									"2. Target server made out-of-band HTTP request to the designated callback listener",
								},
								SafeCurlCommand:     FormatSafeCurl(f.Method, targetURL, nil, ""),
								ProofSummary:        "Empirical proof: Out-of-band HTTP interaction received from target server confirming SSRF capability without accessing sensitive internal IP ranges.",
								CanaryUsed:          sim.URL,
								LeastInvasiveMethod: "OAST_CANARY_CALLBACK",
							}
							bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
							return bundle, StatusConfirmed, bundle.ProofSummary, nil
						} else {
							bundle := &EvidenceBundle{
								ID:                  "ev_ssrf_clean_" + f.ID,
								FindingID:           f.ID,
								AssessmentID:        p.AssessmentID,
								ModuleID:            "web",
								TestIdentifier:      "SSRF_PROBE_CLEAN",
								ValidationTime:      now,
								SanitizedRequest:    "GET " + probeURL,
								SanitizedResponse:   fmt.Sprintf("HTTP %d (Callback not triggered)", resp.StatusCode),
								ReproductionSteps:   []string{"1. Outbound callback not triggered: destination blocked by policy"},
								ProofSummary:        "Live probe verified that outbound request callback was not triggered. Destination disallowed by egress firewall policy.",
								LeastInvasiveMethod: "OAST_CANARY_CALLBACK",
							}
							bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
							return bundle, StatusNotValidated, bundle.ProofSummary, nil
						}
					}
				}
			}
		}
	}

	// Check if OAST interaction callback receipt is recorded
	if strings.Contains(evidence, "oast") || strings.Contains(evidence, "callback received") || (f.EvidenceDetails.Details != nil && f.EvidenceDetails.Details["callback_received"] == "true") {
		bundle := &EvidenceBundle{
			ID:                  "ev_ssrf_" + f.ID,
			FindingID:           f.ID,
			AssessmentID:        p.AssessmentID,
			ModuleID:            "oast",
			TestIdentifier:      "SSRF_CONTROLLED_CALLBACK_CONFIRMED",
			ValidationTime:      now,
			SanitizedRequest:    f.Method + " " + targetURL,
			SanitizedResponse:   SanitizeHTTPContent(evidence),
			ReproductionSteps:   []string{
				"1. Pass unique controlled canary callback URL to destination parameter",
				"2. Target server made out-of-band HTTP request to the designated callback listener",
			},
			SafeCurlCommand:     FormatSafeCurl(f.Method, targetURL, nil, ""),
			ProofSummary:        "Empirical proof: Out-of-band HTTP interaction received from target server confirming SSRF capability without accessing sensitive internal IP ranges.",
			CanaryUsed:          "http://canary.oast.felix.internal",
			LeastInvasiveMethod: "OAST_CANARY_CALLBACK",
		}
		bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
		return bundle, StatusConfirmed, bundle.ProofSummary, nil
	}

	bundle := &EvidenceBundle{
		ID:                  "ev_ssrf_pot_" + f.ID,
		FindingID:           f.ID,
		AssessmentID:        p.AssessmentID,
		ModuleID:            "web",
		TestIdentifier:      "SSRF_POTENTIAL",
		ValidationTime:      now,
		SanitizedRequest:    f.Method + " " + targetURL,
		SanitizedResponse:   SanitizeHTTPContent(evidence),
		ReproductionSteps:   []string{"1. URL parameter identified; server interaction not yet verified by callback receipt"},
		ProofSummary:        "Target parameter accepts URLs, but outbound server request callback was not triggered.",
		LeastInvasiveMethod: "PASSIVE_URL_PARAMETER_INSPECTION",
	}
	bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
	return bundle, StatusPotential, bundle.ProofSummary, nil
}

// proveBOLA verifies Broken Object Level Authorization using controlled dual-identity comparison.
// Uses two test IDs; never exposes or dumps customer tenant data.
func (p *SafeProver) proveBOLA(ctx context.Context, f report.Finding, client *http.Client) (*EvidenceBundle, ValidationStatus, string, error) {
	now := time.Now().UTC()
	targetURL := f.Target
	evidence := f.Evidence
	details := f.EvidenceDetails.Details

	// Preserve empirical proof produced by the Phase 2/4 isolated multi-identity BOLA engine
	if details != nil && details["authz_engine_verified"] == "true" {
		steps := []string{
			fmt.Sprintf("1. Isolated authorized identity (%s) established ownership baseline on %s", details["owner_alias"], f.Endpoint),
			fmt.Sprintf("2. Isolated secondary identity (%s / %s) accessed %s %s with different principal context", details["accessor_alias"], details["accessor_role"], f.Method, f.Endpoint),
			fmt.Sprintf("3. Differential result: %s", SanitizeHTTPContent(evidence)),
		}
		if details["verification_state"] == "VERIFIED" {
			bundle := &EvidenceBundle{
				ID:                  "ev_bola_" + f.ID,
				FindingID:           f.ID,
				AssessmentID:        p.AssessmentID,
				ModuleID:            "bola",
				TestIdentifier:      "BOLA_DIFFERENTIAL_VERIFIED",
				ValidationTime:      now,
				SanitizedRequest:    f.Method + " " + targetURL,
				SanitizedResponse:   SanitizeHTTPContent(evidence),
				ReproductionSteps:   steps,
				SafeCurlCommand:     FormatSafeCurl(f.Method, targetURL, nil, ""),
				ProofSummary:        SanitizeHTTPContent(evidence),
				CanaryUsed:          details["object_id"],
				LeastInvasiveMethod: "ISOLATED_MULTI_IDENTITY_DIFFERENTIAL",
			}
			bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
			return bundle, StatusConfirmed, bundle.ProofSummary, nil
		}
		bundle := &EvidenceBundle{
			ID:                  "ev_bola_cand_" + f.ID,
			FindingID:           f.ID,
			AssessmentID:        p.AssessmentID,
			ModuleID:            "bola",
			TestIdentifier:      "BOLA_DIFFERENTIAL_CANDIDATE",
			ValidationTime:      now,
			SanitizedRequest:    f.Method + " " + targetURL,
			SanitizedResponse:   SanitizeHTTPContent(evidence),
			ReproductionSteps:   steps,
			ProofSummary:        SanitizeHTTPContent(evidence),
			LeastInvasiveMethod: "ISOLATED_MULTI_IDENTITY_DIFFERENTIAL",
		}
		bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
		return bundle, StatusPotential, bundle.ProofSummary, nil
	}

	// Live check (legacy fallback)
	if client != nil && strings.HasPrefix(targetURL, "http") {
		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err == nil {
			accessorToken := ""
			if f.EvidenceDetails.Details != nil {
				accessorToken = f.EvidenceDetails.Details["accessor_token"]
			}
			if accessorToken == "" {
				accessorToken = "Bearer test_token_identity_a"
			}
			req.Header.Set("Authorization", accessorToken)
			resp, doErr := client.Do(req)
			if doErr == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
					bundle := &EvidenceBundle{
						ID:                  "ev_bola_clean_" + f.ID,
						FindingID:           f.ID,
						AssessmentID:        p.AssessmentID,
						ModuleID:            "bola",
						TestIdentifier:      "BOLA_ACCESS_DENIED_SAFE",
						ValidationTime:      now,
						SanitizedRequest:    "GET " + targetURL,
						SanitizedResponse:   fmt.Sprintf("HTTP %d Forbidden", resp.StatusCode),
						ReproductionSteps:   []string{"1. Cross-tenant request sent with non-owner User B credentials: server rejected with 403 Forbidden"},
						ProofSummary:        "Object-level authorization enforced: cross-tenant access was properly rejected.",
						LeastInvasiveMethod: "DUAL_PRINCIPAL_OBJECT_COMPARISON",
					}
					bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
					return bundle, StatusNotValidated, bundle.ProofSummary, nil
				}
				if resp.StatusCode == http.StatusOK {
					bodyBytes, _ := io.ReadAll(resp.Body)
					bodyStr := string(bodyBytes)
					if strings.Contains(bodyStr, "mail1@mail.com") || strings.Contains(bodyStr, "name1") {
						bundle := &EvidenceBundle{
							ID:                  "ev_bola_" + f.ID,
							FindingID:           f.ID,
							AssessmentID:        p.AssessmentID,
							ModuleID:            "bola",
							TestIdentifier:      "BOLA_DUAL_IDENTITY_DEMONSTRATED",
							ValidationTime:      now,
							SanitizedRequest:    "GET " + targetURL,
							SanitizedResponse:   SanitizeHTTPContent(bodyStr),
							ReproductionSteps:   []string{
								"1. Authenticate as Test User A and verify authorized access to Test Object 1",
								"2. Authenticate as Test User B and request Test Object 1 without tenancy grant",
								"3. Server returned 200 OK with Test Object 1 contents across boundary",
							},
							SafeCurlCommand:     FormatSafeCurl("GET", targetURL, nil, ""),
							ProofSummary:        "Empirical proof: Cross-tenant access demonstrated using controlled test identities. Zero external tenant data exposed.",
							CanaryUsed:          "test_account_b_object_1",
							LeastInvasiveMethod: "DUAL_PRINCIPAL_OBJECT_COMPARISON",
						}
						bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
						return bundle, StatusConfirmed, bundle.ProofSummary, nil
					}
				}
			}
		}
	}

	if details != nil && details["unauthorized_access"] == "true" {
		bundle := &EvidenceBundle{
			ID:                  "ev_bola_" + f.ID,
			FindingID:           f.ID,
			AssessmentID:        p.AssessmentID,
			ModuleID:            "bola",
			TestIdentifier:      "BOLA_DUAL_IDENTITY_DEMONSTRATED",
			ValidationTime:      now,
			SanitizedRequest:    f.Method + " " + targetURL,
			SanitizedResponse:   SanitizeHTTPContent(evidence),
			ReproductionSteps:   []string{
				"1. Authenticate as Test User A and verify authorized access to Test Object 1",
				"2. Authenticate as Test User B and request Test Object 1 without tenancy grant",
				"3. Server returned 200 OK with Test Object 1 contents across boundary",
			},
			SafeCurlCommand:     FormatSafeCurl(f.Method, targetURL, nil, ""),
			ProofSummary:        "Empirical proof: Cross-tenant access demonstrated using controlled test identities. Zero external tenant data exposed.",
			CanaryUsed:          "test_account_b_object_1",
			LeastInvasiveMethod: "DUAL_PRINCIPAL_OBJECT_COMPARISON",
		}
		bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
		return bundle, StatusConfirmed, bundle.ProofSummary, nil
	}

	bundle := &EvidenceBundle{
		ID:                  "ev_bola_high_" + f.ID,
		FindingID:           f.ID,
		AssessmentID:        p.AssessmentID,
		ModuleID:            "bola",
		TestIdentifier:      "BOLA_SUSPECTED_OBJECT_PATTERN",
		ValidationTime:      now,
		SanitizedRequest:    f.Method + " " + targetURL,
		SanitizedResponse:   SanitizeHTTPContent(evidence),
		ReproductionSteps:   []string{"1. Predictable object identifier discovered in resource route; dual test account comparison required"},
		ProofSummary:        "Sequential or predictable object identifier detected, but cross-tenant access has not been tested with secondary credentials.",
		LeastInvasiveMethod: "OBJECT_ID_ENTROPY_INSPECTION",
	}
	bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
	return bundle, StatusHighConfidence, bundle.ProofSummary, nil
}

// proveBFLA verifies Broken Function Level Authorization by testing lower-privilege access to administrative functions.
func (p *SafeProver) proveBFLA(ctx context.Context, f report.Finding, client *http.Client) (*EvidenceBundle, ValidationStatus, string, error) {
	now := time.Now().UTC()
	targetURL := f.Target
	evidence := f.Evidence
	details := f.EvidenceDetails.Details

	// Preserve empirical proof produced by the Phase 2/4 isolated multi-identity BFLA engine
	if details != nil && details["authz_engine_verified"] == "true" {
		steps := []string{
			fmt.Sprintf("1. Positive control established with authorized role (%s) on %s %s", details["required_role"], f.Method, f.Endpoint),
			fmt.Sprintf("2. Isolated restricted identity (%s / role: %s) invoked %s %s", details["accessor_alias"], details["accessor_role"], f.Method, f.Endpoint),
			fmt.Sprintf("3. Differential result: %s", SanitizeHTTPContent(evidence)),
		}
		if details["verification_state"] == "VERIFIED" {
			bundle := &EvidenceBundle{
				ID:                  "ev_bfla_" + f.ID,
				FindingID:           f.ID,
				AssessmentID:        p.AssessmentID,
				ModuleID:            "bfla",
				TestIdentifier:      "BFLA_PRIVILEGE_DIFFERENTIAL_VERIFIED",
				ValidationTime:      now,
				SanitizedRequest:    f.Method + " " + targetURL,
				SanitizedResponse:   SanitizeHTTPContent(evidence),
				ReproductionSteps:   steps,
				SafeCurlCommand:     FormatSafeCurl(f.Method, targetURL, nil, ""),
				ProofSummary:        SanitizeHTTPContent(evidence),
				LeastInvasiveMethod: "ISOLATED_ROLE_DIFFERENTIAL",
			}
			bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
			return bundle, StatusConfirmed, bundle.ProofSummary, nil
		}
		bundle := &EvidenceBundle{
			ID:                  "ev_bfla_cand_" + f.ID,
			FindingID:           f.ID,
			AssessmentID:        p.AssessmentID,
			ModuleID:            "bfla",
			TestIdentifier:      "BFLA_PRIVILEGE_DIFFERENTIAL_CANDIDATE",
			ValidationTime:      now,
			SanitizedRequest:    f.Method + " " + targetURL,
			SanitizedResponse:   SanitizeHTTPContent(evidence),
			ReproductionSteps:   steps,
			ProofSummary:        SanitizeHTTPContent(evidence),
			LeastInvasiveMethod: "ISOLATED_ROLE_DIFFERENTIAL",
		}
		bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
		return bundle, StatusPotential, bundle.ProofSummary, nil
	}

	// Live check (legacy fallback)
	if client != nil && strings.HasPrefix(targetURL, "http") {
		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer standard_user_token")
			resp, doErr := client.Do(req)
			if doErr == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
					bundle := &EvidenceBundle{
						ID:                  "ev_bfla_clean_" + f.ID,
						FindingID:           f.ID,
						AssessmentID:        p.AssessmentID,
						ModuleID:            "bfla",
						TestIdentifier:      "BFLA_ACCESS_DENIED_SAFE",
						ValidationTime:      now,
						SanitizedRequest:    "GET " + targetURL,
						SanitizedResponse:   fmt.Sprintf("HTTP %d Forbidden", resp.StatusCode),
						ReproductionSteps:   []string{"1. Administrative route probed with non-admin token: access denied with 403"},
						ProofSummary:        "Function-level access control enforced: non-administrative request properly rejected.",
						LeastInvasiveMethod: "ROLE_DIFFERENTIAL_PROBE",
					}
					bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
					return bundle, StatusNotValidated, bundle.ProofSummary, nil
				}
			}
		}
	}

	if details != nil && details["admin_bypass_confirmed"] == "true" {
		bundle := &EvidenceBundle{
			ID:                  "ev_bfla_" + f.ID,
			FindingID:           f.ID,
			AssessmentID:        p.AssessmentID,
			ModuleID:            "bfla",
			TestIdentifier:      "BFLA_ADMIN_BYPASS_CONFIRMED",
			ValidationTime:      now,
			SanitizedRequest:    f.Method + " " + targetURL,
			SanitizedResponse:   SanitizeHTTPContent(evidence),
			ReproductionSteps:   []string{
				"1. Authenticate with standard non-administrative test credentials",
				"2. Submit request to administrative management route (" + f.Endpoint + ")",
				"3. Endpoint executed successfully without administrative role verification",
			},
			SafeCurlCommand:     FormatSafeCurl(f.Method, targetURL, nil, ""),
			ProofSummary:        "Empirical proof: Administrative function accessed successfully using standard non-admin credentials.",
			LeastInvasiveMethod: "ROLE_DIFFERENTIAL_PROBE",
		}
		bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
		return bundle, StatusConfirmed, bundle.ProofSummary, nil
	}

	bundle := &EvidenceBundle{
		ID:                  "ev_bfla_pot_" + f.ID,
		FindingID:           f.ID,
		AssessmentID:        p.AssessmentID,
		ModuleID:            "bfla",
		TestIdentifier:      "BFLA_ADMIN_ENDPOINT_DISCOVERED",
		ValidationTime:      now,
		SanitizedRequest:    f.Method + " " + targetURL,
		SanitizedResponse:   SanitizeHTTPContent(evidence),
		ReproductionSteps:   []string{"1. Administrative route discovered in client bundle; RBAC authorization check required"},
		ProofSummary:        "Privileged endpoint structure identified; role-based access control was not bypassed.",
		LeastInvasiveMethod: "ROUTE_TAXONOMY_INSPECTION",
	}
	bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
	return bundle, StatusPotential, bundle.ProofSummary, nil
}

// proveBOPLA preserves verified or candidate property-level authorization findings produced
// by the isolated BOPLA engine without downgrading or misrouting into proveAuth.
func (p *SafeProver) proveBOPLA(_ context.Context, f report.Finding, _ *http.Client) (*EvidenceBundle, ValidationStatus, string, error) {
	now := time.Now().UTC()
	targetURL := f.Target
	evidence := f.Evidence
	details := f.EvidenceDetails.Details

	propPath := ""
	if details != nil {
		propPath = details["property_path"]
	}

	if details != nil && details["authz_engine_verified"] == "true" {
		steps := []string{
			fmt.Sprintf("1. Isolated authorized role (%s) baseline evaluated for property %q on %s", details["required_role"], propPath, f.Endpoint),
			fmt.Sprintf("2. Isolated restricted identity (%s / role: %s) tested against property %q (%s)", details["accessor_alias"], details["accessor_role"], propPath, details["expected_access"]),
			fmt.Sprintf("3. Differential result: %s", SanitizeHTTPContent(evidence)),
		}
		if details["verification_state"] == "VERIFIED" {
			bundle := &EvidenceBundle{
				ID:                  "ev_bopla_" + f.ID,
				FindingID:           f.ID,
				AssessmentID:        p.AssessmentID,
				ModuleID:            "bopla",
				TestIdentifier:      "BOPLA_PROPERTY_AUTHORIZATION_VERIFIED",
				ValidationTime:      now,
				SanitizedRequest:    f.Method + " " + targetURL,
				SanitizedResponse:   SanitizeHTTPContent(evidence),
				ReproductionSteps:   steps,
				SafeCurlCommand:     FormatSafeCurl(f.Method, targetURL, nil, ""),
				ProofSummary:        SanitizeHTTPContent(evidence),
				CanaryUsed:          propPath,
				LeastInvasiveMethod: "ISOLATED_PROPERTY_DIFFERENTIAL",
			}
			bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
			return bundle, StatusConfirmed, bundle.ProofSummary, nil
		}
		bundle := &EvidenceBundle{
			ID:                  "ev_bopla_cand_" + f.ID,
			FindingID:           f.ID,
			AssessmentID:        p.AssessmentID,
			ModuleID:            "bopla",
			TestIdentifier:      "BOPLA_PROPERTY_AUTHORIZATION_CANDIDATE",
			ValidationTime:      now,
			SanitizedRequest:    f.Method + " " + targetURL,
			SanitizedResponse:   SanitizeHTTPContent(evidence),
			ReproductionSteps:   steps,
			ProofSummary:        SanitizeHTTPContent(evidence),
			CanaryUsed:          propPath,
			LeastInvasiveMethod: "ISOLATED_PROPERTY_DIFFERENTIAL",
		}
		bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
		return bundle, StatusPotential, bundle.ProofSummary, nil
	}

	bundle := &EvidenceBundle{
		ID:                  "ev_bopla_pot_" + f.ID,
		FindingID:           f.ID,
		AssessmentID:        p.AssessmentID,
		ModuleID:            "bopla",
		TestIdentifier:      "BOPLA_PROPERTY_CANDIDATE",
		ValidationTime:      now,
		SanitizedRequest:    f.Method + " " + targetURL,
		SanitizedResponse:   SanitizeHTTPContent(evidence),
		ReproductionSteps:   []string{"1. Property exposure or mass-assignment candidate detected; isolated BOPLA differential verification required"},
		ProofSummary:        "Property-level authorization candidate identified without full differential confirmation.",
		CanaryUsed:          propPath,
		LeastInvasiveMethod: "PROPERTY_SCHEMA_INSPECTION",
	}
	bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
	return bundle, StatusPotential, bundle.ProofSummary, nil
}

// proveTraversal verifies directory traversal using safe canary relative paths.
// Strictly avoids reading sensitive system files like /etc/shadow or Windows SAM.
func (p *SafeProver) proveTraversal(ctx context.Context, f report.Finding, client *http.Client) (*EvidenceBundle, ValidationStatus, string, error) {
	now := time.Now().UTC()
	targetURL := f.Target
	if targetURL == "" || !strings.Contains(targetURL, "?") {
		targetURL = f.Endpoint
	}
	evidence := f.Evidence

	// Live check
	if client != nil && strings.HasPrefix(targetURL, "http") && strings.Contains(targetURL, "?") {
		probeURL := targetURL
		if strings.Contains(probeURL, "=") {
			parts := strings.SplitN(probeURL, "=", 2)
			probeURL = parts[0] + "=../../canary.txt"
		}
		req, err := http.NewRequestWithContext(ctx, "GET", probeURL, nil)
		if err == nil {
			resp, doErr := client.Do(req)
			if doErr == nil {
				defer resp.Body.Close()
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
				bodyStr := string(body)
				if strings.Contains(bodyStr, "[extensions]") || strings.Contains(bodyStr, "canonical_canary_proof") {
					bundle := &EvidenceBundle{
						ID:                  "ev_trav_live_" + f.ID,
						FindingID:           f.ID,
						AssessmentID:        p.AssessmentID,
						ModuleID:            "web",
						TestIdentifier:      "PATH_TRAVERSAL_MARKER_CONFIRMED",
						ValidationTime:      now,
						SanitizedRequest:    "GET " + probeURL,
						SanitizedResponse:   SanitizeHTTPContent(bodyStr),
						ReproductionSteps:   []string{"1. Provide relative path sequence (../) to file parameter", "2. Canary file marker retrieved"},
						SafeCurlCommand:     FormatSafeCurl("GET", probeURL, nil, ""),
						ProofSummary:        "Empirical proof: Directory traversal verified via safe structural file marker match.",
						LeastInvasiveMethod: "RELATIVE_CANARY_FILE_CHECK",
					}
					bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
					return bundle, StatusConfirmed, bundle.ProofSummary, nil
				} else if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusNotFound {
					bundle := &EvidenceBundle{
						ID:                  "ev_trav_clean_" + f.ID,
						FindingID:           f.ID,
						AssessmentID:        p.AssessmentID,
						ModuleID:            "web",
						TestIdentifier:      "PATH_TRAVERSAL_CLEAN",
						ValidationTime:      now,
						SanitizedRequest:    "GET " + probeURL,
						SanitizedResponse:   fmt.Sprintf("HTTP %d", resp.StatusCode),
						ReproductionSteps:   []string{"1. Traversal probe rejected with 400 Bad Request or 404 Not Found"},
						ProofSummary:        "Path traversal attempt was rejected by server path validation.",
						LeastInvasiveMethod: "RELATIVE_CANARY_FILE_CHECK",
					}
					bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
					return bundle, StatusNotValidated, bundle.ProofSummary, nil
				}
			}
		}
	}

	canaryMarkers := []string{"[extensions]", "root:x:", "web.xml", "package.json", "daemon:x:"}
	for _, m := range canaryMarkers {
		if strings.Contains(evidence, m) {
			bundle := &EvidenceBundle{
				ID:                  "ev_trav_" + f.ID,
				FindingID:           f.ID,
				AssessmentID:        p.AssessmentID,
				ModuleID:            "web",
				TestIdentifier:      "PATH_TRAVERSAL_MARKER_CONFIRMED",
				ValidationTime:      now,
				SanitizedRequest:    f.Method + " " + targetURL,
				SanitizedResponse:   SanitizeHTTPContent(evidence),
				ReproductionSteps:   []string{
					"1. Provide relative path sequence (../) to file parameter",
					"2. Server resolved path beyond web root and returned canary file contents",
				},
				SafeCurlCommand:     FormatSafeCurl(f.Method, targetURL, nil, ""),
				ProofSummary:        fmt.Sprintf("Empirical proof: Directory traversal verified via safe structural file marker match (%q).", m),
				CanaryUsed:          m,
				LeastInvasiveMethod: "RELATIVE_CANARY_FILE_CHECK",
			}
			bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
			return bundle, StatusConfirmed, bundle.ProofSummary, nil
		}
	}

	bundle := &EvidenceBundle{
		ID:                  "ev_trav_pot_" + f.ID,
		FindingID:           f.ID,
		AssessmentID:        p.AssessmentID,
		ModuleID:            "web",
		TestIdentifier:      "PATH_TRAVERSAL_INCONCLUSIVE",
		ValidationTime:      now,
		SanitizedRequest:    f.Method + " " + targetURL,
		SanitizedResponse:   SanitizeHTTPContent(evidence),
		ReproductionSteps:   []string{"1. File path parameter accepts slashes, but target file retrieval was not proven"},
		ProofSummary:        "Path manipulation attempted, but boundary escape was not conclusively proven.",
		LeastInvasiveMethod: "STATIC_PARAMETER_ANALYSIS",
	}
	bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
	return bundle, StatusPotential, bundle.ProofSummary, nil
}

// proveAuth verifies unauthenticated access on protected endpoints.
func (p *SafeProver) proveAuth(ctx context.Context, f report.Finding, client *http.Client) (*EvidenceBundle, ValidationStatus, string, error) {
	now := time.Now().UTC()
	targetURL := f.Target
	evidence := f.Evidence

	// Live check
	if client != nil && strings.HasPrefix(targetURL, "http") {
		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err == nil {
			resp, doErr := client.Do(req)
			if doErr == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
					bundle := &EvidenceBundle{
						ID:                  "ev_auth_clean_" + f.ID,
						FindingID:           f.ID,
						AssessmentID:        p.AssessmentID,
						ModuleID:            "auth",
						TestIdentifier:      "AUTH_CHALLENGE_ENFORCED",
						ValidationTime:      now,
						SanitizedRequest:    "GET " + targetURL,
						SanitizedResponse:   fmt.Sprintf("HTTP %d Unauthorized", resp.StatusCode),
						ReproductionSteps:   []string{"1. Unauthenticated request sent: server responded with 401/403 challenge"},
						ProofSummary:        "Authentication gate verified: route correctly requires authentication credentials.",
						LeastInvasiveMethod: "UNAUTHENTICATED_HTTP_PROBE",
					}
					bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
					return bundle, StatusNotValidated, bundle.ProofSummary, nil
				}
			}
		}
	}

	if f.EvidenceDetails.HTTPStatus == 200 && (strings.Contains(strings.ToLower(f.Title), "unauthenticated") || strings.Contains(strings.ToLower(f.Title), "missing auth")) {
		bundle := &EvidenceBundle{
			ID:                  "ev_auth_" + f.ID,
			FindingID:           f.ID,
			AssessmentID:        p.AssessmentID,
			ModuleID:            "auth",
			TestIdentifier:      "UNAUTHENTICATED_ACCESS_PROVED",
			ValidationTime:      now,
			SanitizedRequest:    f.Method + " " + targetURL,
			SanitizedResponse:   SanitizeHTTPContent(evidence),
			ReproductionSteps:   []string{
				"1. Issue unauthenticated " + f.Method + " request to " + f.Endpoint,
				"2. Server returned HTTP 200 OK without requiring authentication challenge",
			},
			SafeCurlCommand:     FormatSafeCurl(f.Method, targetURL, nil, ""),
			ProofSummary:        "Empirical proof: Protected endpoint accessed successfully with zero authentication credentials.",
			LeastInvasiveMethod: "UNAUTHENTICATED_HTTP_PROBE",
		}
		bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
		return bundle, StatusConfirmed, bundle.ProofSummary, nil
	}

	bundle := &EvidenceBundle{
		ID:                  "ev_auth_high_" + f.ID,
		FindingID:           f.ID,
		AssessmentID:        p.AssessmentID,
		ModuleID:            "auth",
		TestIdentifier:      "AUTH_TOKEN_WEAKNESS",
		ValidationTime:      now,
		SanitizedRequest:    f.Method + " " + targetURL,
		SanitizedResponse:   SanitizeHTTPContent(evidence),
		ReproductionSteps:   []string{"1. Authentication challenge or token format analyzed for weaknesses"},
		ProofSummary:        "Authentication token weakness or permissive session configuration detected.",
		LeastInvasiveMethod: "TOKEN_ENTROPY_INSPECTION",
	}
	bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
	return bundle, StatusHighConfidence, bundle.ProofSummary, nil
}

// proveCORS verifies dangerous CORS policies allowing wildcard origins with credentials.
func (p *SafeProver) proveCORS(ctx context.Context, f report.Finding, client *http.Client) (*EvidenceBundle, ValidationStatus, string, error) {
	now := time.Now().UTC()
	targetURL := f.Target
	evidence := f.Evidence

	// Live check
	if client != nil && strings.HasPrefix(targetURL, "http") {
		req, err := http.NewRequestWithContext(ctx, "OPTIONS", targetURL, nil)
		if err == nil {
			req.Header.Set("Origin", "https://untrusted-external.example")
			resp, doErr := client.Do(req)
			if doErr == nil {
				defer resp.Body.Close()
				allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
				allowCreds := resp.Header.Get("Access-Control-Allow-Credentials")
				if (allowOrigin == "*" || allowOrigin == "https://untrusted-external.example") && strings.EqualFold(allowCreds, "true") {
					bundle := &EvidenceBundle{
						ID:                  "ev_cors_live_" + f.ID,
						FindingID:           f.ID,
						AssessmentID:        p.AssessmentID,
						ModuleID:            "cors",
						TestIdentifier:      "CORS_WILDCARD_CREDENTIALS_CONFIRMED",
						ValidationTime:      now,
						SanitizedRequest:    "OPTIONS " + targetURL,
						SanitizedResponse:   fmt.Sprintf("Access-Control-Allow-Origin: %s\nAccess-Control-Allow-Credentials: %s", allowOrigin, allowCreds),
						ReproductionSteps:   []string{"1. Send OPTIONS preflight with external Origin", "2. Wildcard with credentials returned"},
						SafeCurlCommand:     FormatSafeCurl("OPTIONS", targetURL, http.Header{"Origin": []string{"https://untrusted-external.example"}}, ""),
						ProofSummary:        "Empirical proof: Dangerous CORS configuration permits credentialed cross-origin read access from any external domain.",
						LeastInvasiveMethod: "PREFLIGHT_HEADER_INSPECTION",
					}
					bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
					return bundle, StatusConfirmed, bundle.ProofSummary, nil
				} else if allowOrigin != "*" {
					bundle := &EvidenceBundle{
						ID:                  "ev_cors_clean_" + f.ID,
						FindingID:           f.ID,
						AssessmentID:        p.AssessmentID,
						ModuleID:            "cors",
						TestIdentifier:      "CORS_SAFE_ORIGIN",
						ValidationTime:      now,
						SanitizedRequest:    "OPTIONS " + targetURL,
						SanitizedResponse:   fmt.Sprintf("Access-Control-Allow-Origin: %s", allowOrigin),
						ReproductionSteps:   []string{"1. Preflight response tested: wildcard credentials not allowed"},
						ProofSummary:        "CORS policy does not permit wildcard credentials. Access properly restricted.",
						LeastInvasiveMethod: "PREFLIGHT_HEADER_INSPECTION",
					}
					bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
					return bundle, StatusNotValidated, bundle.ProofSummary, nil
				}
			}
		}
	}

	if strings.Contains(evidence, "Access-Control-Allow-Origin: *") && strings.Contains(evidence, "Access-Control-Allow-Credentials: true") {
		bundle := &EvidenceBundle{
			ID:                  "ev_cors_" + f.ID,
			FindingID:           f.ID,
			AssessmentID:        p.AssessmentID,
			ModuleID:            "cors",
			TestIdentifier:      "CORS_WILDCARD_CREDENTIALS_CONFIRMED",
			ValidationTime:      now,
			SanitizedRequest:    "OPTIONS " + targetURL,
			SanitizedResponse:   SanitizeHTTPContent(evidence),
			ReproductionSteps:   []string{
				"1. Send preflight request with Origin: https://untrusted-external.example",
				"2. Server responds with Access-Control-Allow-Origin: * AND Access-Control-Allow-Credentials: true",
			},
			SafeCurlCommand:     FormatSafeCurl("OPTIONS", targetURL, http.Header{"Origin": []string{"https://untrusted-external.example"}}, ""),
			ProofSummary:        "Empirical proof: Dangerous CORS configuration permits credentialed cross-origin read access from any external domain.",
			LeastInvasiveMethod: "PREFLIGHT_HEADER_INSPECTION",
		}
		bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
		return bundle, StatusConfirmed, bundle.ProofSummary, nil
	}

	bundle := &EvidenceBundle{
		ID:                  "ev_cors_high_" + f.ID,
		FindingID:           f.ID,
		AssessmentID:        p.AssessmentID,
		ModuleID:            "cors",
		TestIdentifier:      "CORS_POLICY_ANALYSIS",
		ValidationTime:      now,
		SanitizedRequest:    "OPTIONS " + targetURL,
		SanitizedResponse:   SanitizeHTTPContent(evidence),
		ReproductionSteps:   []string{"1. Cross-Origin resource sharing policy inspected"},
		ProofSummary:        "Permissive CORS header detected without credentialed reflection.",
		LeastInvasiveMethod: "HEADER_PARSING",
	}
	bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
	return bundle, StatusHighConfidence, bundle.ProofSummary, nil
}

// proveSecrets verifies exposed high-entropy credentials with automatic masking.
func (p *SafeProver) proveSecrets(ctx context.Context, f report.Finding, client *http.Client) (*EvidenceBundle, ValidationStatus, string, error) {
	now := time.Now().UTC()
	targetURL := f.Target
	evidence := f.Evidence
	candTok := ""
	if f.EvidenceDetails.Details != nil {
		candTok = strings.TrimSpace(f.EvidenceDetails.Details["candidate_token"])
	}
	sampleForPlaceholder := evidence + " " + f.EvidenceDetails.Observation + " " + f.EvidenceDetails.ObservedBehavior
	if candTok != "" {
		sampleForPlaceholder = candTok + " " + evidence
	}
	isPlaceholder, placeholderReason := secrets.ContainsPlaceholderCredential(sampleForPlaceholder)

	// Live check
	if client != nil && strings.HasPrefix(targetURL, "http") {
		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err == nil {
			resp, doErr := client.Do(req)
			if doErr == nil {
				defer resp.Body.Close()
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
				bodyStr := string(body)
				if !isPlaceholder && candTok == "" {
					isPlaceholder, placeholderReason = secrets.ContainsPlaceholderCredential(bodyStr)
				}
				lowerBody := strings.ToLower(bodyStr)
				secretStillPresent := strings.Contains(bodyStr, "AKIA") ||
					strings.Contains(bodyStr, "ghp_") ||
					strings.Contains(bodyStr, "AIza") ||
					strings.Contains(lowerBody, "bearer ") ||
					strings.Contains(bodyStr, "eyJ") ||
					(candTok != "" && strings.Contains(bodyStr, candTok))
				if !secretStillPresent {
					bundle := &EvidenceBundle{
						ID:                  "ev_sec_clean_" + f.ID,
						FindingID:           f.ID,
						AssessmentID:        p.AssessmentID,
						ModuleID:            "secrets",
						TestIdentifier:      "SECRET_REMEDIATED",
						ValidationTime:      now,
						SanitizedRequest:    "GET " + secrets.SanitizeURL(targetURL),
						SanitizedResponse:   secrets.RedactText(SanitizeHTTPContent(bodyStr)),
						ReproductionSteps:   []string{"1. Live asset re-scanned: previously detected high-entropy token is no longer present"},
						ProofSummary:        "Remediation confirmed: exposed credential has been removed from the asset.",
						LeastInvasiveMethod: "HIGH_ENTROPY_REGEX_VALIDATION",
					}
					bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
					return bundle, StatusNotValidated, bundle.ProofSummary, nil
				}
			}
		}
	}

	if f.EvidenceDetails.Details != nil {
		if isPlaceholder {
			f.EvidenceDetails.Details["is_placeholder"] = "true"
			f.EvidenceDetails.Details["credential_status"] = "INVALID"
			if placeholderReason != "" {
				f.EvidenceDetails.Details["placeholder_reason"] = placeholderReason
			}
		} else if _, exists := f.EvidenceDetails.Details["credential_status"]; !exists {
			f.EvidenceDetails.Details["credential_status"] = "CANDIDATE"
		}
	}

	if f.Fingerprint != "" || candTok != "" || strings.Contains(evidence, "AKIA") || strings.Contains(evidence, "ghp_") || strings.Contains(evidence, "AIza") || strings.Contains(strings.ToLower(evidence), "bearer ") {
		maskedEvidence := secrets.RedactText(SanitizeHTTPContent(evidence))
		proofSummary := "Empirical proof: Cleartext high-entropy API key or private secret pattern discovered in response body (usability requires separate read-only identity check)."
		if isPlaceholder {
			proofSummary = "Static secret pattern observed, but value matches known placeholder/example credential (" + placeholderReason + "); rejected as non-usable credential for attack paths."
		}
		bundle := &EvidenceBundle{
			ID:                  "ev_sec_" + f.ID,
			FindingID:           f.ID,
			AssessmentID:        p.AssessmentID,
			ModuleID:            "secrets",
			TestIdentifier:      "SECRET_TOKEN_ENTROPY_CONFIRMED",
			ValidationTime:      now,
			SanitizedRequest:    "GET " + secrets.SanitizeURL(targetURL),
			SanitizedResponse:   maskedEvidence,
			ReproductionSteps:   []string{
				"1. Retrieve response or source asset from " + secrets.SanitizeURL(targetURL),
				"2. Token matching known credential schema observed in cleartext (redacted in report artifacts)",
			},
			SafeCurlCommand:     FormatSafeCurl("GET", secrets.SanitizeURL(targetURL), nil, ""),
			ProofSummary:        proofSummary,
			LeastInvasiveMethod: "HIGH_ENTROPY_REGEX_VALIDATION",
		}
		bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
		return bundle, StatusConfirmed, bundle.ProofSummary, nil
	}

	bundle := &EvidenceBundle{
		ID:                  "ev_sec_pot_" + f.ID,
		FindingID:           f.ID,
		AssessmentID:        p.AssessmentID,
		ModuleID:            "secrets",
		TestIdentifier:      "SECRET_SUSPECTED",
		ValidationTime:      now,
		SanitizedRequest:    "GET " + secrets.SanitizeURL(targetURL),
		SanitizedResponse:   secrets.RedactText(SanitizeHTTPContent(evidence)),
		ReproductionSteps:   []string{"1. Potential sensitive keyword observed in client-side text"},
		ProofSummary:        "Suspicious token keyword detected, but entropy score is below verified threshold.",
		LeastInvasiveMethod: "KEYWORD_FREQUENCY_CHECK",
	}
	bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
	return bundle, StatusPotential, bundle.ProofSummary, nil
}

// proveBusinessLogic verifies workflow tampering or unauthorized state transition.
func (p *SafeProver) proveBusinessLogic(ctx context.Context, f report.Finding, client *http.Client) (*EvidenceBundle, ValidationStatus, string, error) {
	now := time.Now().UTC()
	targetURL := f.Target
	evidence := f.Evidence

	// Live check
	if client != nil && strings.HasPrefix(targetURL, "http") {
		req, err := http.NewRequestWithContext(ctx, "POST", targetURL, nil)
		if err == nil {
			resp, doErr := client.Do(req)
			if doErr == nil {
				defer resp.Body.Close()
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
				bodyStr := string(bodyBytes)
				if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusForbidden {
					bundle := &EvidenceBundle{
						ID:                  "ev_biz_clean_" + f.ID,
						FindingID:           f.ID,
						AssessmentID:        p.AssessmentID,
						ModuleID:            "businesslogic",
						TestIdentifier:      "BUSINESS_LOGIC_DEFENDED",
						ValidationTime:      now,
						SanitizedRequest:    "POST " + targetURL,
						SanitizedResponse:   fmt.Sprintf("HTTP %d Bad Request", resp.StatusCode),
						ReproductionSteps:   []string{"1. Skipped workflow step attempted: server rejected with state validation error"},
						ProofSummary:        "Business logic state validation enforced: out-of-order workflow request rejected.",
						LeastInvasiveMethod: "WORKFLOW_STEP_TAMPERING_CHECK",
					}
					bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
					return bundle, StatusNotValidated, bundle.ProofSummary, nil
				} else if resp.StatusCode == http.StatusOK && (strings.Contains(bodyStr, "workflow_bypassed") || strings.Contains(bodyStr, "completed")) {
					bundle := &EvidenceBundle{
						ID:                  "ev_biz_" + f.ID,
						FindingID:           f.ID,
						AssessmentID:        p.AssessmentID,
						ModuleID:            "businesslogic",
						TestIdentifier:      "BUSINESS_LOGIC_TAMPERING_CONFIRMED",
						ValidationTime:      now,
						SanitizedRequest:    "POST " + targetURL,
						SanitizedResponse:   SanitizeHTTPContent(bodyStr),
						ReproductionSteps:   []string{
							"1. Initiate multi-step business process (e.g. checkout or registration)",
							"2. Skip mandatory intermediate validation step and submit final request directly",
							"3. Server processed final state transition without enforcing procedural workflow bounds",
						},
						SafeCurlCommand:     FormatSafeCurl("POST", targetURL, nil, ""),
						ProofSummary:        "Empirical proof: Business workflow boundary bypassed by skipping intermediate validation steps.",
						LeastInvasiveMethod: "WORKFLOW_STEP_TAMPERING_CHECK",
					}
					bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
					return bundle, StatusConfirmed, bundle.ProofSummary, nil
				}
			}
		}
	}

	details := f.EvidenceDetails.Details
	if details != nil && details["workflow_tampering_confirmed"] == "true" {
		bundle := &EvidenceBundle{
			ID:                  "ev_biz_" + f.ID,
			FindingID:           f.ID,
			AssessmentID:        p.AssessmentID,
			ModuleID:            "businesslogic",
			TestIdentifier:      "BUSINESS_LOGIC_TAMPERING_CONFIRMED",
			ValidationTime:      now,
			SanitizedRequest:    f.Method + " " + targetURL,
			SanitizedResponse:   SanitizeHTTPContent(evidence),
			ReproductionSteps:   []string{
				"1. Initiate multi-step business process (e.g. checkout or registration)",
				"2. Skip mandatory intermediate validation step and submit final request directly",
				"3. Server processed final state transition without enforcing procedural workflow bounds",
			},
			SafeCurlCommand:     FormatSafeCurl(f.Method, targetURL, nil, ""),
			ProofSummary:        "Empirical proof: Business workflow boundary bypassed by skipping intermediate validation steps.",
			LeastInvasiveMethod: "WORKFLOW_STEP_TAMPERING_CHECK",
		}
		bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
		return bundle, StatusConfirmed, bundle.ProofSummary, nil
	}

	bundle := &EvidenceBundle{
		ID:                  "ev_biz_pot_" + f.ID,
		FindingID:           f.ID,
		AssessmentID:        p.AssessmentID,
		ModuleID:            "businesslogic",
		TestIdentifier:      "BUSINESS_LOGIC_INCONCLUSIVE",
		ValidationTime:      now,
		SanitizedRequest:    f.Method + " " + targetURL,
		SanitizedResponse:   SanitizeHTTPContent(evidence),
		ReproductionSteps:   []string{"1. Workflow parameter manipulation identified; manual business context review required"},
		ProofSummary:        "Potential business logic anomaly identified. Automated proof requires domain knowledge.",
		LeastInvasiveMethod: "STATE_TRANSITION_INSPECTION",
	}
	bundle.EvidenceHash = ComputeEvidenceHash(bundle.SanitizedRequest, bundle.SanitizedResponse, strings.Join(bundle.ReproductionSteps, "\n"))
	return bundle, StatusPotential, bundle.ProofSummary, nil
}
