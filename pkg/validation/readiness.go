package validation

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"felix/pkg/config"
)

// ReadinessStatus classifies pilot readiness checks without conflating missing, invalid, expired, or unconfigured states.
type ReadinessStatus string

const (
	ReadinessReady         ReadinessStatus = "READY"
	ReadinessMissing       ReadinessStatus = "MISSING"
	ReadinessInvalid       ReadinessStatus = "INVALID"
	ReadinessExpired       ReadinessStatus = "EXPIRED"
	ReadinessNotConfigured ReadinessStatus = "NOT_CONFIGURED"
	ReadinessBlocked       ReadinessStatus = "BLOCKED"
)

// ReadinessCheck records the deterministic, zero-network verification result of one pilot readiness dimension.
type ReadinessCheck struct {
	Number      int             `json:"number"`
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Status      ReadinessStatus `json:"status"`
	Blocking    bool            `json:"blocking"`
	Detail      string          `json:"detail"`
	Remediation string          `json:"remediation,omitempty"`
}

// PilotReadinessOptions supplies file paths and runtime knobs for offline pilot readiness evaluation.
type PilotReadinessOptions struct {
	ManifestPath                 string
	AuthorizationPath            string
	GroundTruthPath              string
	RolesConfigPath              string
	RetestExpectedPath           string
	BaselineReportPath           string
	TargetURL                    string
	OutputDir                    string
	BinaryPath                   string
	OASTServerURL                string
	BrowserAvailable             *bool
	RequirePublicReleaseSignoff  bool
	BinaryAuthenticodeSigned     bool
	CIHistoryAndAPTKeyResolved   bool
	CIRaceDetectorVerified       bool
	GovulncheckVerified          bool
	ExternalAccuracyBenchmarked  bool
	Now                          time.Time
}

// PilotReadinessReport captures the complete 16-point offline onboarding readiness audit.
type PilotReadinessReport struct {
	SchemaVersion           string           `json:"schema_version"`
	GeneratedAt             time.Time        `json:"generated_at"`
	TargetURL               string           `json:"target_url,omitempty"`
	OverallStatus           ReadinessStatus  `json:"overall_status"`
	PilotExecutionStatus    ReadinessStatus  `json:"pilot_execution_status"`
	PublicReleaseStatus     ReadinessStatus  `json:"public_release_status"`
	ExternalRequestsSent    int              `json:"external_requests_sent"`
	BinaryPath              string           `json:"binary_path,omitempty"`
	BinarySHA256            string           `json:"binary_sha256,omitempty"`
	GroundTruthSHA256       string           `json:"ground_truth_sha256,omitempty"`
	Summary                 map[string]int   `json:"summary"`
	BlockingReasons         []string         `json:"blocking_reasons,omitempty"`
	Checks                  []ReadinessCheck `json:"checks"`
}

func isPlaceholderValue(s string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(s))
	if trimmed == "" {
		return false
	}
	markers := []string{
		"<required",
		"template only",
		"example-authorized-app.internal",
		"<campaign_id>",
		"<finding_id",
		"sample placeholder",
		"placeholder_",
	}
	for _, m := range markers {
		if strings.Contains(trimmed, m) {
			return true
		}
	}
	return false
}

// EvaluatePilotReadiness audits all 16 pilot onboarding prerequisites offline without transmitting network traffic.
func EvaluatePilotReadiness(opts PilotReadinessOptions) PilotReadinessReport {
	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	rep := PilotReadinessReport{
		SchemaVersion:        "felix.phase10a.pilot_readiness.v1",
		GeneratedAt:          now,
		TargetURL:            strings.TrimSpace(opts.TargetURL),
		ExternalRequestsSent: 0,
		Summary:              map[string]int{},
	}

	addCheck := func(c ReadinessCheck) {
		rep.Checks = append(rep.Checks, c)
		rep.Summary[string(c.Status)]++
	}

	// 1. Binary integrity
	binPath := strings.TrimSpace(opts.BinaryPath)
	if binPath == "" {
		if exe, err := os.Executable(); err == nil {
			binPath = exe
		}
	}
	if binPath == "" {
		addCheck(ReadinessCheck{Number: 1, ID: "binary_integrity", Name: "Binary Integrity", Status: ReadinessMissing, Blocking: true, Detail: "Unable to locate FELIX binary path", Remediation: "Pass --binary <path-to-felix.exe>"})
	} else if fi, err := os.Stat(binPath); err != nil || fi.IsDir() || fi.Size() == 0 {
		addCheck(ReadinessCheck{Number: 1, ID: "binary_integrity", Name: "Binary Integrity", Status: ReadinessInvalid, Blocking: true, Detail: fmt.Sprintf("Binary path %q is invalid or unreadable", binPath), Remediation: "Rebuild felix.exe before pilot execution"})
	} else if sha, err := ComputeFileSHA256(binPath); err != nil {
		addCheck(ReadinessCheck{Number: 1, ID: "binary_integrity", Name: "Binary Integrity", Status: ReadinessInvalid, Blocking: true, Detail: fmt.Sprintf("Failed hashing binary %q: %v", binPath, err)})
	} else {
		rep.BinaryPath = binPath
		rep.BinarySHA256 = sha
		addCheck(ReadinessCheck{Number: 1, ID: "binary_integrity", Name: "Binary Integrity", Status: ReadinessReady, Blocking: false, Detail: fmt.Sprintf("%s (%d bytes, %s)", filepath.Base(binPath), fi.Size(), sha)})
	}

	// 2. Configuration availability
	cfgStore, cfgErr := config.LoadWithEnv("")
	cfgPath, cfgPathErr := config.Path()
	if cfgErr != nil {
		addCheck(ReadinessCheck{Number: 2, ID: "config_availability", Name: "Configuration Availability", Status: ReadinessInvalid, Blocking: true, Detail: fmt.Sprintf("Failed loading configuration: %v", cfgErr)})
	} else {
		loc := cfgPath
		if cfgPathErr != nil {
			loc = "defaults"
		}
		addCheck(ReadinessCheck{Number: 2, ID: "config_availability", Name: "Configuration Availability", Status: ReadinessReady, Blocking: false, Detail: fmt.Sprintf("Configuration loaded cleanly (path=%s, timeout=%ds, tls_verify=%v)", loc, cfgStore.Timeout, !cfgStore.InsecureSkipVerify)})
	}

	// Load manifest / authorization contract once for checks 3, 4, 5, 7, 9, 10
	var (
		contract        *AuthorizationContract
		manifest        *CampaignManifest
		authLoadStatus  = ReadinessMissing
		authLoadDetail  = "No --manifest or --auth-contract file provided"
		manifestStatus  = ReadinessMissing
		manifestDetail  = "No --manifest campaign manifest JSON provided"
	)

	manifestFile := strings.TrimSpace(opts.ManifestPath)
	authFile := strings.TrimSpace(opts.AuthorizationPath)
	if manifestFile != "" {
		raw, err := os.ReadFile(manifestFile)
		if err != nil {
			status := ReadinessInvalid
			if os.IsNotExist(err) {
				status = ReadinessMissing
			}
			authLoadStatus = status
			authLoadDetail = fmt.Sprintf("Could not read manifest %q: %v", manifestFile, err)
			manifestStatus = status
			manifestDetail = authLoadDetail
		} else {
			c, cm, parseErr := ParseAuthOrCampaignManifest(raw)
			if parseErr != nil {
				authLoadStatus = ReadinessInvalid
				authLoadDetail = fmt.Sprintf("Invalid manifest JSON %q: %v", manifestFile, parseErr)
				manifestStatus = ReadinessInvalid
				manifestDetail = authLoadDetail
			} else {
				contract = &c
				if cm != nil {
					manifest = cm
					if rep.TargetURL == "" && cm.TargetURL != "" {
						rep.TargetURL = strings.TrimSpace(cm.TargetURL)
					}
				}
			}
		}
	}
	if authFile != "" {
		raw, err := os.ReadFile(authFile)
		if err != nil {
			if os.IsNotExist(err) {
				authLoadStatus = ReadinessMissing
			} else {
				authLoadStatus = ReadinessInvalid
			}
			authLoadDetail = fmt.Sprintf("Could not read authorization contract %q: %v", authFile, err)
		} else {
			var c AuthorizationContract
			if parseErr := json.Unmarshal(raw, &c); parseErr != nil {
				authLoadStatus = ReadinessInvalid
				authLoadDetail = fmt.Sprintf("Invalid authorization contract JSON %q: %v", authFile, parseErr)
			} else {
				contract = &c
			}
		}
	}

	effectiveTarget := rep.TargetURL
	if effectiveTarget == "" && contract != nil && len(contract.AuthorizedTargets) > 0 {
		effectiveTarget = strings.TrimSpace(contract.AuthorizedTargets[0])
		rep.TargetURL = effectiveTarget
	}

	// 3. Authorization contract structure & window
	if contract == nil {
		addCheck(ReadinessCheck{Number: 3, ID: "authorization_contract", Name: "Authorization Contract Structure", Status: authLoadStatus, Blocking: true, Detail: authLoadDetail, Remediation: "Provide an owner-signed AuthorizationContract with confirmed=true"})
	} else {
		cCheck := evaluateContractCheck(contract, effectiveTarget, now)
		addCheck(cCheck)
	}

	// 4. Campaign manifest validity
	if manifest == nil {
		addCheck(ReadinessCheck{Number: 4, ID: "campaign_manifest", Name: "Campaign Manifest Validity", Status: manifestStatus, Blocking: true, Detail: manifestDetail, Remediation: "Create campaign_manifest.json with manifest_id, target_url, blind_execution=true, and ground_truth_sha256"})
	} else {
		addCheck(evaluateManifestCheck(manifest))
	}

	// Load ground truth once for checks 5-13
	var (
		gtReg       *GroundTruthRegistry
		gtHash      string
		gtLoadState = ReadinessMissing
		gtLoadMsg   = "No --ground-truth registry file provided"
	)
	if strings.TrimSpace(opts.GroundTruthPath) != "" {
		gtRaw, err := os.ReadFile(opts.GroundTruthPath)
		if err != nil {
			if os.IsNotExist(err) {
				gtLoadState = ReadinessMissing
			} else {
				gtLoadState = ReadinessInvalid
			}
			gtLoadMsg = fmt.Sprintf("Could not read ground-truth registry %q: %v", opts.GroundTruthPath, err)
		} else {
			var reg GroundTruthRegistry
			if uErr := json.Unmarshal(gtRaw, &reg); uErr != nil {
				gtLoadState = ReadinessInvalid
				gtLoadMsg = fmt.Sprintf("Invalid ground-truth JSON %q: %v", opts.GroundTruthPath, uErr)
			} else {
				gtReg = &reg
				if h, hErr := CanonicalGroundTruthSHA256(gtReg); hErr == nil {
					gtHash = h
					rep.GroundTruthSHA256 = h
				}
			}
		}
	}

	// 5. Target origin consistency
	addCheck(evaluateTargetOriginCheck(effectiveTarget, contract, manifest, gtReg))

	// 6. Ground-truth registry structure
	addCheck(evaluateGTStructureCheck(gtReg, gtLoadState, gtLoadMsg))

	// 7. Ground-truth SHA-256 lock
	addCheck(evaluateGTLockCheck(gtReg, gtHash, manifest, gtLoadState, gtLoadMsg))

	// 8. derived_from_scanner: false
	if gtReg == nil {
		addCheck(ReadinessCheck{Number: 8, ID: "ground_truth_independence", Name: "Ground-Truth Independence (derived_from_scanner=false)", Status: gtLoadState, Blocking: true, Detail: gtLoadMsg})
	} else if gtReg.DerivedFromScanner {
		addCheck(ReadinessCheck{Number: 8, ID: "ground_truth_independence", Name: "Ground-Truth Independence (derived_from_scanner=false)", Status: ReadinessInvalid, Blocking: true, Detail: "derived_from_scanner is true; ground truth is not independent", Remediation: "Rebuild ground truth from source/API specs without scanner output"})
	} else {
		addCheck(ReadinessCheck{Number: 8, ID: "ground_truth_independence", Name: "Ground-Truth Independence (derived_from_scanner=false)", Status: ReadinessReady, Blocking: false, Detail: fmt.Sprintf("derived_from_scanner=false (established_by=%q)", gtReg.EstablishedBy)})
	}

	// 9. Ground-truth timestamp precedence
	addCheck(evaluateGTTimestampCheck(gtReg, manifest, now, gtLoadState, gtLoadMsg))

	// 10. Exclusion consistency
	addCheck(evaluateExclusionConsistencyCheck(effectiveTarget, contract, gtReg))

	// 11. Identity configuration
	addCheck(evaluateIdentityConfigCheck(opts.RolesConfigPath, gtReg))

	// 12. Required OAST configuration
	oastURL := strings.TrimSpace(opts.OASTServerURL)
	if oastURL == "" {
		oastURL = strings.TrimSpace(os.Getenv("FELIX_OAST_SERVER"))
	}
	if oastURL == "" {
		oastURL = strings.TrimSpace(os.Getenv("FELIX_OAST_DOMAIN"))
	}
	addCheck(evaluateRequiredCapabilityCheck(12, "oast_configuration", "Required OAST Configuration", "OAST", oastURL != "", "FELIX OAST callback server/domain configured ("+oastURL+")", "Ground truth requires OAST callback server (--oast-server, FELIX_OAST_SERVER, or FELIX_OAST_DOMAIN)", gtReg))

	// 13. Required browser-DOM configuration
	browserOK := detectBrowserAvailability(opts.BrowserAvailable)
	addCheck(evaluateRequiredCapabilityCheck(13, "browser_dom_configuration", "Required Browser-DOM Configuration", "BROWSER_DOM", browserOK, "Local headless browser binary detected", "Ground truth requires BROWSER_DOM engine but no Chromium/Edge binary was detected", gtReg))

	// 14. Output directory permissions
	addCheck(evaluateOutputDirCheck(opts.OutputDir))

	// 15. Retest prerequisites
	addCheck(evaluateRetestPrereqCheck(opts.RetestExpectedPath, opts.BaselineReportPath))

	// 16. Release & CI blockers
	releaseCheck, releaseBlocked := evaluateReleaseBlockersCheck(opts)
	addCheck(releaseCheck)
	if releaseBlocked {
		rep.PublicReleaseStatus = ReadinessBlocked
	} else {
		rep.PublicReleaseStatus = ReadinessReady
	}

	// Compute PilotExecutionStatus & OverallStatus conservatively
	rep.PilotExecutionStatus, rep.OverallStatus, rep.BlockingReasons = summarizeReadinessStatus(rep.Checks, opts.RequirePublicReleaseSignoff)
	return rep
}

func evaluateContractCheck(contract *AuthorizationContract, targetURL string, now time.Time) ReadinessCheck {
	if isPlaceholderValue(contract.AuthorizingParty) || isPlaceholderValue(contract.SignedBy) || isPlaceholderValue(contract.AuthorizationRef) || isPlaceholderValue(contract.Notes) || isPlaceholderValue(targetURL) {
		return ReadinessCheck{Number: 3, ID: "authorization_contract", Name: "Authorization Contract Structure", Status: ReadinessInvalid, Blocking: true, Detail: "Authorization contract contains template placeholders rather than owner-signed data", Remediation: "Replace placeholders with real owner signatory, reference ID, and authorized target origin"}
	}
	if !contract.Confirmed {
		return ReadinessCheck{Number: 3, ID: "authorization_contract", Name: "Authorization Contract Structure", Status: ReadinessBlocked, Blocking: true, Detail: "Authorization contract confirmed=false (not signed/approved by owner)", Remediation: "Obtain signed owner approval and set confirmed=true"}
	}
	if strings.TrimSpace(contract.AuthorizingParty) == "" || strings.TrimSpace(contract.AuthorizationRef) == "" {
		return ReadinessCheck{Number: 3, ID: "authorization_contract", Name: "Authorization Contract Structure", Status: ReadinessInvalid, Blocking: true, Detail: "authorizing_party or authorization_ref is empty"}
	}
	if len(contract.AuthorizedTargets) == 0 {
		return ReadinessCheck{Number: 3, ID: "authorization_contract", Name: "Authorization Contract Structure", Status: ReadinessInvalid, Blocking: true, Detail: "No authorized_targets defined in contract"}
	}
	if contract.WindowStart.IsZero() || contract.WindowEnd.IsZero() {
		return ReadinessCheck{Number: 3, ID: "authorization_contract", Name: "Authorization Contract Structure", Status: ReadinessInvalid, Blocking: true, Detail: "UTC window_start and window_end are mandatory for pilot onboarding"}
	}
	if !contract.WindowEnd.After(contract.WindowStart) {
		return ReadinessCheck{Number: 3, ID: "authorization_contract", Name: "Authorization Contract Structure", Status: ReadinessInvalid, Blocking: true, Detail: "window_end must be strictly after window_start"}
	}
	if now.After(contract.WindowEnd) {
		return ReadinessCheck{Number: 3, ID: "authorization_contract", Name: "Authorization Contract Structure", Status: ReadinessExpired, Blocking: true, Detail: fmt.Sprintf("UTC authorization window expired at %s (now=%s)", contract.WindowEnd.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339)), Remediation: "Obtain renewed UTC testing window from owner"}
	}
	if strings.TrimSpace(targetURL) != "" {
		if err := ValidateAuthorizationGate(*contract, targetURL, now); err != nil {
			if now.Before(contract.WindowStart) {
				return ReadinessCheck{Number: 3, ID: "authorization_contract", Name: "Authorization Contract Structure", Status: ReadinessBlocked, Blocking: true, Detail: err.Error(), Remediation: fmt.Sprintf("Wait until UTC window_start (%s)", contract.WindowStart.UTC().Format(time.RFC3339))}
			}
			return ReadinessCheck{Number: 3, ID: "authorization_contract", Name: "Authorization Contract Structure", Status: ReadinessInvalid, Blocking: true, Detail: err.Error()}
		}
	}
	return ReadinessCheck{Number: 3, ID: "authorization_contract", Name: "Authorization Contract Structure", Status: ReadinessReady, Blocking: false, Detail: fmt.Sprintf("Confirmed by %s (ref=%s, UTC window %s..%s)", contract.AuthorizingParty, contract.AuthorizationRef, contract.WindowStart.UTC().Format(time.RFC3339), contract.WindowEnd.UTC().Format(time.RFC3339))}
}

func evaluateManifestCheck(cm *CampaignManifest) ReadinessCheck {
	if isPlaceholderValue(cm.ManifestID) || isPlaceholderValue(cm.TargetName) || isPlaceholderValue(cm.TargetURL) || isPlaceholderValue(cm.GroundTruthRegistryID) || isPlaceholderValue(cm.GroundTruthSHA256) {
		return ReadinessCheck{Number: 4, ID: "campaign_manifest", Name: "Campaign Manifest Validity", Status: ReadinessInvalid, Blocking: true, Detail: "Campaign manifest contains unedited template placeholder fields"}
	}
	if strings.TrimSpace(cm.ManifestID) == "" || strings.TrimSpace(cm.TargetURL) == "" {
		return ReadinessCheck{Number: 4, ID: "campaign_manifest", Name: "Campaign Manifest Validity", Status: ReadinessInvalid, Blocking: true, Detail: "manifest_id and target_url must be non-empty"}
	}
	if !cm.BlindExecution {
		return ReadinessCheck{Number: 4, ID: "campaign_manifest", Name: "Campaign Manifest Validity", Status: ReadinessInvalid, Blocking: true, Detail: "blind_execution must be true"}
	}
	if err := ValidateGroundTruthSHA256Format(cm.GroundTruthSHA256); err != nil {
		return ReadinessCheck{Number: 4, ID: "campaign_manifest", Name: "Campaign Manifest Validity", Status: ReadinessInvalid, Blocking: true, Detail: err.Error()}
	}
	return ReadinessCheck{Number: 4, ID: "campaign_manifest", Name: "Campaign Manifest Validity", Status: ReadinessReady, Blocking: false, Detail: fmt.Sprintf("Campaign manifest %s valid (blind_execution=true, env=%s)", cm.ManifestID, cm.Environment)}
}

func evaluateTargetOriginCheck(targetURL string, contract *AuthorizationContract, cm *CampaignManifest, gt *GroundTruthRegistry) ReadinessCheck {
	if strings.TrimSpace(targetURL) == "" {
		return ReadinessCheck{Number: 5, ID: "target_origin_consistency", Name: "Target Origin Consistency", Status: ReadinessMissing, Blocking: true, Detail: "No target URL supplied in --target, manifest, or authorization contract"}
	}
	tParsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || tParsed.Scheme == "" || tParsed.Hostname() == "" || isPlaceholderValue(targetURL) {
		return ReadinessCheck{Number: 5, ID: "target_origin_consistency", Name: "Target Origin Consistency", Status: ReadinessInvalid, Blocking: true, Detail: fmt.Sprintf("Target URL %q is missing a valid non-placeholder scheme/host", targetURL)}
	}
	canonicalOrigin := strings.ToLower(tParsed.Scheme + "://" + tParsed.Host)

	if contract != nil {
		sv := BuildScopeValidator(*contract)
		if !sv.IsAllowed(targetURL) {
			return ReadinessCheck{Number: 5, ID: "target_origin_consistency", Name: "Target Origin Consistency", Status: ReadinessInvalid, Blocking: true, Detail: fmt.Sprintf("Target %s is outside contract authorized_targets or matches contract exclusions", targetURL)}
		}
	} else {
		return ReadinessCheck{Number: 5, ID: "target_origin_consistency", Name: "Target Origin Consistency", Status: ReadinessMissing, Blocking: true, Detail: "Cannot confirm target origin consistency without authorization contract"}
	}
	if cm != nil && strings.TrimSpace(cm.TargetURL) != "" {
		if cmp, pErr := url.Parse(strings.TrimSpace(cm.TargetURL)); pErr != nil || !strings.EqualFold(cmp.Scheme+"://"+cmp.Host, canonicalOrigin) {
			return ReadinessCheck{Number: 5, ID: "target_origin_consistency", Name: "Target Origin Consistency", Status: ReadinessInvalid, Blocking: true, Detail: fmt.Sprintf("Campaign manifest target_url %q origin differs from %s", cm.TargetURL, canonicalOrigin)}
		}
	}
	if gt != nil && strings.TrimSpace(gt.TargetOrigin) != "" {
		if gp, pErr := url.Parse(strings.TrimSpace(gt.TargetOrigin)); pErr != nil || !strings.EqualFold(gp.Scheme+"://"+gp.Host, canonicalOrigin) {
			return ReadinessCheck{Number: 5, ID: "target_origin_consistency", Name: "Target Origin Consistency", Status: ReadinessInvalid, Blocking: true, Detail: fmt.Sprintf("Ground-truth target_origin %q differs from %s", gt.TargetOrigin, canonicalOrigin)}
		}
	}
	return ReadinessCheck{Number: 5, ID: "target_origin_consistency", Name: "Target Origin Consistency", Status: ReadinessReady, Blocking: false, Detail: fmt.Sprintf("Canonical origin %s consistent across manifest, contract, and ground truth", canonicalOrigin)}
}

func evaluateGTStructureCheck(gt *GroundTruthRegistry, loadState ReadinessStatus, loadMsg string) ReadinessCheck {
	if gt == nil {
		return ReadinessCheck{Number: 6, ID: "ground_truth_structure", Name: "Ground-Truth Registry Structure", Status: loadState, Blocking: true, Detail: loadMsg, Remediation: "Create independent pre-scan ground_truth.json with positive and negative controls"}
	}
	if isPlaceholderValue(gt.RegistryID) || isPlaceholderValue(gt.Application) || isPlaceholderValue(gt.TargetOrigin) || isPlaceholderValue(gt.EstablishedBy) || isPlaceholderValue(gt.ProvenanceNote) {
		return ReadinessCheck{Number: 6, ID: "ground_truth_structure", Name: "Ground-Truth Registry Structure", Status: ReadinessInvalid, Blocking: true, Detail: "Ground-truth metadata contains template placeholders"}
	}
	if strings.TrimSpace(gt.RegistryID) == "" || strings.TrimSpace(gt.Application) == "" || len(gt.Entries) == 0 {
		return ReadinessCheck{Number: 6, ID: "ground_truth_structure", Name: "Ground-Truth Registry Structure", Status: ReadinessInvalid, Blocking: true, Detail: "Ground-truth registry must declare registry_id, application, and at least one entry"}
	}
	for i, e := range gt.Entries {
		if strings.TrimSpace(e.ID) == "" || strings.TrimSpace(e.EndpointPattern) == "" || strings.TrimSpace(e.Method) == "" || strings.TrimSpace(e.VulnClass) == "" {
			return ReadinessCheck{Number: 6, ID: "ground_truth_structure", Name: "Ground-Truth Registry Structure", Status: ReadinessInvalid, Blocking: true, Detail: fmt.Sprintf("Entry[%d] (%q) is missing id, endpoint_pattern, method, or vuln_class", i, e.ID)}
		}
		switch e.ExpectedStatus {
		case GTVulnerable, GTNegativeControl, GTExcludedScope, GTOutOfScope:
		default:
			return ReadinessCheck{Number: 6, ID: "ground_truth_structure", Name: "Ground-Truth Registry Structure", Status: ReadinessInvalid, Blocking: true, Detail: fmt.Sprintf("Entry %q has invalid expected_status %q", e.ID, e.ExpectedStatus)}
		}
	}
	return ReadinessCheck{Number: 6, ID: "ground_truth_structure", Name: "Ground-Truth Registry Structure", Status: ReadinessReady, Blocking: false, Detail: fmt.Sprintf("Registry %s contains %d valid entries", gt.RegistryID, len(gt.Entries))}
}

func evaluateGTLockCheck(gt *GroundTruthRegistry, gtHash string, cm *CampaignManifest, loadState ReadinessStatus, loadMsg string) ReadinessCheck {
	if gt == nil {
		return ReadinessCheck{Number: 7, ID: "ground_truth_sha256", Name: "Ground-Truth SHA-256 Hash Lock", Status: loadState, Blocking: true, Detail: loadMsg}
	}
	if cm == nil {
		return ReadinessCheck{Number: 7, ID: "ground_truth_sha256", Name: "Ground-Truth SHA-256 Hash Lock", Status: ReadinessMissing, Blocking: true, Detail: fmt.Sprintf("Computed GT digest %s, but no campaign manifest was supplied to verify pre-scan lock", gtHash)}
	}
	if err := ValidateGroundTruthSHA256Format(cm.GroundTruthSHA256); err != nil {
		return ReadinessCheck{Number: 7, ID: "ground_truth_sha256", Name: "Ground-Truth SHA-256 Hash Lock", Status: ReadinessInvalid, Blocking: true, Detail: err.Error()}
	}
	if !strings.EqualFold(strings.TrimSpace(cm.GroundTruthSHA256), gtHash) {
		return ReadinessCheck{Number: 7, ID: "ground_truth_sha256", Name: "Ground-Truth SHA-256 Hash Lock", Status: ReadinessInvalid, Blocking: true, Detail: fmt.Sprintf("Digest mismatch: manifest=%s computed=%s", cm.GroundTruthSHA256, gtHash)}
	}
	return ReadinessCheck{Number: 7, ID: "ground_truth_sha256", Name: "Ground-Truth SHA-256 Hash Lock", Status: ReadinessReady, Blocking: false, Detail: fmt.Sprintf("Locked digest verified (%s)", gtHash)}
}

func evaluateGTTimestampCheck(gt *GroundTruthRegistry, cm *CampaignManifest, now time.Time, loadState ReadinessStatus, loadMsg string) ReadinessCheck {
	if gt == nil {
		return ReadinessCheck{Number: 9, ID: "ground_truth_timestamp_precedence", Name: "Ground-Truth Timestamp Precedence", Status: loadState, Blocking: true, Detail: loadMsg}
	}
	if gt.EstablishedAt.IsZero() {
		return ReadinessCheck{Number: 9, ID: "ground_truth_timestamp_precedence", Name: "Ground-Truth Timestamp Precedence", Status: ReadinessInvalid, Blocking: true, Detail: "ground-truth established_at timestamp is missing"}
	}
	if gt.EstablishedAt.After(now) {
		return ReadinessCheck{Number: 9, ID: "ground_truth_timestamp_precedence", Name: "Ground-Truth Timestamp Precedence", Status: ReadinessInvalid, Blocking: true, Detail: fmt.Sprintf("ground-truth established_at (%s) is in the future relative to current UTC (%s)", gt.EstablishedAt.UTC().Format(time.RFC3339), now.Format(time.RFC3339))}
	}
	if cm != nil && !cm.ExecutedAt.IsZero() && gt.EstablishedAt.After(cm.ExecutedAt) {
		return ReadinessCheck{Number: 9, ID: "ground_truth_timestamp_precedence", Name: "Ground-Truth Timestamp Precedence", Status: ReadinessInvalid, Blocking: true, Detail: fmt.Sprintf("ground-truth established_at (%s) is after manifest executed_at (%s)", gt.EstablishedAt.UTC().Format(time.RFC3339), cm.ExecutedAt.UTC().Format(time.RFC3339))}
	}
	return ReadinessCheck{Number: 9, ID: "ground_truth_timestamp_precedence", Name: "Ground-Truth Timestamp Precedence", Status: ReadinessReady, Blocking: false, Detail: fmt.Sprintf("established_at=%s precedes execution", gt.EstablishedAt.UTC().Format(time.RFC3339))}
}

func evaluateExclusionConsistencyCheck(targetURL string, contract *AuthorizationContract, gt *GroundTruthRegistry) ReadinessCheck {
	if contract == nil {
		return ReadinessCheck{Number: 10, ID: "exclusion_consistency", Name: "Exclusion Consistency", Status: ReadinessMissing, Blocking: true, Detail: "No authorization contract to check exclusions"}
	}
	sv := BuildScopeValidator(*contract)
	if strings.TrimSpace(targetURL) != "" {
		if excluded, reason := sv.IsExcluded(targetURL); excluded {
			return ReadinessCheck{Number: 10, ID: "exclusion_consistency", Name: "Exclusion Consistency", Status: ReadinessInvalid, Blocking: true, Detail: fmt.Sprintf("Root target URL %s is itself excluded (%s)", targetURL, reason)}
		}
	}
	if gt != nil && strings.TrimSpace(targetURL) != "" {
		baseParsed, err := url.Parse(strings.TrimSpace(targetURL))
		if err == nil {
			for _, e := range gt.Entries {
				if !e.InScope || (e.ExpectedStatus != GTVulnerable && e.ExpectedStatus != GTNegativeControl) {
					continue
				}
				cand := baseParsed.Scheme + "://" + baseParsed.Host + e.EndpointPattern
				if !strings.HasPrefix(e.EndpointPattern, "/") {
					cand = baseParsed.Scheme + "://" + baseParsed.Host + "/" + e.EndpointPattern
				}
				if excluded, reason := sv.IsExcluded(cand); excluded {
					return ReadinessCheck{Number: 10, ID: "exclusion_consistency", Name: "Exclusion Consistency", Status: ReadinessInvalid, Blocking: true, Detail: fmt.Sprintf("Ground-truth entry %s (%s) is marked in_scope=true but excluded by contract (%s)", e.ID, e.EndpointPattern, reason)}
				}
			}
		}
	}
	return ReadinessCheck{Number: 10, ID: "exclusion_consistency", Name: "Exclusion Consistency", Status: ReadinessReady, Blocking: false, Detail: fmt.Sprintf("%d path/URL/host exclusions validated consistent with target and ground truth", len(contract.ExcludedPaths)+len(contract.ExcludedURLs)+len(contract.ExcludedHosts))}
}

func evaluateIdentityConfigCheck(rolesPath string, gt *GroundTruthRegistry) ReadinessCheck {
	needsMultiRole := false
	needsAuth := false
	if gt != nil {
		for _, e := range gt.Entries {
			if e.ExpectedStatus == GTOutOfScope || e.ExpectedStatus == GTExcludedScope || !e.InScope {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(e.RequiresConfig), "MULTI_ROLE") || len(e.RequiredIdentities) >= 2 {
				needsMultiRole = true
			}
			if len(e.RequiredIdentities) > 0 {
				needsAuth = true
			}
		}
	}
	if strings.TrimSpace(rolesPath) == "" {
		if needsMultiRole || needsAuth {
			return ReadinessCheck{Number: 11, ID: "identity_configuration", Name: "Approved Test Identity Configuration", Status: ReadinessMissing, Blocking: true, Detail: "Ground truth requires authenticated / multi-role identities, but --roles-config was not provided"}
		}
		return ReadinessCheck{Number: 11, ID: "identity_configuration", Name: "Approved Test Identity Configuration", Status: ReadinessNotConfigured, Blocking: false, Detail: "No --roles-config supplied; unauthenticated testing only"}
	}
	raw, err := os.ReadFile(rolesPath)
	if err != nil {
		st := ReadinessInvalid
		if os.IsNotExist(err) {
			st = ReadinessMissing
		}
		return ReadinessCheck{Number: 11, ID: "identity_configuration", Name: "Approved Test Identity Configuration", Status: st, Blocking: true, Detail: fmt.Sprintf("Could not read --roles-config %q: %v", rolesPath, err)}
	}
	if isPlaceholderValue(string(raw)) {
		return ReadinessCheck{Number: 11, ID: "identity_configuration", Name: "Approved Test Identity Configuration", Status: ReadinessInvalid, Blocking: true, Detail: "Roles config file contains template placeholders instead of approved credentials"}
	}
	var roleMap map[string]interface{}
	if err := json.Unmarshal(raw, &roleMap); err != nil || len(roleMap) == 0 {
		return ReadinessCheck{Number: 11, ID: "identity_configuration", Name: "Approved Test Identity Configuration", Status: ReadinessInvalid, Blocking: true, Detail: fmt.Sprintf("Roles config %q must be a non-empty JSON object of role credentials", rolesPath)}
	}
	if needsMultiRole && len(roleMap) < 2 {
		return ReadinessCheck{Number: 11, ID: "identity_configuration", Name: "Approved Test Identity Configuration", Status: ReadinessNotConfigured, Blocking: true, Detail: fmt.Sprintf("Ground truth requires MULTI_ROLE testing (>=2 identities), found %d in %q", len(roleMap), rolesPath)}
	}
	return ReadinessCheck{Number: 11, ID: "identity_configuration", Name: "Approved Test Identity Configuration", Status: ReadinessReady, Blocking: false, Detail: fmt.Sprintf("%d approved role entries configured cleanly in %s", len(roleMap), filepath.Base(rolesPath))}
}

func evaluateRequiredCapabilityCheck(num int, id, name, reqTag string, available bool, readyMsg, notCfgMsg string, gt *GroundTruthRegistry) ReadinessCheck {
	required := false
	if gt != nil {
		for _, e := range gt.Entries {
			if e.InScope && strings.EqualFold(strings.TrimSpace(e.RequiresConfig), reqTag) {
				required = true
				break
			}
		}
	}
	if required && !available {
		return ReadinessCheck{Number: num, ID: id, Name: name, Status: ReadinessNotConfigured, Blocking: true, Detail: notCfgMsg}
	}
	if !required && !available {
		return ReadinessCheck{Number: num, ID: id, Name: name, Status: ReadinessNotConfigured, Blocking: false, Detail: fmt.Sprintf("Not configured (%s not required by current ground-truth entries)", reqTag)}
	}
	return ReadinessCheck{Number: num, ID: id, Name: name, Status: ReadinessReady, Blocking: false, Detail: readyMsg}
}

func detectBrowserAvailability(override *bool) bool {
	if override != nil {
		return *override
	}
	if envBin := strings.TrimSpace(os.Getenv("FELIX_BROWSER_PATH")); envBin != "" {
		if _, err := os.Stat(envBin); err == nil {
			return true
		}
	}
	candidates := []string{
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return true
		}
	}
	for _, bin := range []string{"chromium", "google-chrome", "msedge"} {
		if _, err := exec.LookPath(bin); err == nil {
			return true
		}
	}
	return false
}

func evaluateOutputDirCheck(outputDir string) ReadinessCheck {
	if strings.TrimSpace(outputDir) == "" {
		return ReadinessCheck{Number: 14, ID: "output_directory_permissions", Name: "Output Directory Permissions", Status: ReadinessNotConfigured, Blocking: false, Detail: "No --output-dir supplied; pass --output-dir <campaign_output_dir> prior to execution"}
	}
	cleanDir := filepath.Clean(outputDir)
	created := false
	if _, err := os.Stat(cleanDir); os.IsNotExist(err) {
		if mkErr := os.MkdirAll(cleanDir, 0700); mkErr != nil {
			return ReadinessCheck{Number: 14, ID: "output_directory_permissions", Name: "Output Directory Permissions", Status: ReadinessInvalid, Blocking: true, Detail: fmt.Sprintf("Cannot create output directory %q: %v", cleanDir, mkErr)}
		}
		created = true
	}
	probe := filepath.Join(cleanDir, ".felix-readiness-perm-check.tmp")
	if err := os.WriteFile(probe, []byte("ok"), 0600); err != nil {
		if created {
			_ = os.RemoveAll(cleanDir)
		}
		return ReadinessCheck{Number: 14, ID: "output_directory_permissions", Name: "Output Directory Permissions", Status: ReadinessInvalid, Blocking: true, Detail: fmt.Sprintf("Output directory %q is not writable: %v", cleanDir, err)}
	}
	_ = os.Remove(probe)
	if created {
		_ = os.Remove(cleanDir)
	}
	return ReadinessCheck{Number: 14, ID: "output_directory_permissions", Name: "Output Directory Permissions", Status: ReadinessReady, Blocking: false, Detail: fmt.Sprintf("Output directory %q writable with private 0600/0700 file permissions", cleanDir)}
}

func evaluateRetestPrereqCheck(retestExpectedPath, baselineReportPath string) ReadinessCheck {
	if strings.TrimSpace(retestExpectedPath) == "" {
		return ReadinessCheck{Number: 15, ID: "retest_prerequisites", Name: "Retest Prerequisites", Status: ReadinessNotConfigured, Blocking: false, Detail: "No --retest-expected file supplied (required before post-patch retest evaluation)"}
	}
	raw, err := os.ReadFile(retestExpectedPath)
	if err != nil {
		st := ReadinessInvalid
		if os.IsNotExist(err) {
			st = ReadinessMissing
		}
		return ReadinessCheck{Number: 15, ID: "retest_prerequisites", Name: "Retest Prerequisites", Status: st, Blocking: true, Detail: fmt.Sprintf("Could not read --retest-expected %q: %v", retestExpectedPath, err)}
	}
	if isPlaceholderValue(string(raw)) {
		return ReadinessCheck{Number: 15, ID: "retest_prerequisites", Name: "Retest Prerequisites", Status: ReadinessInvalid, Blocking: true, Detail: "Retest expectations file contains template placeholders (<finding_id>)"}
	}
	var items []RetestExpectedItem
	if err := json.Unmarshal(raw, &items); err != nil || len(items) == 0 {
		return ReadinessCheck{Number: 15, ID: "retest_prerequisites", Name: "Retest Prerequisites", Status: ReadinessInvalid, Blocking: true, Detail: fmt.Sprintf("--retest-expected %q must contain a non-empty JSON array of expectations", retestExpectedPath)}
	}
	for i, it := range items {
		act := strings.ToUpper(strings.TrimSpace(it.ExpectedAction))
		if strings.TrimSpace(it.FindingID) == "" || (act != "FIXED" && act != "STILL_PRESENT") {
			return ReadinessCheck{Number: 15, ID: "retest_prerequisites", Name: "Retest Prerequisites", Status: ReadinessInvalid, Blocking: true, Detail: fmt.Sprintf("Retest item[%d] invalid (finding_id=%q, expected_action=%q)", i, it.FindingID, it.ExpectedAction)}
		}
	}
	if strings.TrimSpace(baselineReportPath) != "" {
		if _, err := os.Stat(baselineReportPath); err != nil {
			return ReadinessCheck{Number: 15, ID: "retest_prerequisites", Name: "Retest Prerequisites", Status: ReadinessMissing, Blocking: true, Detail: fmt.Sprintf("Baseline report %q not found", baselineReportPath)}
		}
	}
	return ReadinessCheck{Number: 15, ID: "retest_prerequisites", Name: "Retest Prerequisites", Status: ReadinessReady, Blocking: false, Detail: fmt.Sprintf("%d valid retest expectations loaded", len(items))}
}

func evaluateReleaseBlockersCheck(opts PilotReadinessOptions) (ReadinessCheck, bool) {
	var open []string
	if !opts.BinaryAuthenticodeSigned {
		open = append(open, "Windows Authenticode code signing (P12.10)")
	}
	if !opts.CIHistoryAndAPTKeyResolved {
		open = append(open, "Production APT signing key provisioning + historical key 8ABF68D0253A139577CA06E7154B088FE357A53D revocation + Git history scrub")
	}
	if !opts.CIRaceDetectorVerified {
		open = append(open, "CI CGO_ENABLED=1 go test -race verification")
	}
	if !opts.GovulncheckVerified {
		open = append(open, "CI govulncheck verification")
	}
	if !opts.ExternalAccuracyBenchmarked {
		open = append(open, "External real-world accuracy benchmark (n>=20 controls/class)")
	}
	if len(open) == 0 {
		return ReadinessCheck{Number: 16, ID: "release_and_ci_blockers", Name: "Release & CI Blockers", Status: ReadinessReady, Blocking: false, Detail: "All public distribution, CI, and benchmark gates closed"}, false
	}
	return ReadinessCheck{
		Number:      16,
		ID:          "release_and_ci_blockers",
		Name:        "Release & CI Blockers",
		Status:      ReadinessBlocked,
		Blocking:    opts.RequirePublicReleaseSignoff,
		Detail:      fmt.Sprintf("%d public-release/CI blockers remain open: %s", len(open), strings.Join(open, "; ")),
		Remediation: "Hold public binary distribution until CI signing and external benchmark gates close; does not block controlled owner-authorized pilot if checks 1-15 are READY",
	}, true
}

func summarizeReadinessStatus(checks []ReadinessCheck, requirePublicSignoff bool) (ReadinessStatus, ReadinessStatus, []string) {
	var (
		reasons       []string
		hasBlocked    bool
		hasInvalid    bool
		hasMissing    bool
		hasExpired    bool
		hasNotCfgBlk  bool
		hasReleaseBlk bool
	)
	for _, c := range checks {
		if c.ID == "release_and_ci_blockers" {
			if c.Status != ReadinessReady {
				hasReleaseBlk = true
				if requirePublicSignoff {
					hasBlocked = true
					reasons = append(reasons, fmt.Sprintf("[%d:%s] %s: %s", c.Number, c.Status, c.Name, c.Detail))
				}
			}
			continue
		}
		if !c.Blocking && c.Status != ReadinessInvalid && c.Status != ReadinessExpired {
			continue
		}
		if c.Status == ReadinessReady {
			continue
		}
		reasons = append(reasons, fmt.Sprintf("[%d:%s] %s: %s", c.Number, c.Status, c.Name, c.Detail))
		switch c.Status {
		case ReadinessBlocked:
			hasBlocked = true
		case ReadinessInvalid:
			hasInvalid = true
		case ReadinessMissing:
			hasMissing = true
		case ReadinessExpired:
			hasExpired = true
		case ReadinessNotConfigured:
			hasNotCfgBlk = true
		}
	}

	pilotStatus := ReadinessReady
	switch {
	case hasBlocked || hasMissing || hasInvalid || hasNotCfgBlk:
		pilotStatus = ReadinessBlocked
	case hasExpired:
		pilotStatus = ReadinessExpired
	}

	overall := pilotStatus
	if pilotStatus == ReadinessReady && hasReleaseBlk && requirePublicSignoff {
		overall = ReadinessBlocked
	}
	return pilotStatus, overall, reasons
}
