package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

const (
	SARIFSchemaVersion = "2.1.0"
	SARIFSchemaURI     = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	DriverName         = "Felix"
	DriverVersion      = "2.0.0"
	DriverInfoURI      = "https://github.com/felix-security/felix"
)

// SARIFLog represents the top-level root of a SARIF 2.1.0 document.
type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFInvocation specifies execution outcome information.
type SARIFInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

// SARIFRun represents a single assessment run.
type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
	Results     []SARIFResult     `json:"results"`
	Properties  map[string]any    `json:"properties,omitempty"`
}

// SARIFTool describes the analysis tool that produced the run.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver encapsulates driver metadata and reporting rules.
type SARIFDriver struct {
	Name            string                     `json:"name"`
	SemanticVersion string                     `json:"semanticVersion,omitempty"`
	InformationURI  string                     `json:"informationUri,omitempty"`
	Rules           []SARIFReportingDescriptor `json:"rules"`
}

// SARIFReportingDescriptor describes a rule/detector in SARIF.
type SARIFReportingDescriptor struct {
	ID                   string                       `json:"id"`
	Name                 string                       `json:"name,omitempty"`
	ShortDescription     *SARIFMultiformatMessage     `json:"shortDescription,omitempty"`
	FullDescription      *SARIFMultiformatMessage     `json:"fullDescription,omitempty"`
	DefaultConfiguration *SARIFReportingConfiguration `json:"defaultConfiguration,omitempty"`
	HelpURI              string                       `json:"helpUri,omitempty"`
	Help                 *SARIFMultiformatMessage     `json:"help,omitempty"`
	Properties           map[string]any               `json:"properties,omitempty"`
}

// SARIFReportingConfiguration defines the default reporting level.
type SARIFReportingConfiguration struct {
	Level string `json:"level"` // "error", "warning", "note", "none"
}

// SARIFMultiformatMessage stores text and markdown messages.
type SARIFMultiformatMessage struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

// SARIFResult represents a single finding in SARIF.
type SARIFResult struct {
	RuleID        string                  `json:"ruleId"`
	RuleIndex     int                     `json:"ruleIndex"`
	Level         string                  `json:"level"` // "error", "warning", "note", "none"
	Message       SARIFMultiformatMessage `json:"message"`
	Locations     []SARIFLocation         `json:"locations,omitempty"`
	Properties    map[string]any          `json:"properties,omitempty"`
	Fingerprints  map[string]string       `json:"fingerprints,omitempty"`
	BaselineState string                  `json:"baselineState,omitempty"` // "new", "unchanged", "updated", "absent"
}

// SARIFLocation describes the location of a finding without fabricating fake code line numbers.
type SARIFLocation struct {
	PhysicalLocation *SARIFPhysicalLocation   `json:"physicalLocation,omitempty"`
	LogicalLocations []SARIFLogicalLocation   `json:"logicalLocations,omitempty"`
	Message          *SARIFMultiformatMessage `json:"message,omitempty"`
}

// SARIFPhysicalLocation references an endpoint URI or target artifact.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

// SARIFArtifactLocation identifies the target artifact or URI.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFLogicalLocation describes the logical API endpoint or resource without fake lines.
type SARIFLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"` // "endpoint", "route", "resource"
}

// SeverityToSARIFLevel maps Felix severity levels to canonical SARIF 2.1.0 levels.
func SeverityToSARIFLevel(sev string) string {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	case SeverityLow:
		return "note"
	default:
		return "none"
	}
}

// cleanArtifactURI normalizes a target or endpoint into a valid SARIF 2.1.0 uri-reference.
func cleanArtifactURI(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	// Convert Windows path separators to forward slashes per SARIF 2.1.0 section 3.10.1
	s = strings.ReplaceAll(s, "\\", "/")

	// Strip leading HTTP methods if the raw endpoint included one (e.g. "GET /path" or "GET%20/path")
	for _, m := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"} {
		if strings.HasPrefix(strings.ToUpper(s), m+" ") {
			s = strings.TrimSpace(s[len(m)+1:])
			break
		}
		if strings.HasPrefix(strings.ToUpper(s), m+"%20") {
			s = strings.TrimSpace(s[len(m)+3:])
			break
		}
	}

	// Escape unencoded spaces so the output strictly conforms to RFC 3986 format: uri-reference
	return strings.ReplaceAll(s, " ", "%20")
}

// BuildSARIFLog constructs a fully compliant SARIF 2.1.0 document from a sanitized Report.
func BuildSARIFLog(rep Report) SARIFLog {
	sanitized := SanitizeReport(rep)

	// Deduplicate findings by fingerprint/identity while preserving original casing and metadata
	cleanFindings := make([]Finding, 0, len(sanitized.Findings))
	seenFingerprints := make(map[string]bool)
	for _, f := range sanitized.Findings {
		key := strings.TrimSpace(f.Fingerprint)
		if key == "" {
			key = strings.TrimSpace(f.ID)
		}
		if key != "" {
			if seenFingerprints[key] {
				continue
			}
			seenFingerprints[key] = true
		}
		cleanFindings = append(cleanFindings, f)
	}

	rulesMap := make(map[string]SARIFReportingDescriptor)
	var ruleIDs []string

	getRuleID := func(f Finding) string {
		ruleID := strings.TrimSpace(f.Category)
		if ruleID == "" {
			ruleID = strings.TrimSpace(f.RuleID)
		}
		if ruleID == "" {
			ruleID = strings.TrimSpace(f.ID)
		}
		if ruleID == "" {
			ruleID = "FELIX-GENERIC"
		}
		return ruleID
	}

	// 1. Collect and deduplicate rules from findings
	for _, f := range cleanFindings {
		ruleID := getRuleID(f)
		if _, exists := rulesMap[ruleID]; !exists {
			ruleIDs = append(ruleIDs, ruleID)

			name := f.Title
			if name == "" {
				name = ruleID
			}

			desc := f.Description
			if desc == "" {
				desc = name
			}

			var helpMsg *SARIFMultiformatMessage
			if strings.TrimSpace(f.Remediation) != "" {
				helpMsg = &SARIFMultiformatMessage{
					Text: SanitizeEvidence(strings.TrimSpace(f.Remediation)),
				}
			}

			rulesMap[ruleID] = SARIFReportingDescriptor{
				ID:   ruleID,
				Name: name,
				ShortDescription: &SARIFMultiformatMessage{
					Text: name,
				},
				FullDescription: &SARIFMultiformatMessage{
					Text: desc,
				},
				DefaultConfiguration: &SARIFReportingConfiguration{
					Level: SeverityToSARIFLevel(f.Severity),
				},
				Help: helpMsg,
				Properties: map[string]any{
					"category": ruleID,
					"source":   f.Source,
				},
			}
		}
	}

	// Sort rule IDs deterministically
	sort.Strings(ruleIDs)

	// Ensure rules is initialized as an empty non-nil slice to serialize as [] instead of null
	rules := make([]SARIFReportingDescriptor, 0, len(ruleIDs))
	ruleIndexMap := make(map[string]int, len(ruleIDs))
	for idx, id := range ruleIDs {
		rules = append(rules, rulesMap[id])
		ruleIndexMap[id] = idx
	}

	// 2. Generate SARIF results from findings
	// Ensure results is initialized as an empty non-nil slice to serialize as [] instead of null
	results := make([]SARIFResult, 0, len(cleanFindings))
	for _, f := range cleanFindings {
		ruleID := getRuleID(f)
		ruleIdx := ruleIndexMap[ruleID]
		level := SeverityToSARIFLevel(f.Severity)

		msgText := strings.TrimSpace(f.Description)
		if msgText == "" {
			msgText = strings.TrimSpace(f.Title)
		}
		if msgText == "" {
			msgText = fmt.Sprintf("Security finding detected for rule %s", ruleID)
		}
		if f.Evidence != "" {
			msgText += "\n\nEvidence: " + f.Evidence
		}

		// Logical & Physical locations (no fabricated line numbers)
		var locations []SARIFLocation
		rawLoc := f.Endpoint
		if rawLoc == "" {
			rawLoc = f.Target
		}

		cleanedURI := cleanArtifactURI(rawLoc)
		if cleanedURI != "" {
			fqn := rawLoc
			if f.Method != "" && !strings.HasPrefix(strings.ToUpper(rawLoc), f.Method+" ") {
				fqn = f.Method + " " + rawLoc
			}
			locations = append(locations, SARIFLocation{
				LogicalLocations: []SARIFLogicalLocation{
					{
						Name:               rawLoc,
						FullyQualifiedName: fqn,
						Kind:               "endpoint",
					},
				},
				PhysicalLocation: &SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: cleanedURI,
					},
				},
			})
		}

		// Property bag preserving verification state, confidence, score, and provenance
		props := map[string]any{
			"finding_id":          f.ID,
			"category":            f.Category,
			"severity":            f.Severity,
			"confidence":          f.Confidence,
			"score":               f.Score,
			"source":              f.Source,
			"status":              string(f.Status),
			"analysis_method":     string(f.AnalysisMethod),
			"verification_status": string(f.Verification.Status),
			"verification_result": f.Verification.Result,
		}
		if f.Verification.PolicyID != "" {
			props["verification_policy_id"] = f.Verification.PolicyID
		}
		if f.Verification.SafeCurlCommand != "" {
			props["safe_reproduction"] = f.Verification.SafeCurlCommand
		}
		if f.EvidenceDetails.Observation != "" {
			props["observation"] = f.EvidenceDetails.Observation
		}
		if f.EvidenceDetails.DetectionMethod != "" {
			props["detection_method"] = f.EvidenceDetails.DetectionMethod
		}
		if f.Provenance != nil {
			props["provenance"] = f.Provenance
		} else if f.EvidenceDetails.Provenance != nil {
			props["provenance"] = f.EvidenceDetails.Provenance
		}

		var fingerprints map[string]string
		if f.Fingerprint != "" {
			fingerprints = map[string]string{
				"felix/fingerprint/v1": f.Fingerprint,
			}
		}

		var baselineState string
		lcStatus := strings.ToUpper(strings.TrimSpace(f.LifecycleStatus))
		if lcStatus == "" && f.EvidenceDetails.Details != nil {
			lcStatus = strings.ToUpper(strings.TrimSpace(f.EvidenceDetails.Details["lifecycle_status"]))
		}
		switch lcStatus {
		case "NEW":
			baselineState = "new"
		case "PERSISTENT", "ACTIVE":
			baselineState = "unchanged"
		case "CHANGED", "REGRESSED":
			baselineState = "updated"
		case "RESOLVED":
			baselineState = "absent"
		}
		if lcStatus != "" {
			props["lifecycle_status"] = lcStatus
		}

		results = append(results, SARIFResult{
			RuleID:        ruleID,
			RuleIndex:     ruleIdx,
			Level:         level,
			Message:       SARIFMultiformatMessage{Text: SanitizeEvidence(msgText)},
			Locations:     locations,
			Properties:    props,
			Fingerprints:  fingerprints,
			BaselineState: baselineState,
		})
	}

	// Determine execution completeness
	isCompleted := rep.CompletionStatus == "COMPLETED" || (rep.CompletionStatus == "" && rep.RiskLevel != "UNAVAILABLE")
	if rep.Metadata != nil {
		if isPartial, ok := rep.Metadata["is_partial"].(bool); ok && isPartial {
			isCompleted = false
		}
		if isPartialStr, ok := rep.Metadata["is_partial"].(string); ok && isPartialStr == "true" {
			isCompleted = false
		}
	}

	invocations := []SARIFInvocation{
		{ExecutionSuccessful: isCompleted},
	}

	// Attach run-level properties from assessment report metadata (e.g. policy evaluation)
	var runProps map[string]any
	if len(rep.Metadata) > 0 {
		runProps = make(map[string]any, len(rep.Metadata))
		for k, v := range rep.Metadata {
			runProps[k] = v
		}
	} else {
		runProps = make(map[string]any)
	}
	runProps["is_partial"] = !isCompleted
	if rep.CompletionStatus != "" {
		runProps["completion_status"] = rep.CompletionStatus
	}

	return SARIFLog{
		Schema:  SARIFSchemaURI,
		Version: SARIFSchemaVersion,
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:            DriverName,
						SemanticVersion: DriverVersion,
						InformationURI:  DriverInfoURI,
						Rules:           rules,
					},
				},
				Invocations: invocations,
				Results:     results,
				Properties:  runProps,
			},
		},
	}
}

// GenerateSARIF serializes an assessment Report into formatted SARIF 2.1.0 JSON bytes.
func GenerateSARIF(rep Report) ([]byte, error) {
	sarifLog := BuildSARIFLog(rep)
	return json.MarshalIndent(sarifLog, "", "  ")
}

// WriteSARIF writes the SARIF 2.1.0 export to disk after validating against the official schema.
func WriteSARIF(rep Report, filePath string) error {
	data, err := GenerateSARIF(rep)
	if err != nil {
		return fmt.Errorf("failed to generate SARIF: %w", err)
	}

	if err := ValidateSARIF(data); err != nil {
		return fmt.Errorf("generated SARIF failed schema validation: %w", err)
	}

	return os.WriteFile(filePath, data, 0644)
}

// GenerateCommercialSARIF constructs and exports a SARIF log from a CommercialReport.
func GenerateCommercialSARIF(cr CommercialReport) ([]byte, error) {
	var findings []Finding

	convertFinding := func(cf CommercialFinding, isVerified bool) Finding {
		status := VerificationDetected
		if isVerified {
			status = VerificationVerified
		}
		conf := cf.Confidence.OverallConfidence
		if conf == "" {
			conf = cf.Confidence.DetectionConfidence
		}
		if conf == "" {
			conf = ConfidenceMedium
		}
		endpoint := cf.AssetLocation
		if endpoint == "" {
			endpoint = cf.AffectedAsset
		}
		method := cf.Evidence.HTTPMethod
		if method == "" {
			method = "GET"
		}
		evidenceSummary := cf.Evidence.EvidenceSummary
		if evidenceSummary == "" {
			evidenceSummary = cf.Evidence.Observation
		}

		return Finding{
			ID:          cf.ID,
			Title:       cf.Title,
			Category:    cf.Category,
			Severity:    cf.Severity,
			Confidence:  conf,
			Target:      cf.AffectedAsset,
			Endpoint:    endpoint,
			Method:      method,
			Description: cf.Description,
			Verification: VerificationRecord{
				Status:             status,
				Result:             cf.Verification.ResultSummary,
				SafeCurlCommand:    cf.Evidence.SafeCurlCommand,
				ReproductionSteps:  cf.Evidence.ReproductionSteps,
				VerificationMethod: cf.Verification.MethodOrPolicy,
			},
			Evidence:    evidenceSummary,
			Fingerprint: cf.ID,
			Score:       cf.RiskContribution.Score,
		}
	}

	for _, vf := range cr.VerifiedFindings {
		findings = append(findings, convertFinding(vf, true))
	}
	for _, df := range cr.DetectedFindings {
		findings = append(findings, convertFinding(df, false))
	}

	rep := Report{
		Version:  cr.SchemaVersion,
		Target:   cr.ExecutiveSummary.Target,
		Findings: findings,
	}

	return GenerateSARIF(rep)
}
