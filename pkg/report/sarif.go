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
	SARIFSchemaURI     = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
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

// SARIFRun represents a single assessment run.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
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
	RuleID       string                  `json:"ruleId"`
	RuleIndex    int                     `json:"ruleIndex"`
	Level        string                  `json:"level"` // "error", "warning", "note", "none"
	Message      SARIFMultiformatMessage `json:"message"`
	Locations    []SARIFLocation         `json:"locations,omitempty"`
	Properties   map[string]any          `json:"properties,omitempty"`
	Fingerprints map[string]string       `json:"fingerprints,omitempty"`
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

// BuildSARIFLog constructs a fully compliant SARIF 2.1.0 document from a sanitized Report.
func BuildSARIFLog(rep Report) SARIFLog {
	sanitized := SanitizeReport(rep)

	rulesMap := make(map[string]SARIFReportingDescriptor)
	var ruleIDs []string

	getRuleID := func(f Finding) string {
		ruleID := strings.TrimSpace(f.Category)
		if ruleID == "" {
			ruleID = strings.TrimSpace(f.ID)
		}
		if ruleID == "" {
			ruleID = "FELIX-GENERIC"
		}
		return ruleID
	}

	// 1. Collect and deduplicate rules from findings
	for _, f := range sanitized.Findings {
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
				Help: &SARIFMultiformatMessage{
					Text: f.Remediation,
				},
				Properties: map[string]any{
					"category": ruleID,
					"source":   f.Source,
				},
			}
		}
	}

	// Sort rule IDs deterministically
	sort.Strings(ruleIDs)

	var rules []SARIFReportingDescriptor
	ruleIndexMap := make(map[string]int, len(ruleIDs))
	for idx, id := range ruleIDs {
		rules = append(rules, rulesMap[id])
		ruleIndexMap[id] = idx
	}

	// 2. Generate SARIF results from findings
	var results []SARIFResult
	for _, f := range sanitized.Findings {
		ruleID := getRuleID(f)
		ruleIdx := ruleIndexMap[ruleID]
		level := SeverityToSARIFLevel(f.Severity)

		msgText := f.Description
		if msgText == "" {
			msgText = f.Title
		}
		if f.Evidence != "" {
			msgText += "\n\nEvidence: " + f.Evidence
		}

		// Logical & Physical locations (no fabricated line numbers)
		var locations []SARIFLocation
		targetLoc := f.Endpoint
		if targetLoc == "" {
			targetLoc = f.Target
		}
		if targetLoc != "" {
			fqn := targetLoc
			if f.Method != "" {
				fqn = f.Method + " " + targetLoc
			}
			locations = append(locations, SARIFLocation{
				LogicalLocations: []SARIFLogicalLocation{
					{
						Name:               targetLoc,
						FullyQualifiedName: fqn,
						Kind:               "endpoint",
					},
				},
				PhysicalLocation: &SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: targetLoc,
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

		fingerprints := make(map[string]string)
		if f.Fingerprint != "" {
			fingerprints["felix/fingerprint/v1"] = f.Fingerprint
		}

		results = append(results, SARIFResult{
			RuleID:       ruleID,
			RuleIndex:    ruleIdx,
			Level:        level,
			Message:      SARIFMultiformatMessage{Text: SanitizeEvidence(msgText)},
			Locations:    locations,
			Properties:   props,
			Fingerprints: fingerprints,
		})
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
				Results: results,
			},
		},
	}
}

// GenerateSARIF serializes an assessment Report into formatted SARIF 2.1.0 JSON bytes.
func GenerateSARIF(rep Report) ([]byte, error) {
	sarifLog := BuildSARIFLog(rep)
	return json.MarshalIndent(sarifLog, "", "  ")
}

// WriteSARIF writes the SARIF 2.1.0 export to disk.
func WriteSARIF(rep Report, filePath string) error {
	data, err := GenerateSARIF(rep)
	if err != nil {
		return fmt.Errorf("failed to generate SARIF: %w", err)
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
