package apk

import (
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"felix/pkg/api"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

// MobileReportData encapsulates the aggregated data needed to render mobile_audit.html.
type MobileReportData struct {
	Title            string
	GeneratedAt      string
	ReportVersion    string
	Status           string // "COMPLETED", "PARTIAL", "STATIC_ONLY", "FAILED"
	AnalysisMode     string // "Static Analysis & Authorized Assessment" or "Static Analysis Only (Offline)"
	ExecutiveSummary string

	// APK Metadata
	APKFileName           string
	APKPath               string
	APKSHA256             string
	APKFileSize           int64
	APKFileSizeFormatted  string
	IntakeStatus          string
	PackageName           string
	VersionName           string
	VersionCode           string
	MinSDK                string
	TargetSDK             string
	CompileSDK            string
	ManifestFormat        string
	ManifestStatus        string
	ManifestAnalyzed      bool
	DexStatus             string
	DexCount              int
	DexFiles              []string
	Multidex              string
	TotalDecompressedSize string
	ArchiveEntryCount     int

	// Security Findings & Severity Breakdown
	RawFindings    []report.Finding
	Findings       []ReportFinding
	TotalFindings  int
	CriticalCount  int
	HighCount      int
	MediumCount    int
	LowCount       int
	InfoCount      int
	SeverityCounts map[string]int

	// Service Indicators
	ServiceIndicators []ReportServiceIndicator
	TotalServices     int

	// Backend Inventory
	InventoryBuilt      bool
	TotalEndpoints      int
	TotalHosts          int
	ConfirmedCount      int
	InferredCount       int
	UnresolvedCount     int
	InventoryCategories map[string]int
	Hosts               []ReportHostGroup
	Endpoints           []ReportEndpoint

	// Authorized Assessment Results
	AssessmentRequested       bool
	AssessmentExecuted        bool
	AssessmentStatus          string
	AssessmentStartedAt       string
	AssessmentCompletedAt     string
	AssessmentDuration        string
	AssessmentScopeMode       string
	AuthorizedTargets         []string
	AssessmentTotalDiscovered int
	AssessmentTotalEligible   int
	AssessmentTotalAuthorized int
	AssessmentTotalTested     int
	AssessmentTotalSkipped    int
	AssessmentTotalFailed     int
	AssessmentTotalInconcl    int
	AssessmentTotalRequests   int
	AssessmentBudgetExhausted bool
	AssessmentResults         []ReportHandoffResult

	// Remediation Guidance
	Remediations []ReportRemediation

	// Scope and Limitations
	ScopeStages []ReportScopeStage
	Limitations []string
}

// ReportFinding represents an individual finding formatted for the HTML report.
type ReportFinding struct {
	ID             string
	RuleID         string
	Title          string
	Severity       string
	SeverityClass  string // "critical", "high", "medium", "low", "info"
	Confidence     string
	Status         string
	Category       string
	AffectedTarget string
	Description    string
	Evidence       string
	Remediation    string
	Source         string
	Fingerprint    string
	IsActive       bool
}

// ReportServiceIndicator represents a discovered third-party or infrastructure service.
type ReportServiceIndicator struct {
	Category       string
	Provider       string
	HostIdentifier string
	SourceArtifact string
	Confidence     string
	Evidence       string
}

// ReportHostGroup represents a backend host grouping discovered endpoints.
type ReportHostGroup struct {
	HostIdentity      string
	Hostname          string
	Port              int
	EndpointCount     int
	ConfirmedCount    int
	InferredCount     int
	ServiceIndicators []string
	ArtifactOrigins   []string
	Endpoints         []ReportEndpoint
}

// ReportEndpoint represents a discovered backend endpoint.
type ReportEndpoint struct {
	NormalizedURL       string
	Classification      string
	ClassificationBadge string // "confirmed", "inferred", "unresolved"
	Category            string
	CategoryBadge       string
	HostIdentity        string
	Path                string
	Confidence          string
	ProvenanceArtifact  string
	ProvenanceStage     string
	InferredBaseURL     string
	TestedStatus        string
}

// ReportHandoffResult represents the active assessment outcome for an endpoint.
type ReportHandoffResult struct {
	EndpointID        string
	NormalizedURL     string
	HostGroup         string
	Classification    string
	Disposition       string
	DispositionBadge  string // "tested", "skipped", "failed", "inconclusive"
	State             string
	ReasonCode        string
	ReasonMessage     string
	HTTPStatus        int
	DurationMs        int64
	RequestDispatched bool
	RequestCount      int
	APIFindingsCount  int
}

// ReportRemediation represents prioritized, actionable mitigation guidance.
type ReportRemediation struct {
	Priority          string // "P1 - Critical", "P1 - High", "P2 - Medium", "P3 - Low / Info"
	PriorityBadge     string // "p1", "p2", "p3"
	FindingID         string
	FindingTitle      string
	AffectedComponent string
	Recommendation    string
	VerificationStep  string
	ResidualCaveat    string
}

// ReportScopeStage represents the status of an analysis pipeline stage.
type ReportScopeStage struct {
	Name    string
	Status  string // "COMPLETED", "PARTIAL", "SKIPPED", "FAILED", "NOT_REQUESTED"
	Badge   string // "success", "warning", "neutral", "danger"
	Details string
}

// BuildMobileReportData aggregates results from all pipeline stages into a unified report model.
func BuildMobileReportData(
	apkPath string,
	intakeRes *IntakeResult,
	manifestRes *ManifestAnalysisResult,
	artifactRes *ArtifactAnalysisResult,
	inventoryRes *BackendInventory,
	handoffRes *HandoffReport,
) *MobileReportData {
	now := time.Now().UTC()
	genTimestamp := now.Format("2006-01-02 15:04:05 UTC")

	cleanAPKPath := filepath.Clean(apkPath)
	apkFileName := filepath.Base(cleanAPKPath)

	data := &MobileReportData{
		Title:               "FELIX Mobile Security Assessment Report",
		GeneratedAt:         genTimestamp,
		ReportVersion:       "1.0.0",
		APKFileName:         apkFileName,
		APKPath:             cleanAPKPath,
		SeverityCounts:      map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
		InventoryCategories: make(map[string]int),
	}

	// 1. Process Intake Metadata
	if intakeRes != nil {
		data.APKSHA256 = intakeRes.SHA256
		data.APKFileSize = intakeRes.FileSize
		data.APKFileSizeFormatted = formatBytes(intakeRes.FileSize)
		data.IntakeStatus = "Verified & Isolated (Offline Static-Only)"
		data.TotalDecompressedSize = formatBytes(intakeRes.TotalDecompressedBytes)
		data.ArchiveEntryCount = intakeRes.EntryCount
		data.DexCount = intakeRes.DexCount
		data.DexFiles = append([]string{}, intakeRes.DexFiles...)
		if intakeRes.DexCount > 1 {
			data.Multidex = fmt.Sprintf("Enabled (%d DEX files)", intakeRes.DexCount)
		} else if intakeRes.DexCount == 1 {
			data.Multidex = "Single DEX (No Multidex)"
		} else {
			data.Multidex = "Not available (0 DEX files)"
		}
	} else {
		data.IntakeStatus = "Failed or Omitted"
		data.APKSHA256 = "Not available"
		data.APKFileSizeFormatted = "Not available"
		data.Multidex = "Not available"
	}

	// 2. Process Manifest Analysis
	if manifestRes != nil && manifestRes.Document != nil {
		doc := manifestRes.Document
		data.ManifestAnalyzed = true
		data.ManifestStatus = "Completed"
		data.PackageName = nonZeroOrDefault(doc.PackageName, "Not available")
		data.VersionName = nonZeroOrDefault(doc.VersionName, "Not available")
		data.VersionCode = nonZeroOrDefault(doc.VersionCode, "Not available")
		data.ManifestFormat = nonZeroOrDefault(doc.Format, "Binary AXML")

		if doc.MinSDK > 0 {
			data.MinSDK = fmt.Sprintf("%d", doc.MinSDK)
		} else {
			data.MinSDK = "Not available"
		}
		if doc.TargetSDK > 0 {
			data.TargetSDK = fmt.Sprintf("%d", doc.TargetSDK)
		} else {
			data.TargetSDK = "Not available"
		}
		if doc.CompileSDK > 0 {
			data.CompileSDK = fmt.Sprintf("%d", doc.CompileSDK)
		} else {
			data.CompileSDK = "Not available"
		}
	} else {
		data.ManifestStatus = "Not available (omitted or unparsed)"
		data.PackageName = "Not available"
		data.VersionName = "Not available"
		data.VersionCode = "Not available"
		data.MinSDK = "Not available"
		data.TargetSDK = "Not available"
		data.CompileSDK = "Not available"
		data.ManifestFormat = "Not available"
	}

	// 3. Process Artifact Intelligence
	if artifactRes != nil {
		data.DexStatus = fmt.Sprintf("Completed (%d DEX analyzed)", len(artifactRes.DexFilesAnalyzed))
	} else {
		data.DexStatus = "Not evaluated"
	}

	// 4. Collect & Deduplicate Findings
	findingMap := make(map[string]ReportFinding)

	// Collect manifest findings
	if manifestRes != nil {
		for _, f := range manifestRes.Findings {
			rf := convertReportFinding(f, false)
			findingMap[rf.Fingerprint] = rf
		}
	}

	// Collect artifact findings
	if artifactRes != nil {
		for _, f := range artifactRes.Findings {
			// Skip pure informational service indicators from the vulnerabilities list if already categorized
			rf := convertReportFinding(f, false)
			findingMap[rf.Fingerprint] = rf
		}
	}

	// Collect active assessment API findings (if any)
	if handoffRes != nil {
		for _, f := range handoffRes.Findings {
			rf := convertAPIFinding(f, handoffRes.APKSHA256)
			findingMap[rf.Fingerprint] = rf
		}
		for _, r := range handoffRes.Results {
			for _, f := range r.APIFindings {
				rf := convertAPIFinding(f, handoffRes.APKSHA256)
				findingMap[rf.Fingerprint] = rf
			}
		}
	}

	// Flatten and sort findings deterministically
	allFindings := make([]ReportFinding, 0, len(findingMap))
	for _, rf := range findingMap {
		allFindings = append(allFindings, rf)
	}

	sort.Slice(allFindings, func(i, j int) bool {
		si := severityWeight(allFindings[i].Severity)
		sj := severityWeight(allFindings[j].Severity)
		if si != sj {
			return si > sj // Higher severity first
		}
		if allFindings[i].Title != allFindings[j].Title {
			return allFindings[i].Title < allFindings[j].Title
		}
		return allFindings[i].ID < allFindings[j].ID
	})

	data.Findings = allFindings

	var rawFindings []report.Finding
	if manifestRes != nil {
		rawFindings = append(rawFindings, manifestRes.Findings...)
	}
	if artifactRes != nil {
		rawFindings = append(rawFindings, artifactRes.Findings...)
	}
	if handoffRes != nil {
		for _, f := range handoffRes.Findings {
			rawFindings = append(rawFindings, report.Finding{
				ID:          f.Fingerprint,
				RuleID:      "API-AUDIT-" + string(f.Category),
				Title:       f.Description,
				Severity:    string(f.Severity),
				Confidence:  string(f.Confidence),
				Target:      f.Endpoint,
				Endpoint:    f.Endpoint,
				Description: f.Description,
				Evidence:    f.Evidence,
				Remediation: "Review endpoint authorization, restrict public introspection, and enforce role-based access control.",
				Source:      report.SourceAPK,
				Status:      report.FindingStatusConfirmed,
			})
		}
		for _, r := range handoffRes.Results {
			for _, f := range r.APIFindings {
				rawFindings = append(rawFindings, report.Finding{
					ID:          f.Fingerprint,
					RuleID:      "API-AUDIT-" + string(f.Category),
					Title:       f.Description,
					Severity:    string(f.Severity),
					Confidence:  string(f.Confidence),
					Target:      f.Endpoint,
					Endpoint:    f.Endpoint,
					Description: f.Description,
					Evidence:    f.Evidence,
					Remediation: "Review endpoint authorization, restrict public introspection, and enforce role-based access control.",
					Source:      report.SourceAPK,
					Status:      report.FindingStatusConfirmed,
				})
			}
		}
	}
	data.RawFindings = report.DeduplicateFindings(rawFindings)
	data.TotalFindings = len(allFindings)

	// Tally severity counts exactly matching the displayed findings
	for _, f := range allFindings {
		sev := strings.ToUpper(f.Severity)
		switch sev {
		case "CRITICAL":
			data.CriticalCount++
			data.SeverityCounts["CRITICAL"]++
		case "HIGH":
			data.HighCount++
			data.SeverityCounts["HIGH"]++
		case "MEDIUM":
			data.MediumCount++
			data.SeverityCounts["MEDIUM"]++
		case "LOW":
			data.LowCount++
			data.SeverityCounts["LOW"]++
		default:
			data.InfoCount++
			data.SeverityCounts["INFO"]++
		}
	}

	// 5. Synthesize Service Indicators
	serviceMap := make(map[string]ReportServiceIndicator)

	// From artifact findings with category "service-indicator"
	if artifactRes != nil {
		for _, f := range artifactRes.Findings {
			if f.Category == "service-indicator" {
				prov := f.Title
				if p, ok := f.EvidenceDetails.Details["scheme"]; ok && p != "" {
					prov = strings.ToUpper(p)
				}
				hostIdent := f.Endpoint
				if h, ok := f.EvidenceDetails.Details["host"]; ok && h != "" {
					hostIdent = h
				}
				origin := "artifacts"
				if o, ok := f.EvidenceDetails.Details["file_origin"]; ok && o != "" {
					origin = o
				}
				key := prov + ":" + hostIdent
				serviceMap[key] = ReportServiceIndicator{
					Category:       "Database / Cache",
					Provider:       prov,
					HostIdentifier: secrets.RedactText(hostIdent),
					SourceArtifact: origin,
					Confidence:     f.Confidence,
					Evidence:       secrets.RedactText(f.Evidence),
				}
			}
		}
	}

	// From inventory hosts with ServiceIndicators
	if inventoryRes != nil {
		for _, hg := range inventoryRes.Hosts {
			for _, ind := range hg.ServiceIndicators {
				key := ind + ":" + hg.HostIdentity
				if _, exists := serviceMap[key]; !exists {
					cat := categorizeServiceIndicator(ind)
					origin := "classes.dex"
					if len(hg.ArtifactOrigins) > 0 {
						origin = strings.Join(hg.ArtifactOrigins, ", ")
					}
					serviceMap[key] = ReportServiceIndicator{
						Category:       cat,
						Provider:       ind,
						HostIdentifier: secrets.RedactText(hg.HostIdentity),
						SourceArtifact: origin,
						Confidence:     "HIGH",
						Evidence:       fmt.Sprintf("Discovered %s backend reference associated with host %s", ind, secrets.RedactText(hg.HostIdentity)),
					}
				}
			}
		}
	}

	var allServices []ReportServiceIndicator
	for _, s := range serviceMap {
		allServices = append(allServices, s)
	}
	sort.Slice(allServices, func(i, j int) bool {
		if allServices[i].Provider != allServices[j].Provider {
			return allServices[i].Provider < allServices[j].Provider
		}
		return allServices[i].HostIdentifier < allServices[j].HostIdentifier
	})
	data.ServiceIndicators = allServices
	data.TotalServices = len(allServices)

	// 6. Process Backend Inventory
	if inventoryRes != nil {
		data.InventoryBuilt = true
		data.TotalEndpoints = inventoryRes.TotalEndpoints
		data.TotalHosts = inventoryRes.TotalHosts
		data.ConfirmedCount = inventoryRes.ConfirmedCount
		data.InferredCount = inventoryRes.InferredCount
		for k, v := range inventoryRes.Categories {
			data.InventoryCategories[k] = v
		}

		// Count unresolved endpoints
		for _, ep := range inventoryRes.Endpoints {
			if ep.HostIdentity == "(unresolved)" || ep.Host == "" {
				data.UnresolvedCount++
			}
		}

		// Convert and sort endpoints
		var repEndpoints []ReportEndpoint
		for _, ep := range inventoryRes.Endpoints {
			repEndpoints = append(repEndpoints, convertReportEndpoint(ep))
		}
		sort.Slice(repEndpoints, func(i, j int) bool {
			if repEndpoints[i].ClassificationBadge != repEndpoints[j].ClassificationBadge {
				return repEndpoints[i].ClassificationBadge < repEndpoints[j].ClassificationBadge
			}
			return repEndpoints[i].NormalizedURL < repEndpoints[j].NormalizedURL
		})
		data.Endpoints = repEndpoints

		// Convert and sort host groups
		var repHosts []ReportHostGroup
		for _, hg := range inventoryRes.Hosts {
			var hgEndpoints []ReportEndpoint
			for _, ep := range hg.Endpoints {
				hgEndpoints = append(hgEndpoints, convertReportEndpoint(ep))
			}
			repHosts = append(repHosts, ReportHostGroup{
				HostIdentity:      secrets.RedactText(hg.HostIdentity),
				Hostname:          secrets.RedactText(hg.Hostname),
				Port:              hg.Port,
				EndpointCount:     hg.EndpointCount,
				ConfirmedCount:    hg.ConfirmedCount,
				InferredCount:     hg.InferredCount,
				ServiceIndicators: hg.ServiceIndicators,
				ArtifactOrigins:   hg.ArtifactOrigins,
				Endpoints:         hgEndpoints,
			})
		}
		sort.Slice(repHosts, func(i, j int) bool {
			return repHosts[i].HostIdentity < repHosts[j].HostIdentity
		})
		data.Hosts = repHosts
	}

	// 7. Process Authorized Assessment Handoff
	if handoffRes != nil {
		data.AssessmentRequested = true
		data.AssessmentExecuted = true
		data.AssessmentScopeMode = handoffRes.ScopeMode
		data.AuthorizedTargets = handoffRes.AuthorizedTargets
		data.AssessmentTotalDiscovered = handoffRes.TotalDiscovered
		data.AssessmentTotalEligible = handoffRes.TotalEligible
		data.AssessmentTotalAuthorized = handoffRes.TotalAuthorized
		data.AssessmentTotalTested = handoffRes.TotalTested
		data.AssessmentTotalSkipped = handoffRes.TotalSkipped
		data.AssessmentTotalFailed = handoffRes.TotalFailed
		data.AssessmentTotalInconcl = handoffRes.TotalInconclusive
		data.AssessmentTotalRequests = handoffRes.TotalRequestsSent
		data.AssessmentBudgetExhausted = handoffRes.BudgetExhausted

		startStr := handoffRes.StartedAt.Format("2006-01-02 15:04:05 UTC")
		endStr := handoffRes.CompletedAt.Format("2006-01-02 15:04:05 UTC")
		data.AssessmentStartedAt = startStr
		data.AssessmentCompletedAt = endStr
		data.AssessmentDuration = fmt.Sprintf("%dms", handoffRes.DurationMs)

		if handoffRes.DryRun {
			data.AssessmentStatus = "Dry-Run Plan (Zero Network Requests Sent)"
		} else {
			data.AssessmentStatus = "Authorized Assessment Completed"
		}

		var repHandoffResults []ReportHandoffResult
		for _, r := range handoffRes.Results {
			badge := strings.ToLower(string(r.Disposition))
			repHandoffResults = append(repHandoffResults, ReportHandoffResult{
				EndpointID:        r.EndpointID,
				NormalizedURL:     secrets.RedactText(r.NormalizedURL),
				HostGroup:         secrets.RedactText(r.HostGroup),
				Classification:    string(r.Classification),
				Disposition:       string(r.Disposition),
				DispositionBadge:  badge,
				State:             string(r.State),
				ReasonCode:        r.ReasonCode,
				ReasonMessage:     secrets.RedactText(r.ReasonMessage),
				HTTPStatus:        r.HTTPStatus,
				DurationMs:        r.DurationMs,
				RequestDispatched: r.RequestDispatched,
				RequestCount:      r.RequestCount,
				APIFindingsCount:  len(r.APIFindings),
			})
		}
		sort.Slice(repHandoffResults, func(i, j int) bool {
			return repHandoffResults[i].NormalizedURL < repHandoffResults[j].NormalizedURL
		})
		data.AssessmentResults = repHandoffResults

		// Mark endpoints that were tested in the inventory list
		testedSet := make(map[string]bool)
		for _, r := range handoffRes.Results {
			if r.Disposition == DispositionTested {
				testedSet[r.NormalizedURL] = true
			}
		}
		for idx := range data.Endpoints {
			if testedSet[data.Endpoints[idx].NormalizedURL] {
				data.Endpoints[idx].TestedStatus = "Actively Audited"
			}
		}
	} else {
		data.AssessmentRequested = false
		data.AssessmentExecuted = false
		data.AssessmentStatus = "Not requested (Static Analysis Only; zero network requests dispatched)"
	}

	// 8. Synthesize Prioritized Remediation Guidance
	data.Remediations = synthesizeRemediations(data.Findings)

	// 9. Pipeline Stages & Scope Breakdown
	data.ScopeStages = []ReportScopeStage{
		{
			Name:    "APK Intake & Cryptographic Validation",
			Status:  "COMPLETED",
			Badge:   "success",
			Details: fmt.Sprintf("Verified SHA-256 (%s), %d entries isolated in secure sandbox.", truncateHash(data.APKSHA256), data.ArchiveEntryCount),
		},
		{
			Name:    "AndroidManifest Security Audit",
			Status:  ternaryStr(data.ManifestAnalyzed, "COMPLETED", "SKIPPED"),
			Badge:   ternaryStr(data.ManifestAnalyzed, "success", "neutral"),
			Details: ternaryStr(data.ManifestAnalyzed, fmt.Sprintf("Parsed %s format; checked permissions, components, backup, and network config.", data.ManifestFormat), "Manifest static analysis was not requested or file was missing."),
		},
		{
			Name:    "Application Artifact & DEX Intelligence",
			Status:  ternaryStr(artifactRes != nil, "COMPLETED", "SKIPPED"),
			Badge:   ternaryStr(artifactRes != nil, "success", "neutral"),
			Details: ternaryStr(artifactRes != nil, fmt.Sprintf("Inspected %d DEX file(s) and configurations for secrets, services, and routes.", len(data.DexFiles)), "Artifact intelligence analysis was not requested."),
		},
		{
			Name:    "Backend Endpoint & Host Inventory Synthesis",
			Status:  ternaryStr(data.InventoryBuilt, "COMPLETED", "SKIPPED"),
			Badge:   ternaryStr(data.InventoryBuilt, "success", "neutral"),
			Details: ternaryStr(data.InventoryBuilt, fmt.Sprintf("Synthesized %d endpoints across %d hosts (%d confirmed, %d inferred).", data.TotalEndpoints, data.TotalHosts, data.ConfirmedCount, data.InferredCount), "Backend inventory synthesis was not requested."),
		},
		{
			Name:    "Authorized Backend Assessment Handoff",
			Status:  ternaryStr(data.AssessmentExecuted, "COMPLETED", "NOT_REQUESTED"),
			Badge:   ternaryStr(data.AssessmentExecuted, "success", "neutral"),
			Details: ternaryStr(data.AssessmentExecuted, fmt.Sprintf("Scope enforced (%s); dispatched %d request(s) (%d tested, %d skipped, %d failed).", data.AssessmentScopeMode, data.AssessmentTotalRequests, data.AssessmentTotalTested, data.AssessmentTotalSkipped, data.AssessmentTotalFailed), "Active assessment was not requested. Zero network requests dispatched to discovered endpoints."),
		},
	}

	// 10. Compile Overall Scope & Limitations
	limitationsSet := make(map[string]struct{})
	limitationsSet["Static indicators and discovered routes do not prove exploitability without empirical validation."] = struct{}{}
	limitationsSet["Discovered endpoints that were not actively assessed remain unvalidated for server-side vulnerabilities."] = struct{}{}
	limitationsSet["Analysis was performed on APK archive entries without running native code or executing dynamic hooks."] = struct{}{}

	if manifestRes != nil {
		for _, l := range manifestRes.Limitations {
			limitationsSet[l] = struct{}{}
		}
	}
	if artifactRes != nil {
		for _, l := range artifactRes.Limitations {
			limitationsSet[l] = struct{}{}
		}
	}
	if inventoryRes != nil {
		for _, l := range inventoryRes.Limitations {
			limitationsSet[l] = struct{}{}
		}
	}
	if handoffRes != nil {
		for _, l := range handoffRes.Limitations {
			limitationsSet[l] = struct{}{}
		}
	}

	var limList []string
	for l := range limitationsSet {
		limList = append(limList, l)
	}
	sort.Strings(limList)
	data.Limitations = limList

	// 11. Determine Overall Assessment Status and Mode
	if data.AssessmentExecuted {
		data.AnalysisMode = "Static Analysis & Authorized Active Assessment"
		data.Status = "COMPLETED"
	} else {
		data.AnalysisMode = "Static Analysis Only (Offline)"
		data.Status = "STATIC_ONLY"
	}

	// 12. Generate Executive Summary
	activeSummary := "Zero active network requests were dispatched to discovered backend hosts."
	if data.AssessmentExecuted {
		activeSummary = fmt.Sprintf("Active authorized assessment audited %d backend endpoints (%d tested, %d skipped, %d requests dispatched) within approved scope.",
			data.AssessmentTotalDiscovered, data.AssessmentTotalTested, data.AssessmentTotalSkipped, data.AssessmentTotalRequests)
	}

	data.ExecutiveSummary = fmt.Sprintf(
		"FELIX conducted static security analysis of Android application %q (Package: %s, SHA-256: %s). "+
			"The audit identified %d security findings (%d critical, %d high, %d medium, %d low, %d informational), "+
			"%d third-party service indicators, and cataloged %d backend endpoints across %d hosts. %s",
		data.APKFileName, data.PackageName, truncateHash(data.APKSHA256),
		data.TotalFindings, data.CriticalCount, data.HighCount, data.MediumCount, data.LowCount, data.InfoCount,
		data.TotalServices, data.TotalEndpoints, data.TotalHosts, activeSummary,
	)

	return data
}

func convertReportFinding(f report.Finding, isActive bool) ReportFinding {
	sev := strings.ToUpper(f.Severity)
	if sev == "" {
		sev = "INFO"
	}
	sevClass := strings.ToLower(sev)

	statusStr := string(f.Status)
	if statusStr == "" {
		statusStr = "OBSERVED"
	}

	fp := f.Fingerprint
	if fp == "" {
		fp = f.ID
	}

	evidenceText := f.Evidence
	if evidenceText == "" && len(f.EvidenceDetails.Details) > 0 {
		var parts []string
		for k, v := range f.EvidenceDetails.Details {
			parts = append(parts, fmt.Sprintf("%s: %s", k, v))
		}
		sort.Strings(parts)
		evidenceText = strings.Join(parts, "\n")
	}

	return ReportFinding{
		ID:             f.ID,
		RuleID:         f.RuleID,
		Title:          secrets.RedactText(f.Title),
		Severity:       sev,
		SeverityClass:  sevClass,
		Confidence:     nonZeroOrDefault(f.Confidence, "MEDIUM"),
		Status:         statusStr,
		Category:       f.Category,
		AffectedTarget: secrets.RedactText(f.Endpoint),
		Description:    secrets.RedactText(f.Description),
		Evidence:       secrets.RedactText(evidenceText),
		Remediation:    secrets.RedactText(f.Remediation),
		Source:         f.Source,
		Fingerprint:    fp,
		IsActive:       isActive,
	}
}

func convertAPIFinding(f api.APIFinding, apkSHA string) ReportFinding {
	sev := strings.ToUpper(string(f.Severity))
	if sev == "" {
		sev = "INFO"
	}
	return ReportFinding{
		ID:             f.Fingerprint,
		RuleID:         "API-AUDIT-" + string(f.Category),
		Title:          secrets.RedactText(f.Description),
		Severity:       sev,
		SeverityClass:  strings.ToLower(sev),
		Confidence:     string(f.Confidence),
		Status:         "CONFIRMED",
		Category:       "active-api-exposure",
		AffectedTarget: secrets.RedactText(f.Endpoint),
		Description:    secrets.RedactText(f.Description),
		Evidence:       secrets.RedactText(f.Evidence),
		Remediation:    "Review endpoint authorization, restrict public introspection, and enforce role-based access control.",
		Source:         "authorized_handoff",
		Fingerprint:    f.Fingerprint,
		IsActive:       true,
	}
}

func convertReportEndpoint(ep EndpointEntry) ReportEndpoint {
	badge := "confirmed"
	if ep.Classification == ClassificationInferredRoute {
		if ep.HostIdentity == "(unresolved)" || ep.Host == "" {
			badge = "unresolved"
		} else {
			badge = "inferred"
		}
	}

	provArtifact := ""
	provStage := ""
	if len(ep.Provenance) > 0 {
		provArtifact = ep.Provenance[0].ArtifactPath
		provStage = ep.Provenance[0].AnalysisStage
	}

	inferredBase := ""
	if ep.InferredDetails != nil {
		inferredBase = ep.InferredDetails.BaseURL
	}

	return ReportEndpoint{
		NormalizedURL:       secrets.RedactText(ep.NormalizedURL),
		Classification:      string(ep.Classification),
		ClassificationBadge: badge,
		Category:            string(ep.Category),
		CategoryBadge:       string(ep.Category),
		HostIdentity:        secrets.RedactText(ep.HostIdentity),
		Path:                secrets.RedactText(ep.Path),
		Confidence:          ep.Confidence,
		ProvenanceArtifact:  provArtifact,
		ProvenanceStage:     provStage,
		InferredBaseURL:     secrets.RedactText(inferredBase),
		TestedStatus:        "Untested (Static Discovery Only)",
	}
}

func synthesizeRemediations(findings []ReportFinding) []ReportRemediation {
	var remediations []ReportRemediation
	seen := make(map[string]bool)

	for _, f := range findings {
		ruleKey := f.RuleID
		if ruleKey == "" {
			ruleKey = f.ID
		}
		if seen[ruleKey] {
			continue
		}
		seen[ruleKey] = true

		prio := "P3 - Low / Informational"
		prioBadge := "p3"
		switch f.Severity {
		case "CRITICAL":
			prio = "P1 - Critical Priority"
			prioBadge = "p1"
		case "HIGH":
			prio = "P1 - High Priority"
			prioBadge = "p1"
		case "MEDIUM":
			prio = "P2 - Medium Priority"
			prioBadge = "p2"
		}

		rec, verif, caveat := generateRemediationDetails(f)

		remediations = append(remediations, ReportRemediation{
			Priority:          prio,
			PriorityBadge:     prioBadge,
			FindingID:         f.ID,
			FindingTitle:      f.Title,
			AffectedComponent: f.AffectedTarget,
			Recommendation:    rec,
			VerificationStep:  verif,
			ResidualCaveat:    caveat,
		})
	}

	sort.Slice(remediations, func(i, j int) bool {
		pi := remediationWeight(remediations[i].PriorityBadge)
		pj := remediationWeight(remediations[j].PriorityBadge)
		if pi != pj {
			return pi > pj
		}
		return remediations[i].FindingTitle < remediations[j].FindingTitle
	})

	return remediations
}

func generateRemediationDetails(f ReportFinding) (rec string, verif string, caveat string) {
	ruleUpper := strings.ToUpper(f.RuleID)
	switch {
	case strings.Contains(ruleUpper, "DEBUGGABLE"):
		return "Set android:debuggable=\"false\" in AndroidManifest.xml for all release build variants. Ensure Gradle release build type specifies `debuggable false`.",
			"Decompile the release APK with `aapt2 dump badging <apk>` and confirm `application-debuggable` is absent.",
			"Debuggable flags left enabled allow local and remote attackers to attach debuggers and inspect application memory."

	case strings.Contains(ruleUpper, "BACKUP"):
		return "Set android:allowBackup=\"false\" in <application> or define a strict <data-extraction-rules> XML policy excluding private databases and shared preferences.",
			"Run `adb backup <package>` on a test device; the system must reject backup creation.",
			"Disabling backup protects against physical ADB extraction but does not substitute for file encryption."

	case strings.Contains(ruleUpper, "CLEARTEXT"):
		return "Set android:usesCleartextTraffic=\"false\" in AndroidManifest.xml and supply a res/xml/network_security_config.xml enforcing HTTPS.",
			"Configure Network Security Configuration with <base-config cleartextTrafficPermitted=\"false\" /> and re-run static analysis.",
			"Disabling cleartext prevents plaintext HTTP downgrade, but endpoints must also implement valid TLS certificates."

	case strings.Contains(ruleUpper, "SECRET") || strings.Contains(ruleUpper, "TOKEN") || strings.Contains(ruleUpper, "KEY"):
		return "Immediately revoke and rotate the exposed credential in the target provider's management console. Move authentication to runtime backend token exchange.",
			"Verify in the service console that the old token returns HTTP 401/403 and inspect new APK builds with `felix apk --analyze`.",
			"Rotating client-side keys does not revoke historical exposure in previously distributed APK binaries; audit access logs."

	case strings.Contains(ruleUpper, "EXPORTED") || strings.Contains(ruleUpper, "COMPONENT"):
		return "Set android:exported=\"false\" for internal activities, services, receivers, and providers. If external access is required, enforce a custom signature permission.",
			"Attempt invoking the component via `adb shell am start -n <package>/<component>`; verify the system denies the intent.",
			"Exported components lacking permission checks allow unauthorized third-party apps to invoke internal application workflows."

	default:
		rec = f.Remediation
		if rec == "" {
			rec = "Review component exposure and follow Android security architecture principles according to least privilege."
		}
		verif = "Re-analyze the modified APK artifact using FELIX to verify the finding no longer triggers."
		caveat = "Validate architectural changes against application functionality before deploying to production."
		return
	}
}

func severityWeight(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}

func remediationWeight(badge string) int {
	switch badge {
	case "p1":
		return 3
	case "p2":
		return 2
	case "p3":
		return 1
	default:
		return 0
	}
}

func categorizeServiceIndicator(ind string) string {
	lower := strings.ToLower(ind)
	switch {
	case strings.Contains(lower, "s3") || strings.Contains(lower, "storage") || strings.Contains(lower, "bucket"):
		return "Cloud Storage"
	case strings.Contains(lower, "firebase"):
		return "Firebase / Realtime DB"
	case strings.Contains(lower, "cognito") || strings.Contains(lower, "auth"):
		return "Authentication Service"
	case strings.Contains(lower, "mongo") || strings.Contains(lower, "redis") || strings.Contains(lower, "postgres") || strings.Contains(lower, "mysql"):
		return "Database / Cache"
	case strings.Contains(lower, "api") || strings.Contains(lower, "gateway"):
		return "API Gateway / Cloud"
	case strings.Contains(lower, "sentry") || strings.Contains(lower, "analytics") || strings.Contains(lower, "telemetry"):
		return "Telemetry & Monitoring"
	default:
		return "Cloud Service"
	}
}

func nonZeroOrDefault(val, def string) string {
	if strings.TrimSpace(val) == "" {
		return def
	}
	return val
}

func ternaryStr(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func truncateHash(h string) string {
	if len(h) <= 16 {
		return h
	}
	return h[:8] + "..." + h[len(h)-8:]
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB (%d bytes)", float64(b)/float64(div), "KMGTPE"[exp], b)
}

// SanitizeURLRedactingSensitiveQuery redacts sensitive query parameters and userinfo.
func SanitizeURLRedactingSensitiveQuery(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return secrets.RedactText(rawURL)
	}
	if parsed.User != nil {
		parsed.User = url.UserPassword("[REDACTED]", "[REDACTED]")
	}
	q := parsed.Query()
	for k := range q {
		kLower := strings.ToLower(k)
		if strings.Contains(kLower, "token") ||
			strings.Contains(kLower, "key") ||
			strings.Contains(kLower, "secret") ||
			strings.Contains(kLower, "auth") ||
			strings.Contains(kLower, "pass") ||
			strings.Contains(kLower, "code") {
			q.Set(k, "[REDACTED]")
		}
	}
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

// ToReport converts MobileReportData into a canonical FELIX report.Report.
func (data *MobileReportData) ToReport() report.Report {
	if data == nil {
		return report.Report{}
	}

	target := data.PackageName
	if target == "" || target == "Not available" {
		target = data.APKFileName
	}
	if target == "" {
		target = "unknown-apk"
	}

	targets := make([]string, 0, 2)
	if data.PackageName != "" && data.PackageName != "Not available" {
		targets = append(targets, data.PackageName)
	}
	if data.APKFileName != "" && data.APKFileName != "Not available" && data.APKFileName != data.PackageName {
		targets = append(targets, data.APKFileName)
	}
	if len(targets) == 0 {
		targets = append(targets, target)
	}

	status := "COMPLETED"
	if data.Status == "FAILED" || data.Status == "BLOCKED" || data.Status == "PARTIAL" {
		status = data.Status
	}

	var canonicalFindings []report.Finding
	if len(data.RawFindings) > 0 {
		for _, rf := range data.RawFindings {
			f := rf
			if f.Source == "" || f.Source == "manifest_analysis" || f.Source == "artifact_intelligence" || f.Source == "api" {
				f.Source = report.SourceAPK
			}
			if f.Target == "" {
				f.Target = target
			}
			if f.EvidenceDetails.Details == nil {
				f.EvidenceDetails.Details = make(map[string]string)
			}
			if data.PackageName != "" && data.PackageName != "Not available" {
				f.EvidenceDetails.Details["package_name"] = data.PackageName
			}
			if data.APKSHA256 != "" && data.APKSHA256 != "Not available" {
				f.EvidenceDetails.Details["apk_sha256"] = data.APKSHA256
			}
			if data.VersionName != "" && data.VersionName != "Not available" {
				f.EvidenceDetails.Details["version_name"] = data.VersionName
			}
			if data.VersionCode != "" && data.VersionCode != "Not available" {
				f.EvidenceDetails.Details["version_code"] = data.VersionCode
			}
			if f.Endpoint != "" {
				f.EvidenceDetails.Details["component_name"] = f.Endpoint
			}
			if f.Score == 0 {
				f.Score = report.SeverityRank(f.Severity) * 20
			}
			if f.ClassificationOutcome == "" {
				f.ClassificationOutcome = report.OutcomeConfirmed
			}
			if f.Status == "" {
				f.Status = report.FindingStatusConfirmed
			}
			canonicalFindings = append(canonicalFindings, f)
		}
	} else if len(data.Findings) > 0 {
		for _, rf := range data.Findings {
			sev := rf.Severity
			if sev == "" {
				sev = report.SeverityInfo
			}
			conf := rf.Confidence
			if conf == "" {
				conf = report.ConfidenceHigh
			}
			statusEnum := report.FindingStatusConfirmed
			if rf.Status != "" {
				statusEnum = report.FindingStatus(rf.Status)
			}

			details := map[string]string{
				"category": rf.Category,
			}
			if data.PackageName != "" && data.PackageName != "Not available" {
				details["package_name"] = data.PackageName
			}
			if data.APKSHA256 != "" && data.APKSHA256 != "Not available" {
				details["apk_sha256"] = data.APKSHA256
			}
			if data.VersionName != "" && data.VersionName != "Not available" {
				details["version_name"] = data.VersionName
			}
			if data.VersionCode != "" && data.VersionCode != "Not available" {
				details["version_code"] = data.VersionCode
			}
			if rf.AffectedTarget != "" {
				details["component_name"] = rf.AffectedTarget
			}

			cf := report.Finding{
				ID:                    rf.ID,
				RuleID:                rf.RuleID,
				Status:                statusEnum,
				ClassificationOutcome: report.OutcomeConfirmed,
				AnalysisMethod:        report.AnalysisMethodStatic,
				Category:              rf.Category,
				Title:                 rf.Title,
				Severity:              sev,
				Confidence:            conf,
				Target:                target,
				Endpoint:              rf.AffectedTarget,
				Method:                "STATIC_ANALYSIS",
				Description:           rf.Description,
				Evidence:              rf.Evidence,
				EvidenceDetails: report.EvidenceDetails{
					Observation:     rf.Evidence,
					Location:        rf.AffectedTarget,
					DetectionMethod: "static_apk_analysis",
					Details:         details,
				},
				Remediation: rf.Remediation,
				RemediationAdvice: &report.RemediationAdvice{
					Summary: rf.Remediation,
				},
				Source:      report.SourceAPK,
				Fingerprint: rf.Fingerprint,
				Score:       report.SeverityRank(sev) * 20,
				Timestamp:   time.Now().UTC(),
			}
			canonicalFindings = append(canonicalFindings, cf)
		}
	}

	mobileMeta := map[string]any{
		"apk_file_name":         data.APKFileName,
		"apk_sha256":            data.APKSHA256,
		"apk_file_size":         data.APKFileSize,
		"package_name":          data.PackageName,
		"version_name":          data.VersionName,
		"version_code":          data.VersionCode,
		"min_sdk":               data.MinSDK,
		"target_sdk":            data.TargetSDK,
		"compile_sdk":           data.CompileSDK,
		"dex_count":             data.DexCount,
		"multidex":              data.Multidex,
		"intake_status":         data.IntakeStatus,
		"manifest_status":       data.ManifestStatus,
		"assessment_status":     data.AssessmentStatus,
		"assessment_scope_mode": data.AssessmentScopeMode,
		"total_endpoints":       data.TotalEndpoints,
		"total_hosts":           data.TotalHosts,
		"analysis_mode":         data.AnalysisMode,
		"limitations":           data.Limitations,
	}

	rep := report.Report{
		Version:          "1.0.0",
		Target:           target,
		Targets:          targets,
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		CompletionStatus: status,
		Findings:         report.DeduplicateFindings(canonicalFindings),
		Metadata: map[string]any{
			"mobile_metadata": mobileMeta,
		},
	}

	report.RecalculateReportRisk(&rep)
	cr := report.BuildCommercialReport(rep, report.WithCompletionStatus(rep.CompletionStatus))
	rep.CommercialReport = &cr

	return rep
}
