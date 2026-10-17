package apk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"felix/pkg/report"
)

// ManifestAnalysisResult encapsulates the outcome of static Android manifest security analysis.
type ManifestAnalysisResult struct {
	Document              *ManifestDocument
	NetworkSecurityConfig *NetworkSecurityConfigInfo
	Findings              []report.Finding
	Limitations           []string
}

// AnalyzeManifest runs comprehensive security rules against an ingested and staged APK manifest.
func AnalyzeManifest(ctx context.Context, ws *Workspace, limits Limits) (*ManifestAnalysisResult, error) {
	if ws == nil || ws.Dir == "" {
		return nil, WrapError("analyze", "workspace is nil or uninitialized", ErrInvalidInput)
	}

	manifestRelPath := ws.ManifestPath
	if manifestRelPath == "" {
		manifestRelPath = "AndroidManifest.xml"
	}

	targetManifestPath, err := VerifyExtractionTarget(ws.Dir, manifestRelPath)
	if err != nil {
		return nil, WrapError("analyze", "manifest path escapes workspace", err)
	}

	fi, f, err := ValidateFileBasics(targetManifestPath, limits.MaxEntrySize)
	if err != nil {
		return nil, WrapError("analyze", "cannot access staged manifest file", err)
	}
	defer f.Close()

	manifestData := make([]byte, fi.Size())
	if _, err := f.Read(manifestData); err != nil {
		return nil, WrapError("analyze", "failed reading staged manifest", err)
	}

	return ParseAndAnalyzeManifest(ctx, manifestData, ws, limits)
}

// ParseAndAnalyzeManifest parses raw manifest data (AXML or textual XML) and performs static security analysis.
func ParseAndAnalyzeManifest(ctx context.Context, data []byte, ws *Workspace, limits Limits) (*ManifestAnalysisResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, WrapError("analyze", "context cancelled before manifest analysis", err)
	}

	// 1. Detect Manifest Format
	format := DetectManifestFormat(data)
	if format == FormatUnknown {
		return nil, WrapError("analyze", "unrecognized manifest format (neither AXML nor XML)", ErrNotAnAPK)
	}

	// 2. Parse into RawElement tree
	var (
		rawRoot *RawElement
		err     error
	)
	if format == FormatAXML {
		rawRoot, err = ParseAXML(data, limits)
	} else {
		rawRoot, err = ParseTextualManifest(data, limits)
	}
	if err != nil {
		return nil, WrapError("parse_manifest", "", err)
	}

	// 3. Extract structured ManifestDocument
	doc := ExtractManifestDocument(rawRoot, format)
	if doc == nil {
		return nil, WrapError("extract_doc", "failed to extract manifest document", ErrMalformedArchive)
	}

	var limitations []string

	// 4. Parse referenced Network Security Configuration if present
	var netConfig *NetworkSecurityConfigInfo
	if doc.Application.NetworkSecurityConfig != "" && ws != nil {
		cfg, nErr := ParseNetworkSecurityConfig(ws, doc.Application.NetworkSecurityConfig, limits)
		if nErr == nil && cfg != nil {
			netConfig = cfg
			if cfg.ParseError != "" {
				limitations = append(limitations, fmt.Sprintf("Network security config note: %s", cfg.ParseError))
			}
		} else {
			limitations = append(limitations, fmt.Sprintf("Could not parse referenced networkSecurityConfig %q: %v",
				doc.Application.NetworkSecurityConfig, nErr))
		}
	}

	// 5. Run Security Rules
	var findings []report.Finding

	// Rule 1: Debuggability
	findings = append(findings, analyzeDebuggability(doc)...)

	// Rule 2: Exported Components & Permissions
	findings = append(findings, analyzeComponentsAndPermissions(doc)...)

	// Rule 3: Deep Links & Intent Filters
	findings = append(findings, analyzeDeepLinks(doc)...)

	// Rule 4: Cleartext Traffic & Network Security
	findings = append(findings, analyzeNetworkSecurity(doc, netConfig)...)

	// Rule 5: Backup Configuration
	findings = append(findings, analyzeBackup(doc)...)

	// Document limitations
	if doc.TargetSDK > 0 {
		limitations = append(limitations, fmt.Sprintf("Target SDK: %d (rules evaluated against Android API %d semantics)",
			doc.TargetSDK, doc.TargetSDK))
	} else {
		limitations = append(limitations, "Target SDK omitted; evaluated under legacy default compatibility rules")
	}
	limitations = append(limitations, "AXML parser verified via internal synthetic test suites; independent third-party fixture provenance remains incompletely verified in this repository environment")
	limitations = append(limitations, "Network Security Config rules evaluate declarative policies; runtime TLS behavior of non-platform HTTP libraries (e.g. OkHttp, Flutter) cannot be verified from manifest alone")

	return &ManifestAnalysisResult{
		Document:              doc,
		NetworkSecurityConfig: netConfig,
		Findings:              report.DeduplicateFindings(findings),
		Limitations:           limitations,
	}, nil
}

// ----------------------------------------------------------------------------
// RULE 1: Application Debuggability
// ----------------------------------------------------------------------------

func analyzeDebuggability(doc *ManifestDocument) []report.Finding {
	var findings []report.Finding
	app := doc.Application

	if app.Debuggable != nil && *app.Debuggable {
		findings = append(findings, buildFinding(
			"APK-MAN-DEBUGGABLE",
			"android-debuggable",
			"Application Configured as Debuggable",
			report.SeverityHigh,
			report.ConfidenceHigh,
			doc.PackageName,
			"AndroidManifest.xml",
			"The application manifest explicitly declares android:debuggable=\"true\". In debuggable applications, the Java Debug Wire Protocol (JDWP) interface is active, permitting local processes or debuggers (via ADB) to execute arbitrary bytecode, inspect application memory, and extract sensitive data.",
			"android:debuggable=\"true\"",
			"Ensure android:debuggable is set to \"false\" (or omitted so it defaults to false) in production release builds.",
			map[string]string{
				"attribute":  "android:debuggable",
				"value":      "true",
				"risk_level": "Local process takeover via JDWP",
			},
			report.FindingStatusConfirmed,
		))
	} else if app.Debuggable != nil && !*app.Debuggable {
		findings = append(findings, buildFinding(
			"APK-MAN-DEBUGGABLE-DISABLED",
			"android-debuggable",
			"Application Debugging Explicitly Disabled",
			report.SeverityInfo,
			report.ConfidenceHigh,
			doc.PackageName,
			"AndroidManifest.xml",
			"The application explicitly declares android:debuggable=\"false\", preventing JDWP attachment.",
			"android:debuggable=\"false\"",
			"Maintain android:debuggable=\"false\" across all release artifacts.",
			map[string]string{
				"attribute": "android:debuggable",
				"value":     "false",
			},
			report.FindingStatusConfirmed,
		))
	}

	return findings
}

// ----------------------------------------------------------------------------
// RULE 2: Exported Components and Permission Protection
// ----------------------------------------------------------------------------

func analyzeComponentsAndPermissions(doc *ManifestDocument) []report.Finding {
	var findings []report.Finding
	app := doc.Application

	checkComponent := func(comp ComponentInfo) {
		isExported, reason := determineExportedState(comp, doc.TargetSDK)
		if !isExported {
			return
		}

		// Android 12+ (API 31+) explicit export requirement for components with intent filters
		if comp.Exported == nil && len(comp.IntentFilters) > 0 && doc.TargetSDK >= 31 {
			findings = append(findings, buildFinding(
				"APK-MAN-MISSING-EXPORTED-S",
				"android-exported-component",
				fmt.Sprintf("Omitted android:exported on Target SDK 31+ Component: %s", comp.ResolvedName),
				report.SeverityLow,
				report.ConfidenceHigh,
				doc.PackageName,
				comp.ResolvedName,
				fmt.Sprintf("Component %s declares intent filters but omits android:exported. Apps targeting Android 12 (API 31)+ that omit this attribute fail installation with INSTALL_PARSE_FAILED_MANIFEST_MALFORMED. On legacy devices (< Android 12), the component defaults to exported without permissions.", comp.ResolvedName),
				fmt.Sprintf("component=%s, targetSdkVersion=%d, intent_filters=%d, exported=omitted", comp.ResolvedName, doc.TargetSDK, len(comp.IntentFilters)),
				"Explicitly declare android:exported=\"true\" or android:exported=\"false\" on all components with intent filters to prevent installation failure and specify intent visibility.",
				map[string]string{
					"component_type": string(comp.Type),
					"declared_name":  comp.Name,
					"resolved_name":  comp.ResolvedName,
					"target_sdk":     fmt.Sprintf("%d", doc.TargetSDK),
					"issue_type":     "manifest_compliance_and_installability",
				},
				report.FindingStatusConfirmed,
			))
			return
		}

		// Check permissions
		hasPermission := comp.Permission != "" || app.Permission != ""
		permName := comp.Permission
		if permName == "" {
			permName = app.Permission
		}

		// Main launcher activity check
		if comp.Type == ComponentActivity && isMainLauncherActivity(comp) {
			findings = append(findings, buildFinding(
				"APK-MAN-LAUNCHER-EXPORTED",
				"android-exported-component",
				fmt.Sprintf("Main Launcher Activity Exported: %s", comp.ResolvedName),
				report.SeverityInfo,
				report.ConfidenceHigh,
				doc.PackageName,
				comp.ResolvedName,
				"The activity is exported to serve as the main launcher entry point for the application. This is expected standard behavior.",
				fmt.Sprintf("component=%s, exported=true (%s)", comp.ResolvedName, reason),
				"Ensure the launcher activity validates any inbound intent extras and does not perform privileged operations without authentication.",
				map[string]string{
					"component_type":  string(comp.Type),
					"declared_name":   comp.Name,
					"resolved_name":   comp.ResolvedName,
					"exported_reason": reason,
				},
				report.FindingStatusConfirmed,
			))
			return
		}

		// Deep link activity check (will be covered by deep link analysis)
		if isDeepLinkActivity(comp) {
			return
		}

		if !hasPermission {
			var (
				sev    = report.SeverityMedium
				ruleID = "APK-MAN-EXPORTED-COMPONENT"
				title  string
				desc   string
				remed  string
			)

			switch comp.Type {
			case ComponentService:
				title = fmt.Sprintf("Exported Service Without Permission: %s", comp.ResolvedName)
				desc = fmt.Sprintf("Service %s is exported without permission protection. Any application on the device can bind to or start this service, potentially triggering unauthorized actions.", comp.ResolvedName)
				remed = "Set android:exported=\"false\" or protect the service with android:permission."
			case ComponentReceiver:
				title = fmt.Sprintf("Exported Broadcast Receiver Without Permission: %s", comp.ResolvedName)
				desc = fmt.Sprintf("Broadcast receiver %s is exported without permission protection. Any application on the device can broadcast intents to this receiver.", comp.ResolvedName)
				remed = "Set android:exported=\"false\" or enforce signature-level permissions."
			default:
				title = fmt.Sprintf("Exported Activity Without Permission: %s", comp.ResolvedName)
				desc = fmt.Sprintf("Activity %s is exported without requiring permissions, allowing any application on the device to launch it directly.", comp.ResolvedName)
				remed = "Set android:exported=\"false\" if the activity is intended for internal use only."
			}

			findings = append(findings, buildFinding(
				ruleID,
				"android-exported-component",
				title,
				sev,
				report.ConfidenceHigh,
				doc.PackageName,
				comp.ResolvedName,
				desc,
				fmt.Sprintf("component=%s, exported=true (%s), permission=none", comp.ResolvedName, reason),
				remed,
				map[string]string{
					"component_type":  string(comp.Type),
					"declared_name":   comp.Name,
					"resolved_name":   comp.ResolvedName,
					"exported_reason": reason,
					"permission":      "none",
				},
				report.FindingStatusConfirmed,
			))
		} else {
			// Protected by permission -> Informational record
			findings = append(findings, buildFinding(
				"APK-MAN-EXPORTED-PROTECTED",
				"android-exported-component",
				fmt.Sprintf("Exported Component Protected by Permission: %s", comp.ResolvedName),
				report.SeverityInfo,
				report.ConfidenceHigh,
				doc.PackageName,
				comp.ResolvedName,
				fmt.Sprintf("Component %s is exported but protected by permission %q.", comp.ResolvedName, permName),
				fmt.Sprintf("component=%s, permission=%s", comp.ResolvedName, permName),
				"Ensure the declared permission uses signature or signatureOrSystem protection if restricted to authorized apps.",
				map[string]string{
					"component_type":  string(comp.Type),
					"resolved_name":   comp.ResolvedName,
					"permission":      permName,
					"exported_reason": reason,
				},
				report.FindingStatusConfirmed,
			))
		}
	}

	checkProvider := func(p ProviderInfo) {
		comp := p.ComponentInfo
		isExported, reason := determineExportedState(comp, doc.TargetSDK)
		if !isExported {
			return
		}

		// Content Providers can be protected by:
		// 1. Component android:permission or application-level android:permission (covers read & write)
		// 2. Both android:readPermission and android:writePermission
		hasGeneralPerm := comp.Permission != "" || app.Permission != ""
		generalPerm := comp.Permission
		if generalPerm == "" {
			generalPerm = app.Permission
		}

		hasReadPerm := hasGeneralPerm || p.ReadPermission != ""
		hasWritePerm := hasGeneralPerm || p.WritePermission != ""

		if hasReadPerm && hasWritePerm {
			permDesc := generalPerm
			if permDesc == "" {
				permDesc = fmt.Sprintf("read=%s, write=%s", p.ReadPermission, p.WritePermission)
			}
			findings = append(findings, buildFinding(
				"APK-MAN-EXPORTED-PROTECTED",
				"android-exported-component",
				fmt.Sprintf("Exported Content Provider Protected by Permission: %s", comp.ResolvedName),
				report.SeverityInfo,
				report.ConfidenceHigh,
				doc.PackageName,
				comp.ResolvedName,
				fmt.Sprintf("Content Provider %s is exported and protected by permissions (%s).", comp.ResolvedName, permDesc),
				fmt.Sprintf("component=%s, permissions=%s", comp.ResolvedName, permDesc),
				"Ensure the declared permissions use signature protection if provider access is intended only for trusted internal applications.",
				map[string]string{
					"component_type":   string(comp.Type),
					"resolved_name":    comp.ResolvedName,
					"permission":       permDesc,
					"read_permission":  p.ReadPermission,
					"write_permission": p.WritePermission,
					"exported_reason":  reason,
				},
				report.FindingStatusConfirmed,
			))
			return
		}

		if !hasReadPerm && !hasWritePerm {
			findings = append(findings, buildFinding(
				"APK-MAN-EXPORTED-PROVIDER",
				"android-exported-component",
				fmt.Sprintf("Exported Content Provider Without Permission: %s", comp.ResolvedName),
				report.SeverityHigh,
				report.ConfidenceHigh,
				doc.PackageName,
				comp.ResolvedName,
				fmt.Sprintf("Content Provider %s is exported without read or write permissions. Any application on the device can query or modify data through this provider.", comp.ResolvedName),
				fmt.Sprintf("component=%s, exported=true (%s), permission=none", comp.ResolvedName, reason),
				"Set android:exported=\"false\" unless inter-app sharing is required. If sharing is required, enforce android:readPermission and android:writePermission with signature protection.",
				map[string]string{
					"component_type":  string(comp.Type),
					"declared_name":   comp.Name,
					"resolved_name":   comp.ResolvedName,
					"exported_reason": reason,
					"permission":      "none",
				},
				report.FindingStatusConfirmed,
			))
			return
		}

		if !hasWritePerm {
			findings = append(findings, buildFinding(
				"APK-MAN-EXPORTED-PROVIDER-WRITE",
				"android-exported-component",
				fmt.Sprintf("Exported Content Provider Without Write Permission: %s", comp.ResolvedName),
				report.SeverityHigh,
				report.ConfidenceHigh,
				doc.PackageName,
				comp.ResolvedName,
				fmt.Sprintf("Content Provider %s specifies read permission (%s) but lacks write permission. Any application on the device can insert, update, or delete data through this provider.", comp.ResolvedName, p.ReadPermission),
				fmt.Sprintf("component=%s, readPermission=%s, writePermission=none", comp.ResolvedName, p.ReadPermission),
				"Enforce android:writePermission on the content provider or set android:exported=\"false\".",
				map[string]string{
					"component_type":   string(comp.Type),
					"resolved_name":    comp.ResolvedName,
					"read_permission":  p.ReadPermission,
					"write_permission": "none",
					"exported_reason":  reason,
				},
				report.FindingStatusConfirmed,
			))
			return
		}

		if !hasReadPerm {
			findings = append(findings, buildFinding(
				"APK-MAN-EXPORTED-PROVIDER-READ",
				"android-exported-component",
				fmt.Sprintf("Exported Content Provider Without Read Permission: %s", comp.ResolvedName),
				report.SeverityHigh,
				report.ConfidenceHigh,
				doc.PackageName,
				comp.ResolvedName,
				fmt.Sprintf("Content Provider %s specifies write permission (%s) but lacks read permission. Any application on the device can query sensitive data through this provider.", comp.ResolvedName, p.WritePermission),
				fmt.Sprintf("component=%s, readPermission=none, writePermission=%s", comp.ResolvedName, p.WritePermission),
				"Enforce android:readPermission on the content provider or set android:exported=\"false\".",
				map[string]string{
					"component_type":   string(comp.Type),
					"resolved_name":    comp.ResolvedName,
					"read_permission":  "none",
					"write_permission": p.WritePermission,
					"exported_reason":  reason,
				},
				report.FindingStatusConfirmed,
			))
			return
		}
	}

	for _, act := range app.Activities {
		checkComponent(act)
	}
	for _, alias := range app.ActivityAliases {
		checkComponent(alias.ComponentInfo)
	}
	for _, s := range app.Services {
		checkComponent(s)
	}
	for _, r := range app.Receivers {
		checkComponent(r)
	}
	for _, p := range app.Providers {
		checkProvider(p)
	}

	return findings
}

func determineExportedState(comp ComponentInfo, targetSDK int) (bool, string) {
	if comp.Exported != nil {
		if *comp.Exported {
			return true, "explicit android:exported=\"true\""
		}
		return false, "explicit android:exported=\"false\""
	}

	// Omitted android:exported
	hasIntentFilters := len(comp.IntentFilters) > 0

	if comp.Type == ComponentProvider {
		if targetSDK >= 17 {
			return false, "omitted android:exported (default false for ContentProvider on targetSDK >= 17)"
		}
		return true, "omitted android:exported (legacy default true for ContentProvider on targetSDK < 17)"
	}

	if hasIntentFilters {
		if targetSDK >= 31 {
			return true, "omitted android:exported with intent filters (Android 12+ requires explicit exported attribute; default resolved from intent filters)"
		}
		return true, "omitted android:exported with intent filters (default true on targetSDK < 31)"
	}

	return false, "omitted android:exported without intent filters (default false)"
}

func isMainLauncherActivity(comp ComponentInfo) bool {
	for _, f := range comp.IntentFilters {
		hasMain := false
		hasLauncher := false
		for _, a := range f.Actions {
			if a == "android.intent.action.MAIN" {
				hasMain = true
			}
		}
		for _, c := range f.Categories {
			if c == "android.intent.category.LAUNCHER" {
				hasLauncher = true
			}
		}
		if hasMain && hasLauncher {
			return true
		}
	}
	return false
}

func isDeepLinkActivity(comp ComponentInfo) bool {
	for _, f := range comp.IntentFilters {
		for _, d := range f.Data {
			if d.Scheme != "" {
				return true
			}
		}
	}
	return false
}

// ----------------------------------------------------------------------------
// RULE 3: Deep Link and Intent Filter Risks
// ----------------------------------------------------------------------------

func analyzeDeepLinks(doc *ManifestDocument) []report.Finding {
	var findings []report.Finding

	checkFilters := func(comp ComponentInfo) {
		for _, filter := range comp.IntentFilters {
			// Check if filter has VIEW and BROWSABLE (web link capability)
			hasView := false
			hasBrowsable := false
			for _, a := range filter.Actions {
				if a == "android.intent.action.VIEW" {
					hasView = true
				}
			}
			for _, c := range filter.Categories {
				if c == "android.intent.category.BROWSABLE" {
					hasBrowsable = true
				}
			}

			// Aggregate schemes and hosts across data tags in this filter
			var (
				schemes []string
				hosts   []string
			)
			for _, d := range filter.Data {
				if d.Scheme != "" {
					s := strings.ToLower(d.Scheme)
					found := false
					for _, existing := range schemes {
						if existing == s {
							found = true
							break
						}
					}
					if !found {
						schemes = append(schemes, s)
					}
				}
				if d.Host != "" {
					hosts = append(hosts, d.Host)
				}
			}

			primaryHost := ""
			if len(hosts) > 0 {
				primaryHost = hosts[0]
			}

			hasWebScheme := false
			for _, scheme := range schemes {
				if scheme == "http" || scheme == "https" {
					hasWebScheme = true
				}

				// 1. Custom URI Scheme
				if scheme != "http" && scheme != "https" {
					findings = append(findings, buildFinding(
						"APK-MAN-DEEPLINK-CUSTOM-SCHEME",
						"android-deep-link",
						fmt.Sprintf("Custom URI Scheme Deep Link (%s://) in %s", scheme, comp.ResolvedName),
						report.SeverityLow,
						report.ConfidenceHigh,
						doc.PackageName,
						comp.ResolvedName,
						fmt.Sprintf("Activity %s registers a custom URI scheme (%s://). Custom schemes cannot be cryptographically verified to belong to a specific publisher, allowing potential scheme collision or link hijacking by other installed applications.", comp.ResolvedName, scheme),
						fmt.Sprintf("scheme=%s, host=%s, component=%s", scheme, primaryHost, comp.ResolvedName),
						"Prefer Android App Links (verified HTTPS) over custom schemes. If custom schemes are required, thoroughly validate all incoming URI parameters and authenticate sensitive actions.",
						map[string]string{
							"scheme":         scheme,
							"host":           primaryHost,
							"component":      comp.ResolvedName,
							"deep_link_type": "custom_scheme",
						},
						report.FindingStatusConfirmed,
					))
				}

				// 2. Cleartext HTTP Deep Link
				if scheme == "http" {
					findings = append(findings, buildFinding(
						"APK-MAN-DEEPLINK-CLEARTEXT",
						"android-deep-link",
						fmt.Sprintf("Cleartext HTTP Deep Link Scheme in %s", comp.ResolvedName),
						report.SeverityLow,
						report.ConfidenceHigh,
						doc.PackageName,
						comp.ResolvedName,
						fmt.Sprintf("Activity %s declares an intent filter accepting unencrypted http:// links. Network attackers can spoof or manipulate cleartext HTTP links.", comp.ResolvedName),
						fmt.Sprintf("scheme=http, host=%s, component=%s", primaryHost, comp.ResolvedName),
						"Upgrade deep links to HTTPS and enable Android App Links with android:autoVerify=\"true\".",
						map[string]string{
							"scheme":    "http",
							"host":      primaryHost,
							"component": comp.ResolvedName,
						},
						report.FindingStatusConfirmed,
					))
				}
			}

			// 3. Broad Wildcard Path Patterns
			for _, d := range filter.Data {
				if d.PathPattern == ".*" || d.PathPattern == "/*" {
					findings = append(findings, buildFinding(
						"APK-MAN-DEEPLINK-BROAD-PATH",
						"android-deep-link",
						fmt.Sprintf("Broad Wildcard Path Pattern in %s", comp.ResolvedName),
						report.SeverityLow,
						report.ConfidenceMedium,
						doc.PackageName,
						comp.ResolvedName,
						fmt.Sprintf("Activity %s uses a catch-all pathPattern (%q) on host %q, which may capture unintended URLs.", comp.ResolvedName, d.PathPattern, d.Host),
						fmt.Sprintf("pathPattern=%s, host=%s", d.PathPattern, d.Host),
						"Constrain pathPattern to specific expected URL prefixes and routes.",
						map[string]string{
							"pathPattern": d.PathPattern,
							"host":        d.Host,
							"component":   comp.ResolvedName,
						},
						report.FindingStatusConfirmed,
					))
				}
			}

			// 4. AutoVerify analysis on Web Links
			if hasWebScheme && hasView && hasBrowsable {
				if filter.AutoVerify != nil && *filter.AutoVerify {
					findings = append(findings, buildFinding(
						"APK-MAN-DEEPLINK-AUTOVERIFY",
						"android-deep-link",
						fmt.Sprintf("Android App Link AutoVerify Declared on %s", comp.ResolvedName),
						report.SeverityInfo,
						report.ConfidenceHigh,
						doc.PackageName,
						comp.ResolvedName,
						"The intent filter declares android:autoVerify=\"true\". Static analysis establishes that the application requests automatic domain verification. Full App Links verification requires runtime confirmation that the specified domains host a matching /.well-known/assetlinks.json corresponding to the application's signing certificate.",
						"android:autoVerify=\"true\"",
						"Ensure the host domains serve a valid, matching assetlinks.json file with the correct app certificate SHA-256 fingerprint.",
						map[string]string{
							"autoVerify": "true",
							"component":  comp.ResolvedName,
						},
						report.FindingStatusConfirmed,
					))
				} else {
					findings = append(findings, buildFinding(
						"APK-MAN-DEEPLINK-NO-AUTOVERIFY",
						"android-deep-link",
						fmt.Sprintf("Web Link Intent Filter Without autoVerify: %s", comp.ResolvedName),
						report.SeverityInfo,
						report.ConfidenceHigh,
						doc.PackageName,
						comp.ResolvedName,
						fmt.Sprintf("Activity %s registers a web URL intent filter (http/https) without android:autoVerify=\"true\". Static analysis establishes that Android treats this as a standard Web Link rather than an Android App Link, showing a disambiguation chooser if another app claims the same web domain. This is not automatically exploitable by itself; determining whether link hijacking is viable requires domain verification, assetlinks.json inspection, and runtime testing.", comp.ResolvedName),
						"web intent-filter without android:autoVerify=\"true\"",
						"Declare android:autoVerify=\"true\" on web intent filters and host a valid Digital Asset Links file at https://<domain>/.well-known/assetlinks.json to enable exclusive Android App Links handling.",
						map[string]string{
							"component": comp.ResolvedName,
							"host":      primaryHost,
						},
						report.FindingStatusConfirmed,
					))
				}
			}
		}
	}

	for _, act := range doc.Application.Activities {
		checkFilters(act)
	}
	for _, alias := range doc.Application.ActivityAliases {
		checkFilters(alias.ComponentInfo)
	}

	return findings
}

// ----------------------------------------------------------------------------
// RULE 4: Network Security Configuration and Cleartext Traffic
// ----------------------------------------------------------------------------

func analyzeNetworkSecurity(doc *ManifestDocument, netConfig *NetworkSecurityConfigInfo) []report.Finding {
	var findings []report.Finding
	app := doc.Application

	// 1. android:usesCleartextTraffic
	if app.UsesCleartextTraffic != nil && *app.UsesCleartextTraffic {
		sev := report.SeverityLow
		desc := "The application permits unencrypted cleartext HTTP network traffic."
		if doc.TargetSDK >= 28 {
			sev = report.SeverityMedium
			desc = "The application targets Android API 28+ where cleartext traffic is disabled by default, but explicitly overrides this secure default with android:usesCleartextTraffic=\"true\"."
		}

		findings = append(findings, buildFinding(
			"APK-MAN-CLEARTEXT-ENABLED",
			"android-network-security",
			"Application Explicitly Permits Cleartext HTTP Traffic",
			sev,
			report.ConfidenceHigh,
			doc.PackageName,
			"AndroidManifest.xml",
			desc,
			"android:usesCleartextTraffic=\"true\"",
			"Enforce HTTPS across all network endpoints and set android:usesCleartextTraffic=\"false\" (or remove it on API 28+).",
			map[string]string{
				"attribute":  "android:usesCleartextTraffic",
				"value":      "true",
				"target_sdk": fmt.Sprintf("%d", doc.TargetSDK),
			},
			report.FindingStatusConfirmed,
		))
	}

	// 2. Network Security Config Inspection
	if netConfig != nil && netConfig.ConfigFound {
		if netConfig.BaseCleartextPermitted != nil && *netConfig.BaseCleartextPermitted {
			findings = append(findings, buildFinding(
				"APK-MAN-NETSEC-BASE-CLEARTEXT",
				"android-network-security",
				"Network Security Config Permits Base Cleartext Traffic",
				report.SeverityMedium,
				report.ConfidenceHigh,
				doc.PackageName,
				netConfig.ResolvedPath,
				"The network security configuration explicitly sets <base-config cleartextTrafficPermitted=\"true\">, allowing unencrypted HTTP connections across all domains.",
				"<base-config cleartextTrafficPermitted=\"true\">",
				"Disable cleartext traffic globally in network_security_config.xml by setting cleartextTrafficPermitted=\"false\".",
				map[string]string{
					"config_file": netConfig.ResolvedPath,
					"element":     "base-config",
				},
				report.FindingStatusConfirmed,
			))
		}

		if netConfig.UserTrustAnchors {
			findings = append(findings, buildFinding(
				"APK-MAN-NETSEC-USER-CERTS",
				"android-network-security",
				"Network Security Config Trusts User-Installed CA Certificates",
				report.SeverityHigh,
				report.ConfidenceHigh,
				doc.PackageName,
				netConfig.ResolvedPath,
				"The production network security configuration trusts user-installed certificates (<certificates src=\"user\"/>). An attacker or proxy user on the local network can intercept TLS traffic with a custom CA.",
				"<certificates src=\"user\"/> in production trust-anchors",
				"Remove user certificates from production <trust-anchors>. Restrict user CA trust to <debug-overrides> so it is never active in release builds.",
				map[string]string{
					"config_file": netConfig.ResolvedPath,
					"src":         "user",
				},
				report.FindingStatusConfirmed,
			))
		}

		if netConfig.DebugUserTrustAnchors {
			findings = append(findings, buildFinding(
				"APK-MAN-NETSEC-DEBUG-CERTS",
				"android-network-security",
				"User Certificates Permitted in Debug Overrides",
				report.SeverityInfo,
				report.ConfidenceHigh,
				doc.PackageName,
				netConfig.ResolvedPath,
				"User-installed certificates are trusted only when debugging is enabled via <debug-overrides>. This is standard practice for local testing.",
				"<debug-overrides><trust-anchors><certificates src=\"user\"/></debug-overrides>",
				"Ensure debug builds are never distributed to production end-users.",
				map[string]string{
					"config_file": netConfig.ResolvedPath,
					"scope":       "debug-overrides",
				},
				report.FindingStatusConfirmed,
			))
		}

		// Domain-specific cleartext rules
		for _, d := range netConfig.Domains {
			if d.CleartextPermitted != nil && *d.CleartextPermitted {
				findings = append(findings, buildFinding(
					"APK-MAN-NETSEC-DOMAIN-CLEARTEXT",
					"android-network-security",
					fmt.Sprintf("Network Security Config Permits Domain Cleartext: %s", d.Domain),
					report.SeverityLow,
					report.ConfidenceHigh,
					doc.PackageName,
					netConfig.ResolvedPath,
					fmt.Sprintf("The network security configuration explicitly permits cleartext HTTP traffic to domain %q (includeSubdomains=%t).", d.Domain, d.IncludeSubdomains),
					fmt.Sprintf("<domain-config cleartextTrafficPermitted=\"true\"> for domain %s", d.Domain),
					fmt.Sprintf("Enforce HTTPS for domain %s and remove cleartextTrafficPermitted=\"true\".", d.Domain),
					map[string]string{
						"config_file":        netConfig.ResolvedPath,
						"domain":             d.Domain,
						"include_subdomains": fmt.Sprintf("%t", d.IncludeSubdomains),
					},
					report.FindingStatusConfirmed,
				))
			}
			if d.UserTrustAnchors {
				findings = append(findings, buildFinding(
					"APK-MAN-NETSEC-DOMAIN-USER-CERTS",
					"android-network-security",
					fmt.Sprintf("Network Security Config Trusts User Certificates for Domain: %s", d.Domain),
					report.SeverityHigh,
					report.ConfidenceHigh,
					doc.PackageName,
					netConfig.ResolvedPath,
					fmt.Sprintf("The network security configuration trusts user-installed CA certificates for domain %q (includeSubdomains=%t).", d.Domain, d.IncludeSubdomains),
					fmt.Sprintf("<certificates src=\"user\"/> under domain %s", d.Domain),
					fmt.Sprintf("Remove user certificate trust for domain %s in production builds.", d.Domain),
					map[string]string{
						"config_file": netConfig.ResolvedPath,
						"domain":      d.Domain,
					},
					report.FindingStatusConfirmed,
				))
			}
		}

		// Certificate Pinning Declarations
		if len(netConfig.PinSets) > 0 {
			pinCount := 0
			for _, ps := range netConfig.PinSets {
				pinCount += len(ps.Pins)
			}
			findings = append(findings, buildFinding(
				"APK-MAN-NETSEC-PINNING",
				"android-network-security",
				fmt.Sprintf("Certificate Pinning Declared in Network Security Config (%d pin(s))", pinCount),
				report.SeverityInfo,
				report.ConfidenceHigh,
				doc.PackageName,
				netConfig.ResolvedPath,
				"The application declares certificate pinning policies in network_security_config.xml. Static analysis confirms the presence and syntax of declared pins. Note that runtime network clients (e.g. third-party HTTP libraries like OkHttp or Flutter) may bypass platform Network Security Config unless explicitly configured to use the system TrustManager.",
				fmt.Sprintf("pin_sets=%d, total_pins=%d", len(netConfig.PinSets), pinCount),
				"Ensure backup pins are defined and pin expiration dates are monitored to prevent denial of service upon certificate rotation.",
				map[string]string{
					"config_file": netConfig.ResolvedPath,
					"pin_sets":    fmt.Sprintf("%d", len(netConfig.PinSets)),
					"total_pins":  fmt.Sprintf("%d", pinCount),
				},
				report.FindingStatusConfirmed,
			))
		}
	}

	return findings
}

// ----------------------------------------------------------------------------
// RULE 5: Backup Configuration
// ----------------------------------------------------------------------------

func analyzeBackup(doc *ManifestDocument) []report.Finding {
	var findings []report.Finding
	app := doc.Application

	if app.AllowBackup == nil {
		// Documented Android default is true
		findings = append(findings, buildFinding(
			"APK-MAN-BACKUP-DEFAULT",
			"android-backup-config",
			"Application Backup Enabled by Default (android:allowBackup Omitted)",
			report.SeverityLow,
			report.ConfidenceHigh,
			doc.PackageName,
			"AndroidManifest.xml",
			"The application manifest does not declare android:allowBackup. In Android, android:allowBackup defaults to true when omitted, allowing local application data to be extracted via ADB backup or device-to-device transfers.",
			"android:allowBackup omitted (defaults to true)",
			"Explicitly declare android:allowBackup=\"false\" if the application stores sensitive user credentials, tokens, or databases, or define an XML backup rule policy excluding sensitive files.",
			map[string]string{
				"attribute": "android:allowBackup",
				"status":    "omitted",
				"default":   "true",
			},
			report.FindingStatusConfirmed,
		))
	} else if *app.AllowBackup {
		findings = append(findings, buildFinding(
			"APK-MAN-BACKUP-ENABLED",
			"android-backup-config",
			"Application Backup Explicitly Enabled (android:allowBackup=\"true\")",
			report.SeverityLow,
			report.ConfidenceHigh,
			doc.PackageName,
			"AndroidManifest.xml",
			"The application explicitly enables backup via android:allowBackup=\"true\". Users with ADB access can copy local application storage to a connected host machine.",
			"android:allowBackup=\"true\"",
			"If the application stores sensitive session tokens or databases, set android:allowBackup=\"false\" or define a fullBackupContent XML policy excluding sensitive files.",
			map[string]string{
				"attribute": "android:allowBackup",
				"value":     "true",
			},
			report.FindingStatusConfirmed,
		))
	} else {
		findings = append(findings, buildFinding(
			"APK-MAN-BACKUP-DISABLED",
			"android-backup-config",
			"Application Backup Explicitly Disabled",
			report.SeverityInfo,
			report.ConfidenceHigh,
			doc.PackageName,
			"AndroidManifest.xml",
			"The application explicitly declares android:allowBackup=\"false\", preventing extraction of application data via ADB backup.",
			"android:allowBackup=\"false\"",
			"Maintain android:allowBackup=\"false\" for production release artifacts handling sensitive data.",
			map[string]string{
				"attribute": "android:allowBackup",
				"value":     "false",
			},
			report.FindingStatusConfirmed,
		))
	}

	return findings
}

// ----------------------------------------------------------------------------
// Finding Builder Helper
// ----------------------------------------------------------------------------

func buildFinding(
	ruleID string,
	category string,
	title string,
	severity string,
	confidence string,
	target string,
	endpoint string,
	description string,
	observation string,
	remediation string,
	details map[string]string,
	status report.FindingStatus,
) report.Finding {
	hasher := sha256.New()
	hasher.Write([]byte(ruleID))
	hasher.Write([]byte(target))
	hasher.Write([]byte(endpoint))
	hasher.Write([]byte(title))
	hashHex := hex.EncodeToString(hasher.Sum(nil))[:12]

	id := fmt.Sprintf("apk-man-%s-%s", strings.ToLower(ruleID), hashHex)

	return report.Finding{
		ID:                    id,
		RuleID:                ruleID,
		Status:                status,
		ClassificationOutcome: report.OutcomeConfirmed,
		AnalysisMethod:        report.AnalysisMethodStatic,
		Category:              category,
		Title:                 title,
		Severity:              severity,
		Confidence:            confidence,
		Target:                target,
		Endpoint:              endpoint,
		Method:                "STATIC_ANALYSIS",
		Description:           description,
		Evidence:              observation,
		EvidenceDetails: report.EvidenceDetails{
			Observation:     observation,
			Location:        endpoint,
			DetectionMethod: "static_manifest_analysis",
			Details:         details,
		},
		Remediation: remediation,
		RemediationAdvice: &report.RemediationAdvice{
			Summary: remediation,
		},
		Source:      "apk",
		Fingerprint: hashHex,
		Score:       report.SeverityRank(severity) * 20,
		Timestamp:   time.Now().UTC(),
	}
}
