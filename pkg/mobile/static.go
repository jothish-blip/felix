package mobile

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// StaticAnalyzer inspects Android APK and iOS IPA packages.
type StaticAnalyzer struct {
	Limits ArchiveSecurityLimits
}

// NewStaticAnalyzer creates a StaticAnalyzer with default security limits.
func NewStaticAnalyzer() *StaticAnalyzer {
	return &StaticAnalyzer{
		Limits: DefaultArchiveLimits(),
	}
}

// NewStaticAnalyzerWithLimits creates a StaticAnalyzer with customized security limits.
func NewStaticAnalyzerWithLimits(limits ArchiveSecurityLimits) *StaticAnalyzer {
	return &StaticAnalyzer{
		Limits: limits,
	}
}

// InspectPackage inspects an APK or IPA file based on file extension.
func (a *StaticAnalyzer) InspectPackage(ctx context.Context, filePath string) (*PackageInspectionResult, error) {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".apk":
		return a.InspectAPKFile(ctx, filePath)
	case ".ipa":
		return a.InspectIPAFile(ctx, filePath)
	default:
		// Attempt auto-detection from archive contents
		return a.inspectAutoDetect(ctx, filePath)
	}
}

// InspectAPKFile opens and analyzes an Android APK from disk.
func (a *StaticAnalyzer) InspectAPKFile(ctx context.Context, filePath string) (*PackageInspectionResult, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open APK file %q: %w", filePath, err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat APK file %q: %w", filePath, err)
	}

	return a.InspectAPK(ctx, file, stat.Size(), filePath)
}

// InspectAPK analyzes an Android APK from an io.ReaderAt subject to security controls.
func (a *StaticAnalyzer) InspectAPK(ctx context.Context, r io.ReaderAt, size int64, packagePath string) (*PackageInspectionResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	res := &PackageInspectionResult{
		Platform:         PlatformAndroid,
		PackagePath:      packagePath,
		PackageSizeBytes: size,
		AnalyzedAt:       time.Now().UTC(),
		Findings:         make([]MobileFinding, 0),
	}

	// 1. Compute archive SHA-256
	if hasher, ok := r.(io.ReadSeeker); ok {
		h := sha256.New()
		if _, err := hasher.Seek(0, io.SeekStart); err == nil {
			if _, err := io.Copy(h, hasher); err == nil {
				res.PackageSHA256 = hex.EncodeToString(h.Sum(nil))
			}
			_, _ = hasher.Seek(0, io.SeekStart)
		}
	}

	// 2. Open safe zip archive
	zipReader, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("failed to read APK zip archive: %w", err)
	}
	safeReader, err := NewSafeZipReader(zipReader, &a.Limits)
	if err != nil {
		return nil, fmt.Errorf("APK archive security violation: %w", err)
	}
	res.Stats.TotalEntriesScanned = len(zipReader.File)

	// 3. Locate AndroidManifest.xml
	manifestEntry, err := safeReader.FindFirstMatchingEntry(func(name string) bool {
		return strings.EqualFold(name, "AndroidManifest.xml")
	})
	if err != nil && manifestEntry == nil {
		return nil, fmt.Errorf("AndroidManifest.xml not found in APK archive: %w", err)
	}

	// 4. Safely extract AndroidManifest.xml
	manifestData, err := safeReader.ReadTargetEntry(ctx, manifestEntry)
	if err != nil {
		return nil, fmt.Errorf("failed extracting AndroidManifest.xml: %w", err)
	}

	// 5. Parse manifest (AXML or textual)
	rootElem, err := ParseAndroidManifest(manifestData)
	if err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("manifest parse error: %v", err))
		// Inconclusive finding
		finding := MobileFinding{
			ID:             ComputeDeterministicFindingID(PlatformAndroid, packagePath, "MANIFEST-PARSE-FAILED", "AndroidManifest.xml"),
			RuleID:         "MANIFEST-PARSE-FAILED",
			Title:          "[Android] Malformed AndroidManifest.xml",
			Platform:       PlatformAndroid,
			PackageID:      packagePath,
			ComponentOrKey: "AndroidManifest.xml",
			ObservedValue:  "PARSE_ERROR",
			ExpectedValue:  "VALID_AXML_OR_XML",
			Severity:       "MEDIUM",
			Confidence:     "HIGH",
			Classification: ClassificationInconclusive,
			EvidenceSource: "AndroidManifest.xml",
			Explanation:    fmt.Sprintf("Failed to decode Android manifest: %v", err),
			Remediation:    "Ensure the APK was packaged with valid Android AAPT/AAPT2 resource tables.",
		}
		res.Findings = append(res.Findings, finding)
		res.Stats.InconclusiveFindings++
		return res, nil
	}

	// 6. Extract Android metadata and components
	meta, err := a.extractAndroidMetadata(rootElem)
	if err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("metadata extraction error: %v", err))
	}
	res.Android = meta

	// 7. Audit Application Security Flags & Components
	a.auditAndroidSecurity(meta, res)

	// 8. Aggregate Stats and Sort Findings
	a.aggregateAndroidStats(meta, res)
	SortFindings(res.Findings)

	return res, nil
}

// InspectIPAFile opens and analyzes an iOS IPA from disk.
func (a *StaticAnalyzer) InspectIPAFile(ctx context.Context, filePath string) (*PackageInspectionResult, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open IPA file %q: %w", filePath, err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat IPA file %q: %w", filePath, err)
	}

	return a.InspectIPA(ctx, file, stat.Size(), filePath)
}

// InspectIPA analyzes an iOS IPA from an io.ReaderAt subject to security controls.
func (a *StaticAnalyzer) InspectIPA(ctx context.Context, r io.ReaderAt, size int64, packagePath string) (*PackageInspectionResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	res := &PackageInspectionResult{
		Platform:         PlatformIOS,
		PackagePath:      packagePath,
		PackageSizeBytes: size,
		AnalyzedAt:       time.Now().UTC(),
		Findings:         make([]MobileFinding, 0),
	}

	// 1. Compute archive SHA-256
	if hasher, ok := r.(io.ReadSeeker); ok {
		h := sha256.New()
		if _, err := hasher.Seek(0, io.SeekStart); err == nil {
			if _, err := io.Copy(h, hasher); err == nil {
				res.PackageSHA256 = hex.EncodeToString(h.Sum(nil))
			}
			_, _ = hasher.Seek(0, io.SeekStart)
		}
	}

	// 2. Open safe zip archive
	zipReader, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("failed to read IPA zip archive: %w", err)
	}
	safeReader, err := NewSafeZipReader(zipReader, &a.Limits)
	if err != nil {
		return nil, fmt.Errorf("IPA archive security violation: %w", err)
	}
	res.Stats.TotalEntriesScanned = len(zipReader.File)

	// 3. Locate Payload/<AppName>.app/Info.plist
	plistEntry, err := safeReader.FindFirstMatchingEntry(func(name string) bool {
		lower := strings.ToLower(name)
		return strings.HasPrefix(lower, "payload/") && strings.HasSuffix(lower, ".app/info.plist")
	})
	if err != nil && plistEntry == nil {
		// Fallback: any Info.plist if payload prefix missing
		plistEntry, _ = safeReader.FindFirstMatchingEntry(func(name string) bool {
			return strings.EqualFold(filepath.Base(name), "Info.plist")
		})
	}
	if plistEntry == nil {
		return nil, errors.New("Info.plist not found in IPA archive")
	}

	// 4. Extract Info.plist safely
	plistData, err := safeReader.ReadTargetEntry(ctx, plistEntry)
	if err != nil {
		return nil, fmt.Errorf("failed extracting Info.plist: %w", err)
	}

	// 5. Parse Plist (XML or bplist00)
	parsed, err := ParsePlist(plistData)
	if err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("Info.plist parse error: %v", err))
		finding := MobileFinding{
			ID:             ComputeDeterministicFindingID(PlatformIOS, packagePath, "PLIST-PARSE-FAILED", plistEntry.Name),
			RuleID:         "PLIST-PARSE-FAILED",
			Title:          "[iOS] Malformed Info.plist",
			Platform:       PlatformIOS,
			PackageID:      packagePath,
			ComponentOrKey: plistEntry.Name,
			ObservedValue:  "PARSE_ERROR",
			ExpectedValue:  "VALID_PLIST",
			Severity:       "MEDIUM",
			Confidence:     "HIGH",
			Classification: ClassificationInconclusive,
			EvidenceSource: plistEntry.Name,
			Explanation:    fmt.Sprintf("Failed to decode iOS Info.plist: %v", err),
			Remediation:    "Ensure the IPA was packaged with a valid property list (XML or bplist00).",
		}
		res.Findings = append(res.Findings, finding)
		res.Stats.InconclusiveFindings++
		return res, nil
	}

	dict, ok := parsed.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("Info.plist root object is not a dictionary (type: %T)", parsed)
	}

	// 6. Extract iOS metadata
	meta := a.extractIOSMetadata(dict)
	res.IOS = meta

	// 7. Audit iOS Security (ATS & URL Schemes)
	a.auditIOSSecurity(meta, res)

	// 8. Aggregate Stats and Sort
	a.aggregateIOSStats(meta, res)
	SortFindings(res.Findings)

	return res, nil
}

func (a *StaticAnalyzer) inspectAutoDetect(ctx context.Context, filePath string) (*PackageInspectionResult, error) {
	// Try APK first
	res, err := a.InspectAPKFile(ctx, filePath)
	if err == nil {
		return res, nil
	}
	// Try IPA second
	resIPA, errIPA := a.InspectIPAFile(ctx, filePath)
	if errIPA == nil {
		return resIPA, nil
	}
	return nil, fmt.Errorf("unable to analyze package as APK (%v) or IPA (%v)", err, errIPA)
}

// -----------------------------------------------------------------------------
// Android Metadata Extraction
// -----------------------------------------------------------------------------

func (a *StaticAnalyzer) extractAndroidMetadata(root *XMLElement) (*AndroidMetadata, error) {
	meta := &AndroidMetadata{
		Components:           make([]AndroidComponent, 0),
		PermissionsRequested: make([]string, 0),
		PermissionsDeclared:  make([]string, 0),
	}

	// 1. Package name & Version
	if pkg, ok := root.GetAttr("package"); ok {
		meta.PackageName = pkg
	}
	if vcStr, ok := root.GetAttr("versionCode"); ok {
		if vc, err := strconv.Atoi(vcStr); err == nil {
			meta.VersionCode = vc
		}
	}
	if vn, ok := root.GetAttr("versionName"); ok {
		meta.VersionName = vn
	}

	// 2. Uses-SDK
	if usesSDK := root.FindChild("uses-sdk"); usesSDK != nil {
		if minStr, ok := usesSDK.GetAttr("minSdkVersion"); ok {
			if minVal, err := strconv.Atoi(minStr); err == nil {
				meta.MinSDK = minVal
			}
		}
		if tgtStr, ok := usesSDK.GetAttr("targetSdkVersion"); ok {
			if tgtVal, err := strconv.Atoi(tgtStr); err == nil {
				meta.TargetSDK = tgtVal
			}
		}
		if maxStr, ok := usesSDK.GetAttr("maxSdkVersion"); ok {
			if maxVal, err := strconv.Atoi(maxStr); err == nil {
				meta.MaxSDK = maxVal
			}
		}
	}
	if meta.TargetSDK == 0 && meta.MinSDK > 0 {
		meta.TargetSDK = meta.MinSDK
	}

	// 3. Permissions Requested & Declared
	for _, child := range root.Children {
		tag := child.Tag
		if strings.HasSuffix(tag, ":uses-permission") || tag == "uses-permission" {
			if perm, ok := child.GetAttr("name"); ok && perm != "" {
				meta.PermissionsRequested = append(meta.PermissionsRequested, perm)
			}
		} else if strings.HasSuffix(tag, ":permission") || tag == "permission" {
			if perm, ok := child.GetAttr("name"); ok && perm != "" {
				meta.PermissionsDeclared = append(meta.PermissionsDeclared, perm)
			}
		}
	}

	// 4. Application Element
	appElem := root.FindChild("application")
	if appElem != nil {
		// android:debuggable
		if dbgStr, ok := appElem.GetAttr("debuggable"); ok {
			meta.ExplicitDebuggable = true
			meta.Debuggable = strings.EqualFold(dbgStr, "true") || dbgStr == "1"
		} else {
			meta.Debuggable = false // Android default is false
		}

		// android:allowBackup
		if abStr, ok := appElem.GetAttr("allowBackup"); ok {
			meta.ExplicitAllowBackup = true
			meta.AllowBackup = strings.EqualFold(abStr, "true") || abStr == "1"
		} else {
			// Android default: allowBackup is true by default
			meta.AllowBackup = true
		}

		// android:usesCleartextTraffic
		if ctStr, ok := appElem.GetAttr("usesCleartextTraffic"); ok {
			meta.ExplicitCleartext = true
			meta.UsesCleartextTraffic = strings.EqualFold(ctStr, "true") || ctStr == "1"
		} else {
			// On targetSdkVersion >= 28 (Android 9 Pie), default is false; on older targets default is true
			if meta.TargetSDK >= 28 {
				meta.UsesCleartextTraffic = false
			} else {
				meta.UsesCleartextTraffic = true
			}
		}

		// android:networkSecurityConfig
		if nsc, ok := appElem.GetAttr("networkSecurityConfig"); ok {
			meta.NetworkSecurityConfig = nsc
		}

		// android:permission (application-level guard)
		if appPerm, ok := appElem.GetAttr("permission"); ok {
			meta.ApplicationPermission = appPerm
		}

		// 5. Components extraction: activities, services, receivers, providers
		a.extractComponents(appElem, meta)
	}

	return meta, nil
}

func (a *StaticAnalyzer) extractComponents(appElem *XMLElement, meta *AndroidMetadata) {
	for _, elem := range appElem.Children {
		tag := elem.Tag
		var cType ComponentType

		switch {
		case tag == "activity" || strings.HasSuffix(tag, ":activity"):
			cType = ComponentActivity
		case tag == "activity-alias" || strings.HasSuffix(tag, ":activity-alias"):
			cType = ComponentActivity
		case tag == "service" || strings.HasSuffix(tag, ":service"):
			cType = ComponentService
		case tag == "receiver" || strings.HasSuffix(tag, ":receiver"):
			cType = ComponentReceiver
		case tag == "provider" || strings.HasSuffix(tag, ":provider"):
			cType = ComponentProvider
		default:
			continue
		}

		rawName, _ := elem.GetAttr("name")
		if rawName == "" {
			continue
		}

		// Resolve component full class name
		fullName := rawName
		if strings.HasPrefix(rawName, ".") {
			fullName = meta.PackageName + rawName
		} else if !strings.Contains(rawName, ".") && meta.PackageName != "" {
			fullName = meta.PackageName + "." + rawName
		}

		// Permission
		perm, _ := elem.GetAttr("permission")
		if perm == "" {
			perm = meta.ApplicationPermission
		}

		readPerm, _ := elem.GetAttr("readPermission")
		writePerm, _ := elem.GetAttr("writePermission")

		// Enabled state (default true)
		enabled := true
		if enStr, ok := elem.GetAttr("enabled"); ok {
			enabled = !strings.EqualFold(enStr, "false") && enStr != "0"
		}

		// Intent Filters
		intentFilters := make([]IntentFilter, 0)
		hasLauncher := false

		for _, ifElem := range elem.FindChildren("intent-filter") {
			filter := IntentFilter{
				Actions:     make([]string, 0),
				Categories:  make([]string, 0),
				DataSchemes: make([]string, 0),
			}

			for _, act := range ifElem.FindChildren("action") {
				if actName, ok := act.GetAttr("name"); ok && actName != "" {
					filter.Actions = append(filter.Actions, actName)
				}
			}
			for _, cat := range ifElem.FindChildren("category") {
				if catName, ok := cat.GetAttr("name"); ok && catName != "" {
					filter.Categories = append(filter.Categories, catName)
					if catName == "android.intent.category.LAUNCHER" {
						for _, a := range filter.Actions {
							if a == "android.intent.action.MAIN" {
								hasLauncher = true
							}
						}
					}
				}
			}
			for _, dat := range ifElem.FindChildren("data") {
				if scheme, ok := dat.GetAttr("scheme"); ok && scheme != "" {
					filter.DataSchemes = append(filter.DataSchemes, scheme)
				}
			}

			if len(filter.Actions) > 0 || len(filter.Categories) > 0 || len(filter.DataSchemes) > 0 {
				intentFilters = append(intentFilters, filter)
			}
		}

		// Exported calculation
		exported := false
		explicitExported := false

		if expStr, ok := elem.GetAttr("exported"); ok {
			explicitExported = true
			exported = strings.EqualFold(expStr, "true") || expStr == "1"
		} else {
			// Android default rules:
			if cType == ComponentProvider {
				// Providers defaulted to true prior to SDK 17 (JellyBean MR1)
				if meta.TargetSDK < 17 && meta.TargetSDK > 0 {
					exported = true
				} else {
					exported = false
				}
			} else {
				// Activity, Service, Receiver: if intent filters present, defaults to true; otherwise false
				if len(intentFilters) > 0 {
					exported = true
				} else {
					exported = false
				}
			}
		}

		comp := AndroidComponent{
			Type:              cType,
			Name:              fullName,
			Exported:          exported,
			ExplicitExported:  explicitExported,
			Permission:        perm,
			ReadPermission:    readPerm,
			WritePermission:   writePerm,
			Enabled:           enabled,
			IntentFilters:     intentFilters,
			HasLauncherIntent: hasLauncher,
		}

		meta.Components = append(meta.Components, comp)
	}
}

// -----------------------------------------------------------------------------
// Android Security Audit
// -----------------------------------------------------------------------------

func (a *StaticAnalyzer) auditAndroidSecurity(meta *AndroidMetadata, res *PackageInspectionResult) {
	if meta == nil {
		return
	}
	packageID := meta.PackageName
	if packageID == "" {
		packageID = res.PackagePath
	}

	// 1. Audit Debuggable
	if meta.Debuggable {
		f := MobileFinding{
			ID:             ComputeDeterministicFindingID(PlatformAndroid, packageID, "APP-DEBUGGABLE", "android:debuggable"),
			RuleID:         "APP-DEBUGGABLE",
			Title:          "[Android] Application is Marked as Debuggable",
			Platform:       PlatformAndroid,
			PackageID:      packageID,
			ComponentOrKey: "android:debuggable",
			ObservedValue:  "true",
			ExpectedValue:  "false",
			Severity:       "CRITICAL",
			Confidence:     "HIGH",
			Classification: ClassificationConfirmed,
			EvidenceSource: "AndroidManifest.xml:<application android:debuggable=\"true\">",
			Explanation:    "android:debuggable is set to true. Attackers on rooted or developer-enabled devices can attach a JDWP debugger to execute arbitrary code within the application process.",
			Remediation:    "Ensure android:debuggable=\"false\" is set in production release builds.",
		}
		res.Findings = append(res.Findings, f)
	}

	// 2. Audit AllowBackup
	if meta.AllowBackup {
		severity := "MEDIUM"
		classification := ClassificationPotential
		if !meta.ExplicitAllowBackup {
			severity = "LOW"
		}
		f := MobileFinding{
			ID:             ComputeDeterministicFindingID(PlatformAndroid, packageID, "APP-ALLOW-BACKUP", "android:allowBackup"),
			RuleID:         "APP-ALLOW-BACKUP",
			Title:          "[Android] Application Backup Enabled",
			Platform:       PlatformAndroid,
			PackageID:      packageID,
			ComponentOrKey: "android:allowBackup",
			ObservedValue:  fmt.Sprintf("%v (explicit: %v)", meta.AllowBackup, meta.ExplicitAllowBackup),
			ExpectedValue:  "false",
			Severity:       severity,
			Confidence:     "HIGH",
			Classification: classification,
			EvidenceSource: "AndroidManifest.xml:<application android:allowBackup>",
			Explanation:    "android:allowBackup is enabled, permitting extracting local app data, databases, and private shared preferences via 'adb backup'.",
			Remediation:    "Set android:allowBackup=\"false\" unless system backup is explicitly intended.",
		}
		res.Findings = append(res.Findings, f)
	}

	// 3. Audit Cleartext Traffic
	if meta.UsesCleartextTraffic {
		severity := "HIGH"
		if meta.TargetSDK < 28 && !meta.ExplicitCleartext {
			severity = "MEDIUM"
		}
		f := MobileFinding{
			ID:             ComputeDeterministicFindingID(PlatformAndroid, packageID, "APP-CLEARTEXT-TRAFFIC", "android:usesCleartextTraffic"),
			RuleID:         "APP-CLEARTEXT-TRAFFIC",
			Title:          "[Android] Insecure Cleartext Traffic Allowed",
			Platform:       PlatformAndroid,
			PackageID:      packageID,
			ComponentOrKey: "android:usesCleartextTraffic",
			ObservedValue:  fmt.Sprintf("%v (explicit: %v, targetSDK: %d)", meta.UsesCleartextTraffic, meta.ExplicitCleartext, meta.TargetSDK),
			ExpectedValue:  "false",
			Severity:       severity,
			Confidence:     "HIGH",
			Classification: ClassificationConfirmed,
			EvidenceSource: "AndroidManifest.xml:<application android:usesCleartextTraffic>",
			Explanation:    "The application permits transmission of unencrypted HTTP cleartext traffic, exposing user credentials and data to network eavesdropping and MITM manipulation.",
			Remediation:    "Enforce TLS (HTTPS) across all network endpoints and configure android:networkSecurityConfig.",
		}
		res.Findings = append(res.Findings, f)
	}

	// 4. Audit Components (Activities, Services, Receivers, Providers)
	for _, comp := range meta.Components {
		if !comp.Enabled {
			continue // disabled components cannot be triggered externally
		}

		if comp.Exported {
			hasPerm := comp.Permission != ""
			if comp.Type == ComponentProvider {
				hasPerm = hasPerm || (comp.ReadPermission != "" && comp.WritePermission != "")
			}

			if !hasPerm {
				// If activity has launcher intent, it's an intended entry point
				if comp.Type == ComponentActivity && comp.HasLauncherIntent {
					f := MobileFinding{
						ID:             ComputeDeterministicFindingID(PlatformAndroid, packageID, "LAUNCHER-ACTIVITY-EXPORTED", comp.Name),
						RuleID:         "LAUNCHER-ACTIVITY-EXPORTED",
						Title:          fmt.Sprintf("[Android] Launcher Activity Exported (Normal Entry Point): %s", comp.Name),
						Platform:       PlatformAndroid,
						PackageID:      packageID,
						ComponentOrKey: comp.Name,
						ObservedValue:  "exported=true (LAUNCHER intent)",
						ExpectedValue:  "Normal system launcher access",
						Severity:       "INFO",
						Confidence:     "HIGH",
						Classification: ClassificationInfo,
						EvidenceSource: fmt.Sprintf("<activity android:name=%q android:exported=%v>", comp.Name, comp.Exported),
						Explanation:    "Component is the designated primary launcher activity for the Android app drawer.",
						Remediation:    "No action needed for main launcher activity.",
					}
					res.Findings = append(res.Findings, f)
					continue
				}

				// Otherwise, unprotected exported component!
				var ruleID string
				var title string
				var sev string
				switch comp.Type {
				case ComponentActivity:
					ruleID = "EXPORTED-ACTIVITY-UNPROTECTED"
					title = fmt.Sprintf("[Android] Exported Activity Exposed Without Permission: %s", comp.Name)
					sev = "HIGH"
				case ComponentService:
					ruleID = "EXPORTED-SERVICE-UNPROTECTED"
					title = fmt.Sprintf("[Android] Exported Service Exposed Without Permission: %s", comp.Name)
					sev = "HIGH"
				case ComponentReceiver:
					ruleID = "EXPORTED-RECEIVER-UNPROTECTED"
					title = fmt.Sprintf("[Android] Exported Broadcast Receiver Exposed Without Permission: %s", comp.Name)
					sev = "HIGH"
				case ComponentProvider:
					ruleID = "EXPORTED-PROVIDER-UNPROTECTED"
					title = fmt.Sprintf("[Android] Exported Content Provider Exposed Without Permission: %s", comp.Name)
					sev = "CRITICAL"
				}

				f := MobileFinding{
					ID:             ComputeDeterministicFindingID(PlatformAndroid, packageID, ruleID, comp.Name),
					RuleID:         ruleID,
					Title:          title,
					Platform:       PlatformAndroid,
					PackageID:      packageID,
					ComponentOrKey: comp.Name,
					ObservedValue:  fmt.Sprintf("exported=true, permission=none (explicitExported=%v)", comp.ExplicitExported),
					ExpectedValue:  "exported=false or protected with signature permission",
					Severity:       sev,
					Confidence:     "HIGH",
					Classification: ClassificationConfirmed,
					EvidenceSource: fmt.Sprintf("<%s android:name=%q android:exported=%v>", comp.Type, comp.Name, comp.Exported),
					Explanation:    fmt.Sprintf("Component %s of type %s is exported to all external applications without requiring any Android permission.", comp.Name, comp.Type),
					Remediation:    "Set android:exported=\"false\" if not intended for external invocation, or define android:permission.",
				}
				res.Findings = append(res.Findings, f)
			} else {
				// Exported but protected by permission
				f := MobileFinding{
					ID:             ComputeDeterministicFindingID(PlatformAndroid, packageID, "EXPORTED-COMPONENT-PROTECTED", comp.Name),
					RuleID:         "EXPORTED-COMPONENT-PROTECTED",
					Title:          fmt.Sprintf("[Android] Exported %s Protected by Permission (%s): %s", strings.Title(string(comp.Type)), comp.Permission, comp.Name),
					Platform:       PlatformAndroid,
					PackageID:      packageID,
					ComponentOrKey: comp.Name,
					ObservedValue:  fmt.Sprintf("exported=true, permission=%s", comp.Permission),
					ExpectedValue:  "Protected component",
					Severity:       "INFO",
					Confidence:     "HIGH",
					Classification: ClassificationInfo,
					EvidenceSource: fmt.Sprintf("<%s android:name=%q android:permission=%q>", comp.Type, comp.Name, comp.Permission),
					Explanation:    "Component is exported but appropriately guarded by an authorization permission.",
					Remediation:    "Verify that the required permission uses a robust protectionLevel (e.g., signature).",
				}
				res.Findings = append(res.Findings, f)
			}
		}
	}
}

// -----------------------------------------------------------------------------
// iOS Metadata Extraction
// -----------------------------------------------------------------------------

func (a *StaticAnalyzer) extractIOSMetadata(dict map[string]any) *IOSMetadata {
	meta := &IOSMetadata{
		URLSchemes: make([]string, 0),
		ATS: ATSConfig{
			ExceptionDomains: make([]ATSDomainException, 0),
		},
	}

	if bid, ok := dict["CFBundleIdentifier"].(string); ok {
		meta.BundleIdentifier = bid
	}
	if bName, ok := dict["CFBundleName"].(string); ok {
		meta.BundleName = bName
	}
	if dName, ok := dict["CFBundleDisplayName"].(string); ok {
		meta.DisplayName = dName
	}
	if vStr, ok := dict["CFBundleShortVersionString"].(string); ok {
		meta.VersionString = vStr
	}
	if bNum, ok := dict["CFBundleVersion"].(string); ok {
		meta.BuildNumber = bNum
	}
	if minOS, ok := dict["MinimumOSVersion"].(string); ok {
		meta.MinimumOSVersion = minOS
	}

	// CFBundleURLTypes -> CFBundleURLSchemes
	if urlTypes, ok := dict["CFBundleURLTypes"].([]any); ok {
		for _, ut := range urlTypes {
			if utMap, ok := ut.(map[string]any); ok {
				if schemes, ok := utMap["CFBundleURLSchemes"].([]any); ok {
					for _, sc := range schemes {
						if scStr, ok := sc.(string); ok && scStr != "" {
							meta.URLSchemes = append(meta.URLSchemes, scStr)
						}
					}
				}
			}
		}
	}

	// NSAppTransportSecurity
	if atsObj, ok := dict["NSAppTransportSecurity"].(map[string]any); ok {
		meta.ATS.Present = true
		if arb, ok := atsObj["NSAllowsArbitraryLoads"].(bool); ok {
			meta.ATS.AllowsArbitraryLoads = arb
		}
		if arbWeb, ok := atsObj["NSAllowsArbitraryLoadsInWebContent"].(bool); ok {
			meta.ATS.AllowsArbitraryLoadsInWebContent = arbWeb
		}
		if locNet, ok := atsObj["NSAllowsLocalNetworking"].(bool); ok {
			meta.ATS.AllowsLocalNetworking = locNet
		}

		if excDomains, ok := atsObj["NSExceptionDomains"].(map[string]any); ok {
			for domain, dVal := range excDomains {
				domExc := ATSDomainException{DomainName: domain}
				if dMap, ok := dVal.(map[string]any); ok {
					if incSub, ok := dMap["NSIncludesSubdomains"].(bool); ok {
						domExc.IncludesSubdomains = incSub
					}
					if allowInsec, ok := dMap["NSExceptionAllowsInsecureHTTPLoads"].(bool); ok {
						domExc.AllowsInsecureHTTPLoads = allowInsec
					}
					if minTLS, ok := dMap["NSExceptionMinimumTLSVersion"].(string); ok {
						domExc.MinimumTLSVersion = minTLS
					}
				}
				meta.ATS.ExceptionDomains = append(meta.ATS.ExceptionDomains, domExc)
			}
		}
	}

	return meta
}

// -----------------------------------------------------------------------------
// iOS Security Audit
// -----------------------------------------------------------------------------

func (a *StaticAnalyzer) auditIOSSecurity(meta *IOSMetadata, res *PackageInspectionResult) {
	if meta == nil {
		return
	}
	packageID := meta.BundleIdentifier
	if packageID == "" {
		packageID = res.PackagePath
	}

	// 1. Audit ATS NSAllowsArbitraryLoads
	if meta.ATS.AllowsArbitraryLoads {
		f := MobileFinding{
			ID:             ComputeDeterministicFindingID(PlatformIOS, packageID, "ATS-ARBITRARY-LOADS", "NSAppTransportSecurity:NSAllowsArbitraryLoads"),
			RuleID:         "ATS-ARBITRARY-LOADS",
			Title:          "[iOS] App Transport Security Disabled Globally",
			Platform:       PlatformIOS,
			PackageID:      packageID,
			ComponentOrKey: "NSAppTransportSecurity:NSAllowsArbitraryLoads",
			ObservedValue:  "true",
			ExpectedValue:  "false",
			Severity:       "HIGH",
			Confidence:     "HIGH",
			Classification: ClassificationConfirmed,
			EvidenceSource: "Info.plist:<key>NSAllowsArbitraryLoads</key><true/>",
			Explanation:    "NSAllowsArbitraryLoads is set to true, disabling Apple's App Transport Security globally and allowing cleartext HTTP communication.",
			Remediation:    "Remove NSAllowsArbitraryLoads or restrict exceptions to specific domains via NSExceptionDomains.",
		}
		res.Findings = append(res.Findings, f)
	}

	// 2. Audit ATS NSAllowsArbitraryLoadsInWebContent
	if meta.ATS.AllowsArbitraryLoadsInWebContent {
		f := MobileFinding{
			ID:             ComputeDeterministicFindingID(PlatformIOS, packageID, "ATS-WEBVIEW-ARBITRARY-LOADS", "NSAppTransportSecurity:NSAllowsArbitraryLoadsInWebContent"),
			RuleID:         "ATS-WEBVIEW-ARBITRARY-LOADS",
			Title:          "[iOS] App Transport Security Disabled for Web Views",
			Platform:       PlatformIOS,
			PackageID:      packageID,
			ComponentOrKey: "NSAppTransportSecurity:NSAllowsArbitraryLoadsInWebContent",
			ObservedValue:  "true",
			ExpectedValue:  "false",
			Severity:       "MEDIUM",
			Confidence:     "HIGH",
			Classification: ClassificationConfirmed,
			EvidenceSource: "Info.plist:<key>NSAllowsArbitraryLoadsInWebContent</key><true/>",
			Explanation:    "NSAllowsArbitraryLoadsInWebContent allows embedded web views to load arbitrary insecure HTTP URLs.",
			Remediation:    "Ensure all web content uses HTTPS.",
		}
		res.Findings = append(res.Findings, f)
	}

	// 3. Audit Domain Exceptions
	for _, dom := range meta.ATS.ExceptionDomains {
		if dom.AllowsInsecureHTTPLoads {
			f := MobileFinding{
				ID:             ComputeDeterministicFindingID(PlatformIOS, packageID, "ATS-DOMAIN-INSECURE-HTTP", dom.DomainName),
				RuleID:         "ATS-DOMAIN-INSECURE-HTTP",
				Title:          fmt.Sprintf("[iOS] ATS Insecure HTTP Allowed for Domain: %s", dom.DomainName),
				Platform:       PlatformIOS,
				PackageID:      packageID,
				ComponentOrKey: dom.DomainName,
				ObservedValue:  fmt.Sprintf("NSExceptionAllowsInsecureHTTPLoads=true (subdomains: %v)", dom.IncludesSubdomains),
				ExpectedValue:  "Secure HTTPS only",
				Severity:       "MEDIUM",
				Confidence:     "HIGH",
				Classification: ClassificationConfirmed,
				EvidenceSource: fmt.Sprintf("Info.plist:NSExceptionDomains[%s]", dom.DomainName),
				Explanation:    fmt.Sprintf("Domain %s is explicitly configured to allow insecure HTTP traffic.", dom.DomainName),
				Remediation:    "Enforce HTTPS on backend servers and remove domain HTTP exceptions.",
			}
			res.Findings = append(res.Findings, f)
		}

		if dom.MinimumTLSVersion == "TLSv1.0" || dom.MinimumTLSVersion == "TLSv1.1" {
			f := MobileFinding{
				ID:             ComputeDeterministicFindingID(PlatformIOS, packageID, "ATS-WEAK-TLS", dom.DomainName),
				RuleID:         "ATS-WEAK-TLS",
				Title:          fmt.Sprintf("[iOS] Deprecated Minimum TLS Version Allowed for Domain: %s", dom.DomainName),
				Platform:       PlatformIOS,
				PackageID:      packageID,
				ComponentOrKey: dom.DomainName,
				ObservedValue:  dom.MinimumTLSVersion,
				ExpectedValue:  "TLSv1.2 or TLSv1.3",
				Severity:       "MEDIUM",
				Confidence:     "HIGH",
				Classification: ClassificationConfirmed,
				EvidenceSource: fmt.Sprintf("Info.plist:NSExceptionDomains[%s]:NSExceptionMinimumTLSVersion", dom.DomainName),
				Explanation:    fmt.Sprintf("Domain %s allows outdated and deprecated TLS protocol versions (%s).", dom.DomainName, dom.MinimumTLSVersion),
				Remediation:    "Upgrade server to TLSv1.2 or TLSv1.3 and require minimum TLSv1.2 in ATS.",
			}
			res.Findings = append(res.Findings, f)
		}
	}

	// 4. Audit Custom URL Schemes
	for _, scheme := range meta.URLSchemes {
		f := MobileFinding{
			ID:             ComputeDeterministicFindingID(PlatformIOS, packageID, "CUSTOM-URL-SCHEME", scheme),
			RuleID:         "CUSTOM-URL-SCHEME",
			Title:          fmt.Sprintf("[iOS] Custom URL Scheme Registered: %s", scheme),
			Platform:       PlatformIOS,
			PackageID:      packageID,
			ComponentOrKey: scheme,
			ObservedValue:  scheme,
			ExpectedValue:  "Validated deep links / Universal Links",
			Severity:       "INFO",
			Confidence:     "HIGH",
			Classification: ClassificationInfo,
			EvidenceSource: fmt.Sprintf("Info.plist:CFBundleURLTypes:CFBundleURLSchemes[%s]", scheme),
			Explanation:    fmt.Sprintf("Application registers custom URL scheme %q. Any application can query or trigger this scheme; ensure all parameters are strictly validated.", scheme),
			Remediation:    "Adopt Universal Links where possible to prevent scheme hijacking by malicious apps.",
		}
		res.Findings = append(res.Findings, f)
	}
}

// -----------------------------------------------------------------------------
// Stats Aggregation
// -----------------------------------------------------------------------------

func (a *StaticAnalyzer) aggregateAndroidStats(meta *AndroidMetadata, res *PackageInspectionResult) {
	if meta == nil {
		return
	}
	res.Stats.TotalComponents = len(meta.Components)
	for _, c := range meta.Components {
		switch c.Type {
		case ComponentActivity:
			res.Stats.ActivitiesCount++
		case ComponentService:
			res.Stats.ServicesCount++
		case ComponentReceiver:
			res.Stats.ReceiversCount++
		case ComponentProvider:
			res.Stats.ProvidersCount++
		}
		if c.Exported {
			res.Stats.ExportedComponents++
			hasPerm := c.Permission != ""
			if c.Type == ComponentProvider {
				hasPerm = hasPerm || (c.ReadPermission != "" && c.WritePermission != "")
			}
			if hasPerm {
				res.Stats.ProtectedExported++
			} else {
				res.Stats.UnprotectedExported++
			}
		}
	}
	a.countFindingClassifications(res)
}

func (a *StaticAnalyzer) aggregateIOSStats(meta *IOSMetadata, res *PackageInspectionResult) {
	if meta == nil {
		return
	}
	res.Stats.URLSchemesCount = len(meta.URLSchemes)
	a.countFindingClassifications(res)
}

func (a *StaticAnalyzer) countFindingClassifications(res *PackageInspectionResult) {
	for _, f := range res.Findings {
		switch f.Classification {
		case ClassificationConfirmed:
			res.Stats.ConfirmedFindings++
		case ClassificationPotential:
			res.Stats.PotentialFindings++
		case ClassificationInfo:
			res.Stats.InfoFindings++
		case ClassificationInconclusive:
			res.Stats.InconclusiveFindings++
		}
	}
}
